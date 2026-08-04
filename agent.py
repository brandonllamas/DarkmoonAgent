#!/usr/bin/env python3
"""
HackerAgent v2 - Agente de terminal para auditorías de ciberseguridad con Ollama
Mejoras v2: resumen incremental, timeouts por herramienta, circuit breaker,
            recon paralelo, cache por target, nuclei JSON, ranking de modelos.
"""

import subprocess
import requests
from requests.adapters import HTTPAdapter
import json
import re
import argparse
import sys
import os
import threading
import queue
import time
import itertools
import database
from pathlib import Path
from datetime import datetime

# ── Skills ────────────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
try:
    from skills import (load_skills, run_skill, skills_context as _skills_context,
                        skill_names, skills_by_category as _skills_by_category,
                        CATEGORY_LABELS, CATEGORY_ORDER)
    _SKILLS_AVAILABLE = True
except ImportError:
    _SKILLS_AVAILABLE = False
    def load_skills(): return {}
    def run_skill(name, **kw): return {"success": False, "output": "skills no disponibles", "findings": []}
    def _skills_context(enabled=None): return ""
    def skill_names(): return []
    def _skills_by_category(enabled=None): return {}
    CATEGORY_LABELS = {}
    CATEGORY_ORDER  = []

# ── Cargar .env ───────────────────────────────────────────────────────────────
_env_file = Path(__file__).parent / ".env"
if _env_file.exists():
    for _line in _env_file.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))

# ── Tool Manager (auto-install) ──────────────────────────────────────────────
_HAVE_TOOL_MANAGER = False
try:
    import tool_manager
    _HAVE_TOOL_MANAGER = True
except ImportError:
    tool_manager = None  # type: ignore

# ── Colores ANSI ──────────────────────────────────────────────────────────────
R       = "\033[0m"
BOLD    = "\033[1m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
DIM     = "\033[2m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"
BLUE    = "\033[94m"

# ── Rutas de salida ───────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
OUT_DIR    = BASE_DIR / "out"
ENV_FILE   = BASE_DIR / ".env"
CONFS_FILE = BASE_DIR / "confs.json"
OLLAMA_URL       = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")
LMSTUDIO_URL     = os.environ.get("LMSTUDIO_URL", "http://localhost:1234/v1")
DEEPSEEK_API_URL = os.environ.get("DEEPSEEK_API_URL", "https://api.deepseek.com/v1")
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
DEEPSEEK_MODEL   = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")  # deepseek-chat (V3) o deepseek-reasoner (R1)
LLM_BACKEND      = "ollama"   # "ollama", "lmstudio" o "deepseek" — se setea en main()
VERBOSE          = False
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Reutilizar conexiones reduce de forma visible la latencia de los ciclos
# multi-turno y de los SubAgents, especialmente con la API remota de DeepSeek.
_HTTP = requests.Session()
_HTTP.mount("http://", HTTPAdapter(pool_connections=16, pool_maxsize=32))
_HTTP.mount("https://", HTTPAdapter(pool_connections=16, pool_maxsize=32))
_DEEPSEEK_CHECK_CACHE = {"ts": 0.0, "value": None}


def sanitize_target(target: str) -> str:
    t = target.strip()
    for proto in ("https://", "http://", "ftp://"):
        if t.startswith(proto):
            t = t[len(proto):]
    t = t.split("/")[0].split("?")[0].split("#")[0]
    if ":" in t and not t.replace(".", "").replace(":", "").isdigit():
        t = t.rsplit(":", 1)[0]
    t = "".join(c if c.isalnum() or c in ".-_" else "_" for c in t)
    return t.strip("._-") or "target"


def get_target_outdir(target: str) -> Path:
    name = sanitize_target(target) if target else "misc"
    d = OUT_DIR / name
    d.mkdir(parents=True, exist_ok=True)
    return d

# ── Ranking de modelos ────────────────────────────────────────────────────────
_MODEL_RANK = [
    # (keyword_en_nombre, estrellas, descripcion)
    ("deepseek-r1:32b",      5, "MEJOR · razonamiento profundo · 32B · lento"),
    ("deepseek-r1:14b",      5, "RECOMENDADO · razonamiento · 14B · equilibrado"),
    ("deepseek-r1",          4, "chain-of-thought · contexto 64K"),
    ("deepseek-coder-v2",    4, "especializado código/ASM · 128K ctx"),
    ("qwen2.5-coder:32b",    4, "código avanzado · 32B"),
    ("qwen2.5-coder",        4, "código + pentesting · 128K ctx"),
    ("dolphin3",             4, "sin censura · 131K ctx · rápido"),
    ("dolphin-mixtral",      3, "sin censura · MoE · necesita >24GB RAM"),
    ("dolphin-mistral",      2, "sin censura · ⚠ ctx 8K — context overflow"),
    ("dolphin-llama3",       2, "sin censura · ⚠ ctx 8K pequeño"),
    ("dolphin",              2, "sin censura"),
    ("nous-hermes2",         3, "permisivo · buen razonamiento"),
    ("phind-codellama",      3, "código + hacking · sin censura"),
    ("codellama",            3, "código · pentesting"),
    ("llama3.1",             3, "bueno general · 128K ctx"),
    ("llama3.2",             3, "bueno general · 128K ctx"),
    ("llama3",               3, "bueno general"),
    ("mistral",              3, "rápido · 32K ctx"),
    ("wizard-vicuna-uncens", 2, "sin censura · modelo antiguo"),
]

def score_model(name: str) -> tuple:
    nl = name.lower()
    for kw, stars, desc in _MODEL_RANK:
        if kw in nl:
            return stars, desc
    return 2, "modelo general"

# ── Timeouts por herramienta ──────────────────────────────────────────────────
_CMD_TIMEOUTS = {
    "nmap":          600,
    "gobuster":      360,
    "ffuf":          360,
    "wfuzz":         360,
    "feroxbuster":   360,
    "dirsearch":     300,
    "wpscan":        300,
    "nuclei":        600,
    "sqlmap":        600,
    "hydra":         600,
    "hashcat":      1800,
    "john":         1800,
    "msfconsole":    180,
    "nikto":         300,
    "wapiti":        300,
    "enum4linux":    120,
    "crackmapexec":  120,
    "netexec":       120,
    "subfinder":      60,
    "amass":         180,
    "theharvester":   90,
    "httpx":          60,
    "dnsx":           30,
    "dnsrecon":       60,
    "whatweb":        30,
    "wafw00f":        30,
    "searchsploit":   20,
    "curl":           20,
    "wget":           30,
    "dig":            10,
    "whois":          10,
}

def get_cmd_timeout(cmd: str) -> int:
    first = Path(cmd.strip().split()[0]).name.lower() if cmd.strip() else ""
    for k, v in _CMD_TIMEOUTS.items():
        if first.startswith(k):
            return v
    return 300

# ── Herramientas paralelas (recon pasivo sin side-effects) ───────────────────
_PARALLEL_SAFE = {
    "subfinder", "amass", "theharvester", "whatweb", "wafw00f",
    "httpx", "dnsx", "dnsrecon", "dig", "whois", "curl", "wget",
    "nslookup", "host", "ping",
}

def is_parallel_safe(cmd: str) -> bool:
    first = Path(cmd.strip().split()[0]).name.lower() if cmd.strip() else ""
    return first in _PARALLEL_SAFE

# ── Circuit Breaker — detecta bucles de comandos similares ───────────────────
class CircuitBreaker:
    def __init__(self, max_repeats: int = 3):
        self._max = max_repeats
        self._history: list = []

    def _sig(self, cmd: str) -> str:
        parts = cmd.strip().split()
        return " ".join(parts[:2]).lower()

    def tripped(self, cmds: list) -> bool:
        for cmd in cmds:
            sig = self._sig(cmd)
            recent = [self._sig(c) for c in self._history[-(self._max * 2):]]
            if recent.count(sig) >= self._max:
                return True
        return False

    def record(self, cmds: list):
        self._history.extend(cmds)

# ── Scan Cache — evita re-escanear mismos objetivos ──────────────────────────
_CACHEABLE_TOOLS = {
    "nmap", "subfinder", "amass", "gobuster", "ffuf", "dirsearch",
    "feroxbuster", "whatweb", "wafw00f", "httpx", "dnsx", "enum4linux",
}

class ScanCache:
    def __init__(self, target_dir: Path):
        self.project_id = target_dir.name

    def _key(self, cmd: str) -> str:
        return re.sub(r"\s+", " ", cmd.strip())

    def _cacheable(self, cmd: str) -> bool:
        first = Path(cmd.strip().split()[0]).name.lower() if cmd.strip() else ""
        return first in _CACHEABLE_TOOLS

    def get(self, cmd: str) -> dict | None:
        if not self._cacheable(cmd):
            return None
        entry = database.get_cache(self._key(cmd))
        if entry and entry["project_id"] == self.project_id:
            age_h = (time.time() - entry["ts"]) / 3600
            if age_h < 24:
                return {"stdout": entry["stdout"], "stderr": entry["stderr"], "code": entry["code"]}
        return None

    def put(self, cmd: str, stdout: str, stderr: str, code: int):
        if not self._cacheable(cmd):
            return
        database.put_cache(self.project_id, self._key(cmd), stdout, stderr, code, time.time())

# ── SubAgent — agente ligero por tarea ───────────────────────────────────────
class SubAgent:
    """
    Agente con contexto propio que analiza el output de un skill en un hilo separado.
    El agente principal recibe solo un resumen compacto, manteniendo su conversación limpia.
    """

    _SYSTEM = (
        "Eres un analista de ciberseguridad especializado. Recibirás el output de una herramienta "
        "de pentesting ejecutada sobre un objetivo.\n"
        "Tu misión: analizar el output y extraer SOLO lo relevante.\n"
        "Devuelve ÚNICAMENTE un JSON con esta estructura (sin texto extra):\n"
        "{\n"
        '  "summary": "2-3 líneas en español: qué encontraste, qué riesgo supone",\n'
        '  "key_findings": [\n'
        '    {"severity": "critical|high|medium|low|info", "description": "hallazgo concreto"}\n'
        "  ],\n"
        '  "next_step": "acción concreta recomendada para el agente principal (1 línea)",\n'
        '  "task_complete": false\n'
        "}\n"
        "Máximo 5 key_findings. Prioriza severity critical y high."
    )

    def __init__(self, model: str, skill_name: str, skill_output: str, target: str = ""):
        self.model        = model
        self.skill_name   = skill_name
        self.skill_output = skill_output
        self.target       = target
        self.result: dict = {}
        self._q           = queue.Queue()
        self._thread: threading.Thread | None = None

    def _run(self):
        prompt = f"Skill ejecutado: {self.skill_name}"
        if self.target:
            prompt += f"  |  Objetivo: {self.target}"
        prompt += f"\n\nOutput ({len(self.skill_output)} chars):\n{self.skill_output[:6000]}"
        try:
            messages = [
                {"role": "system", "content": self._SYSTEM},
                {"role": "user",   "content": prompt},
            ]
            content = call_llm_raw(self.model, messages, json_mode=True,
                                   temperature=0.1, ctx_size=4096, timeout=120)
            try:
                self.result = json.loads(content)
            except json.JSONDecodeError:
                s, e = content.find("{"), content.rfind("}") + 1
                if s != -1 and e > s:
                    try:
                        self.result = json.loads(content[s:e])
                    except Exception:
                        self.result = {"summary": content[:400], "key_findings": [], "next_step": ""}
                else:
                    self.result = {"summary": content[:400], "key_findings": [], "next_step": ""}
        except Exception as exc:
            self.result = {"summary": f"[SubAgent error: {exc}]", "key_findings": [], "next_step": ""}
        finally:
            self._q.put(self.result)

    def start(self) -> "SubAgent":
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def join(self, timeout: int = 130) -> dict:
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return {"summary": "[SubAgent timeout]", "key_findings": [], "next_step": ""}


# ── Carga de herramientas desde confs.json ────────────────────────────────────
def load_tool_confs() -> list:
    if not CONFS_FILE.exists():
        return []
    try:
        data = json.loads(CONFS_FILE.read_text(encoding="utf-8"))
        return data.get("tools", [])
    except Exception:
        return []


def build_tools_context(tools: list) -> str:
    if not tools:
        return ""
    lines = ["\nHERRAMIENTAS CONFIGURADAS EN confs.json (usa ESTAS rutas/comandos):"]
    for t in tools:
        name   = t.get("name", "?")
        cmd    = t.get("command", "").strip()
        path   = t.get("path", "").strip()
        github = t.get("github", "").strip()
        if path and cmd:
            usage = f"comando: `{cmd}`, ruta de datos: `{path}`"
        elif cmd:
            usage = f"comando: `{cmd}`"
        elif path:
            usage = f"ruta: `{path}` (sin comando directo)"
        else:
            usage = "disponible (ver GitHub)"
        line = f"- **{name}**: {usage}"
        if github:
            line += f"  [{github.split('/')[-1]}]"
        lines.append(line)
        if name.lower() == "seclist" and path:
            lines.append(f"  → gobuster: `{path}/Discovery/Web-Content/common.txt`")
            lines.append(f"  → ffuf:     `{path}/Discovery/Web-Content/raft-medium-words.txt`")
        elif name.lower() == "dirsearch" and cmd:
            lines.append(f"  → Uso: `{cmd} -u <url> -e php,html,js,txt`")
        elif name.lower() == "nuclei" and cmd:
            tpl = _NUCLEI_TEMPLATES_PATH or "~/nuclei-templates"
            lines.append(f"  → Templates detectados: `{tpl}`")
            lines.append(f"  → Uso: `{cmd} -u <url> -t {tpl}/cves/ -t {tpl}/vulnerabilities/ -json-export /tmp/nuclei_out.json`")
            lines.append(f"  → O usa: SKILL:nuclei_scan target=<url> categories=cves,vulnerabilities")
    lines.append("\nNOTA: Si una herramienta tiene 'path' configurado, úsalo en vez del path del sistema.")
    lines.append("IMPORTANTE: Verifica que existe con `which <comando>` antes de usar.")
    lines.append("Si no está instalada, usa el campo 'install' de confs.json.")
    lines.append("\nMETODOLOGÍA INICIAL OBLIGATORIA (SIEMPRE al recibir un objetivo nuevo):")
    lines.append("Cuando el usuario diga 'hackea X' o proporcione un dominio/IP, SIEMPRE sigue este orden:")
    lines.append("1. RECONOCIMIENTO PASIVO PRIMERO (en paralelo):")
    lines.append("   a) SKILL:shodan_search query=<dominio_o_IP> → puertos abiertos, servicios, tecnologías, ISP, geo")
    lines.append("   b) dig +short <dominio> → resolver IP real (puede revelar IP detrás de Cloudflare)")
    lines.append("   c) whois <dominio> → registrante, ASN, rangos IP")
    lines.append("   d) curl -sI http://<dominio> -L -m 10 → headers HTTP, redirects, server, WAF")
    lines.append("   e) curl -sI https://<dominio> -L -m 10 → headers HTTPS")
    lines.append("   f) wafw00f <dominio> → detectar WAF/CDN")
    lines.append("   Si Shodan no está disponible: nmap -sV -sC -T4 -p- --min-rate 2000 <IP> como alternativa")
    lines.append("2. ANALIZAR RESULTADOS DE SHODAN/NMAP → listar TODOS los puertos abiertos con su servicio")
    lines.append("   En 'message' DEBES mostrar tabla: | Puerto | Servicio | Producto | Versión |")
    lines.append("3. PROBAR HTTP/HTTPS EN CADA PUERTO encontrado (no solo 80/443):")
    lines.append("   httpx -u <dominio> -ports <p1>,<p2>,<p3>... -status-code -title -tech-detect -follow-redirects")
    lines.append("   O manualmente: curl -sI http://<dominio>:<puerto> y curl -sI https://<dominio>:<puerto>")
    lines.append("   por cada puerto que tenga un servicio HTTP/web (8080, 8443, 3000, 9090, etc.)")
    lines.append("4. IDENTIFICAR QUÉ CORRE → whatweb -v <cada_url_activa>, tecnologías, CMS, frameworks")
    lines.append("5. SOLO ENTONCES proceder al escaneo dirigido según lo encontrado")
    lines.append("\nMETODOLOGÍA WEB (después del reconocimiento inicial):")
    lines.append("1. Según CMS detectado: WordPress→wpscan --random-user-agent, Joomla→joomscan, Drupal→droopescan, genérico→nuclei")
    lines.append("2. Enumeración de directorios: gobuster dir / ffuf / feroxbuster (en cada URL activa descubierta)")
    lines.append("3. Vulnerabilidades: nikto, nuclei -t cves/ -json-export /tmp/nuclei_out.json, nuclei -t vulnerabilities/, wapiti")
    lines.append("4. Explotación: sqlmap, burpsuite, hydra, payloads manuales con curl")
    lines.append("\nMETODOLOGÍA EXPLOIT (cuando se encuentran CVEs o vulns):")
    lines.append("1. Buscar exploit: searchsploit '<producto> <version>'  |  searchsploit '<CVE>'")
    lines.append("2. Ver detalles:   searchsploit -x <ID>")
    lines.append("3. Copiar exploit: searchsploit -m <ID>")
    lines.append("4. Buscar módulo MSF: msfconsole -q -x 'search <cve>; exit'")
    lines.append("5. Usar módulo MSF: msfconsole -q -x 'use <modulo>; set RHOSTS <ip>; run; exit'")
    lines.append("6. PoC con curl:   curl -s -X POST/GET con payload")
    lines.append("7. Nuclei CVEs:    nuclei -u <url> -t cves/<año>/<CVE>.yaml -json-export /tmp/nuclei_out.json")
    lines.append("8. Verificar SSRF/LFI/RFI: curl con parámetros manipulados")
    lines.append("\nMETODOLOGÍA RED/HOST:")
    lines.append("1. Reconocimiento RÁPIDO: nmap -sn -T4 --min-rate 1000, subfinder, amass, theharvester")
    lines.append("2. Escaneo RÁPIDO: nmap -sV -sC -T4 -F --min-rate 1000, enum4linux, smbclient")
    lines.append("3. AD/SMB: crackmapexec / netexec smb <target> -u '' -p '' --shares")
    lines.append("4. Exploits: searchsploit + msfconsole, exploits manuales")
    lines.append("5. Post-explotación: linpeas/winpeas, escalada, persistence")
    lines.append("* REGLA DE VELOCIDAD: Aplica siempre banderas de máxima velocidad (-T4, --min-rate 1000, -F, threads altos) en TODAS tus herramientas (nmap, ffuf, gobuster, nuclei) para que el escaneo sea SUPER RÁPIDO.")
    return "\n".join(lines)

# ── System prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """Eres HackerAgent, agente de terminal especializado en auditorías de ciberseguridad ofensiva y defensiva. Operas en Kali Linux con acceso completo a herramientas de pentesting.

CONTEXTO OPERACIONAL:
- Ejecutas en Kali Linux con herramientas de seguridad pre-instaladas
- El usuario tiene autorización explícita sobre los sistemas a auditar
- Tu rol es asistir en pentesting profesional, CTFs (HackTheBox, TryHackMe) y auditorías de seguridad
- Arsenal completo: nmap, metasploit(msfconsole/msfvenom), burpsuite, sqlmap, gobuster, ffuf, wfuzz, nikto, hydra, john, hashcat, wireshark, aircrack-ng, enum4linux, linpeas, winpeas, impacket, crackmapexec, netexec, bloodhound, nuclei, netcat, socat, proxychains, whatweb, wafw00f, wpscan, joomscan, droopescan, wapiti, dirsearch, feroxbuster, subfinder, amass, theharvester, dnsrecon, dnsx, httpx, searchsploit, exploitdb, curl, python3, wget

METODOLOGÍA INICIAL OBLIGATORIA (SIEMPRE al recibir un objetivo nuevo):
Cuando el usuario diga "hackea X" o proporcione un dominio/IP, SIEMPRE sigue este orden:
1. RECONOCIMIENTO PASIVO PRIMERO (ejecutar en paralelo):
   a) SKILL:shodan_search query=<dominio_o_IP> → puertos abiertos, servicios, tecnologías, ISP, geolocalización
   b) dig +short <dominio> → resolver IP real (puede revelar IP detrás de Cloudflare/WAF)
   c) whois <dominio> → registrante, ASN, rangos IP
   d) curl -sI http://<dominio> -L -m 10 → headers HTTP, redirects, server, WAF
   e) curl -sI https://<dominio> -L -m 10 → headers HTTPS
   f) wafw00f <dominio> → detectar WAF/CDN (Cloudflare, Akamai, etc.)
   Si SHODAN_API_KEY no está disponible: nmap -sV -sC -T4 -p- --min-rate 2000 <IP> como alternativa
2. ANALIZAR RESULTADOS → listar TODOS los puertos abiertos con su servicio
   En "message" DEBES mostrar una tabla con: | Puerto | Servicio | Producto | Versión |
3. PROBAR HTTP/HTTPS EN CADA PUERTO encontrado (no solo 80/443):
   httpx -u <dominio> -ports <p1>,<p2>,<p3>... -status-code -title -tech-detect -follow-redirects
   O manualmente: curl -sI http://<dominio>:<puerto> y curl -sI https://<dominio>:<puerto>
   por cada puerto que tenga un servicio HTTP/web (8080, 8443, 3000, 9090, 8888, etc.)
4. IDENTIFICAR QUÉ CORRE → whatweb -v <cada_url_activa>, tecnologías, CMS, frameworks
5. SOLO ENTONCES proceder al escaneo dirigido según lo encontrado

METODOLOGÍA WEB (después del reconocimiento inicial):
1. Según CMS detectado: WordPress→wpscan --random-user-agent, Joomla→joomscan, Drupal→droopescan, genérico→nuclei
2. Enumeración de directorios: gobuster dir / ffuf / feroxbuster (en cada URL activa descubierta)
3. Vulnerabilidades: nikto, nuclei -t cves/ -json-export /tmp/nuclei_out.json, nuclei -t vulnerabilities/, wapiti
4. Explotación: sqlmap, burpsuite, hydra, payloads manuales con curl

METODOLOGÍA EXPLOIT (cuando se encuentran CVEs o vulns):
1. Buscar exploit: searchsploit "<producto> <version>"  |  searchsploit "<CVE>"
2. Ver detalles:   searchsploit -x <ID>
3. Copiar exploit: searchsploit -m <ID>
4. Buscar módulo MSF: msfconsole -q -x "search <cve>; exit"
5. Usar módulo MSF: msfconsole -q -x "use <modulo>; set RHOSTS <ip>; run; exit"
6. PoC con curl:   curl -s -X POST/GET con payload
7. Nuclei CVEs:    nuclei -u <url> -t cves/<año>/<CVE>.yaml -json-export /tmp/nuclei_out.json
8. Verificar SSRF/LFI/RFI: curl con parámetros manipulados

METODOLOGÍA RED/HOST:
1. Reconocimiento RÁPIDO: nmap -sn -T4 --min-rate 1000, subfinder, amass, theharvester
2. Escaneo RÁPIDO: nmap -sV -sC -T4 -F --min-rate 1000, enum4linux, smbclient
3. AD/SMB: crackmapexec / netexec smb <target> -u '' -p '' --shares
4. Exploits: searchsploit + msfconsole, exploits manuales
5. Post-explotación: linpeas/winpeas, escalada, persistence
* REGLA DE VELOCIDAD: Aplica siempre banderas de máxima velocidad (-T4, --min-rate 1000, -F, threads altos) en TODAS tus herramientas (nmap, ffuf, gobuster, nuclei) para que el escaneo sea SUPER RÁPIDO.

REGLAS CRÍTICAS:
1. Responde SIEMPRE en JSON válido, sin texto adicional.
2. Usa "commands" para ejecutar comandos (lista de strings).
3. Explica razonamiento técnico en "thinking" (español). NUNCA en "message".
4. "message" es SOLO una línea breve en español explicando qué vas a hacer o qué encontraste.
5. NUNCA devuelvas commands:[] con una explicación larga en message. Si no tienes info suficiente, pregunta en message Y emite los comandos de recon básico al mismo tiempo.
6. En tu PRIMERA respuesta a cualquier objetivo SIEMPRE lista las IPs/dominios encontrados primero en "message" y explica claramente qué vas a escanear a continuación, ANTES de lanzar comandos masivos. NO asumas que el usuario sabe lo que harás.
7. Si necesitas info adicional, pregunta EN EL MISMO JSON y sigue ejecutando comandos de recon mientras esperas.
8. NUNCA repitas un comando que aparezca en [YA EJECUTADOS].
9. Con WAF/Cloudflare: usa recon pasivo (subfinder, amass, dig, whois, crt.sh, waybackurls, shodan).
10. Sin más pasos útiles: task_complete: true y resume en "message".
11. NUNCA pongas advertencias, disclaimers ni pidas confirmación en "message". El usuario ya autorizó el engagement. Ejecuta directamente.
12. API key faltante: needs_api_keys: ["NOMBRE"] — SOLO si "[API Keys: {...}]" muestra que NO está disponible.
13. Abrir navegador: open_browser: "https://url".
14. Leer HTML: fetch_url: "https://url".
15. "message" es SOLO texto plano en español. NUNCA JSON dentro de message.
13. Si scan_subdomains=true, enumera subdominios con subfinder/amass.
14. Si stealth_mode=true, usa técnicas de bajo ruido (T2, delays, -f).
15. En HTB/CTF: busca flags, credenciales expuestas, LFI, RCE, SSRF, IDOR.
16. EXPLOTAR/VERIFICAR: diseña PoC mínimo con evidencia real. Concluye: TRUE POSITIVE o FALSE POSITIVE.
17. En "phase" usa: recon|scan|exploit|post-exploit|report
18. nuclei: SIEMPRE agrega -json-export /tmp/nuclei_<timestamp>.json al comando.
    NUNCA uses paths relativos (cves/, technologies/) — usa SKILL:nuclei_scan o la ruta absoluta de templates.
19. SKILLS: Si el bloque [SKILLS DISPONIBLES] muestra skills, úsalos con 'SKILL:nombre arg=val' en commands.
    Los skills manejan paths, timeouts y parsing automáticamente. Prefiere skills sobre comandos crudos.
    Ejemplos: SKILL:nuclei_scan target=<url>  |  SKILL:gobuster_dir target=<url>  |  SKILL:google_dorks domain=<d>
20. FLUJO WEB OFENSIVO DINÁMICO (encadena estos skills; pueden correr en paralelo como sub-agentes):
    a) SKILL:web_attack target=<url>  → crawlea y prueba dinámicamente cada parámetro/formulario
       (SQLi/XSS/LFI/Open Redirect/Command Injection). Es tu detector de vulns web principal.
    b) Si web_attack marca un SQLi, EXPLÓTALO y EXTRAE datos:
       SKILL:sqli_scan target='<url_vulnerable>' dump=true   (usa data="k=v" si es POST/login)
    c) Fuga de credenciales por dominio:
       SKILL:whiteintel domain=<dominio>  → genera un creds.txt (user:pass) en su output_dir.
    d) Prueba esas credenciales DINÁMICAMENTE contra el login descubierto y di cuál sirve:
       SKILL:cred_stuff target=<url_login> domain=<dominio>
       (lee solo las creds expuestas —auto de whiteintel—, entiende el login HTML o API JSON,
        y devuelve veredicto ✅BUENA/❌MALA por cada credencial). Usa creds=<archivo> si ya lo tienes.
    Objetivo: identificar SQLi y sacarlo, encontrar vulns probando la web en vivo, y validar credenciales filtradas.
21. DESARROLLO DE CÓDIGO / MALWARE (skills de la categoría 🛠 DESARROLLO):
    a) SKILL:model_advisor kind=<malware|c2|payload|exploit|pentest>  → recomienda qué modelo
       de Ollama usar (sin censura para ofensivo, coder/razonamiento para código general).
    b) SKILL:code_dev request="<qué desarrollar>" kind=<...> language=<python|c|bash|ps1|go...>
       → desarrolla el código con el modelo local, itera y lo ENTREGA en out/<proyecto>/dev/.
       Si el usuario no fija modelo, code_dev elige el recomendado automáticamente.
       IMPORTANTE: code_dev es para Python/C/Go/Bash/etc. NUNCA para DuckyScript/Hak5.
    c) SKILL:ducky_dev → payloads para dispositivos Hak5 (Rubber Ducky, Bash Bunny, O.MG, WiFi Pineapple, Shark Jack).
       ÚSALO SIEMPRE cuando el usuario mencione: DuckyScript, Rubber Ducky, inyección de teclado,
       HID attack, Bash Bunny, O.MG Cable, keystroke injection, payload USB, BadUSB, ducky.
       Parámetros clave: payload=<nombre> | request="<descripción>" | device=<dispositivo> | lhost=<ip> | lport=<puerto>
       Ejemplos:
         SKILL:ducky_dev payload=win_disable_defender
         SKILL:ducky_dev payload=win_reverse_shell lhost=10.10.14.1 lport=4444
         SKILL:ducky_dev payload=lockpicker_os_detect lhost=10.10.14.1 lport=4444
         SKILL:ducky_dev request="deshabilitar antivirus según el SO detectado" device=rubber_ducky
       Para listar todos los payloads disponibles: SKILL:ducky_dev list_payloads=true
    Cuando el usuario pida "desarrolla/créame/programa <algo ofensivo o herramienta>", usa code_dev.
    Cuando pida DuckyScript / payload HID / Rubber Ducky / BadUSB, usa ducky_dev.
22. PENTESTING MÓVIL / APK (skills de la categoría 📱 MÓVIL):
    a) SKILL:apk_analyze target=/ruta/app.apk  → RE estático: decompila (jadx/apktool),
       manifest (permisos, componentes exportados, debuggable, cleartext, SSL pinning),
       credenciales/API keys/secretos y lógica (login, cripto, root detection).
    b) SKILL:apk_dynamic action=ssl-unpin target=<paquete> run=true  → bypass de SSL pinning
       en runtime (Frida) para interceptar tráfico; action=hook captura credenciales/cripto.
    Flujo típico: apk_analyze (saca paquete + detecta pinning) → apk_dynamic (unpin + hooks) →
    interceptar con Burp/mitmproxy. Cuando el usuario mencione APK/app Android/móvil, usa estos skills.

FORMATO:
{"thinking":"...","commands":["cmd1"],"message":"...","requires_confirmation":false,"task_complete":false,"risk_level":"low|medium|high|critical","phase":"recon","needs_api_keys":[],"open_browser":"","fetch_url":""}
"""

REPORT_PROMPT = """Eres un consultor de ciberseguridad experto. Genera un reporte profesional en Markdown:

# Reporte de Auditoría de Seguridad
## Información del Objetivo
## Resumen Ejecutivo (3-5 bullets con hallazgos críticos)
## Metodología Utilizada
## Hallazgos Detallados
  - Para cada hallazgo: Título, Severidad (Crítica/Alta/Media/Baja/Info), Descripción, Evidencia, Recomendación
## Tabla de Vulnerabilidades (markdown table: #|Hallazgo|Severidad|CVE|Estado)
## Conclusiones y Próximos Pasos
## Anexo: Comandos Ejecutados

Usa emojis: 🔴 Crítica, 🟠 Alta, 🟡 Media, 🔵 Baja, ⚪ Info
Sé específico con los hallazgos reales. Si no hay vulns, indícalo."""

SUMMARIZE_PROMPT = """Eres un asistente de ciberseguridad. Comprime el historial de auditoría en ~400 palabras.
Incluye: objetivo auditado, fases completadas, hallazgos/CVEs encontrados, herramientas ejecutadas,
estado actual del análisis y próximos pasos pendientes. Sin markdown excesivo, texto directo."""

# ── Resumen incremental de contexto ──────────────────────────────────────────
SUMMARIZE_CHARS = 12000
SUMMARIZE_KEEP  = 3  # últimos N pares user/assistant que se conservan sin comprimir

def _hard_truncate(conv: list, target_chars: int = 16000) -> list:
    """Fallback estricto: reduce el contexto recortando mensajes antiguos y textos largos hasta caber en target_chars."""
    system  = [m for m in conv if m["role"] == "system"]
    history = [m for m in conv if m["role"] != "system"]
    
    # Primero, eliminar mensajes antiguos hasta dejar solo el último mensaje (o los que quepan)
    while history and sum(len(m["content"]) for m in system + history) > target_chars:
        if len(history) <= 1:
            break
        history.pop(0)
    
    # Si sigue pasándose, recortar el contenido de los mensajes en el history (del más viejo al más nuevo)
    current_len = sum(len(m["content"]) for m in system + history)
    if current_len > target_chars:
        excess = current_len - target_chars
        for i in range(len(history)):
            msg_len = len(history[i]["content"])
            # Si este mensaje es lo bastante grande para absorber todo o parte del exceso
            # (dejando al menos 200 caracteres de él)
            if msg_len > 200:
                cut = min(excess, msg_len - 200)
                if cut > 0:
                    history[i]["content"] = history[i]["content"][:-(cut + 100)] + "\n[... TRUNCADO ...]"
                    excess -= cut
            if excess <= 0:
                break
        
        # If we STILL have excess (e.g. system prompt is too big), truncate the system prompt
        if excess > 0 and system:
            sys_len = len(system[0]["content"])
            if sys_len > 1000:
                cut = min(excess, sys_len - 1000)
                if cut > 0:
                    system[0]["content"] = system[0]["content"][:-(cut + 100)] + "\n[... TRUNCADO ...]"
                    excess -= cut

    dropped_notice = {
        "role": "user",
        "content": "[CONTEXTO TRUNCADO AUTOMÁTICAMENTE PARA LIBERAR ESPACIO]"
    }
    return system + [dropped_notice] + history


def summarize_if_needed(model: str, conv: list) -> list:
    total = sum(len(m["content"]) for m in conv)
    if total < SUMMARIZE_CHARS:
        return conv
    system  = [m for m in conv if m["role"] == "system"]
    history = [m for m in conv if m["role"] != "system"]
    if len(history) <= SUMMARIZE_KEEP * 2 + 2:
        return conv
    to_compress = history[: -(SUMMARIZE_KEEP * 2)]
    keep_recent = history[-(SUMMARIZE_KEEP * 2):]
    compress_text = "\n\n".join(
        f"[{m['role'].upper()}]\n{m['content'][:3000]}" for m in to_compress
    )
    prompt = f"{SUMMARIZE_PROMPT}\n\nHISTORIAL:\n{compress_text}"
    print(f"\n  {YELLOW}📝 Comprimiendo contexto ({total//1000}K chars → resumen)...{R}")
    try:
        summary = call_llm_text(model, prompt, timeout=240)
        summary_msg = {"role": "user",
                       "content": f"[RESUMEN COMPRIMIDO DE HALLAZGOS PREVIOS]\n{summary}"}
        ack_msg = {"role": "assistant", "content": json.dumps({
            "thinking": "Resumen recibido. Continúo con contexto comprimido.",
            "commands": [], "message": "Contexto comprimido. Continuando análisis.",
            "task_complete": False, "risk_level": "low", "phase": "recon",
            "requires_confirmation": False, "needs_api_keys": [], "open_browser": "", "fetch_url": ""
        })}
        new_conv = system + [summary_msg, ack_msg] + keep_recent
        new_total = sum(len(m["content"]) for m in new_conv)
        print(f"  {GREEN}✓ Contexto: {total//1000}K → {new_total//1000}K chars{R}\n")
        return new_conv
    except Exception as e:
        print(f"  {YELLOW}⚠ Compresión LLM falló ({e}). Aplicando truncado automático...{R}")
        truncated = _hard_truncate(conv)
        new_total = sum(len(m["content"]) for m in truncated)
        print(f"  {GREEN}✓ Truncado: {total//1000}K → {new_total//1000}K chars{R}\n")
        return truncated

# ── LogWriter ─────────────────────────────────────────────────────────────────
class LogWriter:
    def __init__(self, session_name: str, target_dir: Path):
        self.path = target_dir / f"{session_name}.md"
        self.nuclei_finds: list = []
        self._write(f"# HackerAgent Log — {session_name}\n**Inicio:** {datetime.now():%Y-%m-%d %H:%M:%S}\n\n---\n\n")

    def _write(self, text: str):
        with self.path.open("a", encoding="utf-8") as f:
            f.write(text)

    def _ts(self): return datetime.now().strftime("%H:%M:%S")

    def section(self, title: str):
        self._write(f"\n## {self._ts()} — {title}\n\n")

    def thinking(self, text: str, phase: str, risk: str):
        if text:
            self._write(f"**🧠 [{phase.upper()}] [{risk.upper()}]**\n\n> {text}\n\n")

    def command(self, cmd: str, stdout: str, stderr: str, code: int, cached=False):
        tag = " *(cached)*" if cached else ""
        self._write(
            f"**Comando:** `{cmd}`{tag}\n\n"
            f"```\n{(stdout or stderr or '(sin output)').strip()[:20000]}\n```\n\n"
            f"**Estado:** {'✓ OK' if code == 0 else f'✗ exit {code}'}\n\n"
        )

    def message(self, text: str):
        if text:
            self._write(f"**Agente:** {text}\n\n")

    def fetch(self, url: str, status_code: int, body_preview: str):
        self._write(
            f"**Fetch:** {url} → HTTP {status_code}\n\n"
            f"```html\n{body_preview[:2000]}\n```\n\n"
        )

    def user_input(self, text: str):
        self._write(f"**Usuario:** {text}\n\n")

    def config(self, cfg: dict):
        self._write("### Configuración de sesión\n\n")
        for k, v in cfg.items():
            self._write(f"- **{k}:** {v}\n")
        self._write("\n")

    def nuclei_findings(self, findings: list):
        dicts = [f for f in findings if isinstance(f, dict)]
        if not dicts:
            return
        self.nuclei_finds.extend(dicts)
        self._write(f"**Nuclei findings ({len(dicts)}):**\n\n")
        for f in dicts:
            sev  = f.get("info", {}).get("severity", "?")
            name = f.get("info", {}).get("name", "?")
            url  = f.get("matched-at", "?")
            self._write(f"- [{sev.upper()}] {name} — {url}\n")
        self._write("\n")

    def separator(self):
        self._write("---\n\n")

# ── ProjectState — persistencia de hallazgos entre sesiones ──────────────────
class ProjectState:
    """Guarda dominios descubiertos y hallazgos con severidad en database."""

    _SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def __init__(self, target_dir: Path, project_name: str = "", target: str = "", project_type: str = ""):
        self.project_id = target_dir.name
        self.project_name = project_name or self.project_id
        self.target = target
        self.project_type = project_type
        
        p = database.get_project(self.project_id)
        if p:
            self.project_name = p.get("name") or self.project_name
            self.target = p.get("target") or self.target
            self.project_type = p.get("project_type") or self.project_type
        else:
            database.upsert_project(self.project_id, self.project_name, self.target, self.project_type)

    @property
    def domains(self):
        return set(database.get_domains(self.project_id))
        
    @property
    def findings(self):
        return database.get_findings(self.project_id)

    def save(self):
        database.upsert_project(self.project_id, self.project_name, self.target, self.project_type)

    def add_domain(self, domain: str) -> bool:
        domain = domain.lower().strip().lstrip("*.")
        if domain:
            return database.add_domain(self.project_id, domain)
        return False

    def _finding_key(self, f: dict) -> tuple:
        return (f.get("type", ""), str(f.get("value", ""))[:80])

    def add_finding(self, finding: dict):
        if not isinstance(finding, dict):
            return
        finding.setdefault("severity", "info")
        database.add_finding(self.project_id, finding)

    def ingest_skill_findings(self, skill_name: str, findings: list):
        new_domains = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            ftype = f.get("type", "")
            if ftype in ("subdomain", "subdomain_crt", "http_active"):
                val = f.get("value", "")
                if val and self.add_domain(val):
                    new_domains.append(val)
            elif ftype == "dork_url":
                import re as _re
                raw_url = f.get("value", "") or f.get("url", "")
                m = _re.search(r'https?://([^/\s]+)', raw_url)
                if m:
                    self.add_domain(m.group(1))
            entry = dict(f)
            entry["source"] = skill_name
            self.add_finding(entry)
        return new_domains

    def severity_summary(self) -> str:
        counts = database.get_severity_summary(self.project_id)
        parts = [f"{counts[s]} {s}" for s in ["critical","high","medium","low","info"] if s in counts and counts[s] > 0]
        return f"{len(self.findings)} hallazgos ({', '.join(parts) or 'ninguno'})"

    def has_critical(self) -> bool:
        return any(f.get("severity") in ("critical", "high") for f in self.findings)

    def top_findings(self, n: int = 20) -> list:
        return sorted(self.findings, key=lambda f: self._SEV_RANK.get(f.get("severity","info"), 4))[:n]


# ── Sesiones ──────────────────────────────────────────────────────────────────
def save_session(name: str, conversation: list, model: str, target_dir: Path):
    database.upsert_project(target_dir.name, target_dir.name, "", "full")
    sess = database.get_session(name)
    if not sess:
        database.create_session(name, target_dir.name, model)
    else:
        database.update_session(name, model)
    database.save_messages(name, conversation)
    return target_dir / f"{name}.db_ref"


def load_session(name: str):
    sess = database.get_session(name)
    if sess:
        project_dir = OUT_DIR / sess["project_id"]
        project_dir.mkdir(parents=True, exist_ok=True)
        return database.get_messages(name), sess["model"], project_dir
    return None, None, None


def list_sessions():
    sessions = []
    for p in database.get_all_projects():
        for s in database.get_sessions_for_project(p["id"]):
            sessions.append({
                "name": s["id"], "target": p["id"],
                "saved_at": s["saved_at"],
                "model": s["model"],
                "turns": database.get_turn_count(s["id"])
            })
    return sorted(sessions, key=lambda s: s["saved_at"], reverse=True)


def generate_session_name():
    return datetime.now().strftime("session_%Y%m%d_%H%M%S")


def list_project_sessions(project_dir: Path) -> list:
    sessions = []
    for s in database.get_session_summaries(project_dir.name):
        prompt = (s.get("first_prompt") or "").strip()
        # Do not expose the API-key context that is prepended internally.
        if prompt.startswith("[API Keys:"):
            prompt = prompt.split("\n", 1)[-1] if "\n" in prompt else ""
        title = " ".join(prompt.split())[:72] or s["id"].replace("session_", "Sesi\u00f3n ")
        sessions.append({
            "name": s["id"],
            "saved_at": s["saved_at"],
            "model": s["model"],
            "turns": s.get("turns") or 0,
            "title": title,
        })
    return sessions


def load_session_in_project(name: str, project_dir: Path):
    sess = database.get_session(name)
    if sess and sess["project_id"] == project_dir.name:
        return database.get_messages(name), sess["model"], project_dir
    return None, None, None


def _read_project_meta(project_dir: Path) -> dict:
    p = database.get_project(project_dir.name)
    if p:
        p["findings"] = database.get_findings(project_dir.name)
        p["sev_summary"] = database.get_severity_summary(project_dir.name)
        return p
    return {}


def pick_or_create_project() -> tuple:
    """
    Muestra los proyectos existentes en out/ y permite al usuario elegir uno
    o crear uno nuevo.
    Retorna (project_name, project_dir, session_to_resume_or_None).
    """
    separator("═", CYAN + BOLD, 60)
    print(f"{CYAN}{BOLD}  📁  PROYECTOS GUARDADOS{R}")
    separator("═", CYAN + BOLD, 60)

    # Listar proyectos existentes
    projects = []
    if OUT_DIR.exists():
        for d in sorted(OUT_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if d.is_dir():
                meta    = _read_project_meta(d)
                sessions = list_project_sessions(d)
                # Cuenta hallazgos por severidad
                sev_s = meta.get("sev_summary", {})
                sev_str = "  ".join(
                    f"{RED+BOLD if s=='critical' else YELLOW+BOLD if s=='high' else CYAN}{v} {s}{R}"
                    for s, v in sev_s.items() if v > 0
                ) if sev_s else f"{DIM}sin hallazgos{R}"
                last_date = sessions[0]["saved_at"][:16] if sessions else "—"
                projects.append({
                    "dir":       d,
                    "name":      d.name,
                    "display":   meta.get("project_name") or d.name,
                    "target":    meta.get("target", ""),
                    "sessions":  sessions,
                    "n_sessions": len(sessions),
                    "sev_str":   sev_str,
                    "last_date": last_date,
                })

    if projects:
        print(f"\n  {DIM}Proyectos existentes:{R}\n")
        for i, p in enumerate(projects, 1):
            proj_label = f"{CYAN}{BOLD}{p['display']:<28}{R}"
            tgt_label  = f"{DIM}{p['target'][:22]:<22}{R}" if p["target"] else f"{DIM}{'(sin target)':<22}{R}"
            ses_label  = f"{DIM}{p['n_sessions']} sesión(es){R}"
            print(f"    {BOLD}{i:>2}.{R}  {proj_label}  {tgt_label}  {ses_label}  {DIM}{p['last_date']}{R}")
            print(f"        {p['sev_str']}")
        print()
        print(f"    {DIM} 0.  {GREEN}[Crear nuevo proyecto]{R}")
    else:
        print(f"\n  {DIM}No hay proyectos guardados.{R}")
        print(f"    {DIM} 0.  {GREEN}[Crear nuevo proyecto]{R}")

    print()
    sel = input(f"  {CYAN}?{R} Selecciona proyecto [0-{len(projects)}]: ").strip()

    # ── Crear nuevo proyecto ───────────────────────────────────────────────────
    if sel == "0" or not sel or not sel.isdigit() or int(sel) > len(projects):
        print()
        raw_name = input(f"  {CYAN}?{R} Nombre del nuevo proyecto: ").strip()
        if not raw_name:
            raw_name = f"proyecto_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        # Sanitizar para usar como directorio
        safe = re.sub(r'[^\w\-]', '_', raw_name.lower().replace(' ', '_'))[:40]
        project_dir = OUT_DIR / safe
        project_dir.mkdir(parents=True, exist_ok=True)
        print(f"  {GREEN}✓ Proyecto creado:{R} {CYAN}{safe}{R}  →  {DIM}{project_dir}{R}\n")
        return raw_name, project_dir, None

    # ── Proyecto existente ─────────────────────────────────────────────────────
    idx         = int(sel) - 1
    chosen      = projects[idx]
    project_dir = chosen["dir"]
    display     = chosen["display"]
    sessions    = chosen["sessions"]

    print(f"\n  {GREEN}✓ Proyecto:{R} {CYAN}{BOLD}{display}{R}")
    if chosen["target"]:
        print(f"  {DIM}Target anterior: {chosen['target']}{R}")

    # Mostrar sesiones del proyecto
    if sessions:
        print(f"\n  {CYAN}{BOLD}Sesiones del proyecto:{R}\n")
        for i, s in enumerate(sessions[:10], 1):
            stars_n, _ = score_model(s["model"])
            stars_str  = _STARS.get(stars_n, "")
            print(f"    {DIM}{i:>2}.{R}  {CYAN}{s['name']:<36}{R}  {DIM}{s['turns']} turnos  {s['saved_at'][:16]}{R}  {stars_str}")
        print()
        print(f"    {DIM} 0.  [Nueva sesión en este proyecto]{R}\n")
        ses_sel = input(f"  {CYAN}?{R} Reanudar sesión [0-{min(len(sessions),10)}] (Enter = nueva): ").strip()

        if ses_sel.isdigit() and 1 <= int(ses_sel) <= min(len(sessions), 10):
            chosen_ses = sessions[int(ses_sel) - 1]["name"]
            print(f"  {GREEN}✓ Reanudando:{R} {CYAN}{chosen_ses}{R}\n")
            return display, project_dir, chosen_ses
    else:
        print(f"  {DIM}(sin sesiones — se iniciará una nueva){R}\n")

    print()
    return display, project_dir, None


# ── API Keys ──────────────────────────────────────────────────────────────────
def get_api_key(key_name: str) -> str:
    return os.environ.get(key_name, "").strip()


def save_api_key_to_env(key_name: str, value: str):
    lines = []
    found = False
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s.startswith(f"{key_name}=") or s.startswith(f"{key_name} ="):
                lines.append(f'{key_name}="{value}"')
                found = True
            else:
                lines.append(line)
    if not found:
        lines.append(f'{key_name}="{value}"')
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.environ[key_name] = value


def prompt_api_keys(key_names: list) -> dict:
    acquired = {}
    for key in key_names:
        existing = get_api_key(key)
        if existing:
            acquired[key] = existing
            print(f"  {GREEN}✓ {key} ya configurada{R}")
            continue
        print(f"\n  {YELLOW}⚠ Se necesita {key}{R}")
        hints = {
            "WPSCAN_API_KEY":     "https://wpscan.com/api  (gratuito, 25 req/día)",
            "SHODAN_API_KEY":     "https://account.shodan.io",
            "VIRUSTOTAL_API_KEY": "https://www.virustotal.com/gui/user/apikey",
        }
        if key in hints:
            print(f"    {CYAN}{hints[key]}{R}")
        value = input(f"  Ingresa {key} (Enter para omitir): ").strip()
        if value:
            save_api_key_to_env(key, value)
            acquired[key] = value
            print(f"  {GREEN}✓ Guardada en .env{R}")
        else:
            print(f"  {YELLOW}Omitida.{R}")
    return acquired

# ── Web ───────────────────────────────────────────────────────────────────────
def fetch_url(url: str, timeout: int = 15):
    try:
        import urllib3; urllib3.disable_warnings()
        hdrs = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"}
        r = requests.get(url, headers=hdrs, timeout=timeout, verify=False, allow_redirects=True)
        body = r.text[:8000]
        return {"url": r.url, "status_code": r.status_code, "headers": dict(r.headers),
                "body_preview": body, "body_truncated": len(r.text) > 8000,
                "body_length": len(r.text)}, None
    except Exception as e:
        return None, str(e)


def open_browser(url: str) -> bool:
    browser = os.environ.get("BROWSER", "firefox")
    for b in [browser, "firefox", "chromium", "chromium-browser", "xdg-open"]:
        try:
            subprocess.Popen([b, url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except FileNotFoundError:
            continue
    return False

# ── Ollama ────────────────────────────────────────────────────────────────────
def check_ollama():
    base = OLLAMA_URL.rsplit("/api/chat", 1)[0].rsplit("/api/", 1)[0]
    try:
        r = requests.get(f"{base}/api/tags", timeout=5)
        if r.status_code == 200:
            return True, [m["name"] for m in r.json().get("models", [])]
    except Exception:
        pass
    return False, []


def get_model(preferred=None):
    ok, models = check_ollama()
    if not ok:
        print(f"{RED}✗ Ollama no responde en {OLLAMA_URL}{R}")
        sys.exit(1)
    if not models:
        print(f"{RED}✗ Sin modelos. Prueba: ollama pull deepseek-r1:14b{R}")
        sys.exit(1)
    if preferred and preferred in models:
        return preferred, models
    if preferred:
        print(f"{YELLOW}⚠ Modelo '{preferred}' no encontrado.{R}")
    # Elegir el modelo con mayor puntuación disponible
    scored = sorted(models, key=lambda m: score_model(m)[0], reverse=True)
    return scored[0], models


def call_ollama(model: str, messages: list) -> dict:
    payload = {"model": model, "messages": messages, "stream": False, "format": "json",
               "options": {"temperature": 0.1, "num_ctx": 32768}}
    r = requests.post(OLLAMA_URL, json=payload, timeout=300)
    if not r.ok:
        try:
            err = r.json().get("error", r.text[:300])
        except Exception:
            err = r.text[:300]
        raise Exception(f"Ollama {r.status_code}: {err}")
    content = r.json()["message"]["content"]
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        s, e = content.find("{"), content.rfind("}") + 1
        if s != -1 and e > s:
            try:
                return json.loads(content[s:e])
            except Exception:
                pass
        return {"thinking": "", "commands": [], "message": content,
                "requires_confirmation": False, "task_complete": False,
                "_json_parse_error": True,
                "risk_level": "low", "phase": "recon", "needs_api_keys": [],
                "open_browser": "", "fetch_url": ""}


def call_ollama_text(model: str, prompt: str, timeout: int = 180) -> str:
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}],
               "stream": False, "options": {"temperature": 0.3, "num_ctx": 32768}}
    r = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
    if not r.ok:
        try:
            err = r.json().get("error", r.text[:300])
        except Exception:
            err = r.text[:300]
        raise Exception(f"Ollama {r.status_code}: {err}")
    return r.json()["message"]["content"]


# ── LM Studio ────────────────────────────────────────────────────────────────
def check_lmstudio():
    """Verifica que LM Studio server local esté activo y lista los modelos."""
    try:
        r = requests.get(f"{LMSTUDIO_URL}/models", timeout=5)
        if r.status_code == 200:
            data = r.json().get("data", [])
            return True, [m["id"] for m in data if m.get("id")]
    except Exception:
        pass
    return False, []


def get_model_lmstudio(preferred=None):
    ok, models = check_lmstudio()
    if not ok:
        print(f"{RED}✗ LM Studio no responde en {LMSTUDIO_URL}{R}")
        print(f"  {DIM}Asegúrate de que el server local esté activo (lms server start){R}")
        sys.exit(1)
    if not models:
        print(f"{RED}✗ Sin modelos cargados en LM Studio.{R}")
        print(f"  {DIM}Carga un modelo desde la interfaz de LM Studio.{R}")
        sys.exit(1)
    if preferred and preferred in models:
        return preferred, models
    if preferred:
        # Buscar coincidencia parcial
        match = [m for m in models if preferred.lower() in m.lower()]
        if match:
            return match[0], models
        print(f"{YELLOW}⚠ Modelo '{preferred}' no encontrado en LM Studio.{R}")
    scored = sorted(models, key=lambda m: score_model(m)[0], reverse=True)
    return scored[0], models


def call_lmstudio(model: str, messages: list) -> dict:
    """Llama a LM Studio (API compatible con OpenAI) y espera JSON."""
    # Asegurar que el modelo devuelva JSON puro si es posible
    messages_copy = messages.copy()
    messages_copy.append({"role": "system", "content": "You MUST respond ONLY with valid, raw JSON. Do not use markdown blocks like ```json. Your entire response must be parseable by JSON.parse()."})
    
    payload = {
        "model": model,
        "messages": messages_copy,
        "temperature": 0.1,
        "max_tokens": -1,
        "stream": False,
    }
    r = requests.post(f"{LMSTUDIO_URL}/chat/completions", json=payload, timeout=3600)
    if not r.ok:
        try:
            err = r.json().get("error", {}).get("message", r.text[:300])
        except Exception:
            err = r.text[:300]
        raise Exception(f"LM Studio {r.status_code}: {err}")
    content = r.json()["choices"][0]["message"]["content"]
    finish_reason = r.json()["choices"][0].get("finish_reason", "")
    
    if finish_reason == "length":
        # Simulamos un error 400 de contexto para que _hard_truncate se encargue
        raise Exception("400: LM Studio reached context limit (finish_reason: length). Needs truncation.")
        
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # Fallback: quitar markdown tags si los generó
        cl = content.strip()
        if cl.startswith("```json"): cl = cl[7:]
        elif cl.startswith("```"): cl = cl[3:]
        if cl.endswith("```"): cl = cl[:-3]
        
        s, e = cl.find("{"), cl.rfind("}") + 1
        if s != -1 and e > s:
            try:
                return json.loads(cl[s:e])
            except Exception:
                pass
        
        print(f"\n[DEBUG JSON FALLBACK FAILED] Raw content:\n{content}\n")
        return {"thinking": "", "commands": [], "message": content,
                "requires_confirmation": False, "task_complete": False,
                "_json_parse_error": True,
                "risk_level": "low", "phase": "recon", "needs_api_keys": [],
                "open_browser": "", "fetch_url": ""}


def call_lmstudio_text(model: str, prompt: str, timeout: int = 180) -> str:
    """Llama a LM Studio para respuesta de texto libre (sin JSON forzado)."""
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": -1,
        "stream": False,
    }
    r = requests.post(f"{LMSTUDIO_URL}/chat/completions", json=payload, timeout=timeout)
    if not r.ok:
        try:
            err = r.json().get("error", {}).get("message", r.text[:300])
        except Exception:
            err = r.text[:300]
        raise Exception(f"LM Studio {r.status_code}: {err}")
    return r.json()["choices"][0]["message"]["content"]

# ── DeepSeek API ──────────────────────────────────────────────────────────────
def check_deepseek():
    """Verifica que la API key de DeepSeek esté configurada y la API responda."""
    if not DEEPSEEK_API_KEY:
        return False, []
    cached = _DEEPSEEK_CHECK_CACHE.get("value")
    if cached is not None and time.time() - float(_DEEPSEEK_CHECK_CACHE["ts"]) < 20:
        return cached
    try:
        headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}"}
        r = _HTTP.get(f"{DEEPSEEK_API_URL}/models", headers=headers, timeout=(5, 10))
        if r.status_code == 200:
            data = r.json().get("data", [])
            models = [m["id"] for m in data if m.get("id")]
            result = (True, models if models else [DEEPSEEK_MODEL])
            _DEEPSEEK_CHECK_CACHE.update(ts=time.time(), value=result)
            return result
        if r.status_code in (401, 403):
            result = (False, [])
            _DEEPSEEK_CHECK_CACHE.update(ts=time.time(), value=result)
            return result
        # Algunas versiones de la API no exponen /models pero sí aceptan chat
        result = (True, [DEEPSEEK_MODEL])
    except Exception:
        # Si hay API key, asumimos que funciona (validación real al hacer la primera llamada)
        result = (bool(DEEPSEEK_API_KEY), [DEEPSEEK_MODEL] if DEEPSEEK_API_KEY else [])
    _DEEPSEEK_CHECK_CACHE.update(ts=time.time(), value=result)
    return result


def get_model_deepseek(preferred=None):
    """Obtiene el modelo de DeepSeek a usar."""
    ok, models = check_deepseek()
    if not ok:
        print(f"{RED}✗ DeepSeek API no configurada. Añade DEEPSEEK_API_KEY en .env{R}")
        print(f"  {DIM}Obtén tu API key en: https://platform.deepseek.com/api_keys{R}")
        sys.exit(1)
    if not models:
        models = [DEEPSEEK_MODEL]
    if preferred and preferred in models:
        return preferred, models
    if preferred:
        # Buscar coincidencia parcial
        match = [m for m in models if preferred.lower() in m.lower()]
        if match:
            return match[0], models
        fallback_model = DEEPSEEK_MODEL if DEEPSEEK_MODEL in models else models[0]
        print(f"{YELLOW}⚠ Modelo '{preferred}' no encontrado en DeepSeek. Usando {fallback_model}{R}")
    if DEEPSEEK_MODEL in models:
        return DEEPSEEK_MODEL, models
    return models[0], models


def _deepseek_headers() -> dict:
    return {
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        "Content-Type": "application/json",
    }


def _parse_llm_json(content: str) -> dict:
    """Parsea la salida estructurada sin ocultar la respuesta cruda si falla."""
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        cleaned = content.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        start, end = cleaned.find("{"), cleaned.rfind("}") + 1
        if start != -1 and end > start:
            try:
                return json.loads(cleaned[start:end])
            except Exception:
                pass
        return {
            "thinking": "", "commands": [], "message": content,
            "requires_confirmation": False, "task_complete": False,
            "_json_parse_error": True, "risk_level": "low", "phase": "recon",
            "needs_api_keys": [], "open_browser": "", "fetch_url": "",
        }


def _deepseek_payload(model: str, messages: list, *, stream: bool) -> dict:
    """Construye el payload JSON nativo usado por todos los ciclos DeepSeek."""
    messages_copy = [dict(message) for message in messages]
    json_instruction = (
        "\n\nYou MUST respond ONLY with one valid raw JSON object. "
        "Do not use markdown fences and do not write text outside the JSON object."
    )
    if messages_copy and messages_copy[0].get("role") == "system":
        messages_copy[0]["content"] = str(messages_copy[0].get("content", "")) + json_instruction
    else:
        messages_copy.insert(0, {"role": "system", "content": json_instruction.strip()})
    max_tokens = int(os.environ.get("DEEPSEEK_MAX_TOKENS", "8192"))
    payload = {
        "model": model or DEEPSEEK_MODEL,
        "messages": messages_copy,
        "temperature": 0.1,
        "max_tokens": max(1024, min(max_tokens, 16384)),
        "stream": stream,
        "response_format": {"type": "json_object"},
    }
    if stream:
        payload["stream_options"] = {"include_usage": True}
    return payload


def call_deepseek(model: str, messages: list) -> dict:
    """Llama a la API de DeepSeek (compatible OpenAI) y espera JSON."""
    payload = _deepseek_payload(model, messages, stream=False)
    r = _HTTP.post(f"{DEEPSEEK_API_URL}/chat/completions",
                   json=payload, headers=_deepseek_headers(), timeout=(15, 300))
    if not r.ok:
        try:
            err = r.json().get("error", {}).get("message", r.text[:300])
        except Exception:
            err = r.text[:300]
        raise Exception(f"DeepSeek API {r.status_code}: {err}")
    body = r.json()
    content = body["choices"][0]["message"]["content"]
    finish_reason = body["choices"][0].get("finish_reason", "")

    if finish_reason == "length":
        raise Exception("400: DeepSeek reached context limit (finish_reason: length). Needs truncation.")

    result = _parse_llm_json(content)
    result["_usage"] = body.get("usage", {})
    return result


def call_deepseek_stream(model: str, messages: list, on_delta=None) -> dict:
    """Transmite reasoning/content y devuelve el JSON final del ciclo."""
    payload = _deepseek_payload(model, messages, stream=True)
    content_parts: list[str] = []
    reasoning_parts: list[str] = []
    usage: dict = {}
    finish_reason = ""
    with _HTTP.post(
        f"{DEEPSEEK_API_URL}/chat/completions", json=payload,
        headers=_deepseek_headers(), timeout=(15, 300), stream=True,
    ) as response:
        if not response.ok:
            try:
                detail = response.json().get("error", {}).get("message", response.text[:300])
            except Exception:
                detail = response.text[:300]
            raise Exception(f"DeepSeek API {response.status_code}: {detail}")
        for raw_line in response.iter_lines(decode_unicode=True):
            if isinstance(raw_line, bytes):
                raw_line = raw_line.decode("utf-8", errors="replace")
            if not raw_line or raw_line.startswith(":") or not raw_line.startswith("data:"):
                continue
            data = raw_line[5:].strip()
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except json.JSONDecodeError:
                continue
            if chunk.get("usage"):
                usage = chunk["usage"]
            choices = chunk.get("choices") or []
            if not choices:
                continue
            choice = choices[0]
            finish_reason = choice.get("finish_reason") or finish_reason
            delta = choice.get("delta") or {}
            reasoning = delta.get("reasoning_content") or ""
            content = delta.get("content") or ""
            if reasoning:
                reasoning_parts.append(reasoning)
                if on_delta:
                    on_delta("reasoning", reasoning)
            if content:
                content_parts.append(content)
                if on_delta:
                    on_delta("content", content)

    raw_content = "".join(content_parts)
    if finish_reason == "length":
        raise Exception("DeepSeek reached output limit (finish_reason: length).")
    result = _parse_llm_json(raw_content)
    result["_stream_raw"] = raw_content
    result["_reasoning_content"] = "".join(reasoning_parts)
    result["_usage"] = usage
    return result


def call_deepseek_text(model: str, prompt: str, timeout: int = 180) -> str:
    """Llama a DeepSeek API para respuesta de texto libre (sin JSON forzado)."""
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": max(1024, min(int(os.environ.get("DEEPSEEK_MAX_TOKENS", "8192")), 16384)),
        "stream": False,
    }
    r = _HTTP.post(f"{DEEPSEEK_API_URL}/chat/completions",
                   json=payload, headers=_deepseek_headers(), timeout=(15, timeout))
    if not r.ok:
        try:
            err = r.json().get("error", {}).get("message", r.text[:300])
        except Exception:
            err = r.text[:300]
        raise Exception(f"DeepSeek API {r.status_code}: {err}")
    return r.json()["choices"][0]["message"]["content"]


# ── Backend wrappers — delegan a Ollama, LM Studio o DeepSeek según LLM_BACKEND
def check_backend():
    """Verifica el backend activo y retorna (ok, models_list)."""
    if LLM_BACKEND == "deepseek":
        return check_deepseek()
    if LLM_BACKEND == "lmstudio":
        return check_lmstudio()
    return check_ollama()


def get_model_auto(preferred=None):
    """Obtiene el mejor modelo del backend activo."""
    if LLM_BACKEND == "deepseek":
        return get_model_deepseek(preferred)
    if LLM_BACKEND == "lmstudio":
        return get_model_lmstudio(preferred)
    return get_model(preferred)


def call_llm(model: str, messages: list) -> dict:
    """Llama al backend activo y espera respuesta JSON (para el loop principal)."""
    res = {}
    if LLM_BACKEND == "deepseek":
        res = call_deepseek(model, messages)
    elif LLM_BACKEND == "lmstudio":
        res = call_lmstudio(model, messages)
    else:
        res = call_ollama(model, messages)

    if VERBOSE:
        print(f"\n{YELLOW}[VERBOSE - RAW LLM RESPONSE]{R}")
        try:
            print(json.dumps(res, indent=2, ensure_ascii=False))
        except Exception:
            print(res)
        print(f"{YELLOW}────────────────────────────{R}\n")
    return res


def call_llm_stream(model: str, messages: list, on_delta=None) -> dict:
    """Versión interactiva: DeepSeek transmite; los backends locales mantienen compatibilidad."""
    if LLM_BACKEND == "deepseek":
        return call_deepseek_stream(model, messages, on_delta=on_delta)
    return call_llm(model, messages)


def call_llm_text(model: str, prompt: str, timeout: int = 180) -> str:
    """Llama al backend activo para texto libre (reportes, resúmenes)."""
    res = ""
    if LLM_BACKEND == "deepseek":
        res = call_deepseek_text(model, prompt, timeout)
    elif LLM_BACKEND == "lmstudio":
        res = call_lmstudio_text(model, prompt, timeout)
    else:
        res = call_ollama_text(model, prompt, timeout)

    if VERBOSE:
        print(f"\n{YELLOW}[VERBOSE - RAW LLM TEXT RESPONSE]{R}")
        print(res)
        print(f"{YELLOW}─────────────────────────────────{R}\n")
    return res


def call_llm_raw(model: str, messages: list, json_mode: bool = False,
                 temperature: float = 0.1, ctx_size: int = 4096,
                 timeout: int = 120) -> str:
    """Llamada de bajo nivel que retorna el contenido crudo (str) del backend activo.
    Usada por SubAgent y otros componentes que necesitan control fino."""
    res = ""
    if LLM_BACKEND == "deepseek":
        payload = {
            "model": model, "messages": messages,
            "temperature": temperature, "max_tokens": ctx_size, "stream": False,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        r = _HTTP.post(f"{DEEPSEEK_API_URL}/chat/completions",
                       json=payload, headers=_deepseek_headers(), timeout=(15, timeout))
        r.raise_for_status()
        res = r.json()["choices"][0]["message"]["content"]
    elif LLM_BACKEND == "lmstudio":
        payload = {
            "model": model, "messages": messages,
            "temperature": temperature, "max_tokens": ctx_size, "stream": False,
        }
        if json_mode:
            # LM Studio no soporta json_object de forma nativa sin schema
            pass
        r = requests.post(f"{LMSTUDIO_URL}/chat/completions", json=payload, timeout=timeout)
        r.raise_for_status()
        res = r.json()["choices"][0]["message"]["content"]
    else:
        payload = {
            "model": model, "messages": messages, "stream": False,
            "options": {"temperature": temperature, "num_ctx": ctx_size},
        }
        if json_mode:
            payload["format"] = "json"
        r = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
        r.raise_for_status()
        res = r.json()["message"]["content"]

    if VERBOSE:
        print(f"\n{YELLOW}[VERBOSE - RAW LLM RAW RESPONSE]{R}")
        print(res)
        print(f"{YELLOW}────────────────────────────────{R}\n")
    return res


def _backend_display_name() -> str:
    """Nombre legible del backend activo."""
    if LLM_BACKEND == "deepseek":
        return "DeepSeek API"
    return "LM Studio" if LLM_BACKEND == "lmstudio" else "Ollama"


def _backend_url() -> str:
    """URL del backend activo."""
    if LLM_BACKEND == "deepseek":
        return DEEPSEEK_API_URL
    return LMSTUDIO_URL if LLM_BACKEND == "lmstudio" else OLLAMA_URL


def pick_backend():
    """Menú interactivo para elegir entre Ollama, LM Studio y DeepSeek API."""
    global LLM_BACKEND
    separator("═", CYAN + BOLD, 48)
    print(f"{CYAN}{BOLD}  🤖  BACKEND LLM{R}")
    separator("═", CYAN + BOLD, 48)
    print()

    # Detectar disponibilidad
    ollama_ok, _     = check_ollama()
    lmstudio_ok, _   = check_lmstudio()
    deepseek_ok, _   = check_deepseek()

    ollama_status   = f"{GREEN}✓ online{R}" if ollama_ok   else f"{RED}✗ offline{R}"
    lmstudio_status = f"{GREEN}✓ online{R}" if lmstudio_ok else f"{RED}✗ offline{R}"
    deepseek_status = f"{GREEN}✓ API key configurada{R}" if deepseek_ok else f"{RED}✗ sin API key{R}"

    print(f"    {BOLD}1.{R}  🦙 {CYAN}{BOLD}Ollama{R}        {DIM}({OLLAMA_URL}){R}  {ollama_status}")
    print(f"    {BOLD}2.{R}  🖥️  {CYAN}{BOLD}LM Studio{R}     {DIM}({LMSTUDIO_URL}){R}  {lmstudio_status}")
    print(f"    {BOLD}3.{R}  🌐 {CYAN}{BOLD}DeepSeek API{R}  {DIM}({DEEPSEEK_API_URL}){R}  {deepseek_status}")
    print()

    # Contar backends disponibles
    available = []
    if ollama_ok:   available.append("ollama")
    if lmstudio_ok: available.append("lmstudio")
    if deepseek_ok: available.append("deepseek")

    # Auto-selección si solo uno está activo
    if len(available) == 1:
        LLM_BACKEND = available[0]
        print(f"  {GREEN}✓ Solo {_backend_display_name()} disponible → seleccionado automáticamente{R}")
        print()
        return
    if len(available) == 0:
        print(f"  {RED}✗ Ningún backend disponible.{R}")
        print(f"  {DIM}Inicia Ollama (ollama serve), LM Studio (lms server start),{R}")
        print(f"  {DIM}o configura DEEPSEEK_API_KEY en .env{R}")
        sys.exit(1)

    sel = input(f"  {CYAN}?{R} Selecciona backend [1/2/3] (default=1): ").strip()
    if sel == "3" and deepseek_ok:
        LLM_BACKEND = "deepseek"
        print(f"  {GREEN}✓ Backend:{R} {CYAN}{BOLD}DeepSeek API{R}\n")
    elif sel == "2" and lmstudio_ok:
        LLM_BACKEND = "lmstudio"
        print(f"  {GREEN}✓ Backend:{R} {CYAN}{BOLD}LM Studio{R}\n")
    elif sel == "2" and not lmstudio_ok:
        print(f"  {RED}✗ LM Studio no está online. Usando Ollama.{R}\n")
        LLM_BACKEND = "ollama"
    elif sel == "3" and not deepseek_ok:
        print(f"  {RED}✗ DeepSeek API no configurada. Usando Ollama.{R}\n")
        LLM_BACKEND = "ollama"
    else:
        LLM_BACKEND = "ollama"
        print(f"  {GREEN}✓ Backend:{R} {CYAN}{BOLD}Ollama{R}\n")


# ── Ejecución de comandos ─────────────────────────────────────────────────────

def run_command(cmd: str, cwd=None, timeout: int = None):
    t = timeout if timeout is not None else get_cmd_timeout(cmd)
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                                cwd=cwd or os.getcwd(), timeout=t)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timeout ({t}s) — el comando tardó demasiado", 1
    except Exception as e:
        return "", str(e), 1


def run_commands_parallel(cmds: list, cwd=None) -> list:
    """Corre comandos de recon en paralelo y devuelve lista de resultados ordenados."""
    results = [None] * len(cmds)

    def _run(i, cmd):
        results[i] = run_command(cmd, cwd)

    threads = [threading.Thread(target=_run, args=(i, cmd)) for i, cmd in enumerate(cmds)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results

# ── Nuclei JSON ───────────────────────────────────────────────────────────────
def inject_nuclei_json(cmd: str) -> tuple:
    """Si el comando es nuclei y no tiene -json-export, lo añade. Retorna (cmd, json_path|None)."""
    if "nuclei" not in cmd.split()[0] if cmd.strip() else True:
        return cmd, None
    json_path = f"/tmp/nuclei_{int(time.time())}.json"
    if "-json-export" not in cmd:
        cmd = cmd.rstrip() + f" -json-export {json_path}"
    return cmd, json_path


def parse_nuclei_json(json_path: str) -> list:
    """Lee el JSON de nuclei y devuelve lista de findings."""
    if not json_path:
        return []
    p = Path(json_path)
    if not p.exists():
        return []
    findings = []
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    findings.append(json.loads(line))
                except Exception:
                    pass
        p.unlink(missing_ok=True)
    except Exception:
        pass
    return findings


def format_nuclei_findings(findings: list) -> str:
    """Formatea hallazgos de nuclei como texto estructurado para el modelo."""
    dicts = [f for f in findings if isinstance(f, dict)]
    if not dicts:
        return ""
    lines = [f"\n[NUCLEI FINDINGS — {len(dicts)} hallazgos]"]
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    sorted_f = sorted(dicts, key=lambda f: SEV_ORDER.get(
        f.get("info", {}).get("severity", "unknown"), 5))
    for f in sorted_f[:30]:
        info = f.get("info", {})
        sev  = info.get("severity", "?").upper()
        name = info.get("name", "?")
        url  = f.get("matched-at", "?")
        cve  = ", ".join(info.get("classification", {}).get("cve-id", []) or [])
        lines.append(f"  [{sev}] {name} — {url}" + (f" ({cve})" if cve else ""))
    return "\n".join(lines)

# ── Detección de ruta de nuclei-templates ────────────────────────────────────
_NUCLEI_TEMPLATES_CANDIDATES = [
    Path.home() / ".local" / "nuclei-templates",
    Path.home() / "nuclei-templates",
    Path("/root/nuclei-templates"),
    Path("/root/.local/nuclei-templates"),
    Path("/usr/local/share/nuclei-templates"),
    Path("/usr/share/nuclei-templates"),
    Path("/opt/nuclei-templates"),
]

def find_nuclei_templates() -> str:
    """Retorna la ruta absoluta de nuclei-templates o '' si no se encuentra."""
    for p in _NUCLEI_TEMPLATES_CANDIDATES:
        try:
            if p.exists() and any(p.iterdir()):
                return str(p)
        except Exception:
            pass
    return ""

_NUCLEI_TEMPLATES_PATH: str = find_nuclei_templates()


def nuclei_fix_template_paths(cmd: str) -> str:
    """
    1. Elimina flags inválidos de nuclei v3 (-categories → -tags).
    2. Sustituye rutas relativas y ~/nuclei-templates/* por rutas absolutas.
    """
    if "nuclei" not in cmd:
        return cmd

    # Eliminar -categories (flag inválido en v3) y convertirlo a -tags
    cmd = re.sub(r'-categories\s+(\S+)', r'-tags \1', cmd)

    if not _NUCLEI_TEMPLATES_PATH:
        return cmd

    cats = ["cves", "vulnerabilities", "exposures", "misconfiguration",
            "technologies", "default-logins", "fuzzing", "helpers",
            "network", "workflows"]

    tpl_root = Path(_NUCLEI_TEMPLATES_PATH)

    for cat in cats:
        abs_cat = str(tpl_root / cat)
        if not Path(abs_cat).exists():
            continue
        # Caso 1: ruta relativa  -t cves/  o  -t cves
        cmd = re.sub(
            rf'(?<=-t\s){re.escape(cat)}/?(?=\s|$|-|")',
            abs_cat + "/",
            cmd,
        )
        # Caso 2: ~/nuclei-templates/cves/  o  ~/nuclei-templates/cves
        cmd = re.sub(
            rf'~/nuclei-templates/{re.escape(cat)}/?(?=\s|$|-|")',
            abs_cat + "/",
            cmd,
        )
        # Caso 3: ruta absoluta incorrecta que no existe
        #   /root/nuclei-templates/cves/ → ruta correcta
        cmd = re.sub(
            rf'/[^\s]*/nuclei-templates/{re.escape(cat)}/?(?=\s|$|-|")',
            abs_cat + "/",
            cmd,
        )

    return cmd


def sanitize_commands(commands_list, current_target: str = "") -> list[str]:
    """
    Sanitiza y traduce una lista de comandos generada por el LLM.
    Si el LLM genera comandos como objetos/diccionarios estructurados,
    los convierte a comandos CLI o llamadas de SKILL: legibles por el agente.
    """
    if not isinstance(commands_list, list):
        if isinstance(commands_list, str):
            commands_list = [commands_list]
        elif isinstance(commands_list, dict):
            commands_list = [commands_list]
        else:
            return []

    # Extraer dominio limpio de current_target
    default_domain = ""
    default_url = current_target or ""
    if default_url:
        default_domain = default_url
        for proto in ("https://", "http://"):
            if default_domain.startswith(proto):
                default_domain = default_domain[len(proto):].split("/")[0]

    clean_cmds = []
    for cmd in commands_list:
        if isinstance(cmd, str):
            clean_cmds.append(cmd)
        elif isinstance(cmd, dict):
            # 1. Si tiene directamente command/cmd como str
            cmd_str = cmd.get("command") or cmd.get("cmd") or cmd.get("action")
            if cmd_str and isinstance(cmd_str, str) and (cmd_str.lower().startswith("skill:") or " " in cmd_str):
                # Caso: action="subfinder_enum", domain="commodo.co" (como el último log)
                if cmd_str.lower() == "subfinder_enum":
                    domain = cmd.get("domain") or default_domain
                    clean_cmds.append(f"SKILL:subfinder_enum domain={domain} verify_http=true")
                    continue
                else:
                    clean_cmds.append(cmd_str)
                    continue

            # 2. Obtener campos clave de cualquier formato
            skill_field = str(cmd.get("skill") or cmd.get("tool") or cmd.get("action") or "").strip().lower()
            action_field = str(cmd.get("action") or "").strip().lower()
            target_field = str(cmd.get("target") or cmd.get("domain") or "").strip()
            
            # Obtener parámetros
            params = cmd.get("parameters") or cmd.get("params") or {}
            if not isinstance(params, dict):
                params = {"query": str(params)}

            # Buscar target/url/domain en los parámetros
            param_target = params.get("target") or params.get("ip") or params.get("domain") or params.get("query") or params.get("url") or ""
            
            # Target resuelto: preferir el específico del comando, luego el de params, y de fallback el del proyecto
            resolved_target = target_field or param_target or default_url or ""
            
            # Versión limpia de dominio/IP
            clean_domain = str(resolved_target)
            for proto in ("https://", "http://"):
                if clean_domain.startswith(proto):
                    clean_domain = clean_domain[len(proto):].split("/")[0]
            if not clean_domain:
                clean_domain = default_domain

            # Traducir según el valor del campo 'skill' o 'tool' o 'action'
            if skill_field == "subfinder_enum":
                clean_cmds.append(f"SKILL:subfinder_enum domain={clean_domain} verify_http=true")
            elif any(k in skill_field for k in ("shodan", "recon", "ports")):
                clean_cmds.append(f"SKILL:shodan_search query={clean_domain}")
            elif any(k in skill_field for k in ("whiteintel", "threat", "keys")):
                clean_cmds.append(f"SKILL:whiteintel domain={clean_domain}")
            elif "wpscan" in skill_field:
                clean_cmds.append(f"wpscan --url {resolved_target or default_url}")
            elif "nmap" in skill_field:
                ports = params.get("ports") or "80,443,8080"
                clean_cmds.append(f"nmap -sV -sC -F -T4 --min-rate 1000 -p {ports} {clean_domain}")
            elif "gobuster" in skill_field:
                clean_cmds.append(f"SKILL:gobuster_dir target={resolved_target or default_url}")
            elif "nuclei" in skill_field:
                clean_cmds.append(f"SKILL:nuclei_scan target={resolved_target or default_url}")
            elif "exploit" in skill_field:
                t_lower = resolved_target.lower()
                if "sqli" in t_lower or "sql injection" in t_lower or "sql" in t_lower:
                    clean_cmds.append(f"SKILL:sqli_scan target={resolved_target or default_url}")
                elif "xss" in t_lower or "cross" in t_lower or "contact-form" in t_lower:
                    clean_cmds.append(f"SKILL:web_attack target={resolved_target or default_url}")
                else:
                    clean_cmds.append(f"SKILL:web_attack target={resolved_target or default_url}")
            elif "s3" in skill_field or "bucket" in skill_field:
                bucket = params.get("bucket_name") or "commodo-backup"
                clean_cmds.append(f"curl -sI http://{bucket}.s3.amazonaws.com")
            elif "fetch" in skill_field:
                source = params.get("source") or ""
                if "whiteintel" in source:
                    clean_cmds.append(f"SKILL:whiteintel domain={clean_domain}")
                else:
                    clean_cmds.append(f"curl -sI {resolved_target or default_url}")
            else:
                # Reconstrucción genérica
                param_str = " ".join(f"--{k} {v}" for k, v in params.items() if v)
                parts = []
                if skill_field: parts.append(skill_field)
                if action_field and action_field != skill_field: parts.append(action_field)
                if param_str: parts.append(param_str)
                fallback_cmd = " ".join(parts).strip()
                if fallback_cmd:
                    clean_cmds.append(fallback_cmd)
                else:
                    clean_cmds.append(str(cmd))
        else:
            clean_cmds.append(str(cmd))
    return clean_cmds


# ── Mapeo de comandos crudos → SKILL: equivalentes ───────────────────────────
def _map_raw_to_skill(cmd: str, session_cfg: dict = None) -> str:
    """
    Si el modelo genera un comando crudo conocido (subfinder, gobuster, nuclei raw),
    lo convierte al SKILL: equivalente. Esto hace el agente robusto aunque el modelo
    ignore las instrucciones de usar SKILL:.
    Retorna el comando original si no hay mapeo.
    """
    s = cmd.strip()
    if s.upper().startswith("SKILL:"):
        return cmd  # ya es un skill

    cfg = session_cfg or {}
    _t = cfg.get("target", "")

    # subfinder solo o piped con httpx
    m = re.match(r'subfinder\s+-d\s+(\S+)', s, re.I)
    if m:
        domain = m.group(1)
        return f"SKILL:subfinder_enum domain={domain} verify_http=true"

    # gobuster dir
    m = re.match(r'gobuster\s+dir\s+-u\s+(\S+)', s, re.I)
    if m:
        target = m.group(1).rstrip("/")
        ext_m = re.search(r'-x\s+([^\s]+)', s)
        exts = ext_m.group(1) if ext_m else "php,html,txt,bak"
        return f"SKILL:gobuster_dir target={target} extensions={exts}"

    # nuclei con -t relativo o con ~/
    m = re.match(r'nuclei\s+-u\s+(\S+)', s, re.I)
    if m:
        target = m.group(1)
        sev_m = re.search(r'-severity\s+([^\s]+)', s)
        severity = sev_m.group(1) if sev_m else "critical,high,medium"
        return f"SKILL:nuclei_scan target={target} severity={severity}"

    return cmd


# ── Skill: parse SKILL: commands ─────────────────────────────────────────────
def parse_skill_call(cmd: str):
    """
    Detecta 'SKILL:nombre k1=v1 k2=v2' en un comando.
    Retorna (skill_name, args_dict) o (None, {}) si no es un skill.
    """
    if not cmd.strip().upper().startswith("SKILL:"):
        return None, {}
    import shlex
    rest  = cmd.strip()[6:]  # skip "SKILL:"
    try:
        parts = shlex.split(rest)
    except ValueError:
        # Keep the command usable while returning a helpful skill error later.
        parts = rest.split()
    if not parts:
        return None, {}
    skill_name = parts[0].lower()
    args: dict = {}
    positional_targets = []
    for p in parts[1:]:
        if "=" in p:
            k, _, v = p.partition("=")
            args[k.strip()] = v.strip()
        elif p.startswith(("http://", "https://")):
            positional_targets.append(p)
    # Accept a URL after an empty target argument as the actual target.
    if positional_targets and not args.get("target"):
        args["target"] = positional_targets[-1]
    return skill_name, args


# ── Verificación determinística HTTP ─────────────────────────────────────────
def verify_http_response(stdout: str, stderr: str) -> dict:
    """Analiza output de curl/httpx determinísticamente para validar findings."""
    result = {"vuln_indicators": [], "status_codes": [], "server_info": ""}
    # Extraer HTTP status codes
    for m in re.finditer(r"HTTP/[\d.]+\s+(\d{3})", stdout + stderr):
        result["status_codes"].append(int(m.group(1)))
    # Indicadores de vulnerabilidad
    vuln_patterns = [
        (r"SQL\s+syntax|mysql_fetch|ORA-\d{5}|sqlite_", "SQL Injection"),
        (r"<script>alert|XSS|document\.cookie", "XSS"),
        (r"root:x:0:0|/etc/passwd", "LFI"),
        (r"uid=\d+\(root\)|id=0\(root\)", "RCE"),
        (r"phpinfo\(\)|PHP Version \d+\.\d+", "PHP Info Exposure"),
    ]
    combined = (stdout + stderr)[:10000]
    for pattern, vuln_name in vuln_patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            result["vuln_indicators"].append(vuln_name)
    # Server info
    srv = re.search(r"(?:Server|X-Powered-By):\s*(.+)", combined, re.IGNORECASE)
    if srv:
        result["server_info"] = srv.group(1).strip()[:80]
    return result

# ── Extracción y visualización de vulnerabilidades ───────────────────────────
def _guess_severity(title: str) -> str:
    t = title.lower()
    if any(k in t for k in ("rce", "remote code", "command injection", "arbitrary file write", "unauthenticated sql")):
        return "Crítica"
    if any(k in t for k in ("arbitrary file read", "path traversal", "sql injection", "sqli", "authentication bypass", "file upload", "lfi", "rfi")):
        return "Alta"
    if any(k in t for k in ("xss", "cross-site scripting", "csrf", "ssrf", "open redirect")):
        return "Media"
    if any(k in t for k in ("idor", "information disclosure", "data exposure", "sensitive data")):
        return "Baja"
    return "Media"


def _extract_component_before(text: str, pos: int) -> str:
    pre = text[max(0, pos - 3000):pos]
    plugin_hits = list(re.finditer(r"/plugins/([^/\s\)\"']+)/", pre))
    theme_hits  = list(re.finditer(r"/themes/([^/\s\)\"']+)/", pre))
    last_plugin = plugin_hits[-1].group(1) if plugin_hits else None
    last_theme  = theme_hits[-1].group(1)  if theme_hits  else None
    if last_plugin and last_theme:
        lp = pre.rfind(last_plugin)
        lt = pre.rfind(last_theme)
        return last_plugin if lp > lt else f"Theme: {last_theme}"
    if last_plugin:
        return last_plugin
    if last_theme:
        return f"Theme: {last_theme}"
    if re.search(r"WordPress version \d", pre):
        return "WordPress core"
    return "WordPress"


def parse_wpscan_vulns(text: str) -> list:
    vulns = []
    title_spans = [(m.start(), m.group(1).strip())
                   for m in re.finditer(r"\[!\]\s+Title:\s+(.+)", text)]
    for vid, (pos, title) in enumerate(title_spans, start=1):
        next_pos  = title_spans[vid][0] if vid < len(title_spans) else pos + 900
        ctx       = text[pos: min(next_pos, pos + 900)]
        fixed_m   = re.search(r"Fixed in:\s+(\S+)", ctx)
        cve_m     = re.search(r"CVE-\d{4}-\d+", ctx)
        ref_m     = re.search(r"https://wpscan\.com/vulnerability/[a-z0-9\-]+", ctx)
        vulns.append({
            "id":          vid,
            "titulo":      title,
            "severidad":   _guess_severity(title),
            "cve":         cve_m.group(0) if cve_m else None,
            "componente":  _extract_component_before(text, pos),
            "descripcion": title,
            "fixed_in":    fixed_m.group(1).rstrip(".,)").strip() if fixed_m else None,
            "ref":         ref_m.group(0) if ref_m else None,
        })
    return vulns


def extract_vulns_from_log(model: str, log_content: str) -> list:
    direct = parse_wpscan_vulns(log_content)
    if direct:
        return direct
    prompt = (
        "Del siguiente log de auditoría extrae TODAS las vulnerabilidades.\n"
        "Responde SOLO con un array JSON válido, sin texto extra, sin markdown.\n"
        "Campos por objeto: id(int), titulo(str), severidad(Crítica|Alta|Media|Baja|Info), "
        "cve(str|null), componente(str), descripcion(str), fixed_in(str|null), ref(str|null)\n\n"
        f"LOG:\n{log_content[:60000]}"
    )
    try:
        raw = call_llm_text(model, prompt)
        s, e = raw.find("["), raw.rfind("]") + 1
        if s != -1 and e > s:
            return json.loads(raw[s:e])
    except Exception:
        pass
    return []


def print_vulns(vulns: list):
    SEV_COLOR = {"Crítica": RED + BOLD, "Alta": YELLOW + BOLD,
                 "Media": YELLOW, "Baja": CYAN, "Info": DIM}
    if not vulns:
        print(f"\n  {YELLOW}⚠ No se encontraron vulnerabilidades en el log aún.{R}")
        print(f"  {DIM}Ejecuta un escaneo primero (wpscan, nuclei, nikto...).{R}\n")
        return
    separator("═", RED + BOLD, 62)
    print(f"  {RED}{BOLD}🔴 VULNERABILIDADES — {len(vulns)} total{R}")
    separator("═", RED + BOLD, 62)
    for v in vulns:
        col = SEV_COLOR.get(v.get("severidad", ""), WHITE)
        print(f"\n  {col}[#{v['id']}]  {v.get('titulo', '?')}{R}")
        print(f"       {DIM}Severidad :{R} {col}{v.get('severidad', '?')}{R}")
        print(f"       {DIM}Componente:{R} {v.get('componente', '?')}")
        if v.get("cve"):
            print(f"       {DIM}CVE       :{R} {CYAN}{v['cve']}{R}")
        if v.get("fixed_in"):
            print(f"       {DIM}Fix en    :{R} {BOLD}{v['fixed_in']}{R}")
        if v.get("ref"):
            print(f"       {DIM}Ref       :{R} {DIM}{v['ref']}{R}")
    separator("═", RED + BOLD, 62)
    print(f"\n  {DIM}Escribe {WHITE}explotar <N>{R}{DIM} para crear un PoC{R}\n")

# ── Animaciones / UI ──────────────────────────────────────────────────────────
class Spinner:
    _FRAMES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

    def __init__(self, message="procesando..."):
        self.message = message
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        labels = itertools.cycle(["analizando...","procesando...","consultando modelo...","generando respuesta..."])
        label  = self.message
        tick   = 0
        for frame in itertools.cycle(self._FRAMES):
            if self._stop.is_set():
                break
            if tick % 25 == 0:
                label = next(labels)
            sys.stdout.write(f"\r  {CYAN}{frame}{R}  {DIM}{label}{R}   ")
            sys.stdout.flush()
            time.sleep(0.08)
            tick += 1
        sys.stdout.write("\r" + " " * 52 + "\r")
        sys.stdout.flush()

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._thread.join()


def typewrite(text: str, delay: float = 0.015, color: str = WHITE):
    for ch in text:
        sys.stdout.write(f"{color}{ch}{R}")
        sys.stdout.flush()
        time.sleep(delay)
    print()


def separator(char="─", color=DIM, width=56):
    print(f"{color}{char * width}{R}")


def print_help():
    """Muestra TODO lo que el agente puede hacer: comandos, disparadores y skills."""
    W = 62
    print()
    separator("═", RED + BOLD, W)
    print(f"  {RED}{BOLD}🛠  HACKERAGENT — TODO LO QUE PUEDES HACER{R}")
    separator("═", RED + BOLD, W)

    print(f"\n  {CYAN}{BOLD}▸ COMANDOS DE CONTROL{R}")
    for cmd, desc in [
        ("help / ayuda / ?",            "muestra esta ayuda"),
        ("salir / exit",               "guarda la sesión y sale"),
        ("cd <ruta>",                  "cambia el directorio de trabajo"),
        ("sesiones",                   "lista las sesiones guardadas"),
        ("sesion guardar/cargar <n>",  "guarda o reanuda una sesión por nombre"),
        ("apikeys",                    "estado de las API keys (.env)"),
        ("modelo <nombre>",            "cambia el modelo del backend activo en caliente"),
        ("backend [ollama|lmstudio|deepseek]", "cambia backend LLM (Ollama / LM Studio / DeepSeek)"),
        ("reporte / html",            "genera reporte Markdown + HTML"),
        ("listame vulnerabilidades",   "parsea el log y numera las vulns"),
        ("explotar <N>",               "crea un PoC para la vulnerabilidad N"),
    ]:
        print(f"    {YELLOW}{cmd:<26}{R} {DIM}{desc}{R}")

    print(f"\n  {CYAN}{BOLD}▸ LENGUAJE NATURAL — DISPARADORES AUTOMÁTICOS{R}")
    for trig, desc in [
        ('hackea|escanea|pentest|audita <url>', "recon+scan automático (4 fases sin LLM) y explotación"),
        ('bypass|crackea|reversea|parchea …',   "ing. inversa automática de un binario/script/carpeta"),
        ('"bypass el login"',                  "descubre el archivo del login, lo revierte y te da el bypasseado"),
        ('clasifica|classifica|valida',        "clasifica hallazgos como vulnerabilidad real o falso positivo usando IA"),
        ('clasifica <texto>',                  "clasifica un hallazgo o archivo específico"),
        ('optimiza|optimizar|tunea|mejora',    "optimiza el LLM: benchmark + diagnóstico + auto-tune"),
        ('diagnostica|diagnostico|revisa',     "diagnostica el estado del LLM (conectividad, JSON, rendimiento)"),
        ('explota vuln CVE-XXXX en <target>',  "investiga CVE, busca exploits, y si no hay genera PoC automático"),
    ]:
        print(f"    {GREEN}{trig:<38}{R}\n      {DIM}{desc}{R}")

    print(f"\n  {CYAN}{BOLD}▸ OPTIMIZACIÓN DE IA (nuevos skills){R}")
    print(f"    {WHITE}SKILL:llm_optimizer action=benchmark{R}    {DIM}prueba rendimiento y tasa de éxito JSON{R}")
    print(f"    {WHITE}SKILL:llm_optimizer action=diagnose{R}     {DIM}diagnostica problemas del LLM{R}")
    print(f"    {WHITE}SKILL:llm_optimizer action=optimize task=pentest{R}  {DIM}recomienda parámetros óptimos{R}")
    print(f"    {WHITE}SKILL:llm_optimizer action=full_report{R}  {DIM}reporte completo (recomendado){R}")
    print(f"    {WHITE}SKILL:prompt_engineer action=analyze{R}    {DIM}analiza el system prompt{R}")
    print(f"    {WHITE}SKILL:prompt_engineer action=optimize{R}   {DIM}sugiere mejoras al prompt{R}")
    print(f"    {WHITE}SKILL:prompt_engineer action=test{R}       {DIM}prueba variantes de prompt{R}")
    print(f"    {WHITE}SKILL:prompt_engineer action=template{R}   {DIM}genera templates por tarea{R}")
    print(f"    {WHITE}SKILL:response_validator action=quality_score{R} {DIM}puntúa calidad de respuestas{R}")
    print(f"    {WHITE}SKILL:response_validator action=fix{R}     {DIM}corrige JSON malformado{R}")

    print(f"\n  {CYAN}{BOLD}▸ FLUJOS OFENSIVOS RECOMENDADOS{R}")
    print(f"    {WHITE}Web:{R}   {DIM}web_attack → sqli_scan (dump) → explotar{R}")
    print(f"    {WHITE}Creds:{R} {DIM}whiteintel (descarga) → cred_stuff (prueba y di cuál sirve){R}")
    print(f"    {WHITE}RE:{R}    {DIM}ing_inversa <carpeta|binario|script> → binfinal + run_bypass.sh{R}")
    print(f"    {WHITE}Optim:{R} {DIM}SKILL:llm_optimizer action=full_report → mejora el LLM{R}")

    # ── Skills disponibles, agrupados por categoría (dinámico) ────────────────
    if _SKILLS_AVAILABLE:
        by_cat = _skills_by_category()
        if by_cat:
            print(f"\n  {CYAN}{BOLD}▸ SKILLS DISPONIBLES  (usa: SKILL:<nombre> arg=valor){R}")
            all_cats = list(CATEGORY_ORDER) + [c for c in by_cat if c not in CATEGORY_ORDER]
            for cat in all_cats:
                items = by_cat.get(cat, [])
                if not items:
                    continue
                print(f"\n    {BOLD}{CATEGORY_LABELS.get(cat, cat)}{R}")
                for name, desc, mod in items:
                    ex = mod.META.get("example", "")
                    print(f"      {GREEN}{name:<16}{R} {DIM}{desc[:60]}{R}")
                    if ex:
                        print(f"        {DIM}ej: {ex[:70]}{R}")
    separator("═", RED + BOLD, W)
    print()


RISK_COLORS = {"low": GREEN, "medium": YELLOW, "high": RED, "critical": MAGENTA}
PHASE_ICONS = {"recon": "🔍", "scan": "📡", "exploit": "💥", "post-exploit": "🏴", "report": "📋"}

def _build_banner() -> list:
    return [
    f"{RED}{BOLD}  ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ {R}",
    f"{RED}{BOLD}  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗{R}",
    f"{RED}{BOLD}  ███████║███████║██║     █████╔╝ █████╗  ██████╔╝{R}",
    f"{RED}{BOLD}  ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗{R}",
    f"{RED}{BOLD}  ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║{R}",
    f"{RED}{BOLD}  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{R}",
    f"  {MAGENTA}{BOLD}A G E N T  v2{R}  {DIM}· Cybersecurity AI Terminal · Powered by {_backend_display_name()}{R}",
]

_STARS = {5: f"{GREEN}★★★★★{R}", 4: f"{CYAN}★★★★{DIM}☆{R}",
          3: f"{YELLOW}★★★{DIM}☆☆{R}", 2: f"{DIM}★★☆☆☆{R}", 1: f"{DIM}★☆☆☆☆{R}"}


def print_disclaimer():
    separator("═", RED + BOLD, 58)
    print(f"{RED}{BOLD}  ⚠   A V I S O   L E G A L   /   D I S C L A I M E R{R}")
    separator("═", RED + BOLD, 58)
    for line in [
        "", "  Esta herramienta es para uso EXCLUSIVO en auditorías",
        "  de seguridad con AUTORIZACIÓN EXPRESA del propietario.",
        "", "  El uso no autorizado es un delito:",
        "    · Art. 197 bis CP (España)  ·  CFAA (USA)",
        "    · Equivalentes en cada jurisdicción", "",
        "  Al continuar confirmas autorización escrita.", "",
    ]:
        print(f"{YELLOW}{line}{R}")
        time.sleep(0.04)
    separator("═", RED + BOLD, 58)
    ans = input(f"\n{WHITE}  ¿Confirmas autorización? [s/N]: {R}").strip().lower()
    if ans not in ("s", "si", "sí", "y", "yes"):
        print(f"\n{RED}  Abortando.{R}\n")
        sys.exit(0)
    print(f"\n{GREEN}  ✓ Autorización confirmada.{R}\n")
    time.sleep(0.3)


def print_header(model: str, session_name: str, all_models: list,
                 resumed: bool = False, tool_confs: list = None):
    print()
    banner = _build_banner()
    for line in banner:
        print(line)
        time.sleep(0.05)
    print()
    separator("─", RED, 56)
    print(f"  {DIM}Modelo :{R}  {MAGENTA}{BOLD}{model}{R}")
    print(f"  {DIM}Sesión :{R}  {CYAN}{session_name}{R}  {DIM}{'(reanudada)' if resumed else '(nueva)'}{R}")
    print(f"  {DIM}Salida :{R}  {DIM}{OUT_DIR}{R}")
    print(f"  {DIM}Backend:{R}  {CYAN}{BOLD}{_backend_display_name()}{R}  {DIM}{_backend_url()}{R}")
    separator("─", RED, 56)
    print(f"\n  {BOLD}Modelos disponibles:{R}")
    # Ordenar por puntuación
    ranked = sorted(all_models, key=lambda m: score_model(m)[0], reverse=True)
    for m in ranked:
        stars_n, desc = score_model(m)
        stars_str     = _STARS.get(stars_n, "")
        if m == model:
            print(f"    {GREEN}▸{R} {CYAN}{BOLD}{m:<30}{R}  {stars_str}  {GREEN}← activo{R}")
        else:
            print(f"    {DIM}·  {m:<30}{R}  {stars_str}  {DIM}{desc}{R}")
    if tool_confs:
        separator("─", DIM, 56)
        print(f"\n  {BOLD}Herramientas ({CONFS_FILE.name}):{R}")
        for t in tool_confs:
            name = t.get("name", "?")
            cmd  = t.get("command", "").strip()
            path = t.get("path", "").strip()
            detail = f"{CYAN}{cmd}{R}" if cmd else ""
            if path:
                detail += f"  {DIM}{path}{R}" if detail else f"{DIM}{path}{R}"
            print(f"    {GREEN}·{R}  {BOLD}{name:<20}{R}  {detail}")
    separator("─", DIM, 56)
    print("  " + "  ·  ".join(f"{YELLOW}{v}{R}" for v in
          ["help", "salir", "cd <ruta>", "sesiones", "sesion guardar/cargar <n>",
           "apikeys", "backend", "reporte", "listame vulnerabilidades", "explotar <N>"]))
    separator("─", DIM, 56)
    print()


def print_thinking(text: str, phase: str = "recon", risk: str = "low"):
    if not text:
        return
    icon = PHASE_ICONS.get(phase, "🔍")
    rcol = RISK_COLORS.get(risk, GREEN)
    print(f"\n  {icon} {DIM}[{R}{CYAN}{phase.upper()}{R}{DIM}]{R}  {DIM}[{R}{rcol}{BOLD}{risk.upper()}{R}{DIM}]{R}")
    separator("╌", DIM, 50)
    for line in text.split(". "):
        if line.strip():
            print(f"  {DIM}{line.strip()}.{R}")
    separator("╌", DIM, 50)


def print_command(cmd: str, cached: bool = False):
    separator("─", DIM, 50)
    tag = f"  {DIM}[cache]{R}" if cached else ""
    print(f"  {GREEN}❯{R} {BOLD}{cmd}{R}{tag}")
    separator("─", DIM, 50)


def print_output(stdout: str, stderr: str, code: int):
    if stdout.strip():
        lines = stdout.strip().split("\n")
        for line in lines[:400]:
            print(f"  {DIM}{line}{R}")
        if len(lines) > 400:
            print(f"  {YELLOW}··· {len(lines)-400} líneas omitidas ···{R}")
    if stderr.strip():
        color = RED if code != 0 else YELLOW
        for line in stderr.strip().split("\n")[:30]:
            print(f"  {color}{line}{R}")
    status = f"{GREEN}✓ OK{R}" if code == 0 else f"{RED}✗ exit {code}{R}"
    print(f"  {DIM}└─{R} {status}")


def print_web_fetch(url: str, result: dict):
    separator("─", BLUE, 50)
    print(f"  {BLUE}{BOLD}🌐 {url}{R}")
    sc   = result["status_code"]
    scol = GREEN if sc < 400 else RED
    print(f"  {DIM}Status:{R} {scol}{BOLD}{sc}{R}  {DIM}Size: {result['body_length']} bytes{R}")
    for hdr in ["Server", "server", "X-Powered-By", "x-powered-by"]:
        val = result["headers"].get(hdr, "")
        if val:
            print(f"  {DIM}{hdr}:{R} {CYAN}{val}{R}")
            break
    if result["body_truncated"]:
        print(f"  {YELLOW}⚠ HTML truncado a 8 000 chars{R}")
    separator("─", BLUE, 50)


def confirm(prompt: str) -> bool:
    ans = input(f"\n{YELLOW}  ⚠  {prompt} [s/N]: {R}").strip().lower()
    return ans in ("s", "si", "sí", "y", "yes")


def show_apikeys_status():
    separator("─", CYAN, 48)
    print(f"  {BOLD}API Keys:{R}")
    for k in ["WPSCAN_API_KEY", "SHODAN_API_KEY", "VIRUSTOTAL_API_KEY"]:
        val    = get_api_key(k)
        masked = (val[:4] + "·"*8 + val[-4:]) if len(val) > 8 else "·"*8
        icon   = GREEN + "✓" if val else RED + "✗"
        print(f"    {icon}{R}  {k:<25} {DIM}{masked if val else 'no configurada'}{R}")
    separator("─", CYAN, 48)
    print()

# ── Perfiles de tarea (definen qué skills se muestran por defecto) ────────────
TASK_PROFILES = {
    "1": {
        "name":        "🌐 Pentesting web / Red Team",
        "desc":        "Reconocimiento, escaneo de vulnerabilidades, explotación web",
        "categories":  ["recon_pasivo", "recon_activo", "vuln_scan", "analisis"],
        "target_hint": "Objetivo (URL, IP o dominio  — ej: https://example.com)",
        "agr_default": "3",
    },
    "2": {
        "name":        "🔬 Ingeniería inversa / Binarios",
        "desc":        "Análisis estático, bypass automático (LD_PRELOAD, r2), RE de ejecutables",
        "categories":  ["ing_inversa"],
        "target_hint": "Ruta al binario (ej: /opt/app/programa)",
        "agr_default": "1",
    },
    "3": {
        "name":        "🕵️  OSINT / Reconocimiento pasivo",
        "desc":        "crt.sh, Shodan, Google Dorks, subfinder — sin tocar el target",
        "categories":  ["recon_pasivo"],
        "target_hint": "Dominio o empresa (ej: example.com)",
        "agr_default": "1",
    },
    "4": {
        "name":        "🎯 Escaneo de vulnerabilidades",
        "desc":        "Nuclei, WPScan, Gobuster — detección activa de CVEs",
        "categories":  ["vuln_scan", "recon_activo"],
        "target_hint": "Objetivo (URL, IP o dominio)",
        "agr_default": "3",
    },
    "5": {
        "name":        "🔍 Análisis de código / Secretos",
        "desc":        "Spider web, extracción de API keys y credenciales en JS/HTML",
        "categories":  ["analisis"],
        "target_hint": "URL o dominio a analizar",
        "agr_default": "2",
    },
    "6": {
        "name":        "🔥 Full (todos los skills)",
        "desc":        "Todas las categorías disponibles — selección manual posterior",
        "categories":  None,
        "target_hint": "Objetivo (URL, IP, dominio o ruta)",
        "agr_default": "2",
    },
}


# ── Wizard de configuración ───────────────────────────────────────────────────
def ask_session_config(available_skills: list = None, prefill_project_name: str = "") -> dict:
    separator("═", CYAN + BOLD, 58)
    print(f"{CYAN}{BOLD}  ⚙  CONFIGURACIÓN DE SESIÓN{R}")
    separator("═", CYAN + BOLD, 58)
    print(f"{DIM}  Configura el comportamiento del agente para esta sesión.{R}\n")

    def ask(question: str, default: bool = False) -> bool:
        hint = f"[{'S' if default else 's'}/{'n' if default else 'N'}]"
        ans  = input(f"  {CYAN}?{R} {question} {DIM}{hint}{R}: ").strip().lower()
        return default if not ans else ans in ("s", "si", "sí", "y", "yes")

    def ask_text(question: str, default: str = "") -> str:
        hint = f"(default: {default})" if default else ""
        ans  = input(f"  {CYAN}?{R} {question} {DIM}{hint}{R}: ").strip()
        return ans or default

    def ask_choice(question: str, choices: list, default: str) -> str:
        opts = "/".join(f"{BOLD if c==default else ''}{c}{R}" for c in choices)
        ans  = input(f"  {CYAN}?{R} {question} [{opts}]: ").strip().lower()
        return ans if ans in choices else default

    # ── 1. Tipo de análisis (intent detection) ────────────────────────────────
    print()
    separator("─", CYAN, 58)
    print(f"\n  {CYAN}{BOLD}¿Qué tipo de análisis deseas realizar?{R}\n")
    for num, prof in TASK_PROFILES.items():
        print(f"    {DIM}{num}.{R}  {CYAN}{BOLD}{prof['name']:<38}{R}  {DIM}{prof['desc']}{R}")
    print()
    task_sel    = input(f"  {CYAN}?{R} Tipo de análisis [1-6] (default=6): ").strip()
    task_profile = TASK_PROFILES.get(task_sel, TASK_PROFILES["6"])
    profile_cats = task_profile["categories"]   # None → todos
    target_hint  = task_profile["target_hint"]
    agr_default  = task_profile["agr_default"]
    print(f"  {GREEN}✓{R} Perfil: {CYAN}{task_profile['name']}{R}\n")
    separator("─", CYAN, 58)

    # Pre-filtrar skills del perfil elegido (si el perfil limita categorías)
    if profile_cats is not None and available_skills:
        by_cat_all   = _skills_by_category(available_skills)
        pre_selected = [
            sname
            for cat in profile_cats
            for sname, _, _ in by_cat_all.get(cat, [])
        ]
        pre_selected = pre_selected or list(available_skills)
    else:
        pre_selected = list(available_skills) if available_skills else []

    # ── 2. Preguntas generales ────────────────────────────────────────────────
    print()
    project_name   = ask_text("Nombre del proyecto (ej: Auditoria Corp 2026)", prefill_project_name)
    target         = ask_text(target_hint, "")
    scan_subdoms   = ask("¿Escanear subdominios? (subfinder + amass)", False)
    gen_report     = ask("¿Generar reporte al finalizar? (HTML + Markdown)", True)
    stealth        = ask("¿Modo sigiloso? (bajo ruido, evasión IDS/IPS)", False)
    check_persist  = ask("¿Buscar vectores de persistencia?", False)
    aggressiveness = ask_choice("Agresividad [1=pasivo … 5=agresivo]",
                                ["1", "2", "3", "4", "5"], agr_default)
    use_subagents  = ask("¿Usar sub-agentes por skill? (análisis paralelo, contexto limpio)", True)
    auto_classify  = ask("¿Auto-clasificar hallazgos con LLM? (distingue TP/FP)", True)
    auto_optimize  = ask("¿Auto-optimizar LLM antes de cada instrucción? (recomendado)", True)

    # ── 3. Selección de skills ────────────────────────────────────────────────
    enabled_skills = pre_selected or available_skills or []
    if available_skills:
        separator("─", CYAN, 58)
        print(f"\n  {CYAN}{BOLD}🎯 Skills del perfil «{task_profile['name']}»:{R}")
        if profile_cats:
            print(f"  {DIM}(muestra skills del perfil — escribe 'all' para ver todos){R}")

        # Construir lista numerada por categoría (usando pre_selected como base)
        display_skills = pre_selected if pre_selected else available_skills
        by_cat     = _skills_by_category(display_skills)
        num_map    = {}   # number → skill_name
        cat_map    = {}   # category → [skill_name, ...]
        skill_nums = {}   # skill_name → number
        n = 1
        all_cats   = list(CATEGORY_ORDER) + [c for c in by_cat if c not in CATEGORY_ORDER]
        for cat in all_cats:
            items = by_cat.get(cat, [])
            if not items:
                continue
            label = CATEGORY_LABELS.get(cat, cat)
            print(f"\n  {YELLOW}{BOLD}{label}{R}")
            for skill_name, desc, _mod in items:
                print(f"    {DIM}{n:>2}.{R}  {CYAN}{skill_name:<22}{R} {DIM}{desc[:45]}{R}")
                num_map[n] = skill_name
                skill_nums[skill_name] = n
                cat_map.setdefault(cat, []).append(skill_name)
                n += 1

        print(f"\n  {DIM}Enter = todos del perfil  |  Números: 1,3  |  Categoría: vuln_scan  |  all = todos{R}")
        sel = input(f"  {CYAN}?{R} Seleccionar skills: ").strip().lower()

        if sel == "all":
            # Reconstruir con todos los skills disponibles
            by_cat_all = _skills_by_category(available_skills)
            n = 1; num_map = {}; cat_map = {}; skill_nums = {}
            print(f"\n  {CYAN}{BOLD}Todos los skills disponibles:{R}")
            for cat in list(CATEGORY_ORDER) + [c for c in by_cat_all if c not in CATEGORY_ORDER]:
                for skill_name, desc, _mod in by_cat_all.get(cat, []):
                    print(f"    {DIM}{n:>2}.{R}  {CYAN}{skill_name:<22}{R} {DIM}{desc[:45]}{R}")
                    num_map[n] = skill_name; skill_nums[skill_name] = n
                    cat_map.setdefault(cat, []).append(skill_name); n += 1
            sel = input(f"  {CYAN}?{R} Seleccionar (Enter = todos): ").strip().lower()
            base_pool = available_skills
        else:
            base_pool = display_skills

        if not sel:
            enabled_skills = list(base_pool)
            print(f"  {GREEN}✓ Skills activados ({len(enabled_skills)}): {', '.join(enabled_skills)}{R}")
        else:
            chosen: set = set()
            for token in re.split(r'[,\s]+', sel):
                token = token.strip().lower()
                if not token:
                    continue
                if token.isdigit():
                    sname = num_map.get(int(token))
                    if sname:
                        chosen.add(sname)
                elif token in cat_map:
                    chosen.update(cat_map[token])
                elif token in (available_skills or []):
                    chosen.add(token)
            enabled_skills = sorted(chosen, key=lambda s: skill_nums.get(s, 99)) if chosen else list(base_pool)
            print(f"  {GREEN}✓ Skills activados: {', '.join(enabled_skills)}{R}")

    config = {
        "project_name":   project_name,
        "task_profile":   task_profile["name"],
        "target":         target,
        "scan_subdomains": scan_subdoms,
        "generate_report": gen_report,
        "stealth_mode":   stealth,
        "check_persistence": check_persist,
        "aggressiveness": int(aggressiveness),
        "use_subagents":  use_subagents,
        "auto_classify":  auto_classify,
        "auto_optimize":  auto_optimize,
        "enabled_skills": enabled_skills,
    }
    print(); separator("─", CYAN, 58)
    labels = {
        "project_name":   "Proyecto",
        "task_profile":   "Tipo de análisis",
        "target":         "Objetivo",
        "scan_subdomains": "Subdominios",
        "generate_report": "Reporte automático",
        "stealth_mode":   "Modo sigiloso",
        "check_persistence": "Buscar persistencia",
        "aggressiveness": "Agresividad",
        "use_subagents":  "Sub-agentes por skill",
        "auto_classify":  "Auto-clasificar hallazgos",
        "auto_optimize":  "Auto-optimizar LLM",
        "enabled_skills": "Skills activos",
    }
    for k, v in config.items():
        if k == "enabled_skills":
            icon = GREEN + "✓" if v else DIM + "·"
            val_str = ", ".join(v) if v else "ninguno"
            print(f"    {icon}{R}  {labels[k]:<22} {CYAN}{val_str}{R}")
        else:
            icon = GREEN + "✓" if v and v != 0 else DIM + "·"
            print(f"    {icon}{R}  {labels.get(k, k):<22} {CYAN}{v}{R}")
    separator("─", CYAN, 58); print()
    return config


def config_to_context(cfg: dict) -> str:
    lines = ["[CONFIGURACIÓN DE SESIÓN]"]
    if cfg.get("target"):
        lines.append(f"- Objetivo declarado: {cfg['target']}")
    lines.append(f"- Escanear subdominios: {'SÍ (usa subfinder y amass)' if cfg.get('scan_subdomains') else 'NO'}")
    lines.append(f"- Modo sigiloso: {'SÍ (técnicas T2, delays, evasión)' if cfg.get('stealth_mode') else 'NO'}")
    lines.append(f"- Buscar persistencia: {'SÍ' if cfg.get('check_persistence') else 'NO'}")
    agr = cfg.get("aggressiveness", 2)
    lines.append(f"- Agresividad: {agr}/5 ({'pasivo/OSINT' if agr<=2 else 'activo/moderado' if agr<=3 else 'agresivo'})")
    return "\n".join(lines)

# ── Generación de reporte ─────────────────────────────────────────────────────
def generate_report(model: str, session_name: str, log: LogWriter, target_dir: Path):
    log_content = log.path.read_text(encoding="utf-8") if log.path.exists() else ""
    if len(log_content) < 100:
        print(f"  {YELLOW}⚠ El log está vacío. Ejecuta al menos un escaneo primero.{R}")
        return
    report_path = target_dir / f"{session_name}_report.md"
    prompt = f"{REPORT_PROMPT}\n\n---\n\n{log_content[:24000]}"
    print(f"\n  {MAGENTA}{BOLD}📋 Generando reporte de auditoría...{R}")
    try:
        with Spinner("generando reporte..."):
            report_md = call_llm_text(model, prompt)
    except Exception as e:
        print(f"  {RED}✗ Error generando reporte: {e}{R}"); return
    header = (f"<!-- HackerAgent Report -->\n"
              f"<!-- Sesión: {session_name} -->\n"
              f"<!-- Generado: {datetime.now():%Y-%m-%d %H:%M:%S} -->\n\n")
    report_path.write_text(header + report_md, encoding="utf-8")
    separator("═", MAGENTA + BOLD, 58)
    print(f"\n  {MAGENTA}{BOLD}📋 REPORTE GENERADO{R}")
    separator("═", MAGENTA + BOLD, 58)
    lines = report_md.split("\n")
    for line in lines[:60]:
        if line.startswith("# "):
            print(f"\n  {BOLD}{WHITE}{line}{R}")
        elif line.startswith("## "):
            print(f"\n  {CYAN}{BOLD}{line}{R}")
        elif line.startswith("### "):
            print(f"\n  {YELLOW}{line}{R}")
        elif "🔴" in line or "crítico" in line.lower():
            print(f"  {RED}{line}{R}")
        elif "🟠" in line or "alta" in line.lower():
            print(f"  {YELLOW}{line}{R}")
        elif line.startswith("|"):
            print(f"  {DIM}{line}{R}")
        else:
            print(f"  {line}")
    if len(lines) > 60:
        print(f"\n  {DIM}... ({len(lines)-60} líneas más en el archivo){R}")
    separator("═", MAGENTA + BOLD, 58)
    print(f"\n  {GREEN}✓ Guardado en:{R} {CYAN}{report_path}{R}\n")
    if len(lines) > 60 and confirm("¿Ver el reporte completo en terminal?"):
        print()
        for line in lines:
            print(f"  {line}")
        print()

def generate_html_report(model: str, session_name: str, log: LogWriter,
                          target_dir: Path, session_config: dict = None,
                          project_state: "ProjectState | None" = None) -> Path | None:
    """Genera reporte HTML completo con hallazgos, comandos y subdominios."""
    log_content = log.path.read_text(encoding="utf-8") if log.path.exists() else ""
    if len(log_content) < 100:
        return None

    cfg          = session_config or {}
    target       = cfg.get("target", target_dir.name)
    project_name = cfg.get("project_name", "") or target
    date_str     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_path  = target_dir / f"{session_name}_report.html"

    def esc(s: str) -> str:
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # ── Parseo del log MD ─────────────────────────────────────────────────────
    cmd_blocks = re.findall(
        r'\*\*Comando:\*\*\s+`([^`]+)`[^\n]*\n+```\n(.*?)\n```',
        log_content, re.DOTALL
    )

    # Dominios: preferir ProjectState > parsear MD
    if project_state and project_state.domains:
        subdomains = sorted(project_state.domains)
    else:
        domain_base = re.sub(r'^https?://', '', target).rstrip('/').split('/')[0]
        sub_pat = re.compile(
            r'\b((?:[\w-]+\.)+' + re.escape(domain_base) + r')\b', re.IGNORECASE
        )
        subdomains = sorted(set(
            s.lower() for s in sub_pat.findall(log_content)
            if s.lower() != domain_base.lower()
        ))

    nuclei = [f for f in log.nuclei_finds if isinstance(f, dict)]

    # Hallazgos no-nuclei del ProjectState agrupados por severidad
    ps_findings = []
    if project_state:
        ps_findings = [f for f in project_state.findings
                       if isinstance(f, dict) and f.get("type") not in
                       ("subdomain", "subdomain_crt", "http_active")
                       and f.get("severity") in ("critical", "high", "medium")]

    # ── Cards ─────────────────────────────────────────────────────────────────
    total_findings = len(nuclei) + len(ps_findings)
    crit_count = sum(1 for f in (nuclei + ps_findings) if isinstance(f,dict)
                     and f.get("severity") in ("critical","high"))
    cards_html = (
        f'<div class="card"><div class="num">{len(subdomains)}</div><div class="lbl">Subdominios</div></div>'
        f'<div class="card"><div class="num" style="color:{"#ff2222" if crit_count else "#00d4ff"}">{crit_count}</div><div class="lbl">Críticos/Altos</div></div>'
        f'<div class="card"><div class="num">{total_findings}</div><div class="lbl">Hallazgos totales</div></div>'
        f'<div class="card"><div class="num">{len(cmd_blocks)}</div><div class="lbl">Comandos</div></div>'
    )

    # ── Tablas de hallazgos ───────────────────────────────────────────────────
    SEV_COL = {"critical": "#ff2222", "high": "#ff6600", "medium": "#ffaa00",
               "low": "#4488ff", "info": "#666666"}
    SEV_ORD = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    # Nuclei
    if nuclei:
        rows = ""
        for f in sorted(nuclei, key=lambda x: SEV_ORD.get(x.get("info", {}).get("severity", ""), 5)):
            info = f.get("info", {})
            sev  = info.get("severity", "?")
            col  = SEV_COL.get(sev.lower(), "#888")
            cve  = ", ".join(info.get("classification", {}).get("cve-id", []) or [])
            rows += (
                f'<tr><td><b style="color:{col}">{esc(sev.upper())}</b></td>'
                f'<td>{esc(info.get("name","?"))}</td>'
                f'<td class="sm">{esc(f.get("matched-at","?"))}</td>'
                f'<td>{esc(cve or "—")}</td></tr>\n'
            )
        nuclei_sec = (
            '<h2>🎯 Vulnerabilidades (Nuclei)</h2>'
            '<table><thead><tr><th>Sev</th><th>Nombre</th><th>URL / Target</th><th>CVE</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )
    else:
        nuclei_sec = '<h2>🎯 Vulnerabilidades (Nuclei)</h2><p class="dim">Sin hallazgos de Nuclei en esta sesión.</p>'

    # Hallazgos de ProjectState (puertos peligrosos, CVEs Shodan, WPScan, etc.)
    if ps_findings:
        rows2 = ""
        for f in sorted(ps_findings, key=lambda x: SEV_ORD.get(x.get("severity","info"), 4)):
            sev  = f.get("severity", "info")
            col  = SEV_COL.get(sev.lower(), "#888")
            ftyp = f.get("type", "?")
            desc = (f.get("title") or f.get("cve") or f.get("value") or
                    f.get("path") or f.get("url") or f.get("port", "?"))
            src  = f.get("source", "?")
            rows2 += (
                f'<tr><td><b style="color:{col}">{esc(sev.upper())}</b></td>'
                f'<td>{esc(ftyp)}</td>'
                f'<td class="sm">{esc(str(desc))}</td>'
                f'<td class="sm">{esc(src)}</td></tr>\n'
            )
        ps_sec = (
            '<h2>⚠ Otros Hallazgos (Skills)</h2>'
            '<table><thead><tr><th>Sev</th><th>Tipo</th><th>Detalle</th><th>Fuente</th></tr></thead>'
            f'<tbody>{rows2}</tbody></table>'
        )
    else:
        ps_sec = ""

    # ── Tabla subdominios ─────────────────────────────────────────────────────
    if subdomains:
        sub_rows = "".join(f'<tr><td class="sub">{esc(s)}</td></tr>' for s in subdomains[:200])
        subs_sec = (
            f'<h2>🌐 Subdominios ({len(subdomains)})</h2>'
            '<table><thead><tr><th>Subdominio</th></tr></thead>'
            f'<tbody>{sub_rows}</tbody></table>'
        )
    else:
        subs_sec = '<h2>🌐 Subdominios</h2><p class="dim">Sin subdominios encontrados.</p>'

    # ── Log de comandos ───────────────────────────────────────────────────────
    cmd_parts = []
    for cmd, output in cmd_blocks[:200]:
        short   = esc(cmd[:100])
        out_esc = esc(output[:4000])
        cmd_parts.append(
            f'<details><summary><span class="arr">❯</span> {short}</summary>'
            f'<pre class="out">{out_esc}</pre></details>'
        )
    cmds_sec = '<h2>⌨ Log de Comandos</h2>' + ("".join(cmd_parts) or '<p class="dim">Sin comandos registrados.</p>')

    # ── CSS ───────────────────────────────────────────────────────────────────
    css = (
        "*{box-sizing:border-box;margin:0;padding:0}"
        "body{background:#0d0d0d;color:#e0e0e0;font-family:'Courier New',Courier,monospace;font-size:13px;line-height:1.6}"
        ".wrap{max-width:1200px;margin:0 auto;padding:24px}"
        "h1{color:#ff3333;font-size:1.7em;border-bottom:2px solid #ff3333;padding-bottom:8px;margin-bottom:16px}"
        "h2{color:#00d4ff;font-size:1.1em;margin:28px 0 12px;border-left:3px solid #00d4ff;padding-left:10px}"
        ".meta{color:#555;font-size:.85em;margin-bottom:24px}"
        ".meta span{color:#bbb}"
        ".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:16px 0 28px}"
        ".card{background:#111;border:1px solid #222;border-radius:5px;padding:14px;text-align:center}"
        ".card .num{font-size:2.2em;font-weight:bold;color:#00d4ff}"
        ".card .lbl{font-size:.8em;color:#555;margin-top:4px}"
        "table{width:100%;border-collapse:collapse;margin:10px 0}"
        "th{background:#151515;color:#ff3333;padding:8px 10px;text-align:left;font-size:.82em;border-bottom:1px solid #ff3333}"
        "td{padding:7px 10px;border-bottom:1px solid #1a1a1a;font-size:.83em;word-break:break-all}"
        "tr:hover{background:#111}"
        "td.sub{color:#00d4ff}"
        "td.sm{font-size:.75em}"
        "details{background:#0f0f0f;border:1px solid #1e1e1e;border-radius:3px;margin:4px 0}"
        "details summary{padding:8px 12px;cursor:pointer;color:#00ff88;font-size:.83em;list-style:none}"
        "details summary::-webkit-details-marker{display:none}"
        "details summary:hover{color:#00d4ff;background:#111}"
        "details[open] summary{border-bottom:1px solid #1e1e1e}"
        ".arr{color:#ff3333;margin-right:6px}"
        "pre.out{padding:10px 14px;color:#777;font-size:.8em;white-space:pre-wrap;word-break:break-all;max-height:400px;overflow-y:auto}"
        ".dim{color:#444;font-style:italic;padding:8px 0}"
        "footer{color:#333;text-align:center;margin-top:50px;padding-top:16px;border-top:1px solid #1a1a1a;font-size:.8em}"
    )

    # ── Ensamblado ────────────────────────────────────────────────────────────
    html = (
        '<!DOCTYPE html>\n<html lang="es">\n<head>\n'
        '<meta charset="UTF-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1.0">\n'
        f'<title>{esc(project_name)} — HackerAgent</title>\n'
        f'<style>{css}</style>\n'
        '</head>\n<body><div class="wrap">\n'
        f'<h1>🔍 {esc(project_name)}</h1>\n'
        f'<div class="meta">Target: <span>{esc(target)}</span> &nbsp;·&nbsp; '
        f'Sesión: <span>{esc(session_name)}</span> &nbsp;·&nbsp; '
        f'Fecha: <span>{date_str}</span> &nbsp;·&nbsp; '
        f'Modelo: <span>{esc(model)}</span></div>\n'
        f'<div class="cards">{cards_html}</div>\n'
        f'{nuclei_sec}\n{ps_sec}\n{subs_sec}\n{cmds_sec}\n'
        f'<footer>HackerAgent v2 &nbsp;·&nbsp; {date_str} &nbsp;·&nbsp; Solo para uso autorizado con autorización escrita</footer>\n'
        '</div></body>\n</html>\n'
    )

    report_path.write_text(html, encoding="utf-8")
    return report_path


# ── Fases de pentest automáticas (sin LLM) ───────────────────────────────────
_PENTEST_TRIGGER = re.compile(
    r'\b(?:hackea|escanea|pentest(?:ea)?|audita|analiza|ataca|testea|buscame|busca|encuentra|'
    r'subdominios?|subdomains?|dorks?|reconocimiento|recon)\b.{0,60}?(https?://\S+|[\w.-]+\.\w{2,6})',
    re.IGNORECASE
)

# ── Trigger específico para subdominios (solo enumera, no pentest completo) ──
_SUBDOMAIN_TRIGGER = re.compile(
    r'\b(?:subdominio|subdominios|subdomain|subdomains)\b.{0,40}?(?:de\s+)?([\w.-]+\.[a-z]{2,20})',
    re.IGNORECASE
)

# ── Trigger "explota la vulnerabilidad CVE-XXXX en TARGET" ────────────────────
_EXPLOIT_VULN_TRIGGER = re.compile(
    r'\b(?:explota|explotar|exploit[ae]?r?|verifica|verificar|prueba|probar|'
    r'ataca|atacar|lanza|lanzar)\b'
    r'.{0,30}?'
    r'\b(?:(?:la\s+)?vuln(?:erabilidad)?|cve|exploit)\b'
    r'.{0,40}?'
    r'(CVE-\d{4}-\d{4,7}|[\w\s/.-]{3,40}?)'
    r'\s+(?:en|on|against|contra|sobre|in)\s+'
    r'(https?://\S+|[\w.\-:]+)',
    re.IGNORECASE
)

# ── Ingeniería inversa / bypass automático (sin LLM) ─────────────────────────
_RE_TRIGGER = re.compile(
    r'\b(?:bypass(?:ea|ear)?|crack(?:ea|ear)?|reversea?r?|revierte|revertir|'
    r'parch(?:ea|ear)?|patch(?:ea|ear)?|desbloquea|desbloquear|saltar(?:se)?|'
    r'ingenier[ií]a\s+inversa|ing[\s.]*inversa)\b'
    r'|no\s+pida\s+(?:el\s+)?(?:login|usuario|contrase|clave|credencial)'
    r'|sin\s+(?:login|usuario|contrase|clave|credencial|autenticaci)'
    r'|(?:quita|elimina|omite|salta|remueve)\w*\s+(?:el\s+)?login'
    r'|ingres[ae]\w*\s+(?:autom|direct|sin)',
    re.IGNORECASE
)


def _resolve_re_target(text: str, cwd: str) -> str:
    """
    Extrae del texto la ruta a bypassear. Si no hay ninguna, usa el cwd
    (el skill ing_inversa autodescubre el archivo objetivo dentro de la carpeta).
    """
    def _is_filesystem_root(candidate: str) -> bool:
        """Evita que un '/' suelto gane a una ruta real posterior."""
        try:
            resolved = Path(candidate).resolve()
            return resolved.parent == resolved
        except (OSError, RuntimeError):
            return False

    def _is_explicit_absolute(candidate: str) -> bool:
        """Reconoce rutas POSIX y Windows aunque el servidor use el otro SO."""
        return bool(
            os.path.isabs(candidate)
            or candidate.startswith("/")
            or candidate.startswith("\\\\")
            or re.match(r"^[A-Za-z]:[\\/]", candidate)
        )

    # 1) ruta entre comillas (soporta espacios)
    m = re.search(r'["\']([^"\']+)["\']', text)
    if m:
        quoted = os.path.expanduser(m.group(1))
        if not _is_filesystem_root(quoted):
            # Conservar una ruta absoluta inexistente permite que el skill
            # reporte el target correcto en lugar de analizar cwd en silencio.
            if Path(quoted).exists() or _is_explicit_absolute(quoted):
                return quoted

    # 2) cualquier token separado por espacios que exista como archivo/carpeta
    missing_absolute: list[str] = []
    for raw in text.split():
        tok = raw.strip('.,;:!?)("\'')
        if not tok or tok.lower() in ("bypass", "el", "login", "the", "de", "la", "al", "un"):
            continue
        cand = os.path.expanduser(tok)
        if _is_explicit_absolute(cand):
            if _is_filesystem_root(cand):
                continue
            if Path(cand).exists():
                return cand
            missing_absolute.append(cand)
            continue
        rel = Path(cwd) / tok
        if ("/" in tok or "\\" in tok or "." in tok) and rel.exists():
            return str(rel)
    if missing_absolute:
        return missing_absolute[0]
    # 3) sin ruta explícita → la carpeta actual (autodescubrimiento en el skill)
    return cwd

def _run_phase(title: str, cmds: list, log: LogWriter, cwd: str, cache: ScanCache) -> list:
    """Ejecuta una lista de (label, cmd) y retorna resultados."""
    print(f"\n  {CYAN}{BOLD}▶ {title}{R}\n")
    results = []
    for label, cmd in cmds:
        cached_e = cache.get(cmd)
        if cached_e:
            stdout, stderr, code = cached_e["stdout"], cached_e["stderr"], cached_e["code"]
            is_cached = True
        else:
            print_command(cmd)
            stdout, stderr, code = run_command(cmd, cwd)
            cache.put(cmd, stdout, stderr, code)
            is_cached = False
        if is_cached:
            print_command(cmd, cached=True)
        print_output(stdout, stderr, code)
        log.command(cmd, stdout, stderr, code, cached=is_cached)
        out = (stdout or stderr or "(sin output)").strip()
        results.append(f"[{label}]\n$ {cmd}\n{out[:3000]}")
    return results


def run_pentest_phases(target: str, log: LogWriter, cwd: str, cache: ScanCache) -> str:
    """
    Ejecuta las 4 fases de pentest SIN LLM y retorna un resumen compacto
    para pasar al modelo como contexto de explotación.
    """
    domain   = re.sub(r'^https?://', '', target).rstrip('/').split('/')[0]
    base_url = target if target.startswith('http') else f'https://{target}'

    log.section(f"Auto-pentest → {target}")

    # ── CRT.SH via skill (curl con timeout 10s falla en dominios grandes) ───────
    print(f"\n  {CYAN}{BOLD}▶ Certificate Transparency (crt.sh){R}\n")
    print_command(f"SKILL:crtsh_enum domain={domain}")
    crtsh_r   = run_skill("crtsh_enum", domain=domain)
    crtsh_out = crtsh_r.get("output", "crt.sh sin resultados")
    crtsh_ok  = crtsh_r.get("success", False)
    print_output(crtsh_out, "", 0 if crtsh_ok else 1)
    log.command(f"SKILL:crtsh_enum domain={domain}", crtsh_out, "", 0 if crtsh_ok else 1)

    # ── FASE 1: Reconocimiento pasivo ─────────────────────────────────────────
    phase1 = [
        ("WHOIS",        f'whois {domain} 2>/dev/null | head -30'),
        ("DNS-ANY",      f'dig {domain} ANY +short 2>/dev/null | head -20'),
        ("HEADERS",      f'curl -sIL --max-time 12 {base_url}'),
        ("GOOGLE-LOGIN",  (
            f'echo "Dork manual: site:{domain} inurl:login OR inurl:admin OR inurl:wp-admin OR inurl:panel"; '
            f'curl -s --max-time 10 -A "Mozilla/5.0" '
            f'"https://www.google.com/search?q=site:{domain}+inurl:login+OR+inurl:admin+OR+inurl:wp-admin" '
            f'| grep -oP "(?<=<cite>)[^<]+" | grep {domain} | head -15 2>/dev/null || true'
        )),
        ("GOOGLE-FILES",  (
            f'echo "Dork manual: site:{domain} filetype:env OR filetype:sql OR filetype:bak OR filetype:log"; '
            f'curl -s --max-time 10 -A "Mozilla/5.0" '
            f'"https://www.google.com/search?q=site:{domain}+filetype:env+OR+filetype:sql+OR+filetype:bak" '
            f'| grep -oP "(?<=<cite>)[^<]+" | grep {domain} | head -15 2>/dev/null || true'
        )),
        ("SHODAN-QUICK",  f'curl -s --max-time 10 "https://internetdb.shodan.io/{domain}" 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "shodan sin datos"'),
    ]

    # ── FASE 2: Identificación de tecnologías ─────────────────────────────────
    phase2 = [
        ("WHATWEB",      f'whatweb -v {base_url} 2>/dev/null'),
        ("WAFW00F",      f'wafw00f {base_url} 2>/dev/null'),
        ("ROBOTS",       f'curl -sL --max-time 10 {base_url}/robots.txt 2>/dev/null'),
        ("SITEMAP",      f'curl -sL --max-time 10 {base_url}/sitemap.xml 2>/dev/null | head -30'),
        ("SUBFINDER",    f'subfinder -d {domain} -silent 2>/dev/null | head -30'),
    ]

    # ── FASE 3: Spider y búsqueda de credenciales en código fuente ────────────
    phase3 = [
        ("SOURCE-SECRETS", (
            f'curl -sL --max-time 20 {base_url} '
            f'| grep -iE "(api[_-]?key|apikey|password|passwd|token|secret|authorization|aws_|db_pass|database_url)" '
            f'| head -25 2>/dev/null || echo "Sin secretos visibles en HTML"'
        )),
        ("JS-FILES", (
            f'curl -sL --max-time 20 {base_url} 2>/dev/null'
            r' | python3 -c "import sys,re;html=sys.stdin.read();'
            r'[print(m) for m in re.findall(r\"src=[\\x22\\x27]([^\\x22\\x27]+\\.js[^\\x22\\x27]*)[\\x22\\x27]\",html)]"'
            ' | head -15 || echo "Sin JS externo detectado"'
        )),
        ("EMAIL-HARVEST", (
            f'curl -sL --max-time 20 {base_url} '
            f'| grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{{2,}}" '
            f'| sort -u | head -20 2>/dev/null || echo "Sin emails"'
        )),
        ("COMMENTS-CREDS", (
            f'curl -sL --max-time 20 {base_url} '
            f'| grep -oP "<!--.*?-->" '
            f'| grep -iE "(pass|user|key|todo|fix|hack|admin|debug)" '
            f'| head -10 2>/dev/null || echo "Sin comentarios sospechosos"'
        )),
    ]

    all_results = [f"[CRT.SH]\n{crtsh_out[:3000]}"]
    all_results += _run_phase("FASE 1 — Reconocimiento Pasivo (Google Dorks · whois · DNS)", phase1, log, cwd, cache)
    all_results += _run_phase("FASE 2 — Identificación de Tecnologías y Servicios",              phase2, log, cwd, cache)
    all_results += _run_phase("FASE 3 — Spider y Búsqueda de Credenciales en Código Fuente",    phase3, log, cwd, cache)

    summary = "\n\n".join(all_results)
    print(f"\n  {GREEN}{BOLD}✓ Recon completado — pasando hallazgos al modelo para explotación...{R}\n")
    return summary


# ── Pipeline: explota vulnerabilidad (investigación + búsqueda + PoC) ─────────
def _fetch_cve_details(cve_id: str) -> dict:
    """
    Consulta detalles de una CVE usando cveawg.circl.lu (primaria)
    con fallback a NIST NVD.
    Retorna dict con: description, cvss, severity, products, references.
    """
    result = {"description": "", "cvss": "", "severity": "", "products": [], "references": []}
    try:
        import requests as _rq
    except ImportError:
        return result

    # ── Fuente 1: cveawg.circl.lu (rápida, sin rate-limit) ──
    try:
        r = _rq.get(f"https://cveawg.circl.lu/api/cve/{cve_id}", timeout=12)
        if r.ok:
            data = r.json()
            # Descripción
            cna = data.get("containers", {}).get("cna", {})
            descs = cna.get("descriptions", data.get("cveMetadata", {}).get("descriptions", []))
            if descs:
                for d in descs:
                    if d.get("lang", "en").startswith("en"):
                        result["description"] = d.get("value", "")[:500]
                        break
                if not result["description"]:
                    result["description"] = descs[0].get("value", "")[:500]
            # Productos afectados
            affected = cna.get("affected", [])
            for a in affected[:5]:
                vendor = a.get("vendor", "?")
                product = a.get("product", "?")
                versions = [v.get("version", "?") for v in a.get("versions", [])[:3]]
                result["products"].append(f"{vendor}/{product} {', '.join(versions)}")
            # Métricas CVSS
            metrics = cna.get("metrics", [])
            for m in metrics:
                for key in ("cvssV3_1", "cvssV3_0", "cvssV31", "cvssV30", "cvssV2_0"):
                    if key in m:
                        cv = m[key]
                        result["cvss"] = str(cv.get("baseScore", ""))
                        result["severity"] = cv.get("baseSeverity", "").upper()
                        break
            # Referencias
            refs = cna.get("references", [])
            result["references"] = [ref.get("url", "") for ref in refs[:5] if ref.get("url")]
            if result["description"]:
                return result
    except Exception:
        pass

    # ── Fuente 2: NIST NVD (fallback) ──
    try:
        r = _rq.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
            timeout=15,
            headers={"User-Agent": "HackerAgent/2.0"}
        )
        if r.ok:
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve_data = vulns[0].get("cve", {})
                # Descripción
                for d in cve_data.get("descriptions", []):
                    if d.get("lang") == "en":
                        result["description"] = d.get("value", "")[:500]
                        break
                # CVSS
                metrics = cve_data.get("metrics", {})
                for ver in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    mlist = metrics.get(ver, [])
                    if mlist:
                        cv = mlist[0].get("cvssData", {})
                        result["cvss"] = str(cv.get("baseScore", ""))
                        result["severity"] = cv.get("baseSeverity", "").upper()
                        break
                # Referencias
                refs = cve_data.get("references", [])
                result["references"] = [r2.get("url", "") for r2 in refs[:5] if r2.get("url")]
    except Exception:
        pass
    return result


def _normalize_vuln_term(term: str) -> str:
    """Normaliza nombres comunes de vulns a términos de búsqueda."""
    aliases = {
        "log4shell": "CVE-2021-44228", "log4j": "CVE-2021-44228",
        "eternalblue": "CVE-2017-0144", "eternal blue": "CVE-2017-0144",
        "shellshock": "CVE-2014-6271", "shell shock": "CVE-2014-6271",
        "heartbleed": "CVE-2014-0160", "heart bleed": "CVE-2014-0160",
        "bluekeep": "CVE-2019-0708", "blue keep": "CVE-2019-0708",
        "spring4shell": "CVE-2022-22965", "springshell": "CVE-2022-22965",
        "dirty pipe": "CVE-2022-0847", "dirtypipe": "CVE-2022-0847",
        "dirty cow": "CVE-2016-5195", "dirtycow": "CVE-2016-5195",
        "pwnkit": "CVE-2021-4034", "pkexec": "CVE-2021-4034",
        "zerologon": "CVE-2020-1472", "zero logon": "CVE-2020-1472",
        "proxylogon": "CVE-2021-26855", "proxy logon": "CVE-2021-26855",
        "proxyshell": "CVE-2021-34473", "proxy shell": "CVE-2021-34473",
        "printnightmare": "CVE-2021-34527", "print nightmare": "CVE-2021-34527",
        "smbghost": "CVE-2020-0796", "smb ghost": "CVE-2020-0796",
    }
    key = term.strip().lower()
    return aliases.get(key, term.strip())


def run_exploit_vuln_pipeline(vuln_term: str, target: str, log: LogWriter,
                              cwd: str, cache: ScanCache) -> str:
    """
    Pipeline de investigación + búsqueda de exploits para una vulnerabilidad.
    1. Si es CVE → consulta detalles (cveawg / NVD)
    2. Busca exploits (exploit_db + metasploit + searchsploit)
    3. Retorna resumen compacto para el LLM
    """
    log.section(f"Exploit pipeline → {vuln_term} en {target}")
    all_results = []
    exploits_found = 0

    # ── Normalizar nombre de vuln ──
    original_term = vuln_term.strip()
    vuln_term = _normalize_vuln_term(vuln_term)
    is_cve = bool(re.match(r'CVE-\d{4}-\d{4,7}', vuln_term, re.I))
    if is_cve:
        vuln_term = vuln_term.upper()
    search_term = vuln_term

    # ── FASE 1: Detalles de la CVE ────────────────────────────────────────────
    print(f"\n  {CYAN}{BOLD}▶ FASE 1 — Investigación de la vulnerabilidad{R}\n")
    cve_info = {}
    if is_cve:
        print(f"  {DIM}Consultando detalles de {vuln_term}...{R}")
        cve_info = _fetch_cve_details(vuln_term)
        if cve_info.get("description"):
            sev_color = RED if cve_info.get("severity") in ("CRITICAL", "HIGH") else YELLOW
            print(f"  {WHITE}{BOLD}{vuln_term}{R}")
            if cve_info.get("cvss"):
                print(f"  {sev_color}CVSS: {cve_info['cvss']} {cve_info.get('severity', '')}{R}")
            print(f"  {DIM}{cve_info['description'][:300]}{R}")
            if cve_info.get("products"):
                print(f"  {DIM}Productos: {', '.join(cve_info['products'][:3])}{R}")
            if cve_info.get("references"):
                for ref in cve_info["references"][:3]:
                    print(f"  {DIM}  → {ref}{R}")
            all_results.append(
                f"[CVE DETAILS]\n{vuln_term}\n"
                f"CVSS: {cve_info.get('cvss', 'N/A')} ({cve_info.get('severity', 'N/A')})\n"
                f"Descripción: {cve_info['description']}\n"
                f"Productos: {', '.join(cve_info.get('products', []))}\n"
                f"Referencias: {chr(10).join(cve_info.get('references', []))}"
            )
            log.command(f"CVE lookup {vuln_term}", str(cve_info), "", 0)
        else:
            print(f"  {YELLOW}⚠ No se encontraron detalles para {vuln_term} en APIs públicas{R}")
            all_results.append(f"[CVE DETAILS]\nNo se encontraron detalles de {vuln_term}")
    else:
        print(f"  {WHITE}Búsqueda por término: \"{vuln_term}\"{R}")
        if original_term.lower() != vuln_term.lower():
            print(f"  {DIM}(normalizado de \"{original_term}\" → \"{vuln_term}\"){R}")
        all_results.append(f"[VULN TERM]\nBúsqueda: {vuln_term}")

    # ── FASE 2: Búsqueda de exploits ──────────────────────────────────────────
    print(f"\n  {CYAN}{BOLD}▶ FASE 2 — Búsqueda de exploits existentes{R}\n")

    # 2a. Exploit-DB via skill
    edb_args = {"cve": vuln_term} if is_cve else {"search": vuln_term}
    print_command(f"SKILL:exploit_db {' '.join(f'{k}={v}' for k,v in edb_args.items())}")
    edb_result = run_skill("exploit_db", **edb_args)
    edb_out = edb_result.get("output", "")
    edb_findings = edb_result.get("findings", [])
    edb_exploits = [f for f in edb_findings if f.get("type") in ("exploit_found", "edb_exploit")]
    exploits_found += len(edb_exploits)
    print_output(edb_out[:2000], "", 0 if edb_result.get("success") else 1)
    log.command(f"SKILL:exploit_db {edb_args}", edb_out[:3000], "", 0)
    all_results.append(f"[EXPLOIT-DB]\n{edb_out[:3000]}")

    # 2b. Metasploit search via skill
    msf_args = {"mode": "search"}
    if is_cve:
        msf_args["cve"] = vuln_term
    else:
        msf_args["cve"] = vuln_term  # mode=search acepta término libre también
    print_command(f"SKILL:metasploit mode=search {'cve' if is_cve else 'query'}={vuln_term}")
    msf_result = run_skill("metasploit", **msf_args)
    msf_out = msf_result.get("output", "")
    msf_findings = msf_result.get("findings", [])
    msf_modules = [f for f in msf_findings if f.get("type") in ("msf_module", "exploit_found", "module_found")]
    exploits_found += len(msf_modules)
    print_output(msf_out[:2000], "", 0 if msf_result.get("success") else 1)
    log.command(f"SKILL:metasploit mode=search {vuln_term}", msf_out[:3000], "", 0)
    all_results.append(f"[METASPLOIT]\n{msf_out[:3000]}")

    # 2c. searchsploit directo (fallback/complemento)
    ssploit_cmd = f'searchsploit "{search_term}" 2>/dev/null | head -30'
    print_command(ssploit_cmd)
    ss_out, ss_err, ss_code = run_command(ssploit_cmd, cwd)
    ss_text = (ss_out or ss_err or "").strip()
    if ss_text and "No Results" not in ss_text:
        # Contar líneas con resultados (no headers)
        ss_lines = [l for l in ss_text.split("\n") if l.strip() and not l.startswith("---") and "Exploit Title" not in l]
        exploits_found += len(ss_lines)
    print_output(ss_out, ss_err, ss_code)
    log.command(ssploit_cmd, ss_out or "", ss_err or "", ss_code)
    all_results.append(f"[SEARCHSPLOIT]\n{ss_text[:2000]}")

    # ── Resumen ────────────────────────────────────────────────────────────────
    summary = "\n\n".join(all_results)
    if exploits_found > 0:
        print(f"\n  {GREEN}{BOLD}✓ {exploits_found} exploit(s) encontrado(s) — pasando al modelo para explotación contra {target}...{R}\n")
    else:
        print(f"\n  {YELLOW}{BOLD}⚠ No se encontraron exploits existentes — el modelo intentará crear un PoC de verificación...{R}\n")
    return summary


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="HackerAgent v2")
    parser.add_argument("--model",         "-m", help="Modelo a usar (Ollama o LM Studio)")
    parser.add_argument("--session",       "-s", help="Nombre de sesión")
    parser.add_argument("--list-sessions", "-l", action="store_true")
    parser.add_argument("--no-disclaimer",       action="store_true")
    parser.add_argument("--no-wizard",           action="store_true")
    # ── Web UI mode ────────────────────────────────────────────────────
    parser.add_argument("--web",           action="store_true",
                        help="Lanzar interfaz web (Flask) en lugar del chat de terminal")
    parser.add_argument("--port",          type=int, default=7860,
                        help="Puerto para la interfaz web (default: 7860)")
    parser.add_argument("--host",          default="0.0.0.0",
                        help="Host para la interfaz web (default: 0.0.0.0)")
    parser.add_argument("--backend",       "-b",
                        choices=["ollama", "lmstudio", "deepseek"],
                        default=None,
                        help="Backend LLM: ollama, lmstudio o deepseek (si no se indica, se pregunta)")
    parser.add_argument("--deepseek", "--deepsek", action="store_true",
                        help="Modo DeepSeek rápido (acepta también el alias --deepsek)")
    parser.add_argument("--verbose",       action="store_true",
                        help="Mostrar logs detallados y respuesta cruda del LLM")
    args = parser.parse_args()

    global VERBOSE, LLM_BACKEND
    VERBOSE = args.verbose

    # Debe aplicarse antes del dispatch web: de lo contrario `--web --deepseek`
    # arrancaba Flask con el backend anterior. La variable de entorno hace que
    # todos los skills que usan skills.llm_client hereden la misma elección.
    if args.deepseek or args.backend == "deepseek":
        LLM_BACKEND = "deepseek"
        os.environ["HACKERAGENT_LLM_BACKEND"] = "deepseek"
        os.environ["HACKERAGENT_FAST_MODE"] = "1"
    elif args.backend:
        LLM_BACKEND = args.backend
        os.environ["HACKERAGENT_LLM_BACKEND"] = args.backend

    # ── Dispatch web mode ──────────────────────────────────────────────
    if args.web:
        try:
            from web_server import launch as _web_launch
        except ImportError as _e:
            print(f"{RED}✗ Error importando web_server.py: {_e}{R}")
            sys.exit(1)
        _web_launch(host=args.host, port=args.port, verbose=args.verbose)
        return

    tool_confs    = load_tool_confs()
    tools_context = build_tools_context(tool_confs)
    load_skills()
    available_skill_names = skill_names()

    # ── Auto-install de herramientas esenciales ──────────────────────────────
    if _HAVE_TOOL_MANAGER and not args.list_sessions:
        print(f"\n  {DIM}🔧 Verificando herramientas esenciales...{R}")
        missing = []
        for _essential in ["nmap", "curl", "ffuf", "nuclei", "gobuster",
                           "subfinder", "httpx", "whatweb", "dig", "whois"]:
            if not tool_manager.check_tool(_essential):
                missing.append(_essential)
        if missing:
            print(f"  {YELLOW}⚠ Herramientas faltantes: {', '.join(missing)}{R}")
            print(f"  {DIM}Instalando automáticamente...{R}")
            for _tool in missing:
                _ok = tool_manager.install_tool(_tool)
                if _ok:
                    print(f"  {GREEN}✓ {_tool} instalado{R}")
                else:
                    print(f"  {DIM}· {_tool} — se omitirá (no crítica){R}")
        else:
            print(f"  {GREEN}✓ Todas las herramientas esenciales instaladas{R}")
        print()

    if args.list_sessions:
        sessions = list_sessions()
        if not sessions:
            print(f"{YELLOW}Sin sesiones en {OUT_DIR}{R}")
        else:
            print(f"\n{BOLD}Sesiones guardadas:{R}")
            for s in sessions:
                stars_n, _ = score_model(s["model"])
                stars_str  = _STARS.get(stars_n, "")
                print(f"  {CYAN}{s['name']:<32}{R} {DIM}{s['target']:<24}{s['saved_at'][:19]}  {s['turns']} turnos{R}  {stars_str}  {DIM}[{s['model']}]{R}")
        return

    if not args.no_disclaimer:
        print_disclaimer()

    # ── Selección de backend LLM ──────────────────────────────────────
    if args.deepseek:
        LLM_BACKEND = "deepseek"
        print(f"  {GREEN}✓ Backend (CLI):{R} {CYAN}{BOLD}DeepSeek API{R}\n")
    elif args.backend:
        LLM_BACKEND = args.backend
        print(f"  {GREEN}✓ Backend (CLI):{R} {CYAN}{BOLD}{_backend_display_name()}{R}\n")
    else:
        pick_backend()

    os.environ["HACKERAGENT_LLM_BACKEND"] = LLM_BACKEND
    if LLM_BACKEND == "deepseek":
        os.environ["HACKERAGENT_FAST_MODE"] = "1"
    else:
        os.environ.pop("HACKERAGENT_FAST_MODE", None)

    model, all_models = get_model_auto(args.model)

    # ── Selección / creación de proyecto ──────────────────────────────────────
    session_config      = {}
    conversation        = None
    saved_model         = None
    resumed             = False
    project_name_picked = ""

    if args.session:
        # Modo legacy: --session nombre  →  buscar en todos los subdirs de out/
        session_name        = args.session
        conversation, saved_model, loaded_td = load_session(session_name)
        resumed             = conversation is not None
        project_dir         = loaded_td or get_target_outdir(session_name)
    else:
        # Picker interactivo de proyecto
        project_name_picked, project_dir, resume_session = pick_or_create_project()
        if resume_session:
            # Usuario eligió reanudar una sesión concreta
            session_name = resume_session
            conversation, saved_model, _ = load_session_in_project(resume_session, project_dir)
            resumed      = conversation is not None
        else:
            session_name = generate_session_name()

    if resumed and conversation is not None:
        model      = (saved_model if saved_model in all_models else model) or model
        target_dir = project_dir
        turns      = len([m for m in conversation if m["role"] == "user"])
        print(f"{GREEN}✓ Sesión '{session_name}' reanudada ({turns} turnos) [{target_dir.name}]{R}")
    else:
        target_dir = project_dir
        # Wizard de configuración — proyecto ya elegido, nombre pre-rellenado
        if not args.no_wizard:
            session_config = ask_session_config(
                available_skill_names,
                prefill_project_name=project_name_picked,
            )
        enabled        = session_config.get("enabled_skills", available_skill_names) if session_config else available_skill_names
        skills_ctx     = _skills_context(enabled)
        system_content = SYSTEM_PROMPT + tools_context + skills_ctx
        conversation   = [{"role": "system", "content": system_content}]

    log   = LogWriter(session_name, target_dir)
    cache = ScanCache(target_dir)
    project_state = ProjectState(
        target_dir,
        project_name=(session_config or {}).get("project_name", "") or project_name_picked,
        target=(session_config or {}).get("target", ""),
    )

    if tool_confs:
        log._write(f"### Herramientas cargadas\n\n{tools_context}\n\n")

    print_header(model, session_name, all_models, resumed, tool_confs)

    if session_config:
        log.config(session_config)
        cfg_ctx = config_to_context(session_config)
        conversation.append({"role": "user", "content": cfg_ctx})
        conversation.append({"role": "assistant", "content": json.dumps({
            "thinking": "Configuración recibida.",
            "commands": [], "message": "Configuración aplicada. Dime el objetivo o escribe tu primera instrucción.",
            "requires_confirmation": False, "task_complete": False, "risk_level": "low",
            "phase": "recon", "needs_api_keys": [], "open_browser": "", "fetch_url": ""
        }, ensure_ascii=False)})
        if session_config.get("target"):
            print(f"  {GREEN}✓ Objetivo: {CYAN}{session_config['target']}{R}")
        print()

    cwd          = os.getcwd()
    found_vulns  = []
    breaker      = CircuitBreaker(max_repeats=3)

    # ── Loop principal ────────────────────────────────────────────────────────
    while True:
        sub_match = None
        pt_match = None
        try:
            user_input = input(f"{RED}{BOLD}hacker ❯ {R}").strip()
        except (EOFError, KeyboardInterrupt):
            save_session(session_name, conversation, model, target_dir)
            print(f"\n{DIM}Sesión guardada. Hasta luego.{R}\n")
            break

        if not user_input:
            continue

        # ── Ayuda ─────────────────────────────────────────────────────────────
        if user_input.lower().strip() in (
            "help", "ayuda", "?", "comandos", "que puedo hacer", "qué puedo hacer",
            "que puedes hacer", "qué puedes hacer", "menu", "menú",
        ):
            print_help()
            continue

        # ── Comandos de control ───────────────────────────────────────────────
        if user_input.lower() in ("salir", "exit", "quit", "q"):
            save_session(session_name, conversation, model, target_dir)
            if session_config.get("generate_report") and confirm("¿Generar reporte antes de salir?"):
                generate_report(model, session_name, log, target_dir)
                html_path = generate_html_report(model, session_name, log, target_dir,
                                                  session_config, project_state)
                if html_path:
                    print(f"  {GREEN}✓ Reporte HTML:{R} {CYAN}{html_path}{R}\n")
            print(f"\n{DIM}Sesión guardada. Hasta luego.{R}\n")
            break

        if user_input.lower() in ("reporte", "report", "generar reporte", "genera reporte", "html"):
            generate_report(model, session_name, log, target_dir)
            html_path = generate_html_report(model, session_name, log, target_dir,
                                             session_config, project_state)
            if html_path:
                print(f"  {GREEN}✓ Reporte HTML:{R} {CYAN}{html_path}{R}\n")
            continue

        if user_input.lower() == "sesiones":
            for s in list_sessions():
                stars_n, _ = score_model(s["model"])
                print(f"  {CYAN}{s['name']:<32}{R} {DIM}{s['saved_at'][:19]}  {s['turns']} turnos  [{s['model']}]{R}")
            continue

        if user_input.lower() == "apikeys":
            show_apikeys_status()
            continue

        # ── Listar vulnerabilidades ───────────────────────────────────────────
        if re.match(r'^(?:vulns?|(?:lista(?:me|r)?|mostrar)\s+vulns?|(?:lista(?:me|r)?|mostrar)\s+vulnerabilidades?|vulnerabilidades?)$',
                    user_input.lower().strip()):
            log_content = log.path.read_text(encoding="utf-8") if log.path.exists() else ""
            if len(log_content) < 80:
                print(f"  {YELLOW}⚠ Log vacío. Ejecuta un escaneo primero.{R}")
            else:
                print(f"\n  {MAGENTA}Analizando log...{R}")
                with Spinner("extrayendo vulnerabilidades..."):
                    found_vulns = extract_vulns_from_log(model, log_content)
                print_vulns(found_vulns)
            continue

        # ── Listar IPs / hosts / targets encontrados ─────────────────────────
        if re.match(
            r'^(?:ips?|targets?|hosts?|c[aá]maras?|dispositivos?|'
            r'dame\s+(?:las?\s+)?(?:ips?|hosts?|targets?|c[aá]maras?)|'
            r'(?:lista(?:me|r)?|mostrar|muéstrame|muestrame)\s+(?:(?:los?|las?)\s+)?'
            r'(?:ips?|hosts?|targets?|c[aá]maras?|dispositivos?))\s*$',
            user_input.lower().strip()
        ):
            hosts = [f for f in project_state.findings
                     if f.get("type") in ("device_found", "host_info", "host",
                                          "subdomain", "http_active", "risky_port",
                                          "open_port", "camera", "cve_exposure",
                                          "exploit_available")]
            ips_found = []
            seen = set()
            for f in hosts:
                val = f.get("value", "")
                # Extraer IP del value (puede ser "1.2.3.4:554" o "host info...")
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', val)
                if ip_match:
                    ip = ip_match.group(0)
                    if ip not in seen:
                        seen.add(ip)
                        sev = f.get("severity", "info").upper()
                        desc = f.get("description", "")[:80]
                        ips_found.append((ip, sev, f.get("type","?"), desc))
            if ips_found:
                print(f"\n  {CYAN}{'IP':<20} {'SEV':<8} {'TIPO':<16} DESCRIPCIÓN{R}")
                print(f"  {DIM}{'─'*70}{R}")
                for ip, sev, typ, desc in sorted(ips_found):
                    col = RED if sev in ("CRITICAL","HIGH") else YELLOW if sev == "MEDIUM" else DIM
                    print(f"  {WHITE}{ip:<20}{R} {col}{sev:<8}{R} {DIM}{typ:<16}{R} {desc}")
                print(f"\n  {DIM}Total: {len(ips_found)} hosts/IPs en project_state{R}\n")
            else:
                print(f"  {YELLOW}⚠ No hay IPs/hosts en project_state aún.{R}")
                print(f"  {DIM}Ejecuta un SKILL:shodan_query, SKILL:scan_red o SKILL:subfinder_enum primero.{R}\n")
            continue

        # ── Explotar vulnerabilidad por nombre/CVE en target ───────────────────
        _ev_match = _EXPLOIT_VULN_TRIGGER.search(user_input)
        # Evitar conflicto: NO activar si es solo "explotar <N>" (numérico)
        if _ev_match and not re.match(r'^(?:explotar|exploit|poc)\s+#?\d+$', user_input.strip(), re.I):
            ev_vuln = _ev_match.group(1).strip().rstrip('.,;:')
            ev_target = _ev_match.group(2).strip().rstrip('.,;:')
            print(f"\n  {MAGENTA}{BOLD}▶ Investigando vulnerabilidad: {ev_vuln} → {ev_target}{R}")
            log.separator()
            log.user_input(user_input)
            if not _SKILLS_AVAILABLE:
                print(f"  {RED}✗ Skills no disponibles.{R}")
                continue
            ev_summary = run_exploit_vuln_pipeline(ev_vuln, ev_target, log, cwd, cache)
            # Ingest findings en project_state
            # (los skills ya los ingestan internamente, pero re-consolidamos)
            # Determinar si encontró exploits
            has_exploits = any(kw in ev_summary.lower() for kw in [
                "exploit_found", "edb-", "exploit/", "auxiliary/",
                "msf_module", "module_found", "searchsploit"
            ])
            is_cve = bool(re.match(r'CVE-\d{4}-\d{4,7}', ev_vuln.strip(), re.I))
            vuln_term_clean = _normalize_vuln_term(ev_vuln)
            if has_exploits:
                # Hay exploits → LLM los ejecuta contra el target
                if not ev_target.startswith("http"):
                    ev_target_url = f"https://{ev_target}"
                else:
                    ev_target_url = ev_target
                user_input = (
                    f"[EXPLOIT PIPELINE COMPLETADO — EXPLOITS ENCONTRADOS]\n"
                    f"Vulnerabilidad: {vuln_term_clean}\n"
                    f"Target: {ev_target}\n\n"
                    f"HALLAZGOS:\n{ev_summary[:7000]}\n\n"
                    f"INSTRUCCIONES:\n"
                    f"Se encontraron exploits para {vuln_term_clean}. "
                    f"Ejecuta el exploit MÁS apropiado contra {ev_target} usando:\n"
                    f"1. Si hay módulo Metasploit: SKILL:metasploit mode=exploit target={ev_target} "
                    f"module=<modulo> lhost=<tu_ip>\n"
                    f"2. Si hay script de Exploit-DB: descárgalo con searchsploit -m <EDB-ID> y ejecútalo\n"
                    f"3. Alternativamente: crea un PoC mínimo con curl/python para VERIFICAR la vuln\n"
                    f"4. Concluye: TRUE POSITIVE (explotable) o FALSE POSITIVE\n"
                    f"Emite los comandos concretos AHORA."
                )
            else:
                # No hay exploits → LLM crea un PoC
                cve_desc = ""
                if is_cve:
                    cve_info = _fetch_cve_details(vuln_term_clean)
                    cve_desc = cve_info.get("description", "")
                user_input = (
                    f"[EXPLOIT PIPELINE COMPLETADO — SIN EXPLOITS EXISTENTES]\n"
                    f"Vulnerabilidad: {vuln_term_clean}\n"
                    f"Target: {ev_target}\n"
                    f"{'Descripción CVE: ' + cve_desc + chr(10) if cve_desc else ''}\n"
                    f"HALLAZGOS:\n{ev_summary[:5000]}\n\n"
                    f"INSTRUCCIONES:\n"
                    f"NO se encontraron exploits públicos para {vuln_term_clean}. "
                    f"Debes:\n"
                    f"1. Analizar la vulnerabilidad y entender el vector de ataque\n"
                    f"2. Crear un script de verificación/PoC usando:\n"
                    f"   SKILL:code_dev request=\"PoC para verificar {vuln_term_clean} en {ev_target}\" "
                    f"kind=exploit language=python\n"
                    f"3. El script debe: conectar a {ev_target}, probar la vulnerabilidad, "
                    f"y reportar si es explotable o no\n"
                    f"4. Concluye: TRUE POSITIVE (vulnerable) o FALSE POSITIVE (no afectado)\n"
                    f"Emite los comandos AHORA."
                )
            # Cae al bloque del modelo (sin continue)

        # ── Explotar/verificar vulnerabilidad por número ──────────────────────
        _em = re.match(
            r'^(?:explotar|verificar|exploit|verifica|poc)\s+(?:(?:la\s+)?(?:vuln(?:erabilidad)?\s+))?#?(\d+)$',
            user_input.lower().strip())
        _exploit_bare = re.match(r'^(?:explotar|exploit|poc)$', user_input.lower().strip())

        if _exploit_bare:
            if not found_vulns:
                print(f"\n  {YELLOW}⚠ Aún no hay vulnerabilidades indexadas.{R}")
                print(f"  {DIM}Escribe:{R}  {WHITE}listame vulnerabilidades{R}")
            else:
                print_vulns(found_vulns)
                print(f"  {CYAN}Escribe {WHITE}explotar <N>{R}{CYAN} con el número.{R}\n")
            continue

        if _em:
            vuln_id = int(_em.group(1))
            if not found_vulns:
                print(f"  {YELLOW}⚠ Primero escribe 'listame vulnerabilidades'.{R}")
                continue
            vuln = next((v for v in found_vulns if v.get("id") == vuln_id), None)
            if not vuln:
                print(f"  {RED}✗ Vuln #{vuln_id} no encontrada.{R}")
                continue
            cve_str   = vuln.get("cve") or ""
            comp_str  = vuln.get("componente", "")
            title_str = vuln.get("titulo", "")
            if cve_str:
                primary_search = cve_str
            elif comp_str and comp_str not in ("WordPress", "WordPress core"):
                primary_search = comp_str
            else:
                primary_search = re.split(r'\s*[<>=]', title_str)[0].strip()
            nuclei_tag = f"-tags {cve_str.lower()}" if cve_str else "-tags wordpress"
            user_input = (
                f"[VERIFICAR/EXPLOTAR VULNERABILIDAD #{vuln_id}]\n"
                f"Titulo: {title_str}\nSeveridad: {vuln.get('severidad','?')}\n"
                f"Componente: {comp_str}\nCVE: {cve_str or 'N/A'}\n"
                f"Fix en: {vuln.get('fixed_in','N/A')}\nRef: {vuln.get('ref','')}\n\n"
                f"PASOS:\n"
                f"1. searchsploit \"{primary_search}\"\n"
                f"2. msfconsole -q -x \"search {primary_search}; exit\"\n"
                f"3. nuclei -u <objetivo> -t cves/ {nuclei_tag} -json-export /tmp/nuclei_vuln.json\n"
                f"4. PoC con curl según tipo de vuln.\n"
                f"Concluye: TRUE POSITIVE o FALSE POSITIVE."
            )

        if user_input.lower().startswith("sesion guardar"):
            parts = user_input.split(maxsplit=2)
            name  = parts[2] if len(parts) > 2 else session_name
            f     = save_session(name, conversation, model, target_dir)
            session_name = name
            print(f"  {GREEN}✓ Guardado: {f}{R}")
            continue

        if user_input.lower().startswith("sesion cargar"):
            parts = user_input.split(maxsplit=2)
            if len(parts) < 3:
                print(f"  {RED}Uso: sesion cargar <nombre>{R}")
                continue
            conv, mdl, ltd = load_session(parts[2])
            if conv is None:
                print(f"  {RED}✗ Sesión '{parts[2]}' no encontrada{R}")
            else:
                conversation = conv
                session_name = parts[2]
                target_dir   = ltd or get_target_outdir(parts[2])
                log          = LogWriter(session_name, target_dir)
                cache        = ScanCache(target_dir)
                if mdl:
                    model = mdl
                print(f"  {GREEN}✓ Sesión '{parts[2]}' cargada [{target_dir.name}]{R}")
            continue

        if user_input.lower().startswith("cd "):
            path = user_input[3:].strip()
            try:
                os.chdir(os.path.expanduser(path))
                cwd = os.getcwd()
                print(f"  {DIM}→ {cwd}{R}")
            except Exception as e:
                print(f"  {RED}✗ {e}{R}")
            continue

        # ── Cambio de modelo ──────────────────────────────────────────────────
        _model_match = re.match(
            r'^(?:modelo|model|usa modelo|cambia modelo|cambiar modelo|switch model|use model)\s+(\S+)$',
            user_input.strip(), re.I,
        )
        if _model_match:
            new_model = _model_match.group(1).strip()
            # Verificar que existe en el backend activo
            try:
                _ok, _available = check_backend()
            except Exception:
                _available = []
            if _available and not any(new_model in m for m in _available):
                print(f"  {RED}✗ Modelo '{new_model}' no encontrado en {_backend_display_name()}.{R}")
                print(f"  {DIM}Disponibles: {', '.join(_available)}{R}")
            else:
                model = new_model
                print(f"  {GREEN}✓ Modelo cambiado a:{R} {CYAN}{BOLD}{model}{R}")
                save_session(session_name, conversation, model, target_dir)
            continue

        # ── Cambio de backend (Ollama / LM Studio / DeepSeek) ────────────────
        _backend_match = re.match(
            r'^(?:backend|cambiar backend|switch backend|usa backend)\s*(ollama|lmstudio|lm\s*studio|deepseek|deep\s*seek)?$',
            user_input.strip(), re.I,
        )
        _backend_bare = user_input.lower().strip() in ("backend", "backends")
        if _backend_match or _backend_bare:
            # Mostrar estado actual
            _o_ok, _o_models = check_ollama()
            _l_ok, _l_models = check_lmstudio()
            _d_ok, _d_models = check_deepseek()
            _o_st = f"{GREEN}✓ online ({len(_o_models)} modelos){R}" if _o_ok else f"{RED}✗ offline{R}"
            _l_st = f"{GREEN}✓ online ({len(_l_models)} modelos){R}" if _l_ok else f"{RED}✗ offline{R}"
            _d_st = f"{GREEN}✓ API key configurada ({len(_d_models)} modelos){R}" if _d_ok else f"{RED}✗ sin API key{R}"
            print(f"\n  {CYAN}{BOLD}  BACKENDS LLM{R}")
            separator("─", DIM, 55)
            act_o = f"  {GREEN}← activo{R}" if LLM_BACKEND == "ollama" else ""
            act_l = f"  {GREEN}← activo{R}" if LLM_BACKEND == "lmstudio" else ""
            act_d = f"  {GREEN}← activo{R}" if LLM_BACKEND == "deepseek" else ""
            print(f"    {BOLD}1.{R}  🦙 {CYAN}Ollama{R}        {DIM}({OLLAMA_URL}){R}  {_o_st}{act_o}")
            print(f"    {BOLD}2.{R}  🖥️  {CYAN}LM Studio{R}     {DIM}({LMSTUDIO_URL}){R}  {_l_st}{act_l}")
            print(f"    {BOLD}3.{R}  🌐 {CYAN}DeepSeek API{R}  {DIM}({DEEPSEEK_API_URL}){R}  {_d_st}{act_d}")
            separator("─", DIM, 55)

            new_be = None
            if _backend_match and _backend_match.group(1):
                raw = _backend_match.group(1).strip().lower().replace(" ", "")
                if "deep" in raw or "seek" in raw:
                    new_be = "deepseek"
                elif "lm" in raw or "studio" in raw:
                    new_be = "lmstudio"
                else:
                    new_be = "ollama"
            else:
                sel = input(f"  {CYAN}?{R} Selecciona backend [1=Ollama / 2=LM Studio / 3=DeepSeek]: ").strip()
                if sel == "3":
                    new_be = "deepseek"
                elif sel == "2":
                    new_be = "lmstudio"
                elif sel == "1":
                    new_be = "ollama"
                else:
                    print(f"  {DIM}Sin cambios.{R}\n")
                    continue

            if new_be:
                _check_fns = {"ollama": check_ollama, "lmstudio": check_lmstudio, "deepseek": check_deepseek}
                _be_names  = {"ollama": "Ollama", "lmstudio": "LM Studio", "deepseek": "DeepSeek API"}
                _be_ok, _be_models = _check_fns[new_be]()
                if not _be_ok:
                    print(f"  {RED}✗ {_be_names[new_be]} no está disponible.{R}")
                else:
                    LLM_BACKEND = new_be
                    os.environ["HACKERAGENT_LLM_BACKEND"] = new_be
                    if new_be == "deepseek":
                        os.environ["HACKERAGENT_FAST_MODE"] = "1"
                    else:
                        os.environ.pop("HACKERAGENT_FAST_MODE", None)
                    # Re-seleccionar el mejor modelo del nuevo backend
                    model, all_models = get_model_auto()
                    print(f"  {GREEN}✓ Backend:{R} {CYAN}{BOLD}{_backend_display_name()}{R}")
                    print(f"  {GREEN}✓ Modelo:{R}  {CYAN}{BOLD}{model}{R}")
                    print(f"  {DIM}{len(all_models)} modelos disponibles{R}")
                    save_session(session_name, conversation, model, target_dir)
            print()
            continue

        # ── Vuln Classifier: detecta "clasifica / classifica / valida / verifica hallazgos" ─
        _classify_match = re.match(
            r'^(?:clasifica|classifica|valida|verifica|classify|validate)\s+(.+?)$',
            user_input.strip(), re.I,
        )
        _classify_bare = re.match(
            r'^(?:clasifica|classifica|valida|verifica(?:\s+hallazgos?)?|'
            r'classify(?:\s+findings?)?|validate(?:\s+findings?)?|'
            r'clasificar|validar|classificar)\s*$',
            user_input.strip(), re.I,
        )
        if _classify_bare or _classify_match:
            log.separator()
            log.user_input(user_input)
            if not _SKILLS_AVAILABLE:
                print(f"  {RED}✗ Skills no disponibles.{R}")
                continue

            # Determinar qué clasificar
            log_content = log.path.read_text(encoding="utf-8") if log.path.exists() else ""
            target_text = ""
            classify_source = "auto"

            if _classify_match:
                # Clasificar un texto/hallazgo específico
                target_text = _classify_match.group(1).strip()
                # Si es una ruta de archivo
                p_check = Path(os.path.expanduser(target_text))
                if p_check.exists():
                    print(f"  {MAGENTA}{BOLD}▶ Clasificando archivo: {target_text}{R}")
                    s_result = run_skill("vuln_classifier", file=str(p_check), source="auto")
                else:
                    print(f"  {MAGENTA}{BOLD}▶ Clasificando hallazgo: {target_text[:100]}...{R}")
                    s_result = run_skill("vuln_classifier", input=target_text, source="auto")
            else:
                # Clasificar el log completo o findings del proyecto
                if log_content and len(log_content) > 200:
                    print(f"  {MAGENTA}{BOLD}▶ Clasificando hallazgos del log ({len(log_content)} chars)...{R}")
                    # Si hay project_state findings, usarlos como JSON
                    if project_state.findings:
                        findings_json = json.dumps(project_state.findings, ensure_ascii=False)
                        s_result = run_skill("vuln_classifier", input=log_content[:30000],
                                              findings_json=findings_json, source="auto")
                    else:
                        s_result = run_skill("vuln_classifier", input=log_content[:30000], source="auto")
                else:
                    print(f"  {YELLOW}⚠ No hay hallazgos en el log aún. Ejecuta un escaneo primero.{R}")
                    print(f"  {DIM}Usa: clasifica <texto del hallazgo>{R}")
                    print(f"  {DIM}O  : clasifica /ruta/al/archivo.txt{R}")
                    continue

            s_out = s_result.get("output", "")
            s_ok  = s_result.get("success", False)
            s_findings = s_result.get("findings", [])

            print()
            for line in s_out.strip().split("\n"):
                print(f"  {line}")

            log.command("vuln_classifier (manual)", s_out[:5000], "", 0 if s_ok else 1)

            if s_findings:
                project_state.ingest_skill_findings("vuln_classifier", s_findings)
                project_state.save()
                true_pos = sum(1 for f in s_findings if f.get("verdict") == "TRUE_POSITIVE")
                false_pos = sum(1 for f in s_findings if f.get("verdict") == "FALSE_POSITIVE")
                print(f"\n  {GREEN}{BOLD}✓ Clasificación guardada:{R} {true_pos} TP, {false_pos} FP{R}")
            continue

        # ── Optimización IA: detecta "optimiza / tunea / mejora / diagnostica" ─
        _opt_match = re.match(
            r'^(?:optimiza|optimizar|tunea|mejora|mejorar|auto[- ]?tune)\s*$',
            user_input.strip(), re.I,
        )
        _diag_match = re.match(
            r'^(?:diagnostica|diagn[oó]stico|diagnostic|revisa|revisar|check)\s+'
            r'(?:llm|modelo?|ia|ai)?\s*$',
            user_input.strip(), re.I,
        )
        if _opt_match:
            log.separator()
            log.user_input(user_input)
            if not _SKILLS_AVAILABLE:
                print(f"  {RED}✗ Skills no disponibles.{R}")
                continue
            print(f"\n  {MAGENTA}{BOLD}▶ Optimizando LLM...{R}")
            print(f"  {DIM}Ejecutando benchmark, diagnóstico y auto-tune...{R}")
            s_result = run_skill("llm_optimizer", action="full_report", task="pentest")
            s_out = s_result.get("output", "")
            for line in s_out.strip().split("\n"):
                print(f"  {line}")
            log.command("llm_optimizer full_report", s_out[:3000], "", 0)
            s_findings = s_result.get("findings", [])
            if s_findings:
                project_state.ingest_skill_findings("llm_optimizer", s_findings)
                project_state.save()
            print(f"\n  {YELLOW}💡 Prueba también:{R}")
            print(f"     {CYAN}SKILL:prompt_engineer action=analyze{R}   — analiza el system prompt")
            print(f"     {CYAN}SKILL:response_validator action=quality_score{R}")
            continue

        if _diag_match:
            log.separator()
            log.user_input(user_input)
            if not _SKILLS_AVAILABLE:
                print(f"  {RED}✗ Skills no disponibles.{R}")
                continue
            print(f"\n  {MAGENTA}{BOLD}▶ Diagnosticando LLM...{R}")
            s_result = run_skill("llm_optimizer", action="diagnose")
            s_out = s_result.get("output", "")
            for line in s_out.strip().split("\n"):
                print(f"  {line}")
            log.command("llm_optimizer diagnose", s_out[:2000], "", 0)
            continue

        # ── Auto-RE: detecta "bypass / crackea / reversea …" ──────────────────
        _re_match = _RE_TRIGGER.search(user_input)
        if _re_match and not _PENTEST_TRIGGER.search(user_input):
            re_target = _resolve_re_target(user_input, cwd)
            print(f"\n  {MAGENTA}{BOLD}▶ Ingeniería inversa automática → {re_target}{R}")
            log.separator()
            log.user_input(user_input)
            if not _SKILLS_AVAILABLE:
                print(f"  {RED}✗ Skills no disponibles.{R}")
                continue
            # Log EN VIVO: imprime cada paso mientras el skill trabaja (r2/strings tardan)
            def _re_progress(msg, _t0=[time.time()]):
                dt = time.time() - _t0[0]
                print(f"  {DIM}[{dt:5.1f}s]{R} {msg}", flush=True)
            print(f"  {DIM}(análisis en vivo — r2/strings sobre binarios grandes puede tardar 1-3 min){R}")
            re_result = run_skill("ing_inversa", target=re_target, progress=_re_progress)
            re_out    = re_result.get("output", "")
            # El flujo de binario ya se mostró en vivo (trae 'analysis'); para scripts
            # rápidos o errores sí imprimimos la salida completa.
            if not re_result.get("analysis"):
                print(re_out)
            # el detalle completo del binario va al log de la sesión
            log.command(f"SKILL:ing_inversa target={re_target}", re_out, "", 0)
            re_findings = re_result.get("findings", [])
            if re_findings:
                project_state.ingest_skill_findings("ing_inversa", re_findings)
                project_state.save()
            binfinal  = re_result.get("binfinal", "")
            creds     = re_result.get("credentials", []) or []
            auth_mech = re_result.get("auth_mechanism", "")
            artifacts = re_result.get("online_artifacts", {}) or {}
            if re_result.get("success") and binfinal:
                print(f"\n  {GREEN}{BOLD}✓ ARCHIVO BYPASSEADO:{R} {CYAN}{binfinal}{R}")
                if re_result.get("bypass_sh"):
                    print(f"  {GREEN}✓ EJECUTAR:{R} {WHITE}{re_result['bypass_sh']}{R}")
                if creds:
                    print(f"  {GREEN}🔑 CREDENCIALES:{R} {YELLOW}{', '.join(creds[:8])}{R}")
                conversation.append({"role": "user", "content": user_input})
                conversation.append({"role": "assistant", "content":
                    f"Bypass completado. Archivo: {binfinal}. "
                    f"Credenciales: {creds[:8]}. Wrapper: {re_result.get('bypass_sh','')}"})
                save_session(session_name, conversation, model, target_dir)
                continue
            # ── Auth ONLINE: el bypass es en runtime, no un archivo parcheado ──
            if auth_mech in ("online_keyauth", "online_generic"):
                print(f"\n  {YELLOW}{BOLD}⚠ Login ONLINE (KeyAuth/API).{R} "
                      f"{DIM}El login está compilado en el binario; se bypassa en runtime.{R}")
                launcher = artifacts.get("launcher") or re_result.get("bypass_sh")
                if launcher:
                    print(f"  {GREEN}{BOLD}▶ PRUEBA PRIMERO (shim KeyAuth, no toca el binario):{R}")
                    print(f"     {WHITE}{launcher}{R}")
                if artifacts.get("frida"):
                    print(f"  {GREEN}▸ Alternativa Frida:{R} {WHITE}frida -f \"{re_target}\" "
                          f"-l {artifacts['frida']} --no-pause{R}")
                if artifacts.get("fake_server"):
                    print(f"  {GREEN}▸ Alternativa servidor falso:{R} {WHITE}{artifacts['fake_server']}{R} "
                          f"{DIM}(+ /etc/hosts keyauth.win → 127.0.0.1){R}")
                print(f"  {DIM}Si la respuesta de KeyAuth va firmada, el shim no basta → usa Frida.{R}")
                conversation.append({"role": "user", "content": user_input})
                conversation.append({"role": "assistant", "content":
                    f"Auth online ({auth_mech}). Bypass en runtime. Ejecutar: {launcher}. "
                    f"Artefactos: {artifacts}."})
                save_session(session_name, conversation, model, target_dir)
                continue
            # bypass incompleto (local) → pasar el análisis al modelo para que continúe
            user_input = (
                f"[INGENIERÍA INVERSA — ANÁLISIS PARCIAL]\n"
                f"Objetivo: {re_target}\n"
                f"El bypass automático no se completó. Resultados del análisis:\n"
                f"{re_out[:6000]}\n\n"
                f"INSTRUCCIÓN: decide la técnica correcta (LD_PRELOAD, patch r2/Python, "
                f"o parcheo de la comparación de la clave) y emite los comandos exactos "
                f"para crear el binario/script bypasseado. No te detengas hasta lograrlo."
            )
            # cae al bloque del modelo (sin continue)

        # ── Subdominios: detecta "subdominios de dominio.com" ──────────────────
        sub_match = _SUBDOMAIN_TRIGGER.search(user_input) if not _re_match else None
        if sub_match and _SKILLS_AVAILABLE:
            sub_domain = sub_match.group(1).strip().rstrip(".")
            print(f"\n  {MAGENTA}{BOLD}▶ Enumerando subdominios → {sub_domain}{R}")
            log.separator()
            log.user_input(user_input)

            all_subs: set[str] = set()
            sources_stats: list[str] = []
            http_active: list[str] = []

            # CRT.SH (100% pasivo, sin API key)
            crtsh_r = run_skill("crtsh_enum", domain=sub_domain)
            if crtsh_r.get("success"):
                crt_names = {f["value"] for f in crtsh_r.get("findings", [])}
                all_subs.update(crt_names)
                sources_stats.append(f"CRT.SH:{len(crt_names)}")
                for f in crtsh_r.get("findings", []):
                    project_state.add_finding(f)

            # Subfinder + httpx
            subf_r = run_skill("subfinder_enum", domain=sub_domain, verify_http="true")
            if subf_r.get("success"):
                subf_names = {f["value"] for f in subf_r.get("findings", []) if f["type"] == "subdomain"}
                all_subs.update(subf_names)
                sources_stats.append(f"Subfinder:{len(subf_names)}")
                for f in subf_r.get("findings", []):
                    project_state.add_finding(f)
                    if f["type"] == "http_active":
                        http_active.append(f["value"])

            # HackerTarget (DNS lookup gratuito, similar a dnsdumpster.com)
            try:
                ht_r = subprocess.run(
                    ["curl", "-s", "--max-time", "15",
                     f"https://api.hackertarget.com/hostsearch/?q={sub_domain}"],
                    capture_output=True, text=True, timeout=20,
                )
                ht_out = ht_r.stdout.strip()
                if ht_out and not ht_out.startswith("error") and "," in ht_out:
                    ht_lines = [l.split(",")[0].strip() for l in ht_out.splitlines() if l.strip() and "," in l]
                    all_subs.update(ht_lines)
                    sources_stats.append(f"HackerTarget:{len(ht_lines)}")
                    for h in ht_lines:
                        project_state.add_finding({"type": "subdomain", "value": h, "severity": "info"})
            except Exception:
                pass  # HackerTarget no crítico

            project_state.save()

            # ── Unificar ───────────────────────────────────────────────────
            sorted_subs = sorted(all_subs)
            source_line = " + ".join(sources_stats)
            body = "\n".join(f"  {s}" for s in sorted_subs)
            if http_active:
                body += "\n\n  🌐 Responden HTTP:\n" + "\n".join(f"  {h}" for h in http_active[:20])

            summary = (
                f"Subdominios de {sub_domain}: {len(sorted_subs)} únicos ({source_line})\n\n{body}"
            )
            print(f"\n{GREEN}{summary}{R}")

            # Pasar al LLM para que continúe si quiere
            user_input = (
                f"[SUB-DOMINIOS ENCONTRADOS PARA {sub_domain}]\n{summary[:6000]}\n\n"
                f"El usuario pidió: {user_input}\n"
                f"Ya se ejecutó crtsh_enum y subfinder_enum. "
                f"Si el usuario quiere más (Google dorks, nuclei, scan de puertos), "
                f"emite los comandos correspondientes. Si no, responde con el resumen."
            )
            pt_match = None  # Evitar que el auto-pentest también se dispare
            # Continuar al bloque del modelo

        # ── Auto-pentest: detecta "hackea / escanea / pentest <url>" ───────────
        pt_match = _PENTEST_TRIGGER.search(user_input) if not _re_match else None

        # ── Auto-optimización antes de cada instrucción ────────────────────
        if _SKILLS_AVAILABLE and not pt_match and not _re_match and not sub_match:
            try:
                _opt_cfg = session_config or {}
                if _opt_cfg.get("auto_optimize", True):
                    _opt_result = run_skill("auto_optimizer", action="auto", input=user_input)
                    if _opt_result.get("success") and _opt_result.get("output", "").strip():
                        print(f"\n  {DIM}{_opt_result['output'].strip()}{R}")
            except Exception:
                pass  # No crítico

        if pt_match:
            pt_target = pt_match.group(1)
            if not pt_target.startswith("http"):
                pt_target = f"https://{pt_target}"
            print(f"\n  {MAGENTA}{BOLD}▶ Auto-pentest activado → {pt_target}{R}")
            log.separator()
            log.user_input(user_input)
            recon_summary = run_pentest_phases(pt_target, log, cwd, cache)
            # Extraer CMS del recon para decidir qué herramienta usar
            cms_hint = ""
            rs_lower = recon_summary.lower()
            if "wordpress" in rs_lower or "wp-content" in rs_lower:
                cms_hint = "CMS detectado: WordPress → usa wpscan --enumerate vp,vt,u,tt,cb,dbe --random-user-agent"
            elif "joomla" in rs_lower:
                cms_hint = "CMS detectado: Joomla → usa joomscan --url"
            elif "drupal" in rs_lower:
                cms_hint = "CMS detectado: Drupal → usa droopescan scan drupal -u"
            elif "magento" in rs_lower:
                cms_hint = "CMS detectado: Magento → usa magescan scan:all"
            domain_hint = re.sub(r'^https?://', '', pt_target).rstrip('/').split('/')[0]
            # Construir mensaje de explotación para el modelo
            user_input = (
                f"[RECON AUTOMÁTICO COMPLETADO]\n"
                f"Target: {pt_target}\n"
                f"{cms_hint}\n\n"
                f"HALLAZGOS DE LAS FASES 1-3:\n"
                f"{recon_summary[:7000]}\n\n"
                f"INSTRUCCIONES PARA FASE 4 Y 5:\n"
                f"Basándote en los hallazgos anteriores, emite AHORA los comandos para:\n"
                f"1. {'wpscan/joomscan/droopescan según el CMS detectado' if cms_hint else 'SKILL:nuclei_scan target=' + pt_target + ' severity=info (detectar tecnologías)'}\n"
                f"2. SKILL:subfinder_enum domain={domain_hint} verify_http=true\n"
                f"3. SKILL:nuclei_scan target={pt_target} severity=critical,high,medium\n"
                f"   (alternativa manual: nuclei -u {pt_target} -t {_NUCLEI_TEMPLATES_PATH or '/root/.local/nuclei-templates'}/cves/ -json-export /tmp/nuclei_{domain_hint}.json)\n"
                f"4. SKILL:gobuster_dir target={pt_target} extensions=php,html,txt,bak\n"
                f"5. Cuando tengas vulns → explotar con searchsploit/msfconsole/sqlmap/curl PoC\n"
                f"Emite al menos 4 comandos CONCRETOS en el campo 'commands' ahora mismo."
            )
            # Continuar al bloque del modelo (no hacer 'continue')

        # ── Resumen incremental antes de cada turno ───────────────────────────
        conversation = summarize_if_needed(model, conversation)

        # ── Procesar con el modelo ────────────────────────────────────────────
        if not pt_match:
            log.separator()
            log.user_input(user_input)
        available_keys = {k: bool(get_api_key(k)) for k in ["WPSCAN_API_KEY","SHODAN_API_KEY","VIRUSTOTAL_API_KEY"]}
        context_msg = (
            f"[Directorio: {cwd}]\n"
            f"[API Keys: {json.dumps(available_keys)}]\n"
            f"{user_input}"
        )
        conversation.append({"role": "user", "content": context_msg})

        max_rounds = 10
        executed_this_turn: set = set()
        keys_requested_rounds   = 0
        empty_cmd_count         = 0

        for _ in range(max_rounds):
            try:
                with Spinner():
                    response = call_llm(model, conversation)
            except Exception as e:
                print(f"\n{RED}  ✗ Error {_backend_display_name()}: {e}{R}")
                break

            thinking      = response.get("thinking", "")
            cur_target = ""
            if "project_state" in locals() and project_state and getattr(project_state, "target", None):
                cur_target = project_state.target
            elif "pt_target" in locals() and pt_target:
                cur_target = pt_target
            commands      = sanitize_commands(response.get("commands", []), current_target=cur_target)
            message       = response.get("message", "")
            if not message:
                message = response.get("summary", "") or response.get("content", "") or response.get("response", "")
            needs_confirm = response.get("requires_confirmation", False)
            task_done     = response.get("task_complete", False)
            risk          = response.get("risk_level", "low")
            phase         = response.get("phase", "recon")
            needed_keys   = response.get("needs_api_keys", [])
            browser_url   = response.get("open_browser", "")
            fetch_target  = response.get("fetch_url", "")
            json_error    = response.get("_json_parse_error", False)

            # Sanitizar tipos de datos para prevenir crashes
            if isinstance(thinking, dict):
                thinking = thinking.get("content", str(thinking))
            elif not isinstance(thinking, str):
                thinking = str(thinking) if thinking is not None else ""

            if isinstance(message, dict):
                message = message.get("content", str(message))
            elif not isinstance(message, str):
                message = str(message) if message is not None else ""

            if message and message.strip().startswith("{"):
                message = ""

            # ── Si el modelo devolvió markdown/texto en vez de JSON ───────────
            if json_error:
                print(f"  {YELLOW}⚠ Respuesta no-JSON detectada — forzando formato correcto...{R}")
                conversation.append({"role": "assistant", "content": message[:500] if message else "(sin JSON)"})
                conversation.append({"role": "user", "content": (
                    "❌ FORMATO INCORRECTO. Debes responder ÚNICAMENTE con JSON válido.\n"
                    "NO uses markdown, NO uses bloques ```, NO escribas texto libre.\n"
                    "Responde SOLO con este objeto JSON (sin nada antes ni después):\n"
                    '{"thinking":"...","commands":["SKILL:nuclei_scan target=<url>"],'
                    '"message":"1 línea","requires_confirmation":false,"task_complete":false,'
                    '"risk_level":"medium","phase":"scan","needs_api_keys":[],"open_browser":"","fetch_url":""}\n'
                    "Usa SKILL: commands en vez de comandos crudos cuando sea posible."
                )})
                continue

            # ── Mapear comandos crudos a SKILL: equivalentes ─────────────────
            commands = [_map_raw_to_skill(c, session_config) for c in commands]

            log.thinking(thinking, phase, risk)
            print_thinking(thinking, phase, risk)

            if message:
                log.message(message)
                print(f"\n  {RED}{BOLD}agente ❯{R} ", end="")
                typewrite(message, delay=0.014, color=WHITE)

            # Filtrar repetidos
            if commands:
                repeated = [c for c in commands if c in executed_this_turn]
                commands = [c for c in commands if c not in executed_this_turn]
                if repeated:
                    print(f"\n  {YELLOW}⚠ Omitidos (ya ejecutados): {repeated}{R}")

            if not commands and not fetch_target and not needed_keys and not browser_url:
                conversation.append({"role": "assistant", "content": json.dumps(response, ensure_ascii=False)})
                if not task_done and empty_cmd_count < 3:
                    empty_cmd_count += 1
                    print(f"  {YELLOW}⚠ Sin comandos ({empty_cmd_count}/3) — forzando ejecución...{R}")
                    _target_hint = session_config.get("target", "el objetivo")
                    conversation.append({"role": "user", "content":
                        f"EJECUTA COMANDOS AHORA. No expliques. Pon al menos 3 comandos en 'commands'.\n"
                        f"Usa SKILL: siempre que sea posible. Ejemplos:\n"
                        f"  SKILL:nuclei_scan target={_target_hint} severity=critical,high,medium\n"
                        f"  SKILL:gobuster_dir target={_target_hint} extensions=php,html,txt,bak\n"
                        f"  SKILL:subfinder_enum domain={_target_hint} verify_http=true\n"
                        f"  SKILL:web_code target={_target_hint}\n"
                        f"El campo message debe ser UNA línea breve, no un ensayo."})
                    continue
                if not message:
                    print(f"  {DIM}(sin nuevas acciones){R}")
                break

            # Circuit breaker
            if commands and breaker.tripped(commands):
                print(f"\n  {RED}⛔ Circuit breaker: comandos similares repetidos 3+ veces. Deteniendo bucle.{R}")
                conversation.append({"role": "assistant", "content": json.dumps(response, ensure_ascii=False)})
                conversation.append({"role": "user", "content":
                    "DETENIDO por circuit breaker: estás repitiendo los mismos comandos. "
                    "Cambia de estrategia o marca task_complete: true si no hay más pasos."})
                break

            # Abrir navegador
            if browser_url:
                print(f"\n  {BLUE}🌐 Abriendo: {browser_url}{R}")
                if open_browser(browser_url):
                    print(f"  {GREEN}✓ Navegador abierto{R}")
                else:
                    print(f"  {YELLOW}⚠ No se pudo abrir. Abre: {browser_url}{R}")

            # Fetch URL
            fetch_result_text = ""
            if fetch_target:
                print(f"\n  {BLUE}📥 Fetching: {fetch_target}{R}")
                import urllib3; urllib3.disable_warnings()
                res, err = fetch_url(fetch_target)
                if err:
                    print(f"  {RED}✗ {err}{R}")
                    fetch_result_text = f"Error: {err}"
                else:
                    print_web_fetch(fetch_target, res)
                    log.fetch(fetch_target, res["status_code"], res["body_preview"])
                    fetch_result_text = json.dumps({
                        "url": res["url"], "status_code": res["status_code"],
                        "headers": res["headers"], "body_preview": res["body_preview"],
                        "body_truncated": res["body_truncated"]
                    }, ensure_ascii=False)

            # API keys faltantes
            if needed_keys:
                keys_requested_rounds += 1
                # Cortar bucle si el modelo lleva 3+ rondas pidiendo keys
                if keys_requested_rounds > 3:
                    print(f"\n  {RED}⛔ Bucle API keys ({keys_requested_rounds} rondas) — forzando salida del loop{R}")
                    conversation.append({"role": "assistant", "content": json.dumps(response, ensure_ascii=False)})
                    conversation.append({"role": "user", "content":
                        f"[FORZADO] Deja de pedir API keys. Ya están configuradas o no están disponibles. "
                        f"Keys actuales: {json.dumps(available_keys)}. "
                        "EJECUTA LOS COMANDOS QUE PUEDAS sin las keys faltantes. "
                        "Si SHODAN_API_KEY no está, sáltala y continúa con otras herramientas."})
                    break
                print(f"\n  {YELLOW}API keys necesarias:{R}")
                acquired      = prompt_api_keys(needed_keys)
                all_available = all(bool(v) for v in acquired.values())
                keys_status   = json.dumps({k: bool(v) for k, v in acquired.items()})
                if all_available and keys_requested_rounds >= 2:
                    print(f"  {YELLOW}⚠ Bucle de API keys — forzando ejecución de comandos{R}")
                    keys_ctx = (
                        f"[BUCLE DETECTADO] Keys disponibles: {keys_status}.\n"
                        f"DEBES emitir los comandos ahora. El token wpscan se añade automáticamente.\n"
                        f"Para SHODAN: usa SKILL:shodan_query target=<ip> que maneja la key internamente."
                    )
                else:
                    keys_ctx = (
                        f"Keys disponibles: {keys_status}. Procede con comandos. "
                        f"Token wpscan se inyecta automáticamente."
                    )
                if fetch_result_text:
                    keys_ctx += f"\nFetch: {fetch_result_text}"
                conversation.append({"role": "assistant", "content": json.dumps(response, ensure_ascii=False)})
                conversation.append({"role": "user", "content": keys_ctx})
                continue

            if fetch_result_text and not commands:
                conversation.append({"role": "assistant", "content": json.dumps(response, ensure_ascii=False)})
                conversation.append({"role": "user", "content":
                    f"Resultado del fetch de {fetch_target}:\n{fetch_result_text}\nAnaliza y determina siguientes pasos."})
                continue

            if not commands:
                conversation.append({"role": "assistant", "content": json.dumps(response, ensure_ascii=False)})
                break

            # ── Separar comandos: skills, paralelos, secuenciales ────────────
            skill_cmds      = [c for c in commands if c.strip().upper().startswith("SKILL:")]
            rest_cmds       = [c for c in commands if not c.strip().upper().startswith("SKILL:")]
            # Arreglar paths relativos de nuclei en comandos no-skill
            rest_cmds       = [nuclei_fix_template_paths(c) for c in rest_cmds]
            parallel_cmds   = [c for c in rest_cmds if is_parallel_safe(c)]
            sequential_cmds = [c for c in rest_cmds if not is_parallel_safe(c)]

            all_output        = []
            all_nuclei_finds  = []
            print()

            # ── Skills Python ─────────────────────────────────────────────────
            _use_sa      = session_config.get("use_subagents", True)
            _sa_target   = session_config.get("target", "")
            _pending_sa: list[tuple[str, SubAgent, dict]] = []  # (skill_name, agent, base_entry)

            def _prepare_cli_skill(skill_cmd: str):
                name, args = parse_skill_call(skill_cmd)
                if name in ("code_dev",) and "output_dir" not in args:
                    args["output_dir"] = str(target_dir)
                if name == "web_asset_mirror" and "output_dir" not in args:
                    args["output_dir"] = str(target_dir / "web_assets")
                return name, args

            _prefetched_skills: dict[str, dict] = {}
            _fast_skill_deny = {
                "metasploit", "cred_stuff", "sqli_scan", "web_attack",
                "apk_dynamic", "code_dev", "ducky_dev", "evasion_dev",
                "ing_inversa", "vuln_classifier",
            }
            _fast_jobs = []
            if os.environ.get("HACKERAGENT_FAST_MODE") == "1":
                for _cmd in skill_cmds:
                    _name, _args = _prepare_cli_skill(_cmd)
                    if _name and _name not in _fast_skill_deny:
                        _fast_jobs.append((_cmd, _name, _args))
            if len(_fast_jobs) > 1:
                import concurrent.futures
                _workers = max(2, min(int(os.environ.get("HACKERAGENT_WORKERS", "6")), len(_fast_jobs), 12))
                print(f"  {MAGENTA}⚡ DeepSeek rápido: {len(_fast_jobs)} skills en paralelo ({_workers} workers){R}")
                with concurrent.futures.ThreadPoolExecutor(max_workers=_workers) as _executor:
                    _futures = {_executor.submit(run_skill, _name, **_args): _cmd
                                for _cmd, _name, _args in _fast_jobs}
                    for _future in concurrent.futures.as_completed(_futures):
                        _cmd = _futures[_future]
                        try:
                            _prefetched_skills[_cmd] = _future.result()
                        except Exception as _exc:
                            _prefetched_skills[_cmd] = {
                                "success": False, "output": f"Error: {_exc}", "findings": []}

            for skill_cmd in skill_cmds:
                skill_name, skill_args = _prepare_cli_skill(skill_cmd)
                if not skill_name:
                    continue
                executed_this_turn.add(skill_cmd)
                separator("─", CYAN, 50)
                print(f"  {CYAN}🎯 SKILL:{R} {BOLD}{skill_name}{R}  {DIM}{skill_args}{R}")
                separator("─", CYAN, 50)
                s_result   = _prefetched_skills.get(skill_cmd)
                if s_result is None:
                    s_result = run_skill(skill_name, **skill_args)
                s_out      = s_result.get("output", "")
                s_ok       = s_result.get("success", False)
                s_findings = s_result.get("findings", [])
                s_code     = 0 if s_ok else 1
                # Mostrar output
                for line in s_out.strip().split("\n")[:200]:
                    print(f"  {DIM}{line}{R}")
                status = f"{GREEN}✓ OK{R}" if s_ok else f"{RED}✗ Error{R}"
                print(f"  {DIM}└─{R} {status}")
                log.command(f"SKILL:{skill_name} {skill_args}", s_out, "", s_code)
                # Ingerir hallazgos en ProjectState (dominios + severidad)
                if s_findings:
                    new_doms = project_state.ingest_skill_findings(skill_name, s_findings)
                    if new_doms:
                        print(f"  {GREEN}+{len(new_doms)} dominio(s) nuevo(s){R}: {', '.join(new_doms[:5])}")
                    project_state.save()
                # Hallazgos nuclei embebidos en skill de nuclei
                if skill_name == "nuclei_scan" and s_findings:
                    all_nuclei_finds.extend(s_findings)
                    log.nuclei_findings(s_findings)
                    fmt = format_nuclei_findings(s_findings)
                    s_out += fmt
                # Mostrar resumen de severidad si hay algo crítico/high
                critical_finds = [f for f in s_findings if isinstance(f, dict)
                                  and f.get("severity") in ("critical", "high")]
                if critical_finds:
                    print(f"  {RED}{BOLD}⚠ {len(critical_finds)} hallazgo(s) CRÍTICO/ALTO{R}")
                    for cf in critical_finds[:3]:
                        sev  = cf.get("severity","?").upper()
                        desc = cf.get("title") or cf.get("cve") or cf.get("value") or cf.get("port","?")
                        print(f"    {RED}[{sev}]{R} {desc}")

                base_entry = {
                    "command": f"SKILL:{skill_name}",
                    "stdout": s_out[:12000], "stderr": "", "returncode": s_code,
                    "findings": s_findings[:50],
                }

                if _use_sa and s_out.strip() and skill_name != "web_asset_mirror":
                    # Lanzar SubAgent en hilo paralelo — analiza output sin bloquear
                    print(f"  {MAGENTA}🤖 SubAgent[{skill_name}] lanzado (análisis en paralelo){R}")
                    sa = SubAgent(model, skill_name, s_out, target=_sa_target).start()
                    _pending_sa.append((skill_name, sa, base_entry))
                else:
                    all_output.append(base_entry)

            # ── Recoger resultados de SubAgents (todos corren concurrentemente) ─
            if _pending_sa:
                print(f"\n  {MAGENTA}⏳ Esperando {len(_pending_sa)} SubAgent(s)...{R}")
            for _sname, _sa, _base in _pending_sa:
                _sa_res   = _sa.join(timeout=130)
                _summary  = _sa_res.get("summary", "")
                _kf       = _sa_res.get("key_findings", [])
                _next     = _sa_res.get("next_step", "")
                # Mostrar análisis del SubAgent en terminal
                print(f"\n  {MAGENTA}┌─ SubAgent [{_sname}]{R}")
                if _summary:
                    for _ln in _summary.splitlines():
                        print(f"  {MAGENTA}│{R}  {_ln}")
                for _kfi in _kf[:5]:
                    _sev = _kfi.get("severity","info").upper()
                    _dsc = _kfi.get("description","")
                    _col = RED+BOLD if _sev in ("CRITICAL","HIGH") else YELLOW if _sev=="MEDIUM" else DIM
                    print(f"  {MAGENTA}│{R}  {_col}[{_sev}]{R} {_dsc}")
                if _next:
                    print(f"  {MAGENTA}└─ ▶{R} {CYAN}{_next}{R}")
                else:
                    print(f"  {MAGENTA}└─{R}")
                # El agente principal recibe un resumen compacto en lugar del output raw (mantiene conversación limpia)
                all_output.append({
                    "command":               _base["command"],
                    "returncode":            _base["returncode"],
                    "findings":              _base["findings"],
                    "subagent_summary":      _summary,
                    "subagent_key_findings": _kf,
                    "subagent_next_step":    _next,
                })

            # Paralelo
            if parallel_cmds:
                if len(parallel_cmds) > 1:
                    print(f"  {CYAN}⚡ Ejecutando {len(parallel_cmds)} comandos de recon en paralelo...{R}\n")
                par_results = run_commands_parallel(parallel_cmds, cwd)
                for cmd, (stdout, stderr, code) in zip(parallel_cmds, par_results):
                    cached_entry = cache.get(cmd)
                    if cached_entry and not stdout:
                        stdout, stderr, code = cached_entry["stdout"], cached_entry["stderr"], cached_entry["code"]
                        is_cached = True
                    else:
                        cache.put(cmd, stdout, stderr, code)
                        is_cached = False
                    executed_this_turn.add(cmd)
                    breaker.record([cmd])
                    print_command(cmd, cached=is_cached)
                    print_output(stdout, stderr, code)
                    log.command(cmd, stdout, stderr, code, cached=is_cached)
                    all_output.append({"command": cmd, "stdout": stdout[:12000], "stderr": stderr[:2000], "returncode": code})

            # Secuencial (con cache y nuclei JSON)
            for cmd in sequential_cmds:
                # Wpscan: inyectar API token y --random-user-agent
                wk = get_api_key("WPSCAN_API_KEY")
                if "wpscan" in cmd:
                    if wk and "--api-token" not in cmd:
                        cmd = cmd.rstrip() + f" --api-token {wk}"
                    if "--random-user-agent" not in cmd:
                        cmd = cmd.rstrip() + " --random-user-agent"

                # Nuclei: inyectar -json-export
                nuclei_json_path = None
                first_word = Path(cmd.strip().split()[0]).name.lower() if cmd.strip() else ""
                if first_word == "nuclei":
                    cmd, nuclei_json_path = inject_nuclei_json(cmd)

                # Revisar cache
                cached_entry = cache.get(cmd)
                if cached_entry:
                    stdout, stderr, code = cached_entry["stdout"], cached_entry["stderr"], cached_entry["code"]
                    is_cached = True
                else:
                    executed_this_turn.add(cmd)
                    breaker.record([cmd])
                    print_command(cmd)
                    stdout, stderr, code = run_command(cmd, cwd=cwd)

                    # Gobuster wildcard 403: reejecutar automáticamente con --wildcard
                    if (first_word == "gobuster"
                            and code != 0
                            and "wildcard" in stderr.lower()
                            and "--wildcard" not in cmd):
                        print(f"  {YELLOW}⚠ Gobuster detectó wildcard 403 — reintentando con --wildcard{R}")
                        cmd_wc = cmd.rstrip() + " --wildcard"
                        stdout, stderr, code = run_command(cmd_wc, cwd=cwd)
                        cmd = cmd_wc

                    cache.put(cmd, stdout, stderr, code)
                    is_cached = False

                if is_cached:
                    print_command(cmd, cached=True)
                print_output(stdout, stderr, code)
                log.command(cmd, stdout, stderr, code, cached=is_cached)

                # Verificación determinística HTTP (si el comando usa curl/httpx)
                if first_word in ("curl", "httpx", "wget"):
                    http_check = verify_http_response(stdout, stderr)
                    if http_check["vuln_indicators"]:
                        print(f"\n  {RED}{BOLD}⚠ INDICADORES DETERMINÍSTICOS: {', '.join(http_check['vuln_indicators'])}{R}")
                        log._write(f"**⚠ Indicadores HTTP:** {', '.join(http_check['vuln_indicators'])}\n\n")

                # Parsear nuclei JSON
                if nuclei_json_path:
                    findings = parse_nuclei_json(nuclei_json_path)
                    if findings:
                        all_nuclei_finds.extend(findings)
                        log.nuclei_findings(findings)
                        formatted = format_nuclei_findings(findings)
                        stdout += formatted

                all_output.append({"command": cmd, "stdout": stdout[:12000], "stderr": stderr[:2000], "returncode": code})

            # Mostrar hallazgos de nuclei si los hay
            if all_nuclei_finds:
                print(f"\n  {RED}{BOLD}🎯 Nuclei: {len(all_nuclei_finds)} hallazgos{R}")
                SEV_COLOR = {"CRITICAL": RED+BOLD, "HIGH": YELLOW+BOLD, "MEDIUM": YELLOW, "LOW": CYAN, "INFO": DIM}
                for f in all_nuclei_finds[:15]:
                    if not isinstance(f, dict):
                        continue
                    sev  = f.get("info", {}).get("severity", "?").upper()
                    name = f.get("info", {}).get("name", "?")
                    url  = f.get("matched-at", "?")
                    col  = SEV_COLOR.get(sev, WHITE)
                    print(f"  {col}[{sev}]{R} {name} → {DIM}{url}{R}")

            # ── Auto-classificación de hallazgos con Ollama ──────────────────
            _auto_classify = (
                session_config.get("auto_classify", True)
                and _SKILLS_AVAILABLE
                and bool(all_nuclei_finds or
                         any(f.get("severity") in ("critical", "high")
                             for e in all_output
                             for f in (e.get("findings", []) if isinstance(e, dict) else [])))
            )
            if _auto_classify:
                # Reunir findings de esta ronda para clasificar
                _round_text_parts = []
                for _e in all_output:
                    if isinstance(_e, dict):
                        _c = _e.get("stdout", "")
                        if _c:
                            _round_text_parts.append(_c[:5000])
                _round_text = "\n\n".join(_round_text_parts)
                if _round_text and len(_round_text) > 200:
                    _classify_logged = False
                    try:
                        _cr = run_skill("vuln_classifier", input=_round_text[:25000], source="auto", format="normal")
                        if _cr.get("success"):
                            _cf = _cr.get("findings", [])
                            if _cf:
                                _tps = sum(1 for f in _cf if f.get("verdict") == "TRUE_POSITIVE")
                                _fps = sum(1 for f in _cf if f.get("verdict") == "FALSE_POSITIVE")
                                _incs = sum(1 for f in _cf if f.get("verdict") == "INCONCLUSIVE")
                                _risky_tp = [f for f in _cf
                                             if f.get("verdict") == "TRUE_POSITIVE"
                                             and f.get("severity") in ("critical", "high")]
                                print(f"\n  {MAGENTA}{BOLD}🔬 AUTO-CLASSIFY:{R} "
                                      f"{GREEN}{_tps} TP{R} / {YELLOW}{_fps} FP{R} / "
                                      f"{DIM}{_incs} inconclusos{R}")
                                if _risky_tp:
                                    print(f"  {RED}{BOLD}⚠ {len(_risky_tp)} vulnerabilidad(es) confirmada(s):{R}")
                                    for _rtp in _risky_tp[:5]:
                                        print(f"    {RED}[{_rtp.get('severity','?').upper()}]{R} "
                                              f"{_rtp.get('value','?')}")
                                # Ingerir findings clasificados
                                project_state.ingest_skill_findings("vuln_classifier_auto", _cf)
                                project_state.save()
                                _classify_logged = True
                                # Añadir resumen al output para el modelo
                                _classify_summary = (
                                    f"\n[AUTO-CLASSIFY: {_tps} TP, {_fps} FP, {_incs} inconclusos"
                                    f" — Riesgo: {_cr.get('classifier_summary', {}).get('risk_assessment', '?')}]\n"
                                )
                                # Agregar al resultado para el modelo
                                if _tps > 0:
                                    _tp_details = "\n".join(
                                        f"  ✓ CONFIRMADO: {f.get('value','?')} [{f.get('severity','?')}]"
                                        for f in _cf if f.get("verdict") == "TRUE_POSITIVE"
                                    )
                                    _classify_summary += f"TRUE POSITIVES:\n{_tp_details}\n"
                                if _fps > 0:
                                    _fp_details = "\n".join(
                                        f"  ✗ FALSO: {f.get('value','?')} — {f.get('description','?')[:80]}"
                                        for f in _cf if f.get("verdict") == "FALSE_POSITIVE"
                                    )
                                    _classify_summary += f"FALSE POSITIVES:\n{_fp_details}\n"
                                result_summary += _classify_summary
                    except Exception:
                        pass

            result_summary = json.dumps(all_output, ensure_ascii=False)
            if fetch_result_text:
                result_summary += f"\nFetch {fetch_target}: {fetch_result_text}"
            if all_nuclei_finds:
                result_summary += f"\n{format_nuclei_findings(all_nuclei_finds)}"

            # Build pre-formatted device/host table from this turn's skill findings
            _DEVICE_TYPES = {"device_found", "host_info", "risky_port", "cve_exposure",
                             "exploit_available", "subdomain", "http_active"}
            _turn_finds = []
            for _e in all_output:
                for _f in _e.get("findings", []):
                    if _f.get("type") in _DEVICE_TYPES and _f.get("value"):
                        _turn_finds.append(_f)
            _devices_block = ""
            if _turn_finds:
                _rows = []
                for _i, _f in enumerate(_turn_finds[:40], 1):
                    _sev  = _f.get("severity", "info").upper()
                    _val  = _f.get("value", "")
                    _desc = _f.get("description", "")[:90]
                    _rows.append(f"| {_i} | `{_val}` | {_sev} | {_desc} |")
                _devices_block = (
                    "\n\n[TABLA OBLIGATORIA — COPIAR ÍNTEGRA EN message]\n"
                    "| # | IP / Host | Sev | Detalle |\n"
                    "|---|-----------|-----|---------|\n"
                    + "\n".join(_rows)
                )

            conversation.append({"role": "assistant", "content": json.dumps(response, ensure_ascii=False)})

            if task_done:
                conversation.append({"role": "user", "content": f"Resultado: {result_summary}{_devices_block}"})
                break

            already_ran = sorted(executed_this_turn)

            # Contexto de hallazgos acumulados para que el modelo no olvide lo encontrado
            ps_ctx = ""
            if project_state.findings:
                top = project_state.top_findings(30)
                ip_set = []
                seen_ips = set()
                for f in project_state.findings:
                    ip_m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', f.get("value",""))
                    if ip_m and ip_m.group(0) not in seen_ips:
                        seen_ips.add(ip_m.group(0))
                        ip_set.append(ip_m.group(0))
                ps_ctx = (
                    f"\n[PROYECTO — hallazgos acumulados: {len(project_state.findings)} total]\n"
                    + (f"IPs/hosts conocidos: {', '.join(ip_set[:20])}\n" if ip_set else "")
                    + "Top hallazgos:\n"
                    + "\n".join(
                        f"  [{f.get('severity','?').upper()}] {f.get('type','?')}: {f.get('value','')[:80]}"
                        for f in top[:15]
                    )
                )

            conversation.append({"role": "user", "content": (
                f"Resultados:\n{result_summary}\n\n"
                f"{ps_ctx}"
                f"{_devices_block}\n\n"
                f"[YA EJECUTADOS — NO repetir]: {json.dumps(already_ran)}\n"
                "IMPORTANTE: Si los resultados incluyen hosts, IPs, dispositivos, cámaras, servicios "
                "o credenciales, DEBES listarlos TODOS en tu message en tabla markdown con IP, puerto, "
                "ISP y ciudad. No omitas ninguno aunque no haya CVEs. "
                "Las IPs de Shodan SON válidas aunque nmap no las alcance (NAT/firewall). "
                "Con WAF/Cloudflare usa recon pasivo: subfinder, amass, dig, whois, crt.sh. "
                "task_complete: true SOLO si realmente no hay nada más útil que hacer."
            )})
            print()

        save_session(session_name, conversation, model, target_dir)
        print()


if __name__ == "__main__":
    main()
