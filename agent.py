#!/usr/bin/env python3
"""
HackerAgent v2 - Agente de terminal para auditorías de ciberseguridad con Ollama
Mejoras v2: resumen incremental, timeouts por herramienta, circuit breaker,
            recon paralelo, cache por target, nuclei JSON, ranking de modelos.
"""

import subprocess
import requests
import json
import re
import argparse
import sys
import os
import threading
import queue
import time
import itertools
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
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")
OUT_DIR.mkdir(parents=True, exist_ok=True)


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
        self._path = target_dir / "scan_cache.json"
        self._data: dict = {}
        if self._path.exists():
            try:
                self._data = json.loads(self._path.read_text(encoding="utf-8"))
            except Exception:
                pass

    def _key(self, cmd: str) -> str:
        return re.sub(r"\s+", " ", cmd.strip())

    def _cacheable(self, cmd: str) -> bool:
        first = Path(cmd.strip().split()[0]).name.lower() if cmd.strip() else ""
        return first in _CACHEABLE_TOOLS

    def get(self, cmd: str) -> dict | None:
        if not self._cacheable(cmd):
            return None
        entry = self._data.get(self._key(cmd))
        if entry:
            age_h = (time.time() - entry.get("_ts", 0)) / 3600
            if age_h < 24:
                return entry
        return None

    def put(self, cmd: str, stdout: str, stderr: str, code: int):
        if not self._cacheable(cmd):
            return
        self._data[self._key(cmd)] = {
            "stdout": stdout, "stderr": stderr, "code": code,
            "_ts": time.time(), "_cached_at": datetime.now().isoformat()
        }
        try:
            self._path.write_text(json.dumps(self._data, ensure_ascii=False, indent=2),
                                  encoding="utf-8")
        except Exception:
            pass

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
            payload = {
                "model":    self.model,
                "messages": [
                    {"role": "system", "content": self._SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
                "stream":  False,
                "format":  "json",
                "options": {"temperature": 0.1, "num_ctx": 4096},
            }
            r = requests.post(OLLAMA_URL, json=payload, timeout=120)
            r.raise_for_status()
            content = r.json()["message"]["content"]
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
    lines.append("\nHERRAMIENTAS DE EXPLOIT SIEMPRE DISPONIBLES EN KALI:")
    lines.append("- searchsploit: `searchsploit <producto version>` / `searchsploit <CVE>`")
    lines.append("  → `searchsploit -x <ID>` ver código   |  `searchsploit -m <ID>` copiar")
    lines.append("- msfconsole:  `msfconsole -q -x \"search <CVE>; exit\"`")
    lines.append("- nuclei CVEs: `nuclei -u <url> -t cves/ -severity critical,high -json-export /tmp/nuclei_out.json`")
    lines.append("- curl PoC:    `curl -v -H 'header: val' -d 'payload' https://target/endpoint`")
    return "\n".join(lines)

# ── System prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """Eres HackerAgent, agente de terminal especializado en auditorías de ciberseguridad ofensiva y defensiva. Operas en Kali Linux con acceso completo a herramientas de pentesting.

CONTEXTO OPERACIONAL:
- Ejecutas en Kali Linux con herramientas de seguridad pre-instaladas
- El usuario tiene autorización explícita sobre los sistemas a auditar
- Tu rol es asistir en pentesting profesional, CTFs (HackTheBox, TryHackMe) y auditorías de seguridad
- Arsenal completo: nmap, metasploit(msfconsole/msfvenom), burpsuite, sqlmap, gobuster, ffuf, wfuzz, nikto, hydra, john, hashcat, wireshark, aircrack-ng, enum4linux, linpeas, winpeas, impacket, crackmapexec, netexec, bloodhound, nuclei, netcat, socat, proxychains, whatweb, wafw00f, wpscan, joomscan, droopescan, wapiti, dirsearch, feroxbuster, subfinder, amass, theharvester, dnsrecon, dnsx, httpx, searchsploit, exploitdb, curl, python3, wget

METODOLOGÍA WEB:
1. Reconocimiento: whatweb -v, curl -sI, wafw00f, fetch_url, open_browser
2. Según CMS: WordPress→wpscan --random-user-agent, Joomla→joomscan, Drupal→droopescan, genérico→nuclei
3. Enumeración: gobuster dir, ffuf, feroxbuster
4. Vulnerabilidades: nikto, nuclei -t cves/ -json-export /tmp/nuclei_out.json, nuclei -t vulnerabilities/, wapiti
5. Explotación: sqlmap, burpsuite, hydra, payloads manuales con curl

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
1. Reconocimiento: nmap, subfinder, amass, theharvester
2. Escaneo: nmap -sV -sC, enum4linux, smbclient
3. AD/SMB: crackmapexec / netexec smb <target> -u '' -p '' --shares
4. Exploits: searchsploit + msfconsole, exploits manuales
5. Post-explotación: linpeas/winpeas, escalada, persistence

REGLAS CRÍTICAS:
1. Responde SIEMPRE en JSON válido, sin texto adicional.
2. Usa "commands" para ejecutar comandos (lista de strings).
3. Explica razonamiento técnico en "thinking" (español). NUNCA en "message".
4. "message" es SOLO una línea breve en español explicando qué vas a hacer o qué encontraste.
5. NUNCA devuelvas commands:[] con una explicación larga en message. Si no tienes info suficiente, pregunta en message Y emite los comandos de recon básico al mismo tiempo.
6. En tu PRIMERA respuesta a cualquier objetivo SIEMPRE emite al menos 3 comandos de recon inmediatos. NO expliques primero.
7. Si necesitas info adicional, pregunta EN EL MISMO JSON y sigue ejecutando comandos de recon mientras esperas.
8. NUNCA repitas un comando que aparezca en [YA EJECUTADOS].
6. Con WAF/Cloudflare: usa recon pasivo (subfinder, amass, dig, whois, crt.sh, waybackurls, shodan).
7. Sin más pasos útiles: task_complete: true y resume en "message".
8. Alto impacto: requires_confirmation: true.
9. API key faltante: needs_api_keys: ["NOMBRE"] — SOLO si "[API Keys: {...}]" muestra que NO está disponible.
10. Abrir navegador: open_browser: "https://url".
11. Leer HTML: fetch_url: "https://url".
12. "message" es SOLO texto plano en español. NUNCA JSON dentro de message.
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
    Cuando el usuario pida "desarrolla/créame/programa <algo ofensivo o herramienta>", usa code_dev
    y avísale del archivo generado en la carpeta del proyecto.

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
SUMMARIZE_CHARS = 22000
SUMMARIZE_KEEP  = 3  # últimos N pares user/assistant que se conservan sin comprimir

def _hard_truncate(conv: list, target_chars: int = 16000) -> list:
    """Fallback sin LLM: descarta mensajes antiguos (excepto system) hasta caber en target_chars."""
    system  = [m for m in conv if m["role"] == "system"]
    history = [m for m in conv if m["role"] != "system"]
    # Conservar siempre los últimos SUMMARIZE_KEEP * 2 mensajes
    while history and sum(len(m["content"]) for m in system + history) > target_chars:
        if len(history) <= SUMMARIZE_KEEP * 2:
            break
        history.pop(0)
    dropped_notice = {
        "role": "user",
        "content": "[CONTEXTO TRUNCADO AUTOMÁTICAMENTE — mensajes antiguos eliminados para liberar espacio]"
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
        summary = call_ollama_text(model, prompt, timeout=240)
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
    """Guarda dominios descubiertos y hallazgos con severidad en project_state.json."""

    _SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def __init__(self, target_dir: Path, project_name: str = "", target: str = ""):
        self.path         = target_dir / "project_state.json"
        self.project_name = project_name
        self.target       = target
        self.domains: set = set()
        self.findings: list = []
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self.project_name = self.project_name or data.get("project_name", "")
                self.target       = self.target or data.get("target", "")
                self.domains      = set(data.get("domains", []))
                self.findings     = data.get("findings", [])
            except Exception:
                pass

    def save(self):
        sev_counts: dict = {}
        for f in self.findings:
            sev = f.get("severity", "info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        data = {
            "project_name": self.project_name,
            "target":       self.target,
            "updated_at":   datetime.now().isoformat(),
            "domains":      sorted(self.domains),
            "sev_summary":  sev_counts,
            "findings":     self.findings[-1000:],
        }
        self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def add_domain(self, domain: str) -> bool:
        domain = domain.lower().strip().lstrip("*.")
        if domain and domain not in self.domains:
            self.domains.add(domain)
            return True
        return False

    def _finding_key(self, f: dict) -> tuple:
        """Clave de deduplicación: tipo + valor truncado."""
        return (f.get("type", ""), str(f.get("value", ""))[:80])

    def add_finding(self, finding: dict):
        if not isinstance(finding, dict):
            return
        finding.setdefault("severity", "info")
        # Deduplicar: no añadir si ya existe el mismo tipo+valor
        key = self._finding_key(finding)
        if any(self._finding_key(f) == key for f in self.findings[-200:]):
            return
        self.findings.append(finding)

    def ingest_skill_findings(self, skill_name: str, findings: list):
        """Extrae dominios y añade hallazgos con severidad al estado del proyecto."""
        new_domains = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            ftype = f.get("type", "")
            # Extraer dominios de findings conocidos
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
            # Guardar finding con fuente
            entry = dict(f)
            entry["source"] = skill_name
            self.add_finding(entry)
        return new_domains

    def severity_summary(self) -> str:
        counts: dict = {}
        for f in self.findings:
            s = f.get("severity", "info")
            counts[s] = counts.get(s, 0) + 1
        parts = [f"{counts[s]} {s}" for s in ["critical","high","medium","low","info"] if s in counts]
        return f"{len(self.findings)} hallazgos ({', '.join(parts) or 'ninguno'})"

    def has_critical(self) -> bool:
        return any(f.get("severity") in ("critical", "high") for f in self.findings)

    def top_findings(self, n: int = 20) -> list:
        return sorted(self.findings, key=lambda f: self._SEV_RANK.get(f.get("severity","info"), 4))[:n]


# ── Sesiones ──────────────────────────────────────────────────────────────────
def save_session(name: str, conversation: list, model: str, target_dir: Path):
    session_file = target_dir / f"{name}.json"
    data = {"name": name, "model": model, "saved_at": datetime.now().isoformat(),
            "target": target_dir.name, "conversation": conversation}
    session_file.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return session_file


def load_session(name: str):
    if OUT_DIR.exists():
        for d in sorted(OUT_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if d.is_dir():
                f = d / f"{name}.json"
                if f.exists():
                    try:
                        data = json.loads(f.read_text(encoding="utf-8"))
                        return data.get("conversation", []), data.get("model"), d
                    except Exception:
                        return None, None, None
    return None, None, None


def list_sessions():
    sessions = []
    if not OUT_DIR.exists():
        return sessions
    for d in OUT_DIR.iterdir():
        if d.is_dir():
            for f in d.glob("*.json"):
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                    sessions.append({
                        "name": f.stem, "target": f.parent.name,
                        "saved_at": data.get("saved_at", "?"),
                        "model": data.get("model", "?"),
                        "turns": len([m for m in data.get("conversation", []) if m["role"] == "user"])
                    })
                except Exception:
                    pass
    return sorted(sessions, key=lambda s: s["saved_at"], reverse=True)


def generate_session_name():
    return datetime.now().strftime("session_%Y%m%d_%H%M%S")


def list_project_sessions(project_dir: Path) -> list:
    """Lista sesiones dentro de un directorio de proyecto concreto."""
    sessions = []
    for f in sorted(project_dir.glob("session_*.json"),
                    key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            # Ignorar project_state.json y report files
            if "conversation" not in data:
                continue
            sessions.append({
                "name":     f.stem,
                "saved_at": data.get("saved_at", "?"),
                "model":    data.get("model", "?"),
                "turns":    len([m for m in data.get("conversation", []) if m["role"] == "user"]),
            })
        except Exception:
            pass
    return sessions


def load_session_in_project(name: str, project_dir: Path):
    """Carga una sesión directamente desde un directorio de proyecto."""
    f = project_dir / f"{name}.json"
    if f.exists():
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if "conversation" in data:
                return data.get("conversation", []), data.get("model"), project_dir
        except Exception:
            pass
    return None, None, None


def _read_project_meta(project_dir: Path) -> dict:
    """Lee project_state.json del directorio y devuelve metadata resumida."""
    ps_file = project_dir / "project_state.json"
    if not ps_file.exists():
        return {}
    try:
        return json.loads(ps_file.read_text(encoding="utf-8"))
    except Exception:
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
               "options": {"temperature": 0.1, "num_ctx": 8192}}
    r = requests.post(OLLAMA_URL, json=payload, timeout=300)
    r.raise_for_status()
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
               "stream": False, "options": {"temperature": 0.3, "num_ctx": 8192}}
    r = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
    r.raise_for_status()
    return r.json()["message"]["content"]

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
    rest  = cmd.strip()[6:]  # skip "SKILL:"
    parts = rest.split()
    if not parts:
        return None, {}
    skill_name = parts[0].lower()
    args: dict = {}
    for p in parts[1:]:
        if "=" in p:
            k, _, v = p.partition("=")
            args[k.strip()] = v.strip()
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
        raw = call_ollama_text(model, prompt)
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
        ("modelo <nombre>",            "cambia el modelo de Ollama en caliente"),
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
    ]:
        print(f"    {GREEN}{trig:<38}{R}\n      {DIM}{desc}{R}")

    print(f"\n  {CYAN}{BOLD}▸ FLUJOS OFENSIVOS RECOMENDADOS{R}")
    print(f"    {WHITE}Web:{R}   {DIM}web_attack → sqli_scan (dump) → explotar{R}")
    print(f"    {WHITE}Creds:{R} {DIM}whiteintel (descarga) → cred_stuff (prueba y di cuál sirve){R}")
    print(f"    {WHITE}RE:{R}    {DIM}ing_inversa <carpeta|binario|script> → binfinal + run_bypass.sh{R}")

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

_BANNER = [
    f"{RED}{BOLD}  ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ {R}",
    f"{RED}{BOLD}  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗{R}",
    f"{RED}{BOLD}  ███████║███████║██║     █████╔╝ █████╗  ██████╔╝{R}",
    f"{RED}{BOLD}  ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗{R}",
    f"{RED}{BOLD}  ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║{R}",
    f"{RED}{BOLD}  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{R}",
    f"  {MAGENTA}{BOLD}A G E N T  v2{R}  {DIM}· Cybersecurity AI Terminal · Powered by Ollama{R}",
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
    for line in _BANNER:
        print(line)
        time.sleep(0.05)
    print()
    separator("─", RED, 56)
    print(f"  {DIM}Modelo :{R}  {MAGENTA}{BOLD}{model}{R}")
    print(f"  {DIM}Sesión :{R}  {CYAN}{session_name}{R}  {DIM}{'(reanudada)' if resumed else '(nueva)'}{R}")
    print(f"  {DIM}Salida :{R}  {DIM}{OUT_DIR}{R}")
    print(f"  {DIM}Ollama :{R}  {DIM}{OLLAMA_URL}{R}")
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
           "apikeys", "reporte", "listame vulnerabilidades", "explotar <N>"]))
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
        "categories":  ["recon_pasivo", "recon_activo", "vuln_scan"],
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
            report_md = call_ollama_text(model, prompt)
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
    r'\b(?:hackea|escanea|pentest(?:ea)?|audita|analiza|ataca|testea)\b.{0,60}?(https?://\S+|[\w.-]+\.\w{2,6})',
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
    # 1) ruta entre comillas (soporta espacios)
    m = re.search(r'["\']([^"\']+)["\']', text)
    if m and Path(os.path.expanduser(m.group(1))).exists():
        return os.path.expanduser(m.group(1))
    # 2) cualquier token separado por espacios que exista como archivo/carpeta
    for raw in text.split():
        tok = raw.strip('.,;:!?)("\'')
        if not tok or tok.lower() in ("bypass", "el", "login", "the", "de", "la", "al", "un"):
            continue
        cand = os.path.expanduser(tok)
        if os.path.isabs(cand) and Path(cand).exists():
            return cand
        rel = Path(cwd) / tok
        if ("/" in tok or "\\" in tok or "." in tok) and rel.exists():
            return str(rel)
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


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="HackerAgent v2")
    parser.add_argument("--model",         "-m", help="Modelo de Ollama a usar")
    parser.add_argument("--session",       "-s", help="Nombre de sesión")
    parser.add_argument("--list-sessions", "-l", action="store_true")
    parser.add_argument("--no-disclaimer",       action="store_true")
    parser.add_argument("--no-wizard",           action="store_true")
    args = parser.parse_args()

    tool_confs    = load_tool_confs()
    tools_context = build_tools_context(tool_confs)
    load_skills()
    available_skill_names = skill_names()

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

    model, all_models = get_model(args.model)

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
        model      = saved_model or model
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
            # Verificar que existe en Ollama
            try:
                _r = requests.get(
                    OLLAMA_URL.replace("/api/chat", "/api/tags"), timeout=10
                )
                _available = [m["name"] for m in _r.json().get("models", [])]
            except Exception:
                _available = []
            if _available and not any(new_model in m for m in _available):
                print(f"  {RED}✗ Modelo '{new_model}' no encontrado en Ollama.{R}")
                print(f"  {DIM}Disponibles: {', '.join(_available)}{R}")
            else:
                model = new_model
                print(f"  {GREEN}✓ Modelo cambiado a:{R} {CYAN}{BOLD}{model}{R}")
                save_session(session_name, conversation, model, target_dir)
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

        # ── Auto-pentest: detecta "hackea / escanea / pentest <url>" ───────────
        pt_match = _PENTEST_TRIGGER.search(user_input) if not _re_match else None
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
                    response = call_ollama(model, conversation)
            except Exception as e:
                print(f"\n{RED}  ✗ Error Ollama: {e}{R}")
                break

            thinking      = response.get("thinking", "")
            commands      = response.get("commands", [])
            message       = response.get("message", "")
            needs_confirm = response.get("requires_confirmation", False)
            task_done     = response.get("task_complete", False)
            risk          = response.get("risk_level", "low")
            phase         = response.get("phase", "recon")
            needed_keys   = response.get("needs_api_keys", [])
            browser_url   = response.get("open_browser", "")
            fetch_target  = response.get("fetch_url", "")
            json_error    = response.get("_json_parse_error", False)

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

            if needs_confirm:
                print(f"\n  {YELLOW}Comandos a ejecutar:{R}")
                for cmd in commands:
                    print(f"    {DIM}$ {cmd}{R}")
                if not confirm("¿Ejecutar?"):
                    print(f"  {YELLOW}Cancelado.{R}")
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

            for skill_cmd in skill_cmds:
                skill_name, skill_args = parse_skill_call(skill_cmd)
                if not skill_name:
                    continue
                # Skills de desarrollo: entregar el resultado en la carpeta del proyecto
                if skill_name in ("code_dev",) and "output_dir" not in skill_args:
                    skill_args["output_dir"] = str(target_dir)
                executed_this_turn.add(skill_cmd)
                separator("─", CYAN, 50)
                print(f"  {CYAN}🎯 SKILL:{R} {BOLD}{skill_name}{R}  {DIM}{skill_args}{R}")
                separator("─", CYAN, 50)
                s_result   = run_skill(skill_name, **skill_args)
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

                if _use_sa and s_out.strip():
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

            result_summary = json.dumps(all_output, ensure_ascii=False)
            if fetch_result_text:
                result_summary += f"\nFetch {fetch_target}: {fetch_result_text}"
            if all_nuclei_finds:
                result_summary += f"\n{format_nuclei_findings(all_nuclei_finds)}"

            conversation.append({"role": "assistant", "content": json.dumps(response, ensure_ascii=False)})

            if task_done:
                conversation.append({"role": "user", "content": f"Resultado: {result_summary}"})
                break

            already_ran = sorted(executed_this_turn)
            conversation.append({"role": "user", "content": (
                f"Resultados:\n{result_summary}\n\n"
                f"[YA EJECUTADOS — NO repetir]: {json.dumps(already_ran)}\n"
                "Con WAF/Cloudflare usa recon pasivo: subfinder, amass, dig, whois, crt.sh. "
                "Si tienes suficiente info, marca task_complete: true."
            )})
            print()

        save_session(session_name, conversation, model, target_dir)
        print()


if __name__ == "__main__":
    main()
