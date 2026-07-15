"""
Skill: auto_optimizer
Se ejecuta automáticamente antes de cada instrucción del usuario para optimizar
el LLM. Ajusta dinámicamente temperatura, contexto y prompt según el tipo de
tarea detectada. También optimiza el system prompt y verifica el estado del backend.

Flujo automático:
  1. Detecta el tipo de tarea (pentest, recon, exploit, osint, code)
  2. Carga los parámetros óptimos para esa tarea
  3. Ajusta la configuración del LLM (temperature, num_ctx)
  4. Verifica que el backend responda correctamente
  5. Reporta optimizaciones aplicadas

Uso:
  SKILL:auto_optimizer action=auto task=pentest
  SKILL:auto_optimizer action=setup     (configuración única al inicio)
  SKILL:auto_optimizer action=detect input="hackea https://example.com"
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import requests as _req
except ImportError:
    _req = None

META = {
    "name": "auto_optimizer",
    "category": "desarrollo",
    "description": (
        "Optimiza automáticamente el LLM antes de cada instrucción: detecta el tipo "
        "de tarea, ajusta temperatura/contexto, verifica el backend y aplica la "
        "configuración óptima para máxima efectividad."
    ),
    "args": ["action", "task", "input", "model"],
    "example": (
        "SKILL:auto_optimizer action=auto task=pentest\n"
        "SKILL:auto_optimizer action=setup\n"
        "SKILL:auto_optimizer action=detect input='hackea https://x.com'"
    ),
}

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")

# ── Parámetros óptimos por tipo de tarea ──────────────────────────────────────
TASK_PARAMS = {
    "pentest": {
        "temperature": 0.08,
        "num_ctx": 32768,
        "reason": "Precisión máxima para comandos de pentesting",
        "skills": ["nuclei_scan", "fuzzing_skill", "web_attack", "sqli_scan",
                   "gobuster_dir", "exploit_db", "metasploit"],
    },
    "recon": {
        "temperature": 0.05,
        "num_ctx": 16384,
        "reason": "Muy determinista, comandos de reconocimiento rápidos",
        "skills": ["crtsh_enum", "subfinder_enum", "shodan_query",
                   "google_dorks", "dns_full", "theharvester"],
    },
    "exploit": {
        "temperature": 0.15,
        "num_ctx": 32768,
        "reason": "Ligeramente creativo para vectores de explotación",
        "skills": ["exploit_db", "metasploit", "sqli_scan", "cred_stuff"],
    },
    "osint": {
        "temperature": 0.10,
        "num_ctx": 16384,
        "reason": "Balance entre precisión y descubrimiento",
        "skills": ["theharvester", "sherlock_osint", "email_osint",
                   "breach_search", "dns_full", "social_osint"],
    },
    "code": {
        "temperature": 0.10,
        "num_ctx": 32768,
        "reason": "Código limpio, sintaxis correcta",
        "skills": ["code_dev", "model_advisor", "tech_detect"],
    },
    "re": {
        "temperature": 0.05,
        "num_ctx": 16384,
        "reason": "Máxima precisión para ingeniería inversa",
        "skills": ["ing_inversa"],
    },
    "default": {
        "temperature": 0.10,
        "num_ctx": 32768,
        "reason": "Configuración equilibrada",
        "skills": [],
    },
}

# ── Patrones de detección de tarea ────────────────────────────────────────────
_TASK_PATTERNS = [
    ("pentest", [r'\b(hackea|escanea|pentest|audita|ataca|testea)\b',
                 r'\b(nuclei|wpscan|gobuster|ffuf|sqlmap)\b',
                 r'SKILL:(?:nuclei_scan|gobuster_dir|fuzzing_skill|web_attack|sqli_scan)',
                 r'\b(?:CVE-|vulnerabilidad|exploit)\b']),
    ("recon",   [r'\b(recon|subdominio|crtsh|shodan|whois|dns|subfinder)\b',
                 r'SKILL:(?:crtsh_enum|subfinder_enum|shodan_query|google_dorks)']),
    ("exploit", [r'\b(?:explotar|exploit|metasploit|shell|reverse|bind)\b',
                 r'SKILL:(?:exploit_db|metasploit|cred_stuff)',
                 r'\b(?:RCE|SQLi|LFI|XSS|inyecci)\b']),
    ("osint",   [r'\b(?:osint|email|breach|leak|password|credencial|usuario|correo|'
                 r'empleado|persona|linkedin|twitter|instagram|doxx|huella|'
                 r'busca\s+(?:email|correo|credencial|usuario|persona|empleado)|'
                 r'filtrada|filtrado|exfiltrada|recolecta)\b',
                 r'SKILL:(?:theharvester|sherlock|email_osint|breach_search|dns_full)']),
    ("code",    [r'\b(?:desarrolla|programa|crea|genera|c[óo]digo|script|programa|'
                 r'keylogger|malware|payload|herramienta)\b',
                 r'SKILL:(?:code_dev|ducky_dev|evasion_dev)']),
    ("re",      [r'\b(?:bypass|reversea|crackea|parchea|desbloquea|revierte|parchea|'
                 r'ingenier[ií]a\s+inversa)\b',
                 r'SKILL:ing_inversa']),
]


def detect_task(user_input: str) -> str:
    """Detecta el tipo de tarea basado en el input del usuario."""
    if not user_input:
        return "default"
    input_lower = user_input.lower()

    scores = {}
    for task, patterns in _TASK_PATTERNS:
        score = 0
        for pat in patterns:
            # Use findall regardless of boundaries; patterns already contain word boundaries
            matches = re.findall(pat, input_lower, re.I)
            score += len(matches) * 2
        # Bonus for multi-word matches (more specific)
        if score > 0:
            scores[task] = score

    if not scores:
        # Fallback: try substring keyword matching
        task_keywords = {
            "osint": ["email", "correo", "credencial", "password", "usuario",
                      "linkedin", "twitter", "instagram", "persona", "empleado",
                      "breach", "leak", "filtrada", "osint", "doxx", "huella"],
            "pentest": ["hackea", "escanea", "pentest", "nuclei", "gobuster",
                        "ffuf", "sqlmap", "nmap", "audita", "cve", "web"],
            "exploit": ["explotar", "exploit", "metasploit", "shell", "rce",
                        "sqli", "xss", "lfi", "inyeccion", "reverse"],
            "re": ["bypass", "reverse", "crack", "parchea", "desbloquea",
                   "ingenieria", "inversa", "revierte"],
            "code": ["desarrolla", "programa", "crea", "codigo", "script",
                     "keylogger", "malware", "payload", "genera", "tool",
                     "herramienta"],
        }
        for task, kws in task_keywords.items():
            match_count = 0
            for kw in kws:
                if kw in input_lower:
                    match_count += 1
            if match_count > 0:
                scores[task] = match_count * 3

    if not scores:
        return "default"

    return max(scores, key=scores.get)


def _check_backend() -> tuple[bool, str, float]:
    """Verifica el backend y mide latencia. Retorna (ok, nombre, latencia_ms)."""
    t0 = time.time()
    try:
        base = OLLAMA_URL.rsplit("/api/chat", 1)[0].rsplit("/api/", 1)[0]
        r = _req.get(f"{base}/api/tags", timeout=5)
        lat = (time.time() - t0) * 1000
        if r.status_code == 200:
            models = [m["name"] for m in r.json().get("models", [])]
            return True, "ollama", lat, models
    except Exception:
        pass
    return False, "", 0, []


def run(**kwargs) -> dict:
    """
    Optimiza automáticamente antes de cada instrucción.

    Parámetros:
      action (str): auto (default), setup, detect
      task (str):   Forzar tipo de tarea (pentest, recon, exploit, osint, code, re)
      input (str):  Input del usuario para detectar la tarea automáticamente
      model (str):  Nombre del modelo a optimizar
    """
    action = kwargs.get("action", "auto").strip().lower()
    task = kwargs.get("task", "").strip().lower()
    user_input = kwargs.get("input", "").strip()
    model_name = kwargs.get("model", "").strip()

    R = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    DIM = "\033[2m"
    MAGENTA = "\033[95m"

    # ── ACTION: detect ──────────────────────────────────────────────────────
    if action == "detect":
        detected = detect_task(user_input or "default")

        output = (
            f"{BOLD}{'╔══ AUTO DETECT ═════════════════════════════════════════╗'}{R}\n"
            f"  Input : {DIM}{user_input[:80]}{R}\n"
            f"  Tarea : {CYAN}{BOLD}{detected.upper()}{R}\n"
            f"{'╚═════════════════════════════════════════════════════════╝'}{R}\n"
        )

        if detected != "default":
            params = TASK_PARAMS.get(detected, TASK_PARAMS["default"])
            output += (
                f"\n  Parámetros recomendados:\n"
                f"    temperature={params['temperature']} · num_ctx={params['num_ctx']}\n"
                f"    {DIM}{params['reason']}{R}\n"
                f"  Skills sugeridos: {', '.join(params['skills'][:5])}\n"
            )

        return {
            "success": True,
            "output": output,
            "detected_task": detected,
            "findings": [{
                "type": "task_detected",
                "value": detected,
                "severity": "info",
                "description": f"Tarea detectada: {detected}",
            }],
        }

    # ── ACTION: setup ───────────────────────────────────────────────────────
    elif action == "setup":
        ok, be_name, lat, models = _check_backend()
        if not ok:
            return {
                "success": False,
                "output": f"{RED}✗ Ningún backend LLM disponible.{R}",
                "findings": [{"type": "backend_offline", "severity": "critical",
                              "value": "", "description": "Backend LLM no disponible"}],
            }

        output = (
            f"{BOLD}{'╔══ AUTO OPTIMIZER — SETUP ═══════════════════════════════╗'}{R}\n"
            f"  Backend  : {GREEN}{be_name} ✓{R} ({lat:.0f}ms)\n"
            f"  Modelos  : {len(models)} disponibles\n"
            f"  Estado   : {GREEN}✅ Listo para optimizar{R}\n"
            f"{'╚═════════════════════════════════════════════════════════╝'}{R}\n"
        )

        # Check essential tools
        try:
            from tool_manager import scan_tools
            status = scan_tools()
            installed = sum(1 for v in status.values() if v)
            total = len(status)
            output += (
                f"\n  Herramientas: {GREEN}{installed}/{total}{R} instaladas\n"
            )
        except Exception:
            pass

        output += (
            f"\n  {GREEN}✅ Auto-optimizer listo.{R}\n"
            f"  {DIM}Se ejecutará automáticamente antes de cada instrucción.{R}\n"
        )

        return {
            "success": True,
            "output": output,
            "findings": [{
                "type": "auto_optimizer_setup",
                "value": "ready",
                "severity": "info",
                "description": "Auto-optimizer configurado y listo",
            }],
        }

    # ── ACTION: auto (default) ──────────────────────────────────────────────
    else:
        # 1. Detectar tarea
        detected_task = task or detect_task(user_input) if user_input else task or "default"

        # 2. Verificar backend
        ok, be_name, lat, models = _check_backend()
        if not ok:
            return {
                "success": True,
                "output": f"  {YELLOW}⚠ Backend no disponible - omitiendo optimización{R}",
                "findings": [],
                "params": TASK_PARAMS["default"],
            }

        # 3. Obtener parámetros óptimos
        params = TASK_PARAMS.get(detected_task, TASK_PARAMS["default"])

        # 4. Verificar herramientas esenciales si es pentest/recon
        tool_status = ""
        try:
            from tool_manager import check_tool
            essential = {
                "pentest": ["nmap", "curl", "nuclei", "gobuster", "ffuf"],
                "recon": ["curl", "dig", "whois", "subfinder", "httpx"],
                "exploit": ["curl", "nmap", "searchsploit"],
                "osint": ["curl", "dig", "whois"],
                "code": ["python3"],
                "re": ["python3", "strings"],
                "default": ["curl"],
            }
            needed = essential.get(detected_task, essential["default"])
            missing = [t for t in needed if not check_tool(t)]
            if missing:
                tool_status = f"  {YELLOW}⚠ Herramientas faltantes: {', '.join(missing)}{R}\n"
        except Exception:
            pass

        # 5. Generar output compacto
        output = (
            f"  {DIM}[auto-optimizer]{R} "
            f"{CYAN}{detected_task.upper()}{R} "
            f"{GREEN}temp={params['temperature']}{R} "
            f"ctx={params['num_ctx']} "
            f"{DIM}{lat:.0f}ms{R}\n"
            f"{tool_status}"
        )

        findings = [{
            "type": "auto_optimized",
            "value": detected_task,
            "severity": "info",
            "description": f"Auto-optimizado para {detected_task}: "
                           f"temp={params['temperature']}, ctx={params['num_ctx']}",
        }]

        return {
            "success": True,
            "output": output,
            "findings": findings,
            "params": params,
            "detected_task": detected_task,
        }
