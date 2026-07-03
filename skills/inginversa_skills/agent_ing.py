#!/usr/bin/env python3
"""
ReverseAgent - Agente de ingeniería inversa con Ollama
Uso: python3 agent_ing.py [--target RUTA] [--model MODELO] [--session NOMBRE]

El agente corre el análisis inicial él mismo (sin LLM) y luego pide al modelo
que decida el bypass y genere el binario parcheado en out_re/<nombre>/binfinal.
"""

import subprocess, requests, json, argparse, sys, os, threading, time, itertools, re
from pathlib import Path
from datetime import datetime

# ── .env ─────────────────────────────────────────────────────────────────────
_env_file = Path(__file__).parent / ".env"
if _env_file.exists():
    for _l in _env_file.read_text(encoding="utf-8").splitlines():
        _l = _l.strip()
        if _l and not _l.startswith("#") and "=" in _l:
            _k, _, _v = _l.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))

# ── Colores ───────────────────────────────────────────────────────────────────
R="\033[0m"; BOLD="\033[1m"; CYAN="\033[96m"; GREEN="\033[92m"
YELLOW="\033[93m"; RED="\033[91m"; DIM="\033[2m"; MAGENTA="\033[95m"; WHITE="\033[97m"

# Directorio raíz del proyecto (dos niveles arriba: inginversa_skills/ → skills/ → HackerAgent/)
BASE_DIR  = Path(__file__).parent.parent.parent
OUT_DIR   = BASE_DIR / "out_re"
OUT_DIR.mkdir(parents=True, exist_ok=True)
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")

# ── Nombres de directorio ─────────────────────────────────────────────────────
def sanitize_name(name: str) -> str:
    n = Path(name).name
    n = "".join(c if c.isalnum() or c in ".-_" else "_" for c in n)
    return n.strip("._-") or "target"

def get_outdir(target: str) -> Path:
    d = OUT_DIR / (sanitize_name(target) if target else "misc")
    d.mkdir(parents=True, exist_ok=True)
    return d

# ── System Prompt (corto y enfocado) ─────────────────────────────────────────
SYSTEM_PROMPT = """Eres ReverseAgent, experto en ingeniería inversa en Kali Linux.
Se te dan los resultados del análisis ya ejecutado. Tu trabajo es:
1. Interpretar los resultados
2. Decidir la técnica de bypass correcta
3. Emitir los comandos exactos para crear el binario parcheado en OUTDIR/binfinal

TÉCNICAS DE BYPASS DISPONIBLES:

A) LD_PRELOAD (intercepta memcmp/strcmp sin modificar el binario):
   cat > /tmp/bp.c << 'EOF'
   #include <stddef.h>
   int memcmp(const void*a,const void*b,size_t n){return 0;}
   int strcmp(const char*a,const char*b){return 0;}
   int strncmp(const char*a,const char*b,size_t n){return 0;}
   EOF
   gcc -shared -fPIC -nostartfiles -o /tmp/bp.so /tmp/bp.c
   cp "BINPATH" "OUTDIR/binfinal" && chmod +x "OUTDIR/binfinal"
   printf '#!/bin/bash\\nLD_PRELOAD=/tmp/bp.so "OUTDIR/binfinal" "$@"\\n' > "OUTDIR/run_bypass.sh"
   chmod +x "OUTDIR/run_bypass.sh"

B) Patch con r2 (modifica bytes del binario):
   cp "BINPATH" "OUTDIR/binfinal" && chmod +x "OUTDIR/binfinal"
   r2 -w -q -c "seek sym.FUNC; wa ret" "OUTDIR/binfinal"
   # O parchear JNE→JMP: r2 -w -q -c "seek 0xOFFSET; wa jmp 0xDEST" "OUTDIR/binfinal"

C) Patch con Python (bytes exactos):
   python3 -c "
   import shutil, os
   shutil.copy('BINPATH','OUTDIR/binfinal')
   d=bytearray(open('OUTDIR/binfinal','rb').read())
   d[0xOFFSET]=0x90; d[0xOFFSET+1]=0x90  # NOP el JNE
   open('OUTDIR/binfinal','wb').write(d)
   os.chmod('OUTDIR/binfinal',0o755)
   print('DONE: OUTDIR/binfinal')
   "

D) Script wrapper (para binarios Cython/Python):
   cp "BINPATH" "OUTDIR/binfinal" && chmod +x "OUTDIR/binfinal"
   # El bypass ya está en run_bypass.sh con LD_PRELOAD

REGLAS:
1. Responde SIEMPRE en JSON válido.
2. Usa OUTDIR y BINPATH de las variables del contexto.
3. task_complete: true SOLO cuando OUTDIR/binfinal exista y esté listo.
4. Si detectas que es Cython (__pyx_ símbolos) → usa LD_PRELOAD como técnica principal.
5. Si detectas funciones de auth con r2 → usa patch r2 en esa función.
6. "message" es texto plano en español. NUNCA JSON en message.
7. Emite TODOS los comandos del bypass en una sola ronda.

FORMATO:
{"thinking":"...","commands":["cmd1","cmd2"],"message":"...","requires_confirmation":false,"task_complete":false,"risk_level":"low","phase":"identify|static|decompile|bypass|verify","install_needed":[]}
"""

REPORT_PROMPT = """Experto en ingeniería inversa. Genera reporte Markdown del análisis:
# Reporte RE
## Target y Tipo
## Hallazgos (strings, funciones de auth, técnica de bypass)
## Bypass Aplicado (qué se parcheo y por qué)
## Cómo usar el binfinal
## Conclusiones
Sé técnico y específico con lo que hay en el log."""

# ── LogWriter ─────────────────────────────────────────────────────────────────
class LogWriter:
    def __init__(self, session: str, outdir: Path):
        self.path = outdir / f"{session}.md"
        self._w(f"# ReverseAgent — {session}\n**{datetime.now():%Y-%m-%d %H:%M:%S}**\n\n---\n\n")

    def _w(self, t: str):
        with self.path.open("a", encoding="utf-8") as f: f.write(t)

    def cmd(self, cmd: str, out: str, code: int):
        self._w(f"**`{cmd}`** → exit {code}\n\n```\n{out.strip()[:25000]}\n```\n\n")

    def msg(self, t: str):
        if t: self._w(f"**Agente:** {t}\n\n")

    def section(self, t: str):
        self._w(f"\n## {datetime.now():%H:%M:%S} — {t}\n\n")

    def user(self, t: str):
        self._w(f"**Usuario:** {t}\n\n")

    def sep(self): self._w("---\n\n")

# ── Sesiones ──────────────────────────────────────────────────────────────────
def save_session(name: str, conv: list, model: str, outdir: Path):
    f = outdir / f"{name}.json"
    f.write_text(json.dumps({"name":name,"model":model,"saved_at":datetime.now().isoformat(),
                              "target":outdir.name,"conversation":conv},
                             ensure_ascii=False, indent=2), encoding="utf-8")
    return f

def load_session(name: str):
    for d in sorted(OUT_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True) if OUT_DIR.exists() else []:
        if d.is_dir():
            f = d / f"{name}.json"
            if f.exists():
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                    return data.get("conversation",[]), data.get("model"), d
                except Exception: return None,None,None
    return None,None,None

def list_sessions():
    rows = []
    if not OUT_DIR.exists(): return rows
    for d in OUT_DIR.iterdir():
        if d.is_dir():
            for f in d.glob("*.json"):
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                    rows.append({"name":f.stem,"target":d.name,"saved_at":data.get("saved_at","?"),
                                 "model":data.get("model","?"),
                                 "turns":len([m for m in data.get("conversation",[]) if m["role"]=="user"])})
                except Exception: pass
    return sorted(rows, key=lambda s: s["saved_at"], reverse=True)

def gen_session_name(): return datetime.now().strftime("re_%Y%m%d_%H%M%S")

# ── Análisis inicial (sin LLM) ────────────────────────────────────────────────
ANALYSIS_CMDS = [
    ('ls_dir',    lambda b: f'ls -la "{Path(b).parent}/"'),
    ('file',      lambda b: f'file "{b}"'),
    ('strings',   lambda b: f'strings -a -n 6 "{b}" | grep -iE "pass|auth|login|token|check|verify|admin|unlock|key|secret|api|user|cred|bypass|crack" | head -100'),
    ('nm',        lambda b: f'nm "{b}" 2>/dev/null | grep -iE "pass|auth|check|unlock|verify|login|cred|memcmp|strcmp" | head -50'),
    ('nm_all',    lambda b: f'nm "{b}" 2>/dev/null | head -30'),
    ('checksec',  lambda b: f'checksec --file="{b}" 2>/dev/null || echo "checksec no instalado"'),
    ('readelf',   lambda b: f'readelf -h "{b}" 2>/dev/null | head -20'),
    ('compiler',  lambda b: f'strings -a "{b}" | grep -iE "pyinstaller|nuitka|cython|__pyx_|MEIPASS|cx_freeze|go build|rustc" | head -10'),
    # 'aa' (análisis rápido) en vez de 'aaa': mucho más veloz en binarios grandes;
    # con símbolos (Cython no-stripped) basta para listar las funciones de auth.
    ('r2_funcs',  lambda b: f'r2 -q -e bin.cache=true -c "aa;afl" "{b}" 2>/dev/null | grep -iE "auth|pass|check|unlock|login|verify|cred|bypass" | head -20'),
]

# ═══════════════════════════════════════════════════════════════════════════════
# SKILL INTERFACE — META + run()  (se carga automáticamente por skills/__init__.py)
# ═══════════════════════════════════════════════════════════════════════════════

META = {
    "name": "ing_inversa",
    "category": "ing_inversa",
    "description": (
        "Ingeniería inversa + bypass automático. target puede ser un binario, un SCRIPT "
        "(bash/python/php/…) o un DIRECTORIO (autodescubre el login). En binarios: file, "
        "strings, nm, checksec, r2, detección de tipo (Cython/PyInstaller/ELF/PE/Go/Rust) "
        "y bypass LD_PRELOAD/patch r2. En scripts: entiende el código, extrae la contraseña "
        "embebida, ve qué archivos usa y devuelve una copia bypasseada + run_bypass.sh."
    ),
    "args": ["target", "mode", "output_dir"],
    "example": "SKILL:ing_inversa target=/ruta/al/binario_o_carpeta",
}

_SKILL_OUT_DIR = OUT_DIR  # reutiliza el BASE_DIR ya calculado arriba


def _skill_detect_type(analysis: dict) -> str:
    """Detecta el tipo de binario a partir de los resultados del análisis."""
    nm     = analysis.get("nm", "") + analysis.get("nm_all", "")
    comp   = analysis.get("compiler", "")
    file_o = analysis.get("file", "")

    if "__pyx_" in nm or "cython" in comp.lower():
        return "cython"
    if "MEIPASS" in comp or "pyinstaller" in comp.lower():
        return "pyinstaller"
    if "nuitka" in comp.lower():
        return "nuitka"
    if "go build" in comp.lower() or "Go build" in comp:
        return "golang"
    if "rustc" in comp.lower():
        return "rust"
    if "elf" in file_o.lower():
        if "memcmp@glibc" in nm.lower() or "strcmp@glibc" in nm.lower():
            return "elf_cmp"
        return "elf"
    if "pe32" in file_o.lower() or "ms windows" in file_o.lower():
        return "pe"
    return "unknown"


def _skill_apply_bypass(target: str, outdir: Path, binary_type: str,
                        auth_funcs: list) -> tuple:
    """
    Aplica el bypass más apropiado según el tipo de binario.
    Retorna (technique: str, log_text: str, success: bool).
    """
    binfinal  = outdir / "binfinal"
    bypass_sh = outdir / "run_bypass.sh"
    log_lines = []

    def rc(cmd, tout=60):
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=tout)
            return (r.stdout or r.stderr or "").strip(), r.returncode
        except subprocess.TimeoutExpired:
            return f"Timeout ({tout}s)", 1
        except Exception as e:
            return str(e), 1

    if binary_type in ("cython", "pyinstaller", "nuitka", "elf_cmp", "unknown") \
            or not auth_funcs:
        technique = "LD_PRELOAD"
        cmds = [
            "cat > /tmp/bp.c << 'EOF'\n"
            "#include <stddef.h>\n"
            "int memcmp(const void*a,const void*b,size_t n){return 0;}\n"
            "int strcmp(const char*a,const char*b){return 0;}\n"
            "int strncmp(const char*a,const char*b,size_t n){return 0;}\n"
            "EOF",
            "gcc -shared -fPIC -nostartfiles -o /tmp/bp.so /tmp/bp.c",
            f'cp "{target}" "{binfinal}" && chmod +x "{binfinal}"',
            f'printf \'#!/bin/bash\\nLD_PRELOAD=/tmp/bp.so "{binfinal}" "$@"\\n\''
            f' > "{bypass_sh}"',
            f'chmod +x "{bypass_sh}"',
        ]
    elif auth_funcs and binary_type in ("elf", "golang", "rust"):
        technique = "r2 patch"
        func = auth_funcs[0]
        cmds = [
            f'cp "{target}" "{binfinal}" && chmod +x "{binfinal}"',
            f'r2 -w -q -e bin.cache=true -c "aa; seek {func}; wa ret" "{binfinal}"',
            f'printf \'#!/bin/bash\\n"{binfinal}" "$@"\\n\' > "{bypass_sh}"',
            f'chmod +x "{bypass_sh}"',
        ]
    else:
        technique = "LD_PRELOAD (fallback)"
        cmds = [
            "cat > /tmp/bp.c << 'EOF'\n"
            "#include <stddef.h>\n"
            "int memcmp(const void*a,const void*b,size_t n){return 0;}\n"
            "int strcmp(const char*a,const char*b){return 0;}\n"
            "EOF",
            "gcc -shared -fPIC -nostartfiles -o /tmp/bp.so /tmp/bp.c",
            f'cp "{target}" "{binfinal}" && chmod +x "{binfinal}"',
            f'printf \'#!/bin/bash\\nLD_PRELOAD=/tmp/bp.so "{binfinal}" "$@"\\n\''
            f' > "{bypass_sh}"',
            f'chmod +x "{bypass_sh}"',
        ]

    for cmd in cmds:
        o, code = rc(cmd)
        log_lines.append(f"  $ {cmd.split(chr(10))[0][:80]}")
        if o:
            log_lines.append(f"    {o[:200]}")
        log_lines.append(f"  └─ {'OK' if code == 0 else f'exit {code}'}")

    return technique, "\n".join(log_lines), binfinal.exists()


# ═══════════════════════════════════════════════════════════════════════════════
# Detección del MECANISMO de autenticación (local vs online) + bypass online
# ═══════════════════════════════════════════════════════════════════════════════

def _detect_auth_mechanism(analysis: dict) -> tuple:
    """
    Distingue si el login es LOCAL (comparación memcmp/strcmp, parcheable con
    LD_PRELOAD/r2) u ONLINE (KeyAuth, licencias, API HTTP → NO se parchea con memcmp).
    Retorna (mecanismo, evidencia).
    """
    blob = " ".join(analysis.get(k, "") for k in
                    ("strings", "nm", "compiler", "r2_funcs", "file", "deep_auth")).lower()
    if "keyauth" in blob or "auth.win" in blob or "keyauth.win" in blob:
        return "online_keyauth", "KeyAuth (autenticación online contra keyauth.win)"
    online_kw = ["requests", "urllib", "http://", "https://", "api_key", "apikey",
                 "license", "licencia", "activation", "subscription", "hwid",
                 "session_id", "access_token", "bearer", "sellix", "shoppy", "\"success\""]
    hits = [k for k in online_kw if k in blob]
    if len(hits) >= 2:
        return "online_generic", f"auth online/licencia (indicadores: {', '.join(hits[:6])})"
    if "memcmp@glibc" in blob or "strcmp@glibc" in blob:
        return "local_cmp", "comparación local (memcmp/strcmp)"
    return "unknown", "no determinado"


def _extract_keyauth_info(analysis: dict) -> dict:
    """Extrae de los strings la config de KeyAuth (app, ownerid, versión, url)."""
    blob = analysis.get("strings", "") + "\n" + analysis.get("nm", "")
    info = {}
    for key, pat in [
        ("name",    r'(?:app_?name|name)["\']?\s*[:=]\s*["\']([\w\-. ]{2,40})["\']'),
        ("ownerid", r'(?:ownerid|owner_id)["\']?\s*[:=]\s*["\']([\w]{6,30})["\']'),
        ("version", r'(?:version|ver)["\']?\s*[:=]\s*["\']?(\d+\.\d+[\w.]*)'),
        ("url",     r'(https?://[\w./\-]*keyauth[\w./\-]*)'),
        ("secret",  r'(?:secret|app_?secret)["\']?\s*[:=]\s*["\']([0-9a-f]{32,64})["\']'),
    ]:
        m = re.search(pat, blob, re.I)
        if m:
            info[key] = m.group(1)
    return info


def _apply_online_bypass(target: str, outdir: Path, analysis: dict,
                         auth_funcs: list, auth_mech: str) -> tuple:
    """
    Genera artefactos para auth ONLINE (no parcheable con memcmp):
      - frida_bypass.js  : hook de las funciones de auth para forzar éxito
      - fake_keyauth.py  : servidor local que responde 'success' + guía /etc/hosts
      - intento de patch r2 sobre las funciones de auth (crea binfinal, SIN verificar)
    Retorna (technique, log_text, verified_ok, artifacts_dict).
    NO marca éxito verificado: el usuario debe probar en runtime.
    """
    binfinal  = outdir / "binfinal"
    bypass_sh = outdir / "run_bypass.sh"
    log_lines, artifacts = [], {}

    def rc(cmd, tout=120):
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=tout)
            return (r.stdout or r.stderr or "").strip(), r.returncode
        except Exception as e:
            return str(e), 1

    ka = _extract_keyauth_info(analysis) if auth_mech == "online_keyauth" else {}

    # nombres de funciones candidatas a "login/auth/verify" para hookear
    login_syms = [f for f in auth_funcs
                  if re.search(r"login|auth|verif|valid|unlock|check|licen|activ", f, re.I)]
    login_syms = login_syms or auth_funcs

    # ── 1. Frida hook ─────────────────────────────────────────────────────────
    syms_js = ",\n  ".join(json.dumps(s.replace("sym.", "").replace("dbg.", "")) for s in login_syms[:12])
    frida_js = f"""// Frida hook — fuerza éxito en las funciones de auth de un binario Cython/ELF.
// Uso:   frida -f "{target}" -l frida_bypass.js --no-pause
//   o:   frida -p <PID> -l frida_bypass.js
// Nota: en binarios Cython la función devuelve un PyObject*; forzar 1 puede no bastar.
//       Si falla, usa este script para TRAZAR qué función decide el login y ajusta.
const NAMES = [
  {syms_js}
];
function hookAll() {{
  NAMES.forEach(function(name) {{
    let addr = null;
    try {{ addr = Module.findExportByName(null, name); }} catch(e) {{}}
    if (!addr) {{ try {{ addr = DebugSymbol.fromName(name).address; }} catch(e) {{}} }}
    if (addr) {{
      Interceptor.attach(addr, {{
        onEnter(args) {{ console.log("[+] entra " + name); }},
        onLeave(retval) {{
          console.log("[+] " + name + " retorna " + retval + " → forzando éxito");
          retval.replace(ptr(1));   // ajusta según el valor de éxito real
        }}
      }});
      console.log("[hook] " + name + " @ " + addr);
    }}
  }});
}}
setTimeout(hookAll, 100);
"""
    (outdir / "frida_bypass.js").write_text(frida_js, encoding="utf-8")
    artifacts["frida"] = str(outdir / "frida_bypass.js")
    log_lines.append(f"  ✓ Frida hook   → {outdir/'frida_bypass.js'}  ({len(login_syms)} funciones)")

    # ── 2. Servidor KeyAuth falso + guía de redirección ───────────────────────
    if auth_mech == "online_keyauth":
        fake = f'''#!/usr/bin/env python3
"""Servidor KeyAuth FALSO — responde 'success' a todas las peticiones.
Config detectada del binario: {json.dumps(ka)}
Pasos:
 1) Redirige el dominio de KeyAuth a tu máquina:
      echo "127.0.0.1  keyauth.win" >> /etc/hosts
 2) Levanta este server con TLS (mitmproxy es más fiable para HTTPS):
      pip install mitmproxy ; ver fake_keyauth_README
 3) Ejecuta el binario y prueba cualquier usuario/clave.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
class H(BaseHTTPRequestHandler):
    def _ok(self):
        self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
        self.wfile.write(json.dumps({{"success": True, "message": "ok",
            "info": {{"username":"admin","subscriptions":[{{"subscription":"default",
            "expiry":"9999999999","timeleft":999999999}}]}}, "sessionid":"fakesess"}}).encode())
    def do_GET(self):  self._ok()
    def do_POST(self): self._ok()
    def log_message(self,*a): pass
HTTPServer(("0.0.0.0",80), H).serve_forever()
'''
        (outdir / "fake_keyauth.py").write_text(fake, encoding="utf-8")
        artifacts["fake_server"] = str(outdir / "fake_keyauth.py")
        log_lines.append(f"  ✓ Fake KeyAuth → {outdir/'fake_keyauth.py'}  (redirige keyauth.win → localhost)")

    # ── 3. SHIM de KeyAuth/requests (lo más fiable para apps Python/Cython) ────
    # Intercepta las llamadas de `requests` a keyauth y devuelve success, y
    # además provee un módulo `keyauth` falso por si la app hace `import keyauth`.
    shim_dir = outdir / "keyauth_shim"
    shim_dir.mkdir(parents=True, exist_ok=True)
    (shim_dir / "sitecustomize.py").write_text(
        "# Shim KeyAuth — fuerza 'success' interceptando requests hacia keyauth.\n"
        "import json\n"
        "try:\n"
        "    import requests\n"
        "    _orig = requests.sessions.Session.request\n"
        "    def _patched(self, method, url, *a, **k):\n"
        "        u = str(url).lower()\n"
        "        if 'keyauth' in u or 'auth.win' in u:\n"
        "            body = k.get('data') or {}\n"
        "            nonce = body.get('nonce','') if isinstance(body, dict) else ''\n"
        "            payload = {'success': True, 'message': 'Logged in!',\n"
        "                'sessionid': 'bypass', 'nonce': nonce,\n"
        "                'info': {'username': 'admin', 'ip': '127.0.0.1', 'hwid': 'BYPASS',\n"
        "                    'createdate': '0', 'lastlogin': '0',\n"
        "                    'subscriptions': [{'subscription': 'default', 'key': 'BYPASS',\n"
        "                        'expiry': '9999999999', 'timeleft': 999999999}]}}\n"
        "            r = requests.models.Response(); r.status_code = 200\n"
        "            r._content = json.dumps(payload).encode()\n"
        "            r.headers['Content-Type'] = 'application/json'\n"
        "            return r\n"
        "        return _orig(self, method, url, *a, **k)\n"
        "    requests.sessions.Session.request = _patched\n"
        "    print('[keyauth-shim] requests interceptado — login forzado a success')\n"
        "except Exception as _e:\n"
        "    pass\n",
        encoding="utf-8")
    (shim_dir / "keyauth.py").write_text(
        "# Fake KeyAuth SDK — usado si la app hace `import keyauth`.\n"
        "class _Info:\n"
        "    username='admin'; ip='127.0.0.1'; hwid='BYPASS'; expiry='9999999999'\n"
        "    subscriptions=['default']; createdate='0'; lastlogin='0'\n"
        "class _Resp:\n"
        "    success=True; message='Logged in!'\n"
        "class api:\n"
        "    def __init__(self,*a,**k):\n"
        "        self.user_data=_Info(); self.response=_Resp()\n"
        "    def init(self,*a,**k): return True\n"
        "    def login(self,*a,**k): self.response=_Resp(); return True\n"
        "    def register(self,*a,**k): return True\n"
        "    def license(self,*a,**k): return True\n"
        "    def check(self,*a,**k): return True\n"
        "    def __getattr__(self,n): return lambda *a,**k: True\n",
        encoding="utf-8")
    artifacts["shim"] = str(shim_dir)
    log_lines.append(f"  ✓ KeyAuth shim → {shim_dir}  (intercepta requests + fake `import keyauth`)")

    # ── 4. Intento de patch r2 (NO verificado) sobre las funciones de auth ─────
    #     Una sola invocación r2 con 'aa' (rápido) y varios seek/write.
    rc(f'cp "{target}" "{binfinal}" && chmod +x "{binfinal}"')
    r2_cmds = "aa"
    for func in login_syms[:6]:
        r2_cmds += f'; s {func}; wa \'mov eax, 1; ret\''
    _, code = rc(f'r2 -w -q -e bin.cache=true -c "{r2_cmds}" "{binfinal}"', 240)
    log_lines.append(f"  ~ Patch r2 intentado en {min(6,len(login_syms))} funciones "
                     f"({'OK' if code == 0 else 'con avisos'}) — SIN verificar")

    # run_bypass.sh PRIMARIO: lanza el binario ORIGINAL con el shim en PYTHONPATH
    bypass_sh.write_text(
        f'#!/bin/bash\n'
        f'# Bypass KeyAuth en runtime: fuerza el login a success vía shim de requests.\n'
        f'export PYTHONPATH="{shim_dir}:$PYTHONPATH"\n'
        f'exec "{target}" "$@"\n',
        encoding="utf-8")
    try:
        os.chmod(bypass_sh, 0o755)
    except Exception:
        pass
    artifacts["launcher"] = str(bypass_sh)
    log_lines.append(f"  ▶ Ejecuta: {bypass_sh}  (binario original + shim, sin tocar el binario)")

    technique = "online_auth: shim KeyAuth (requests) + Frida + patch r2 — probar en runtime"
    return technique, "\n".join(log_lines), False, artifacts


# ═══════════════════════════════════════════════════════════════════════════════
# Recuperación de código fuente + parcheo del login (para apps Python/Cython)
# ═══════════════════════════════════════════════════════════════════════════════

_PY_AUTH_LINE = re.compile(
    r'keyauth|\.login\s*\(|def\s+login|authenticate|check_login|logged_?in|'
    r'access_granted|is_authenticated|invalid\s+username|unlock_with|password',
    re.I)
_SKIP_PY_PARTS = {".git", "__pycache__", "venv", ".venv", "env",
                  "node_modules", "site-packages", "build", "dist"}


def _deep_auth_scan(target: str) -> str:
    """Escaneo dedicado de strings para detectar auth online (no depende del grep limitado)."""
    out, _ = _run(
        'strings -a "%s" 2>/dev/null | grep -iE '
        '"keyauth|auth\\.win|licenc?|activation|requests|urllib|hwid|sellix|shoppy|'
        'api/1\\.[0-9]|\\"success\\"|bearer|access_token|session_?id" | head -80' % target, 40)
    return out


def _find_py_sources(root: Path, limit: int = 600) -> list:
    out = []
    try:
        for p in root.rglob("*.py"):
            if set(p.parts) & _SKIP_PY_PARTS:
                continue
            out.append(p)
            if len(out) >= limit:
                break
    except Exception:
        pass
    return out


def _neutralize_login(src: str) -> tuple:
    """Fuerza el login a pasar en código Python: flags de auth = True, login()→pass, gates flip."""
    changed = 0
    out = []
    for line in src.splitlines():
        # 1) flags de autenticación → True
        m = re.match(r'^(\s*)(logged_?in|is_authenticated|authenticated|auth_ok|'
                     r'access_granted|is_valid|valid_login|login_ok)\s*=\s*(?!True\b).+$', line, re.I)
        if m:
            out.append(f"{m.group(1)}{m.group(2)} = True  # [bypass]")
            changed += 1
            continue
        # 2) llamadas directas a .login(...) de keyauth → neutralizadas
        m = re.match(r'^(\s*)(?!.*=)\s*[\w.]*\.login\s*\(.*\)\s*$', line)
        if m and re.search(r'key\s*auth|\.login\(', line, re.I):
            out.append(f"{m.group(1)}pass  # [bypass] {line.strip()}")
            changed += 1
            continue
        # 3) while not logged_in / while True (bucle de login) → no entrar
        m = re.match(r'^(\s*)while\s+(?:not\s+)?(logged_?in|is_authenticated|True)\s*:\s*$', line, re.I)
        if m and "not" in line.lower():
            out.append(f"{m.group(1)}while False:  # [bypass] {line.strip()}")
            changed += 1
            continue
        # 4) if/elif con comparación de credencial → forzar rama de éxito
        m = re.match(r'^(\s*)(if|elif)\s+(.*?):\s*$', line)
        if m and re.search(r'(==|!=)', m.group(3)) and re.search(
                r'pass|login|auth|user|clave|cred|key', m.group(3), re.I):
            neg = "!=" in m.group(3)
            out.append(f"{m.group(1)}{m.group(2)} {'False' if neg else 'True'}:  # [bypass]")
            changed += 1
            continue
        out.append(line)
    return "\n".join(out), changed


def _source_recovery(binary_path: str, outdir: Path) -> dict:
    """
    Busca el código fuente Python del proyecto (junto al binario), localiza el login
    y genera una copia parcheada que entra sin credenciales. Devuelve dict o None.
    """
    b = Path(binary_path)
    # nombre esperado del entry-point (p.ej. PegasusAndroid_pro_bin → pegasusandroid_pro)
    entry_stem = re.sub(r'[_-]?bin$', '', b.stem, flags=re.I).lower()

    roots, seen_root = [], set()
    for r in (b.parent, b.parent.parent):
        if r not in seen_root and r.exists():
            seen_root.add(r)
            roots.append(r)

    pys, seen = [], set()
    for root in roots:
        for p in _find_py_sources(root):
            if p not in seen:
                seen.add(p)
                pys.append(p)
    if not pys:
        return None

    # Un "auth gate" REAL pide credencial al usuario Y decide el acceso.
    # (evita falsos positivos como ftp.login()/connection.login() de submódulos)
    GATE_PROMPT = re.compile(
        r'getpass|input\s*\([^)]*(?:pass|user|clave|contrase|login)|'
        r'enter\s+your\s+(?:username|password)|_unlock_with_password', re.I)
    GATE_DECISION = re.compile(
        r'keyauth|logged_?in|is_authenticated|access_granted|authenticate\b|'
        r'invalid\s+username|"\s*success\s*"|def\s+login\b', re.I)

    scored = []
    for p in pys:
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        name = p.name.lower()
        is_gate = bool(GATE_PROMPT.search(txt) and GATE_DECISION.search(txt))
        is_entry = (p.stem.lower() == entry_stem) or ("__main__" in txt and entry_stem in name)
        keyauth_hits = len(re.findall(r'keyauth', txt, re.I))
        in_submodule = any(seg.lower() in ("modules", "plugins", "libs", "vendor")
                           for seg in p.parts)
        score = 0
        if is_entry:      score += 25
        if is_gate:       score += 15
        score += min(keyauth_hits, 6) * 2
        if ("__main__" in txt) or re.search(r'\bdef\s+main\b', txt): score += 4
        if any(k in name for k in ("main", "login", "auth")):        score += 3
        if in_submodule and not is_gate:  score -= 8   # castiga submódulos sin gate real
        scored.append((score, is_gate, is_entry, p, txt))

    scored.sort(key=lambda x: x[0], reverse=True)
    scored = [s for s in scored if s[0] > 0]
    if not scored:
        return None

    top_score, top_gate, top_entry, top_p, top_txt = scored[0]

    # Si el mejor candidato NO es un gate real NI el entry-point → el login
    # probablemente está COMPILADO en el binario. No parchees un submódulo random.
    if not (top_gate or top_entry):
        return {"files": [str(s[3]) for s in scored[:8]], "main": "", "patched": "",
                "launcher": "", "changed": 0, "no_gate": True,
                "pinpoints": [(str(top_p), 0, "sin auth-gate en fuente; login compilado en el binario")]}

    # localizar líneas de login en los mejores archivos
    pinpoints = []
    for score, is_gate, is_entry, p, txt in scored[:8]:
        for i, line in enumerate(txt.splitlines(), 1):
            if re.search(r'keyauth|def\s+login\b|authenticate|logged_?in|'
                         r'invalid\s+username|access_granted|getpass|enter\s+your\s+password',
                         line, re.I):
                pinpoints.append((str(p), i, line.strip()[:110]))

    # parchear el archivo principal (SOLO parcheo quirúrgico del login,
    # no _patch_generic — voltear todos los `if ==` rompería la lógica de la app)
    patched, changed = _neutralize_login(top_txt)

    # escribir la copia parcheada JUNTO al original (preserva imports relativos)
    out_py   = top_p.with_name(top_p.stem + "_bypass.py")
    launcher = outdir / "run_bypass.sh"
    try:
        out_py.write_text(patched, encoding="utf-8")
    except Exception:
        out_py = outdir / (top_p.stem + "_bypass.py")
        out_py.write_text(patched, encoding="utf-8")
    launcher.write_text(f'#!/bin/bash\ncd "{top_p.parent}"\npython3 "{out_py.name}" "$@"\n'
                        if out_py.parent == top_p.parent else
                        f'#!/bin/bash\ncd "{top_p.parent}"\npython3 "{out_py}" "$@"\n',
                        encoding="utf-8")
    try:
        os.chmod(launcher, 0o755)
    except Exception:
        pass

    return {
        "files":     [str(s[3]) for s in scored[:8]],
        "main":      str(top_p),
        "patched":   str(out_py),
        "launcher":  str(launcher),
        "changed":   changed,
        "pinpoints": pinpoints[:25],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Autodescubrimiento de objetivo + soporte de scripts (bash/python/…)
# ═══════════════════════════════════════════════════════════════════════════════

_SCRIPT_EXTS = {".sh", ".bash", ".zsh", ".py", ".pl", ".rb", ".php", ".js", ".lua"}
_LANG_BY_EXT = {".sh": "bash", ".bash": "bash", ".zsh": "bash", ".py": "python",
                ".pl": "perl", ".rb": "ruby", ".php": "php", ".js": "node", ".lua": "lua"}
# Ruido que nunca es el objetivo de un login/bypass
_DISCOVER_SKIP = {"readme", "readme.md", "readme.txt", "license", "license.txt",
                  "makefile", ".gitignore", "requirements.txt", "flag.txt", "flag"}

# Patrones para localizar credenciales embebidas en código fuente
_CRED_PATTERNS = [
    (r'(?:PASS(?:WORD)?|PASSWD|PWD|CLAVE|SECRET|SECRETO|APIKEY|API_KEY|TOKEN|PIN|CODE|CODIGO|MASTER)\s*=\s*["\']([^"\']{1,80})["\']', "asignación de credencial"),
    (r'\[\[?\s*["\']?\$\{?\w+\}?["\']?\s*(?:==?|!=)\s*["\']([^"\']{2,80})["\']\s*\]?\]?', "comparación bash"),
    (r'(?:if|elif|while)\s+.*?(?:==|!=)\s*["\']([^"\']{2,80})["\']', "comparación en condicional"),
    (r'(?:input|getpass|raw_input)\s*\([^)]*\)\s*==\s*["\']([^"\']{2,80})["\']', "comparación de input python"),
    (r'expr\s+["\']?([^"\'\s]{3,80})["\']?\s*(?:==|=)', "expresión"),
]

# Patrones para localizar archivos que el script usa (lee, incluye, compara)
_FILE_REF_PATTERNS = [
    r'(?:^|\s)(?:source|\.)\s+([~./][\w./\-]+)',
    r'(?:cat|less|more|head|tail|grep|awk|sed)\s+[^\n|]*?([~./][\w./\-]+\.\w{1,6})',
    r'(?:open|read|load|include|require|require_once)\s*\(\s*["\']([^"\']+)["\']',
    r'<\s*([~./][\w./\-]+\.\w{1,6})',
    r'["\']([~./]?[\w./\-]+\.(?:txt|dat|conf|cfg|ini|json|db|sqlite|passwd|shadow|creds?|key|pem|env|htpasswd))["\']',
]


def _run(cmd, tout=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=tout)
        return (r.stdout or r.stderr or "").strip(), r.returncode
    except subprocess.TimeoutExpired:
        return f"Timeout ({tout}s)", 1
    except Exception as e:
        return str(e), 1


def _file_type(path: str) -> str:
    out, _ = _run(f'file -b "{path}"', 10)
    return out


def _script_lang(path: Path) -> str:
    """Devuelve 'bash'|'python'|... si es un script legible; '' si es binario."""
    ext = path.suffix.lower()
    if ext in _LANG_BY_EXT:
        return _LANG_BY_EXT[ext]
    try:
        head = path.read_bytes()[:256]
        if b"\x00" in head[:64]:
            return ""  # binario
        first = head.split(b"\n", 1)[0].decode("utf-8", "replace").lower()
        if first.startswith("#!"):
            for lang, kw in (("bash", "sh"), ("python", "python"), ("perl", "perl"),
                             ("ruby", "ruby"), ("php", "php"), ("node", "node")):
                if kw in first:
                    return lang
    except Exception:
        pass
    ftype = _file_type(str(path)).lower()
    if "shell script" in ftype or "bash" in ftype:
        return "bash"
    if "python script" in ftype:
        return "python"
    if "perl script" in ftype:
        return "perl"
    if "php script" in ftype:
        return "php"
    if "ascii text" in ftype or "script text" in ftype:
        return "bash"
    return ""


def _discover_target(base: Path):
    """
    Dentro de un directorio, elige el archivo más probable a bypassear:
    binarios ejecutables, o scripts con nombre tipo login/auth/vault/crack.
    """
    candidates = []
    files = [p for p in base.iterdir() if p.is_file()]
    # incluir un nivel de subdirectorios comunes
    for sub in base.iterdir():
        if sub.is_dir() and sub.name.lower() in ("bin", "src", "app", "challenge", "dist"):
            files += [p for p in sub.iterdir() if p.is_file()]

    for p in files:
        name = p.name.lower()
        if name in _DISCOVER_SKIP or name.endswith((".md", ".o", ".c", ".h", ".log")):
            continue
        score = 0
        try:
            if os.access(str(p), os.X_OK):
                score += 3
        except Exception:
            pass
        ftype = _file_type(str(p)).lower()
        if "elf" in ftype or "pe32" in ftype or "executable" in ftype or "mach-o" in ftype:
            score += 4
        if p.suffix.lower() in _SCRIPT_EXTS or "script" in ftype:
            score += 2
        if any(k in name for k in ("login", "auth", "vault", "crack", "unlock",
                                    "pass", "chall", "flag", "key", "secret", "admin", "bin")):
            score += 3
        if score > 0:
            candidates.append((score, p.stat().st_size, p))
    if not candidates:
        return None
    # mayor score; a igualdad, el más grande (probable binario real)
    candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
    return candidates[0][2]


def _extract_creds(source: str) -> list:
    creds = []
    seen = set()
    for pat, label in _CRED_PATTERNS:
        for m in re.finditer(pat, source, re.I):
            val = m.group(1).strip()
            low = val.lower()
            # descartar referencias a variables ($X, ${X}, %X%) y palabras vacías
            if val.startswith(("$", "%", "@")) or re.fullmatch(r'\$?\{?\w+\}?', val) and val.isupper():
                continue
            if len(val) < 2 or low in ("", "true", "false", "yes", "no", "0", "1",
                                       "then", "fi", "done", "null", "none", "eq", "ne"):
                continue
            key = (label, val)
            if key in seen:
                continue
            seen.add(key)
            line = source[:m.start()].count("\n") + 1
            creds.append({"value": val, "context": label, "line": line})
    return creds


def _find_referenced_files(source: str, script_dir: Path) -> list:
    refs = []
    seen = set()
    for pat in _FILE_REF_PATTERNS:
        for m in re.finditer(pat, source, re.I | re.M):
            raw = m.group(1).strip()
            if not raw or raw in seen or raw.startswith(("http", "$(", "-")):
                continue
            seen.add(raw)
            resolved = Path(os.path.expanduser(raw))
            if not resolved.is_absolute():
                resolved = (script_dir / raw).resolve()
            exists = resolved.exists()
            entry = {"ref": raw, "path": str(resolved), "exists": exists, "secrets": []}
            if exists and resolved.is_file() and resolved.stat().st_size < 200_000:
                try:
                    content = resolved.read_text(encoding="utf-8", errors="replace")
                    entry["secrets"] = _extract_creds(content)[:20]
                    if not entry["secrets"] and len(content) < 2000:
                        # archivo de credenciales plano (user:pass o líneas sueltas)
                        for ln in content.splitlines()[:20]:
                            ln = ln.strip()
                            if ln and not ln.startswith("#"):
                                entry["secrets"].append({"value": ln[:80],
                                                         "context": "línea de archivo", "line": 0})
                except Exception:
                    pass
            refs.append(entry)
    return refs


def _patch_bash(src: str) -> tuple:
    out, changed = [], 0
    for line in src.splitlines():
        m = re.match(r'^(\s*)(if|elif)\s+(.*?)(;\s*then\s*)$', line)
        if m and re.search(r'(==|!=|\s=\s|-eq|-ne|-z|-n)', m.group(3)):
            neg = ("!=" in m.group(3)) or ("-ne" in m.group(3)) or ("-n " in m.group(3))
            cond = "false" if neg else "true"
            out.append(f"{m.group(1)}{m.group(2)} {cond}{m.group(4)}  # [bypassed]")
            changed += 1
        else:
            out.append(line)
    return "\n".join(out), changed


def _patch_generic(src: str) -> tuple:
    """Para python/perl/ruby/php: neutraliza comparaciones en condicionales."""
    out, changed = [], 0
    for line in src.splitlines():
        m = re.match(r'^(\s*)(if|elif|unless)\s+(.*?)(:\s*|\)\s*\{?\s*|\s+then\s*)$', line)
        if m and re.search(r'(==|!=|\bne\b|\beq\b)', m.group(3)):
            neg = ("!=" in m.group(3)) or (" ne " in m.group(3))
            tok = "False" if neg else "True"
            out.append(f"{m.group(1)}{m.group(2)} {tok}{m.group(4)}  # [bypassed]")
            changed += 1
        else:
            out.append(line)
    return "\n".join(out), changed


def _script_flow(target: str, outdir: Path, lang: str) -> dict:
    """Análisis y bypass a nivel de código fuente para scripts."""
    src_path = Path(target)
    source = src_path.read_text(encoding="utf-8", errors="replace")
    script_dir = src_path.parent

    creds = _extract_creds(source)
    refs  = _find_referenced_files(source, script_dir)

    # Patchear
    if lang == "bash":
        patched, changed = _patch_bash(source)
    else:
        patched, changed = _patch_generic(source)

    binfinal  = outdir / src_path.name        # copia bypasseada con el mismo nombre
    bypass_sh = outdir / "run_bypass.sh"
    binfinal.write_text(patched, encoding="utf-8")
    try:
        os.chmod(binfinal, 0o755)
    except Exception:
        pass
    interp = {"bash": "bash", "python": "python3", "perl": "perl",
              "ruby": "ruby", "php": "php", "node": "node", "lua": "lua"}.get(lang, "bash")
    bypass_sh.write_text(f'#!/bin/bash\n{interp} "{binfinal}" "$@"\n', encoding="utf-8")
    try:
        os.chmod(bypass_sh, 0o755)
    except Exception:
        pass

    # Recolectar todas las credenciales (del script y de archivos que usa)
    all_creds = list(creds)
    for r in refs:
        all_creds.extend(r["secrets"])

    lines = [
        "╔═══ SKILL: INGENIERÍA INVERSA (SCRIPT) ════════════════════╗",
        f"  Target  : {target}",
        f"  Lenguaje: {lang}",
        f"  Salida  : {outdir}",
        "╚═══════════════════════════════════════════════════════════╝",
        "",
        "▶ [FASE 1] Entendiendo el código fuente...",
        f"  Líneas: {source.count(chr(10))+1}   Credenciales embebidas: {len(creds)}",
    ]
    if creds:
        lines.append("\n  🔑 CREDENCIALES ENCONTRADAS EN EL CÓDIGO:")
        for c in creds[:20]:
            lines.append(f"     línea {c['line']:>4}: {c['value']}   [{c['context']}]")
    if refs:
        lines.append("\n  📂 ARCHIVOS QUE USA EL SCRIPT:")
        for r in refs[:20]:
            mark = "✓ existe" if r["exists"] else "✗ no existe"
            lines.append(f"     {r['ref']}  →  {r['path']}  [{mark}]")
            for s in r["secrets"][:5]:
                lines.append(f"        ↳ secreto: {s['value']}   [{s['context']}]")

    lines.append(f"\n▶ [FASE 2] Generando copia bypasseada...")
    lines.append(f"  Condicionales de auth neutralizados: {changed}")
    lines.append(f"  Archivo bypasseado : {binfinal}")
    lines.append(f"  Wrapper            : {bypass_sh}")

    findings = [{"type": "binary_type", "value": f"script_{lang}", "severity": "info",
                 "description": f"Script {lang} analizado a nivel de código"}]
    for c in creds:
        findings.append({"type": "hardcoded_credential", "value": c["value"],
                         "severity": "critical",
                         "description": f"Credencial embebida ({c['context']}) línea {c['line']}: {c['value']}"})
    for r in refs:
        findings.append({"type": "file_used", "value": r["path"], "severity": "info",
                         "description": f"El script usa {r['ref']} ({'existe' if r['exists'] else 'no existe'})"})
        for s in r["secrets"]:
            findings.append({"type": "hardcoded_credential", "value": s["value"],
                             "severity": "critical",
                             "description": f"Secreto en {r['ref']}: {s['value']}"})

    bypass_ok = binfinal.exists() and (changed > 0 or bool(all_creds))
    if bypass_ok:
        findings.append({"type": "bypass_success", "value": str(binfinal), "severity": "critical",
                         "description": (f"Login bypasseado. Ejecuta: {bypass_sh}"
                                         + (f"  |  Password: {creds[0]['value']}" if creds else ""))})
    else:
        findings.append({"type": "bypass_failed", "value": "script", "severity": "medium",
                         "description": "No se detectaron condicionales ni credenciales claras; revisa el código manualmente."})

    lines.append(f"\n{'═'*60}")
    lines.append(f"  Credenciales totales : {len(all_creds)}")
    lines.append(f"  Bypass generado      : {'SÍ' if bypass_ok else 'PARCIAL'}")
    if creds:
        lines.append(f"  👉 Password probable : {creds[0]['value']}")
    lines.append(f"  Ejecutar bypass      : {bypass_sh}")
    lines.append(f"{'═'*60}")

    return {
        "success": bypass_ok,
        "output": "\n".join(lines),
        "findings": findings,
        "binary_type": f"script_{lang}",
        "bypass_type": "source_patch",
        "binfinal": str(binfinal),
        "bypass_sh": str(bypass_sh),
        "credentials": [c["value"] for c in all_creds],
        "files_used": [r["path"] for r in refs],
        "output_dir": str(outdir),
    }


def run(target: str, mode: str = "auto", output_dir: str = "", **kwargs) -> dict:
    """
    Ejecuta análisis estático de RE y bypass automático sin el loop LLM interactivo.
    Acepta un archivo (binario o script) o un DIRECTORIO (autodescubre el objetivo).
    Retorna findings estructurados con severidad para integrarse en agent.py.
    """
    if not target:
        return {
            "success": False,
            "output": "Parámetro 'target' requerido (ruta a binario/script/carpeta)",
            "findings": [],
        }

    # Log en vivo: si el llamador pasa progress(callable), emitimos cada paso al momento
    progress = kwargs.get("progress")
    def emit(msg=""):
        if progress:
            try:
                progress(msg)
            except Exception:
                pass

    t = Path(target)
    if not t.exists():
        return {"success": False, "output": f"No existe: {target}", "findings": []}

    # ── Autodescubrimiento si es un directorio ────────────────────────────────
    discover_note = ""
    if t.is_dir():
        disc = _discover_target(t)
        if not disc:
            listing, _ = _run(f'ls -la "{t}"', 10)
            return {"success": False,
                    "output": f"No encontré un binario/script objetivo en {t}.\n{listing}",
                    "findings": []}
        discover_note = f"[autodescubierto en {t}] → {disc}"
        target = str(disc)
        t = disc

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not output_dir:
        safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in t.name)[:28]
        output_dir = str(_SKILL_OUT_DIR / f"{safe}_{ts}")
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    # ── Ruta de scripts (bash/python/…): análisis y bypass a nivel de fuente ───
    lang = _script_lang(t)
    if lang:
        res = _script_flow(target, outdir, lang)
        if discover_note:
            res["output"] = f"  {discover_note}\n" + res["output"]
        return res

    size_kb = round(t.stat().st_size / 1024, 1)
    lines = ["╔═══ SKILL: INGENIERÍA INVERSA ═════════════════════════════╗",
             f"  Target  : {target}"]
    if discover_note:
        lines.append(f"  {discover_note}")
    lines += [
        f"  Tamaño  : {size_kb} KB",
        f"  Salida  : {output_dir}",
        "╚═══════════════════════════════════════════════════════════╝",
        "",
        "▶ [FASE 1] Análisis estático automático...",
    ]
    emit(f"  🎯 Objetivo: {t.name}  ({size_kb} KB)")
    emit("  ▶ [FASE 1] Análisis estático...")

    # ── Ejecutar ANALYSIS_CMDS ────────────────────────────────────────────────
    analysis: dict = {}
    _slow = {"r2_funcs": "analizando funciones con r2 (puede tardar en binarios grandes)…"}
    for label, cmd_fn in ANALYSIS_CMDS:
        cmd  = cmd_fn(target)
        tout = 300 if "r2" in cmd else 30
        emit(f"     · {label}… {_slow.get(label, '')}".rstrip())
        try:
            r   = subprocess.run(cmd, shell=True, capture_output=True,
                                 text=True, timeout=tout)
            out = (r.stdout or r.stderr or "(sin output)").strip()
        except subprocess.TimeoutExpired:
            out = f"Timeout ({tout}s)"
        except Exception as e:
            out = str(e)

        analysis[label] = out
        lines.append(f"\n  [{label.upper()}]")
        for ln in out.split("\n")[:12]:
            lines.append(f"    {ln}")
        extra = len(out.split("\n")) - 12
        if extra > 0:
            lines.append(f"    ... ({extra} líneas más)")
        # muestra un par de líneas en vivo
        preview = [x for x in out.split("\n") if x.strip()][:3]
        for pv in preview:
            emit(f"        {pv[:100]}")

    # ── Detectar tipo de binario ──────────────────────────────────────────────
    binary_type = _skill_detect_type(analysis)
    lines.append(f"\n▶ [DETECCIÓN] Tipo de binario: {binary_type.upper()}")
    emit(f"  ▶ Tipo detectado: {binary_type.upper()}")

    # Escaneo profundo de strings para clasificar bien el mecanismo de auth
    emit("     · escaneo profundo de auth (strings)…")
    analysis["deep_auth"] = _deep_auth_scan(target)

    # Extraer funciones de auth detectadas por r2
    auth_funcs: list = []
    for ln in analysis.get("r2_funcs", "").split("\n"):
        m = re.search(r"(sym\.\S+)", ln)
        if m:
            auth_funcs.append(m.group(1))
    if auth_funcs:
        lines.append(f"  Auth detectadas: {', '.join(auth_funcs[:5])}")

    # ── Detectar el MECANISMO de auth (local vs online) ───────────────────────
    auth_mech, auth_evidence = _detect_auth_mechanism(analysis)
    lines.append(f"  Mecanismo de auth: {auth_mech.upper()}  ({auth_evidence})")
    emit(f"  ▶ Mecanismo de auth: {auth_mech.upper()}  ({auth_evidence})")

    # ── FASE 2 ────────────────────────────────────────────────────────────────
    lines.append(f"\n▶ [FASE 2] Aplicando bypass...")
    emit("  ▶ [FASE 2] Buscando código fuente del login para parchearlo…")
    online_artifacts = {}

    # ── 2a. Preferir RECUPERACIÓN DE CÓDIGO FUENTE (lo más fiable y dinámico) ──
    src_rec = _source_recovery(target, outdir)
    if src_rec and src_rec.get("changed", 0) > 0:
        binfinal  = Path(src_rec["patched"])
        bypass_sh = Path(src_rec["launcher"])
        technique = "source_patch (código fuente del proyecto parcheado)"
        emit(f"  ✓ Fuente del login encontrada: {Path(src_rec['main']).name} "
             f"({src_rec['changed']} parches)")
        lines.append(f"  ✓ Código fuente encontrado junto al binario → parcheo directo del login")
        lines.append(f"    Archivo principal : {src_rec['main']}")
        lines.append(f"    Copia parcheada   : {src_rec['patched']}  ({src_rec['changed']} cambios)")
        if src_rec["pinpoints"]:
            lines.append("    Líneas de login localizadas:")
            for f, ln_no, txt in src_rec["pinpoints"][:8]:
                lines.append(f"      {Path(f).name}:{ln_no}  {txt}")
        lines.append(f"\n  ▶ Ejecuta la app SIN login:")
        lines.append(f"  $ {bypass_sh}")

        findings = [
            {"type": "binary_type", "value": binary_type, "severity": "info",
             "description": f"Tipo detectado: {binary_type}"},
            {"type": "source_recovered", "value": src_rec["main"], "severity": "high",
             "description": f"Código fuente Python recuperado: {src_rec['main']}"},
            {"type": "bypass_success", "value": str(binfinal), "severity": "critical",
             "description": f"Login parcheado en el código fuente. Ejecuta: {bypass_sh}"},
        ]
        for f, ln_no, txt in src_rec["pinpoints"][:15]:
            findings.append({"type": "login_code", "value": f"{Path(f).name}:{ln_no}",
                             "severity": "info", "description": txt})

        lines.append(f"\n{'═'*60}")
        lines.append(f"  Tipo detectado  : {binary_type.upper()}")
        lines.append(f"  Técnica         : source_patch")
        lines.append(f"  Archivo listo   : {binfinal}")
        lines.append(f"  Ejecutar        : {bypass_sh}")
        lines.append(f"{'═'*60}")
        return {
            "success": True,
            "output": "\n".join(lines),
            "findings": findings,
            "binary_type": binary_type,
            "auth_mechanism": auth_mech,
            "bypass_type": technique,
            "binfinal": str(binfinal),
            "bypass_sh": str(bypass_sh),
            "source_main": src_rec["main"],
            "output_dir": str(outdir),
            "analysis": {k: v[:2000] for k, v in analysis.items()},
        }
    elif src_rec and src_rec.get("no_gate"):
        lines.append("  · Hay .py en el proyecto pero NINGUNO contiene el auth-gate del login "
                     "(pide credencial + decide acceso).")
        lines.append("    → El login está COMPILADO dentro del binario. Voy a bypass en runtime.")
        emit("  · Login compilado en el binario (sin .py) → bypass en runtime")
    elif src_rec and src_rec.get("main"):
        lines.append(f"  · Código fuente encontrado ({src_rec['main']}) pero sin patrón de login "
                     f"claro para parchear automáticamente. Revisa las líneas localizadas.")

    # ── 2b. Sin fuente parcheable → bypass a nivel binario ────────────────────
    if auth_mech in ("online_keyauth", "online_generic"):
        emit("  ▶ Auth ONLINE → generando shim KeyAuth + Frida + patch r2 (r2 puede tardar)…")
        lines.append("  ⚠ Auth ONLINE detectada → LD_PRELOAD de memcmp/strcmp NO sirve aquí.")
        lines.append("    Genero artefactos de bypass en runtime (Frida / servidor falso / patch r2).")
        technique, bypass_log, bypass_ok, online_artifacts = _apply_online_bypass(
            target, outdir, analysis, auth_funcs, auth_mech
        )
    else:
        emit("  ▶ Aplicando bypass a nivel binario (LD_PRELOAD / patch r2)…")
        technique, bypass_log, bypass_ok = _skill_apply_bypass(
            target, outdir, binary_type, auth_funcs
        )
    emit(f"  ✓ Técnica: {technique}")
    lines.append(f"  Técnica: {technique}")
    lines.append(bypass_log)

    # ── Verificación ──────────────────────────────────────────────────────────
    binfinal  = outdir / "binfinal"
    bypass_sh = outdir / "run_bypass.sh"
    is_online = auth_mech in ("online_keyauth", "online_generic")
    lines.append(f"\n▶ [VERIFICACIÓN]")
    lines.append(f"  binfinal     : {'✓ CREADO' if binfinal.exists() else '✗ NO CREADO'}")
    lines.append(f"  run_bypass.sh: {'✓ CREADO' if bypass_sh.exists() else '✗ NO CREADO'}")
    if is_online:
        lines.append("  ⚠ NO verificado: la auth es online. Prueba en runtime con:")
        if online_artifacts.get("frida"):
            lines.append(f"     frida -f \"{target}\" -l {online_artifacts['frida']} --no-pause")
        if online_artifacts.get("fake_server"):
            lines.append(f"     # o servidor falso: redirige keyauth.win → localhost y corre {online_artifacts['fake_server']}")
    elif binfinal.exists():
        lines.append(f"\n  Ejecutar bypass (usa el WRAPPER, no ./binfinal directo):")
        lines.append(f"  $ {bypass_sh}")

    # ── Findings estructurados ────────────────────────────────────────────────
    findings = [
        {
            "type": "binary_type",
            "value": binary_type,
            "severity": "info",
            "description": f"Tipo detectado: {binary_type}",
        },
        {
            "type": "bypass_method",
            "value": technique,
            "severity": "info",
            "description": f"Técnica aplicada: {technique}",
        },
    ]

    for func in auth_funcs[:10]:
        findings.append({
            "type": "auth_function",
            "value": func,
            "severity": "high",
            "description": f"Función de autenticación: {func}",
        })

    if is_online:
        findings.append({
            "type": "auth_online",
            "value": auth_evidence,
            "severity": "high",
            "description": (
                f"Autenticación ONLINE ({auth_evidence}). El LD_PRELOAD de memcmp/strcmp "
                "NO aplica. Requiere bypass en runtime: Frida hook, servidor falso, o "
                "patch del branch tras la respuesta del servidor."
            ),
        })
        for k, v in online_artifacts.items():
            findings.append({"type": "bypass_artifact", "value": v, "severity": "info",
                             "description": f"Artefacto de bypass ({k}): {v}"})
    elif binfinal.exists():
        findings.append({
            "type": "bypass_success",
            "value": str(binfinal),
            "severity": "critical",
            "description": (
                f"Bypass exitoso con {technique}. "
                f"Ejecutar (usa el wrapper): {bypass_sh}"
            ),
        })
    else:
        findings.append({
            "type": "bypass_failed",
            "value": technique,
            "severity": "medium",
            "description": (
                f"Bypass automático con {technique} falló. "
                "Usa agent_ing.py para análisis interactivo profundo."
            ),
        })

    checksec = analysis.get("checksec", "")
    for prot, sev, desc in [
        ("NX enabled",    "low", "No-Execute bit activo"),
        ("Canary found",  "low", "Stack canary presente"),
        ("PIE enabled",   "low", "PIE (Position Independent Executable) activo"),
        ("Full RELRO",    "low", "Full RELRO activo"),
    ]:
        if prot in checksec:
            findings.append({
                "type": "protection",
                "value": prot,
                "severity": sev,
                "description": desc,
            })

    lines.append(f"\n{'═'*60}")
    lines.append(f"  Tipo detectado  : {binary_type.upper()}")
    lines.append(f"  Mecanismo auth  : {auth_mech.upper()}")
    lines.append(f"  Técnica bypass  : {technique}")
    if is_online:
        lines.append(f"  Bypass          : ⚠ NO verificado (auth online) — prueba los artefactos en runtime")
    else:
        lines.append(f"  Bypass exitoso  : {'SÍ' if bypass_ok else 'NO — usa agent_ing.py'}")
    lines.append(f"  Hallazgos       : {len(findings)}")
    if binfinal.exists():
        lines.append(f"  Ejecutar        : {bypass_sh}")
    lines.append(f"  Directorio      : {output_dir}/")
    lines.append(f"{'═'*60}")

    return {
        "success": bypass_ok,
        "output": "\n".join(lines),
        "findings": findings,
        "binary_type": binary_type,
        "auth_mechanism": auth_mech,
        "bypass_type": technique,
        "binfinal": str(binfinal) if binfinal.exists() else "",
        "bypass_sh": str(bypass_sh) if bypass_sh.exists() else "",
        "online_artifacts": online_artifacts,
        "output_dir": str(outdir),
        "analysis": {k: v[:2000] for k, v in analysis.items()},
    }


# ═══════════════════════════════════════════════════════════════════════════════
# FIN DE SKILL INTERFACE — el resto es el agente interactivo standalone
# ═══════════════════════════════════════════════════════════════════════════════

def run_analysis(target: str, log: LogWriter) -> str:
    """Corre análisis estático sin LLM. Retorna texto con todos los resultados."""
    results = []
    print(f"\n  {CYAN}▶ Análisis automático del binario...{R}\n")
    for label, cmd_fn in ANALYSIS_CMDS:
        cmd = cmd_fn(target)
        separator()
        print(f"  {GREEN}❯{R} {DIM}{cmd[:90]}...{R}" if len(cmd) > 90 else f"  {GREEN}❯{R} {DIM}{cmd}{R}")
        separator()
        stdout, stderr, code = run_cmd(cmd)
        out = (stdout or stderr or "(sin output)").strip()
        # Mostrar solo primeras 30 líneas en terminal
        lines = out.split("\n")
        for l in lines[:30]: print(f"  {DIM}{l}{R}")
        if len(lines) > 30: print(f"  {YELLOW}··· {len(lines)-30} líneas más ···{R}")
        print(f"  {DIM}└─{R} {'OK' if code==0 else f'exit {code}'}")
        log.cmd(cmd, out, code)
        results.append(f"[{label.upper()}]\n$ {cmd}\n{out[:4000]}\n")
    print()
    return "\n".join(results)

# ── Detección del target ──────────────────────────────────────────────────────
def detect_target(path: str) -> dict:
    p = Path(path)
    info = {"path": str(p.resolve()), "name": p.name, "exists": p.exists(),
            "is_dir": p.is_dir(), "size_kb": 0, "type_raw": "", "category": "unknown"}
    if not p.exists(): return info
    if p.is_dir(): info["category"] = "directory"; return info
    info["size_kb"] = round(p.stat().st_size / 1024, 1)
    try:
        r = subprocess.run(["file", str(p.resolve())], capture_output=True, text=True, timeout=10)
        info["type_raw"] = r.stdout.strip()
        s = r.stdout.lower()
        if "elf" in s:           info["category"] = "elf"
        elif "pe32" in s:        info["category"] = "pe"
        elif "python" in s and "bytecode" in s: info["category"] = "pyc"
        elif "shell script" in s: info["category"] = "script"
        elif p.suffix == ".py":  info["category"] = "python"
        elif p.suffix in (".apk",): info["category"] = "apk"
        else:                    info["category"] = "binary"
    except Exception: pass
    return info

# ── Ollama ────────────────────────────────────────────────────────────────────
def check_ollama():
    base = OLLAMA_URL.rsplit("/api/chat",1)[0].rsplit("/api/",1)[0]
    try:
        r = requests.get(f"{base}/api/tags", timeout=5)
        if r.status_code == 200:
            return True, [m["name"] for m in r.json().get("models",[])]
    except Exception: pass
    return False, []

def get_model(preferred=None):
    ok, models = check_ollama()
    if not ok: print(f"{RED}✗ Ollama no responde{R}"); sys.exit(1)
    if not models: print(f"{RED}✗ Sin modelos{R}"); sys.exit(1)
    if preferred and preferred in models: return preferred, models
    for kw in ["deepseek-r1","dolphin","qwen","codellama","llama3","mistral"]:
        for m in models:
            if kw in m.lower(): return m, models
    return models[0], models

def call_ollama(model: str, messages: list) -> dict:
    payload = {"model": model, "messages": messages, "stream": False, "format": "json",
               "options": {"temperature": 0.1, "num_ctx": 8192}}
    r = requests.post(OLLAMA_URL, json=payload, timeout=300)
    r.raise_for_status()
    content = r.json()["message"]["content"]
    try: return json.loads(content)
    except json.JSONDecodeError:
        s, e = content.find("{"), content.rfind("}")+1
        if s != -1 and e > s:
            try: return json.loads(content[s:e])
            except Exception: pass
        return {"thinking":"","commands":[],"message":content,"requires_confirmation":False,
                "task_complete":True,"risk_level":"low","phase":"identify","install_needed":[]}

def call_ollama_text(model: str, prompt: str) -> str:
    payload = {"model":model,"messages":[{"role":"user","content":prompt}],
               "stream":False,"options":{"temperature":0.3,"num_ctx":16384}}
    r = requests.post(OLLAMA_URL, json=payload, timeout=600)
    r.raise_for_status()
    return r.json()["message"]["content"]

# ── Ejecución de comandos ─────────────────────────────────────────────────────
def run_cmd(cmd: str, cwd=None, timeout: int = 300):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                             cwd=cwd or os.getcwd(), timeout=timeout)
        return res.stdout, res.stderr, res.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timeout ({timeout}s)", 1
    except Exception as e:
        return "", str(e), 1

def tool_missing(stdout: str, stderr: str) -> bool:
    c = (stdout+stderr).lower()
    return any(p in c for p in ("command not found","not found","no such file","is not installed"))

# ── UI ────────────────────────────────────────────────────────────────────────
class Spinner:
    _F = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    def __init__(self, msg="analizando..."):
        self.msg=msg; self._s=threading.Event()
        self._t=threading.Thread(target=self._run,daemon=True)
    def _run(self):
        labels=itertools.cycle(["analizando...","procesando...","generando bypass...","consultando modelo..."])
        label=self.msg; tick=0
        for frame in itertools.cycle(self._F):
            if self._s.is_set(): break
            if tick%25==0: label=next(labels)
            sys.stdout.write(f"\r  {CYAN}{frame}{R}  {DIM}{label}{R}   ")
            sys.stdout.flush(); time.sleep(0.08); tick+=1
        sys.stdout.write("\r"+" "*52+"\r"); sys.stdout.flush()
    def __enter__(self): self._t.start(); return self
    def __exit__(self,*_): self._s.set(); self._t.join()

def separator(c="─",color=DIM,w=50): print(f"{color}{c*w}{R}")
def typewrite(t,d=0.012,color=WHITE):
    for ch in t: sys.stdout.write(f"{color}{ch}{R}"); sys.stdout.flush(); time.sleep(d)
    print()
def confirm(p): return input(f"\n{YELLOW}  ⚠  {p} [s/N]: {R}").strip().lower() in("s","si","sí","y","yes")

PHASE_ICONS = {"identify":"🔎","static":"🔬","dynamic":"⚡","decompile":"📄","bypass":"💉","verify":"✅","report":"📋"}
RISK_COLORS = {"low":GREEN,"medium":YELLOW,"high":RED}

_BANNER=[
    f"{MAGENTA}{BOLD}  ██████╗ ███████╗██╗   ██╗███████╗██████╗ ███████╗{R}",
    f"{MAGENTA}{BOLD}  ██╔══██╗██╔════╝██║   ██║██╔════╝██╔══██╗██╔════╝{R}",
    f"{MAGENTA}{BOLD}  ██████╔╝█████╗  ██║   ██║█████╗  ██████╔╝███████╗{R}",
    f"{MAGENTA}{BOLD}  ██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║{R}",
    f"{MAGENTA}{BOLD}  ██║  ██║███████╗ ╚████╔╝ ███████╗██║  ██║███████║{R}",
    f"{MAGENTA}{BOLD}  ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝{R}",
    f"  {CYAN}{BOLD}A G E N T{R}  {DIM}· Reverse Engineering · Powered by Ollama{R}",
]

def print_header(model,session,models,ti,resumed=False):
    print()
    for l in _BANNER: print(l); time.sleep(0.03)
    print(); separator("─",MAGENTA,56)
    print(f"  {DIM}Modelo :{R}  {MAGENTA}{BOLD}{model}{R}")
    print(f"  {DIM}Sesión :{R}  {CYAN}{session}{R}  {DIM}{'(reanudada)' if resumed else '(nueva)'}{R}")
    print(f"  {DIM}Salida :{R}  {DIM}{OUT_DIR}{R}")
    if ti.get("path"):
        cat_c = {"elf":GREEN,"pe":CYAN,"script":DIM,"python":CYAN,"apk":YELLOW}.get(ti.get("category",""),WHITE)
        print(f"  {DIM}Target :{R}  {cat_c}{BOLD}{ti['name']}{R}  {DIM}[{ti.get('category','?')} · {ti.get('size_kb','?')} KB]{R}")
    separator("─",MAGENTA,56)
    print(f"\n  {BOLD}Modelos:{R}")
    for m in models:
        print(f"    {GREEN}▸{R} {CYAN}{BOLD}{m}{R}  {GREEN}← activo{R}" if m==model else f"    {DIM}·  {m}{R}")
    separator("─",DIM,56)
    print("  "+"  ·  ".join(f"{YELLOW}{v}{R}" for v in
          ["salir","reporte","sesiones","sesion guardar/cargar <n>","target <ruta>","cd <ruta>"]))
    separator("─",DIM,56); print()

def print_thinking(t,phase="identify",risk="low"):
    if not t: return
    icon=PHASE_ICONS.get(phase,"🔎"); rcol=RISK_COLORS.get(risk,GREEN)
    print(f"\n  {icon} {DIM}[{R}{CYAN}{phase.upper()}{R}{DIM}]{R}  {DIM}[{R}{rcol}{BOLD}{risk.upper()}{R}{DIM}]{R}")
    separator("╌",DIM,50)
    for l in t.split(". "):
        if l.strip(): print(f"  {DIM}{l.strip()}.{R}")
    separator("╌",DIM,50)

def print_cmd(cmd): separator("─",DIM,50); print(f"  {GREEN}❯{R} {BOLD}{cmd}{R}"); separator("─",DIM,50)

def print_out(stdout,stderr,code):
    if stdout.strip():
        lines=stdout.strip().split("\n")
        for l in lines[:300]: print(f"  {DIM}{l}{R}")
        if len(lines)>300: print(f"  {YELLOW}··· {len(lines)-300} líneas omitidas ···{R}")
    if stderr.strip():
        col=RED if code!=0 else YELLOW
        for l in stderr.strip().split("\n")[:30]: print(f"  {col}{l}{R}")
    print(f"  {DIM}└─{R} {GREEN}✓ OK{R}" if code==0 else f"  {DIM}└─{R} {RED}✗ exit {code}{R}")

# ── Reporte ───────────────────────────────────────────────────────────────────
def generate_report(model,session,log,outdir,target_name):
    content = log.path.read_text(encoding="utf-8") if log.path.exists() else ""
    if len(content)<100: print(f"  {YELLOW}⚠ Log vacío.{R}"); return
    rpath = outdir / f"{session}_report.md"
    print(f"\n  {MAGENTA}{BOLD}📋 Generando reporte...{R}")
    try:
        with Spinner("generando reporte..."):
            md = call_ollama_text(model, f"{REPORT_PROMPT}\n\nTarget: {target_name}\n\n---\n\n{content[:28000]}")
    except Exception as e:
        print(f"  {RED}✗ {e}{R}"); return
    header = f"<!-- ReverseAgent · {session} · {datetime.now():%Y-%m-%d %H:%M:%S} -->\n\n"
    rpath.write_text(header+md, encoding="utf-8")
    separator("═",MAGENTA+BOLD,56)
    print(f"  {MAGENTA}{BOLD}📋 REPORTE{R}")
    for l in md.split("\n")[:50]:
        if l.startswith("# "): print(f"\n  {BOLD}{WHITE}{l}{R}")
        elif l.startswith("## "): print(f"\n  {CYAN}{BOLD}{l}{R}")
        else: print(f"  {l}")
    separator("═",MAGENTA+BOLD,56)
    print(f"\n  {GREEN}✓{R} {CYAN}{rpath}{R}\n")

# ── Wizard ────────────────────────────────────────────────────────────────────
def wizard() -> dict:
    separator("═",CYAN+BOLD,58)
    print(f"{CYAN}{BOLD}  ⚙  CONFIGURACIÓN DE ANÁLISIS{R}")
    separator("═",CYAN+BOLD,58)
    def ask(q,d=""): return input(f"  {CYAN}?{R} {q}: ").strip() or d
    def askb(q,d=False):
        a=input(f"  {CYAN}?{R} {q} [{'S' if d else 's'}/{'n' if d else 'N'}]: ").strip().lower()
        return d if not a else a in("s","si","sí","y","yes")
    print()
    target  = ask("Ruta del binario/script/carpeta a analizar")
    dynamic = askb("¿Análisis dinámico? (ltrace/strace — ejecuta el binario controlado)", False)
    report  = askb("¿Generar reporte al finalizar?", True)
    cfg = {"target":target,"run_dynamic":dynamic,"generate_report":report}
    print(); separator("─",CYAN,58)
    for k,v in cfg.items():
        print(f"    {GREEN}✓{R}  {k:<22} {CYAN}{v}{R}")
    separator("─",CYAN,58); print()
    return cfg

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="ReverseAgent")
    ap.add_argument("--target","-t"); ap.add_argument("--model","-m")
    ap.add_argument("--session","-s"); ap.add_argument("--list-sessions","-l",action="store_true")
    ap.add_argument("--no-wizard",action="store_true")
    args = ap.parse_args()

    if args.list_sessions:
        for s in list_sessions():
            print(f"  {CYAN}{s['name']:<32}{R} {DIM}{s['target']:<24}{s['saved_at'][:19]}  {s['turns']} turnos{R}")
        return

    model, all_models = get_model(args.model)
    session  = args.session or gen_session_name()
    conv, saved_model, loaded_dir = load_session(session)
    resumed  = conv is not None

    cfg: dict = {}
    ti:  dict = {}

    if resumed:
        model   = saved_model or model
        outdir  = loaded_dir or get_outdir(session)
        ti      = {"name": outdir.name, "category":"?", "type_raw":"sesión reanudada", "size_kb":0}
    else:
        conv = [{"role":"system","content":SYSTEM_PROMPT}]
        if not args.no_wizard:
            cfg = wizard()
        if args.target:
            cfg["target"] = args.target
        ti     = detect_target(cfg.get("target","")) if cfg.get("target") else {}
        outdir = get_outdir(cfg.get("target", session))

    log     = LogWriter(session, outdir)
    target  = cfg.get("target","")
    current_target = target

    print_header(model, session, all_models, ti, resumed)
    if target:
        print(f"  {GREEN}✓ Target:{R} {CYAN}{target}{R}")
        print(f"  {GREEN}✓ Salida:{R} {CYAN}{outdir}/binfinal{R}\n")

    # ── Análisis inicial automático (sin LLM) ─────────────────────────────────
    analysis_results = ""
    if target and not resumed and Path(target).exists():
        log.section("Análisis automático inicial")
        analysis_results = run_analysis(target, log)

        # Primer mensaje al LLM: resultados + instrucción de bypass
        bypass_instruction = (
            f"[ANÁLISIS COMPLETADO — RESULTADOS]\n"
            f"BINPATH={target}\n"
            f"OUTDIR={outdir}\n"
            f"BINFINAL={outdir}/binfinal\n\n"
            f"{analysis_results[:6000]}\n\n"
            f"[INSTRUCCIÓN]\n"
            f"Basándote en los resultados anteriores:\n"
            f"1. Identifica la técnica de bypass adecuada (LD_PRELOAD, patch r2, patch Python)\n"
            f"2. Emite los comandos exactos para crear {outdir}/binfinal con el bypass\n"
            f"3. Si detectas símbolos __pyx_* → es Cython → usa LD_PRELOAD\n"
            f"4. Si hay funciones de auth en r2 → parchea esa función con r2 -w\n"
            f"5. Siempre crea también {outdir}/run_bypass.sh como wrapper de ejecución\n"
            f"6. Cuando {outdir}/binfinal exista → task_complete: true"
        )
        conv.append({"role":"user","content":bypass_instruction})
        print(f"  {MAGENTA}▶ Consultando modelo para bypass...{R}\n")

    cwd = os.getcwd()
    executed: set = set()

    # ── Loop principal ────────────────────────────────────────────────────────
    first_run = bool(analysis_results)  # si ya tenemos análisis, empezar con el LLM

    while True:
        if first_run:
            user_input = ""
            first_run  = False
        else:
            try:
                user_input = input(f"{MAGENTA}{BOLD}reverse ❯ {R}").strip()
            except (EOFError,KeyboardInterrupt):
                save_session(session,conv,model,outdir)
                print(f"\n{DIM}Guardado. Hasta luego.{R}\n"); break
            if not user_input: continue

        # ── Comandos de control ───────────────────────────────────────────────
        if user_input.lower() in ("salir","exit","quit","q"):
            save_session(session,conv,model,outdir)
            if cfg.get("generate_report") and confirm("¿Generar reporte?"):
                generate_report(model,session,log,outdir,current_target)
            print(f"\n{DIM}Hasta luego.{R}\n"); break

        if user_input.lower() in ("reporte","report"):
            generate_report(model,session,log,outdir,current_target); continue

        if user_input.lower() == "sesiones":
            for s in list_sessions():
                print(f"  {CYAN}{s['name']:<32}{R} {DIM}{s['target']:<24}{s['saved_at'][:19]}{R}")
            continue

        if user_input.lower().startswith("sesion guardar"):
            parts=user_input.split(maxsplit=2); n=parts[2] if len(parts)>2 else session
            f=save_session(n,conv,model,outdir); session=n; print(f"  {GREEN}✓ {f}{R}"); continue

        if user_input.lower().startswith("sesion cargar"):
            parts=user_input.split(maxsplit=2)
            if len(parts)<3: print(f"  {RED}Uso: sesion cargar <nombre>{R}"); continue
            c2,m2,d2=load_session(parts[2])
            if c2 is None: print(f"  {RED}✗ No encontrada{R}")
            else:
                conv=c2; session=parts[2]; outdir=d2 or outdir
                log=LogWriter(session,outdir); model=m2 or model
                print(f"  {GREEN}✓ Cargada: {parts[2]} [{outdir.name}]{R}")
            continue

        if user_input.lower().startswith("target "):
            new_t=user_input[7:].strip()
            if not Path(new_t).exists(): print(f"  {RED}✗ No existe: {new_t}{R}"); continue
            current_target=new_t; ti=detect_target(new_t)
            outdir=get_outdir(new_t); log=LogWriter(session,outdir)
            print(f"  {GREEN}✓ Target: {CYAN}{new_t}{R}  {DIM}[{ti.get('category','?')} · {ti.get('size_kb','?')} KB]{R}")
            log.section("Análisis automático — nuevo target")
            results=run_analysis(new_t,log)
            msg=(f"[NUEVO TARGET ANALIZADO]\nBINPATH={new_t}\nOUTDIR={outdir}\nBINFINAL={outdir}/binfinal\n\n"
                 f"{results[:6000]}\n\nAplica el bypass y crea {outdir}/binfinal")
            conv.append({"role":"user","content":msg}); first_run=True; continue

        if user_input.lower().startswith("cd "):
            try: os.chdir(os.path.expanduser(user_input[3:].strip())); cwd=os.getcwd(); print(f"  {DIM}→ {cwd}{R}")
            except Exception as e: print(f"  {RED}✗ {e}{R}")
            continue

        # ── Procesar con el modelo ────────────────────────────────────────────
        if user_input:  # no inyectar input vacío (caso first_run ya inyectó)
            log.sep(); log.user(user_input)
            ctx = (f"[BINPATH: {current_target}]\n[OUTDIR: {outdir}]\n[BINFINAL: {outdir}/binfinal]\n"
                   if current_target else "")
            conv.append({"role":"user","content":f"{ctx}{user_input}"})

        max_rounds  = 10
        empty_count = 0

        for _ in range(max_rounds):
            try:
                with Spinner():
                    resp = call_ollama(model, conv)
            except Exception as e:
                print(f"\n{RED}  ✗ Ollama: {e}{R}"); break

            thinking  = resp.get("thinking","")
            commands  = resp.get("commands",[])
            message   = resp.get("message","")
            confirm_r = resp.get("requires_confirmation",False)
            done      = resp.get("task_complete",False)
            risk      = resp.get("risk_level","low")
            phase     = resp.get("phase","identify")
            to_ins    = resp.get("install_needed",[])

            if message and message.strip().startswith("{"): message=""
            log.msg(message); print_thinking(thinking,phase,risk)
            if message:
                print(f"\n  {MAGENTA}{BOLD}reverse ❯{R} ",end="")
                typewrite(message,color=WHITE)

            # Filtrar repetidos
            commands = [c for c in commands if c not in executed]

            if not commands and not to_ins:
                conv.append({"role":"assistant","content":json.dumps(resp,ensure_ascii=False)})
                if done: break
                empty_count+=1
                if empty_count>=3:
                    print(f"  {YELLOW}⚠ El modelo no avanza. Escribe tu próxima instrucción.{R}")
                    break
                print(f"  {YELLOW}⚠ Sin comandos — reintentando ({empty_count}/3)...{R}")
                conv.append({"role":"user","content":(
                    f"Emite ahora los comandos de bypass. Recuerda: OUTDIR={outdir}, BINFINAL={outdir}/binfinal. "
                    f"Usa LD_PRELOAD si detectaste __pyx_ (Cython). Emite al menos 3 comandos concretos.")})
                continue

            # Auto-instalar herramientas faltantes
            if to_ins:
                for tool in to_ins:
                    ic = f"apt-get install -y {tool} 2>&1 || pip3 install {tool} 2>&1"
                    print_cmd(ic); o,e,c=run_cmd(ic,timeout=120); print_out(o,e,c); log.cmd(ic,o or e,c)

            if not commands:
                conv.append({"role":"assistant","content":json.dumps(resp,ensure_ascii=False)}); break

            if confirm_r:
                print(f"\n  {YELLOW}Comandos:{R}")
                for cm in commands: print(f"    {DIM}$ {cm}{R}")
                if not confirm("¿Ejecutar?"): print(f"  {YELLOW}Cancelado.{R}"); break

            all_out=[]; missing=[]
            print()
            for cmd in commands:
                # Sustituir placeholders que el modelo devuelve literalmente
                cmd = (cmd
                    .replace("BINPATH",  current_target)
                    .replace("OUTDIR",   str(outdir))
                    .replace("BINFINAL", str(outdir / "binfinal"))
                )
                executed.add(cmd)
                print_cmd(cmd)
                o,e,code=run_cmd(cmd,cwd=cwd); print_out(o,e,code); log.cmd(cmd,o or e,code)
                all_out.append({"cmd":cmd,"stdout":o[:8000],"stderr":e[:1000],"code":code})
                if tool_missing(o,e): missing.append(cmd.split()[0])

            summary = json.dumps(all_out,ensure_ascii=False)
            miss_hint = f"\n[HERRAMIENTAS FALTANTES: {missing} — instálalas con apt-get/pip3]" if missing else ""

            # Verificar si binfinal fue creado
            binfinal=outdir/"binfinal"
            if binfinal.exists():
                print(f"\n  {GREEN}{BOLD}✓ BINFINAL CREADO: {binfinal}{R}")
                if (outdir/"run_bypass.sh").exists():
                    print(f"  {GREEN}✓ WRAPPER: {outdir}/run_bypass.sh{R}")
                print(f"\n  {CYAN}Ejecutar bypass:{R} {WHITE}{outdir}/run_bypass.sh{R}\n")
                done=True

            conv.append({"role":"assistant","content":json.dumps(resp,ensure_ascii=False)})

            if done:
                conv.append({"role":"user","content":f"Resultados finales:\n{summary}{miss_hint}"})
                break

            ran=sorted(executed)
            conv.append({"role":"user","content":(
                f"Resultados:\n{summary}{miss_hint}\n\n"
                f"[YA EJECUTADOS: {json.dumps(ran)}]\n"
                f"OUTDIR={outdir} BINFINAL={outdir}/binfinal\n"
                f"¿Está listo {outdir}/binfinal? Si no, continúa con más comandos de bypass."
            )})
            print()

        save_session(session,conv,model,outdir); print()


if __name__ == "__main__":
    main()
