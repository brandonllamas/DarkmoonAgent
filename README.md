# HackerAgent 💀

Agente de terminal para **auditorías de ciberseguridad** impulsado por modelos locales vía Ollama.  
Diseñado para Kali Linux con acceso completo al arsenal de herramientas de pentesting.

> ⚠️ **AVISO LEGAL**  
> Uso exclusivo en sistemas con **autorización expresa y por escrito** del propietario.  
> El uso no autorizado es delito (art. 197 bis CP España · CFAA USA · Ley 1273 Colombia).  
> **Hackea solo lo que te pertenece o tienes permiso de auditar.**

---

## Características

- **Gestor de proyectos**: al arrancar muestra tus proyectos previos con hallazgos, sesiones y fechas — elige uno o crea uno nuevo
- **Persistencia total**: dominios descubiertos, hallazgos y sesiones se acumulan en `out/<proyecto>/` entre sesiones
- **Multi-agente**: cada skill lanza un SubAgent en hilo paralelo que analiza el output y devuelve un resumen compacto al agente principal
- **Wizard de configuración**: tipo de análisis, target, sigilo, agresividad y skills antes de empezar
- **12 skills de pentesting**: recon pasivo/activo, vuln scan, análisis de código fuente web, Metasploit, ingeniería inversa
- **Auto-pentest**: escribe `hackea https://ejemplo.com` y ejecuta 3 fases de recon sin intervención
- **PoC automatizado**: `listame vulnerabilidades` → `explotar <N>` construye y ejecuta proof of concept
- **Reporte HTML**: dark theme con gráficos, tabla de hallazgos por severidad y log colapsable
- **Anti-bucle**: circuit breaker, cache TTL 24h, límite de rondas por API keys

---

## Instalación

```bash
# 1. Copiar el proyecto
cd /opt && cp -r /media/sf_CarpetaCompartida/tools/HackerAgent .
cd HackerAgent

# 2. Instalar dependencia Python
pip3 install requests

# 3. Configurar Ollama (en la misma máquina o en otra VM)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull deepseek-r1:14b   # recomendado

# 4. Configurar .env
nano .env

# 5. Ejecutar
python3 agent.py
```

---

## Configuración — `.env`

```env
OLLAMA_URL="http://192.168.80.120:11434/api/chat"

WPSCAN_API_KEY=""        # https://wpscan.com/api  (gratis, 25 req/día)
SHODAN_API_KEY=""        # https://account.shodan.io
VIRUSTOTAL_API_KEY=""    # https://www.virustotal.com/gui/user/apikey

BROWSER="firefox"
```

Las API keys también se pueden ingresar durante la sesión; el agente las pedirá cuando las necesite y las guarda en `.env`.

---

## Modelos recomendados

| Modelo | RAM | Velocidad | Ideal para |
|--------|-----|-----------|-----------|
| `deepseek-r1:14b` | 16 GB | ★★★☆ | **Recomendado** — razonamiento técnico |
| `deepseek-r1:32b` | 32 GB | ★★★ | Máxima profundidad de análisis |
| `dolphin-mistral:7b` | 8 GB | ★★★★ | Pentesting sin restricciones, CTFs |
| `qwen2.5-coder:14b` | 16 GB | ★★★☆ | Scripts, payloads, código |
| `llama3.2:3b` | 4 GB | ★★★★★ | Hardware limitado / VM pequeña |

> Los modelos `dolphin-*` son fine-tunes sin RLHF restrictivo: no se niegan a ayudar con payloads, escalada de privilegios, etc.

---

## Uso

```bash
# Sesión nueva (muestra picker de proyectos → wizard)
python3 agent.py

# Especificar modelo
python3 agent.py --model deepseek-r1:14b

# Cargar sesión directamente por nombre (salta el picker)
python3 agent.py --session mi_auditoria

# Listar sesiones guardadas
python3 agent.py --list-sessions

# Sin disclaimer ni wizard
python3 agent.py --no-disclaimer --no-wizard
```

---

## Flujo de inicio

Al ejecutar `python3 agent.py` aparece primero el **picker de proyectos**:

```
📁  PROYECTOS GUARDADOS
══════════════════════════════════════════════════════════
   1.  corp_auditoria_2026    example.com    3 sesiones   2026-07-01
       2 critical  5 high  8 medium
   2.  ctf_hackthebox         10.10.11.1     7 sesiones   2026-06-30
       1 high  3 info

    0.  [Crear nuevo proyecto]

? Selecciona proyecto [0-2]:
```

Si eliges un proyecto existente, muestra sus sesiones y ofrece reanudar una:

```
Sesiones del proyecto:
   1.  session_20260701_143022    12 turnos   2026-07-01 14:30
   2.  session_20260630_091544     8 turnos   2026-06-30 09:15
    0.  [Nueva sesión en este proyecto]
? Reanudar sesión [0-2]:
```

Después viene el **wizard de configuración** (solo en sesiones nuevas):

| Paso | Qué configura |
|------|--------------|
| 1 | Tipo de análisis (Web Pentest / Ing. Inversa / OSINT / Vuln Scan / Código / Full) |
| 2 | Target, subdominios, reporte, sigilo, persistencia, agresividad, sub-agentes |
| 3 | Selección de skills por número, categoría o nombre |

---

## Skills disponibles

| Skill | Categoría | Descripción |
|-------|-----------|-------------|
| `crtsh_enum` | recon pasivo | Subdominios vía Certificate Transparency |
| `google_dorks` | recon pasivo | Google dorks de seguridad (login, archivos, expuestos) |
| `shodan_query` | recon pasivo | Shodan API + InternetDB fallback |
| `subfinder_enum` | recon pasivo | Subfinder + verificación HTTP con httpx |
| `gobuster_dir` | recon activo | Fuerza bruta de directorios (manejo wildcard 403) |
| `scan_red` | recon activo | Nmap con clasificación de puertos críticos + NSE vuln |
| `nuclei_scan` | vuln scan | Nuclei con auto-detección de templates + JSON export |
| `wpscan_run` | vuln scan | WPScan con API key automática |
| `spider_code` | análisis | Spider HTML/JS buscando secretos, credenciales y source maps |
| `web_code` | análisis | Spider profundo de código fuente: frameworks, Firebase config+colecciones+storage, endpoints, credenciales, WebSockets, GraphQL, comentarios sensibles y source maps |
| `metasploit` | ataque | Search, exploit, auxiliary, payload y scan con msfconsole |
| `ing_inversa` | ing. inversa | Análisis estático + bypass automático (LD_PRELOAD / r2 patch) |

---

## Comandos dentro del agente

| Comando | Acción |
|---------|--------|
| `hackea <url>` / `escanea <url>` | Auto-pentest: 3 fases de recon sin intervención |
| `listame vulnerabilidades` / `vulns` | Extrae y lista todas las vulns del log (numeradas) |
| `explotar <N>` | Construye y ejecuta PoC para la vulnerabilidad N |
| `reporte` / `html` | Genera reporte HTML dark theme + Markdown |
| `apikeys` | Muestra estado de las API keys configuradas |
| `sesiones` | Lista todas las sesiones guardadas |
| `sesion guardar <nombre>` | Guarda la sesión actual con nombre personalizado |
| `sesion cargar <nombre>` | Carga una sesión anterior |
| `cd <ruta>` | Cambia el directorio de trabajo |
| `salir` / `exit` | Guarda sesión y termina |

---

## Estructura de salida

Todo se organiza por proyecto en `out/`:

```text
out/
└── corp_auditoria_2026/
    ├── project_state.json              ← dominios, hallazgos, resumen (acumulado entre sesiones)
    ├── scan_cache.json                 ← cache TTL 24h por comando
    ├── session_20260701_143022.json    ← conversación completa
    ├── session_20260701_143022.md      ← log en tiempo real (thinking + comandos + output)
    ├── session_20260701_143022_report.md
    └── session_20260701_143022_report.html  ← dark theme con gráficos y tabla de findings
```

`project_state.json` acumula **todos los hallazgos y dominios** de todas las sesiones del proyecto, permitiendo retomar cualquier punto sin perder contexto.

---

## Herramientas externas — `confs.json`

```json
{
  "tools": [
    { "name": "Seclist",   "path": "/media/sf_CarpetaCompartida/tools/seclists" },
    { "name": "nuclei",    "command": "nuclei" },
    { "name": "subfinder", "command": "subfinder" },
    { "name": "ffuf",      "command": "ffuf" },
    { "name": "metasploit","command": "msfconsole" }
  ]
}
```

---

## Flujo de trabajo típico

```text
python3 agent.py
  │
  ├─ [PICKER]   selecciona proyecto o crea uno nuevo
  │
  ├─ [WIZARD]   tipo de análisis, target, skills, agresividad
  │
  ├─ [RECON]    SKILL:crtsh_enum → SKILL:subfinder_enum → SKILL:shodan_query
  │              SKILL:gobuster_dir → SKILL:scan_red
  │              (cada skill → SubAgent analiza en paralelo)
  │
  ├─ [SCAN]     SKILL:nuclei_scan → SKILL:wpscan_run → SKILL:spider_code → SKILL:web_code
  │
  ├─ [EXPLOIT]  listame vulnerabilidades → explotar <N>
  │              SKILL:metasploit mode=exploit ...
  │
  └─ [REPORT]   reporte → out/<proyecto>/session_*_report.html
```

---

## Ejemplos

```text
hacker ❯ hackea https://ejemplo.com
hacker ❯ escanea todos los puertos de 10.10.11.1 y busca CVEs
hacker ❯ enumera subdominios de banco.com y escanea con nuclei los activos
hacker ❯ analiza el código fuente de https://app.ejemplo.com — quiero ver el framework, Firebase y endpoints
hacker ❯ busca credenciales expuestas en el código fuente de https://app.ejemplo.com
hacker ❯ listame vulnerabilidades
hacker ❯ explotar 3
hacker ❯ tengo una shell como www-data, escala privilegios
hacker ❯ crackea este hash: 5f4dcc3b5aa765d61d8327deb882cf99
hacker ❯ reporte
```

---

## Licencia

MIT — para uso en pentesting autorizado, CTFs, laboratorios y formación en ciberseguridad.
