<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=0,2,5,20,30&height=230&section=header&text=HackerAgent&fontSize=82&fontColor=ffffff&animation=fadeIn&fontAlignY=36&desc=Agente%20de%20IA%20para%20Pentesting%20e%20Ingenier%C3%ADa%20Inversa&descSize=18&descAlignY=58" width="100%"/>

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=22&duration=3200&pause=700&color=F7768E&center=true&vCenter=true&width=820&height=48&lines=Pentesting+web+din%C3%A1mico+%2B+SQLi;Ingenier%C3%ADa+inversa+%2B+bypass+de+login;Credenciales+filtradas+%2B+credential+stuffing;Desarrollo+de+c%C3%B3digo+ofensivo+con+Ollama;100%25+local+%C2%B7+multi-agente+%C2%B7+sin+nube" alt="typing"/>

<br/>

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Ollama](https://img.shields.io/badge/Ollama-local-000000?style=for-the-badge&logo=ollama&logoColor=white)
![Kali](https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![Skills](https://img.shields.io/badge/skills-18-F7768E?style=for-the-badge)
![Multiagente](https://img.shields.io/badge/multi--agente-SubAgents-BB9AF7?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-9ECE6A?style=for-the-badge)

</div>

<div align="center">

### 🧠 IA local (Ollama) · ⚡ 18 skills · 🔬 RE + bypass · 🕸️ web dinámico · 🔑 credential intel · 🛠️ dev de código

</div>

> ### ⚠️ AVISO LEGAL
> Uso **exclusivo** en sistemas con **autorización expresa y por escrito** del propietario.
> El uso no autorizado es delito · *Art. 197 bis CP (España)* · *CFAA (USA)* · *Ley 1273 (Colombia)*.
> **Audita solo lo que te pertenece o tienes permiso de auditar.**

---

## ✨ ¿Qué es?

**HackerAgent** es un agente de terminal que orquesta **modelos locales de Ollama** para hacer pentesting, ingeniería inversa y desarrollo de herramientas ofensivas — **sin enviar nada a la nube**. Tú describes el objetivo en lenguaje natural y el agente ejecuta los *skills* adecuados, analiza los resultados con **sub-agentes en paralelo** y te entrega hallazgos, PoCs, binarios bypasseados o código, todo organizado por proyecto.

<div align="center">

| 🎯 | Capacidad | 
|:---:|:---|
| 🕸️ | **Pentest web dinámico** — crawlea y prueba SQLi / XSS / LFI / redirect / cmdi en vivo |
| 💉 | **SQL injection** — detecta y **extrae** datos con sqlmap (o fallback manual) |
| 🔑 | **Credential intel** — descarga credenciales filtradas (WhiteIntel) y las **prueba** contra el login |
| 🔬 | **Ingeniería inversa** — scripts, binarios y KeyAuth; bypass de login con **log en vivo** |
| 🛠️ | **Desarrollo de código** — genera payloads/malware/exploits con el mejor modelo local |
| 🤖 | **Multi-agente** — cada skill lanza un SubAgent que analiza en paralelo con contexto propio |
| 💾 | **Persistencia** — dominios, hallazgos y sesiones se acumulan por proyecto |
| 📊 | **Reportes** — HTML dark-theme con gráficos + Markdown |

</div>

---

## 🗺️ Cómo funciona

```mermaid
flowchart TD
    A([python3 agent.py]) --> B[🗂️ Picker de proyectos]
    B --> C[⚙️ Wizard: tipo · target · skills · agresividad]
    C --> D{¿Qué le pides?}
    D -->|hackea una url| E[🌐 Auto-pentest 4 fases sin LLM]
    D -->|bypass el login| F[🔬 Ing. inversa con log en vivo]
    D -->|desarrolla X| G[🛠️ code_dev]
    D -->|whiteintel y cred_stuff| H[🔑 Credenciales]
    E --> S[🤖 SubAgents en paralelo]
    F --> OUT2[binfinal y run_bypass.sh en out_re]
    G --> OUT3[código en out del proyecto dev]
    H --> S
    S --> R[💾 project_state.json y 📊 reporte HTML]
```

---

## 🚀 Instalación

```bash
# 1) Copiar el proyecto a la máquina (Kali recomendado)
cd /opt && cp -r /media/sf_CarpetaCompartida/tools/HackerAgent . && cd HackerAgent

# 2) Dependencia Python
pip3 install requests

# 3) Ollama (local o en otra VM)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull deepseek-r1:14b        # razonamiento / pentest
ollama pull dolphin-mistral        # sin censura / desarrollo ofensivo

# 4) Configurar .env  (ver abajo)
nano .env

# 5) Ejecutar
python3 agent.py
```

---

## 🔧 Configuración — `.env`

```env
OLLAMA_URL="http://192.168.80.120:11434/api/chat"

WPSCAN_API_KEY=""        # https://wpscan.com/api  (gratis, 25 req/día)
SHODAN_API_KEY=""        # https://account.shodan.io
VIRUSTOTAL_API_KEY=""    # https://www.virustotal.com/gui/user/apikey
WHITEINTEL_API_KEY=""    # https://whiteintel.io  (stealer logs)

BROWSER="firefox"
```

> Las API keys también se piden durante la sesión cuando hacen falta y se guardan solas en `.env`.

---

## 🧩 Skills (18)

<div align="center">

| Skill | Categoría | Qué hace |
|:------|:---------:|:---------|
| `crtsh_enum` | 🔍 recon pasivo | Subdominios vía Certificate Transparency |
| `google_dorks` | 🔍 recon pasivo | Google dorks de seguridad |
| `shodan_query` | 🔍 recon pasivo | Shodan API + InternetDB fallback |
| `subfinder_enum` | 🔍 recon pasivo | Subfinder + verificación HTTP (httpx) |
| ✨ `whiteintel` | 🔍 recon pasivo | Descarga credenciales filtradas (stealer logs) |
| `gobuster_dir` | ⚡ recon activo | Fuzzing de directorios (maneja wildcard 403) |
| `scan_red` | ⚡ recon activo | Nmap con clasificación de puertos críticos |
| `nuclei_scan` | 🎯 vuln scan | Nuclei con auto-detección de templates + JSON |
| `wpscan_run` | 🎯 vuln scan | WPScan con API key automática |
| ✨ `sqli_scan` | 🎯 vuln scan | Detecta **y extrae** SQLi con sqlmap (+ fallback) |
| ✨ `web_attack` | 🎯 vuln scan | Pentest web dinámico: SQLi/XSS/LFI/redirect/cmdi |
| `spider_code` | 🔬 análisis | Spider HTML/JS: secretos, creds, source maps |
| `web_code` | 🔬 análisis | Análisis profundo: framework, Firebase, endpoints |
| `ing_inversa` | 🔬 ing. inversa | RE + bypass (scripts, binarios, carpetas, KeyAuth) |
| `metasploit` | 💥 ataque | search / exploit / auxiliary / payload / scan |
| ✨ `cred_stuff` | 💥 ataque | Prueba credenciales contra el login (bueno/malo) |
| ✨ `model_advisor` | 🛠️ desarrollo | Recomienda qué modelo Ollama usar por tarea |
| ✨ `code_dev` | 🛠️ desarrollo | Desarrolla código y lo entrega en `out/<proj>/dev/` |

<sub>✨ = nuevo</sub>

</div>

---

## 🗣️ Lenguaje natural — disparadores automáticos

<div align="center">

| Escribe… | Y el agente… |
|:---------|:-------------|
| `hackea https://ejemplo.com` | ejecuta **auto-pentest** (4 fases de recon sin LLM) y pasa a explotación |
| `bypass el login de /ruta/bin` | hace **ingeniería inversa con log en vivo** y devuelve el archivo bypasseado |
| `créame un keylogger en python` | usa **code_dev** y deja el código en `out/<proyecto>/dev/` |
| `help` · `ayuda` · `?` | muestra **todo** lo que puede hacer, agrupado por categoría |

</div>

---

## ⚔️ Flujos ofensivos encadenados

<table>
<tr>
<td width="50%" valign="top">

**🕸️ Web**
```text
web_attack   → detecta vulns en vivo
   └─ sqli_scan (dump) → extrae la BD
```

**🔑 Credenciales**
```text
whiteintel   → descarga creds filtradas
   └─ cred_stuff → dice cuál sirve
```

</td>
<td width="50%" valign="top">

**🔬 Ingeniería inversa**
```text
ing_inversa <bin|script|carpeta>
   ├─ scripts  → extrae clave + copia parcheada
   ├─ ELF      → LD_PRELOAD / patch r2
   └─ KeyAuth  → shim + Frida + servidor falso
```

**🛠️ Desarrollo**
```text
model_advisor → mejor modelo
   └─ code_dev → out/<proj>/dev/
```

</td>
</tr>
</table>

---

## 🤖 Modelos recomendados

<div align="center">

| Modelo | RAM | Velocidad | Ideal para |
|:-------|:---:|:---------:|:-----------|
| `deepseek-r1:14b` | 16 GB | ★★★☆ | **Recomendado** — razonamiento técnico |
| `deepseek-r1:32b` | 32 GB | ★★★☆ | Máxima profundidad de análisis |
| `dolphin-mistral` | 8 GB | ★★★★ | Desarrollo **sin censura**, payloads, CTF |
| `qwen2.5-coder` | 16 GB | ★★★★ | Código, scripts, exploits |

</div>

> `model_advisor` inspecciona tu Ollama y te dice **cuál usar** según la tarea (sin censura para ofensivo, coder/razonamiento para código).

---

## 💻 Uso

```bash
python3 agent.py                        # picker de proyectos → wizard
python3 agent.py --model deepseek-r1:14b
python3 agent.py --session mi_auditoria  # carga sesión por nombre
python3 agent.py --list-sessions
python3 agent.py --no-wizard
```

<details>
<summary><b>⌨️  Comandos dentro del agente</b> (click para desplegar)</summary>

<br/>

| Comando | Acción |
|:--------|:-------|
| `help` / `ayuda` / `?` | Muestra todo lo que el agente puede hacer |
| `listame vulnerabilidades` / `vulns` | Extrae y lista las vulns del log (numeradas) |
| `explotar <N>` | Construye y ejecuta un PoC para la vuln N |
| `reporte` / `html` | Genera reporte HTML dark-theme + Markdown |
| `apikeys` | Estado de las API keys |
| `modelo <nombre>` | Cambia el modelo de Ollama en caliente |
| `sesiones` | Lista las sesiones guardadas |
| `sesion guardar/cargar <n>` | Guarda o reanuda una sesión |
| `cd <ruta>` | Cambia el directorio de trabajo |
| `salir` / `exit` | Guarda sesión y termina |

</details>

---

## 📁 Estructura de salida

```text
out/
└── mi_proyecto/
    ├── project_state.json              ← dominios + hallazgos (acumulado entre sesiones)
    ├── scan_cache.json                 ← cache TTL 24h por comando
    ├── session_YYYYMMDD_HHMMSS.json    ← conversación completa
    ├── session_YYYYMMDD_HHMMSS.md      ← log en tiempo real
    ├── session_*_report.html           ← dark theme con gráficos
    └── dev/                            ← 🛠️ código generado por code_dev
out_re/
└── <binario>_TS/
    ├── binfinal / <archivo>_bypass     ← 🔬 resultado del bypass
    └── run_bypass.sh                   ← wrapper de ejecución
```

---

## 🧪 Ejemplos

```text
hacker ❯ hackea https://ejemplo.com
hacker ❯ enumera subdominios de banco.com y escanea con nuclei los activos
hacker ❯ SKILL:web_attack target=https://app.ejemplo.com tests=sqli,xss,lfi
hacker ❯ SKILL:whiteintel domain=ejemplo.com
hacker ❯ SKILL:cred_stuff target=https://ejemplo.com/login domain=ejemplo.com
hacker ❯ bypass el login de /home/kali/reto/vault_bin
hacker ❯ créame un reverse shell TCP en C con reconexión
hacker ❯ listame vulnerabilidades
hacker ❯ explotar 3
hacker ❯ reporte
```

---

<div align="center">

### 🧱 Arquitectura multi-agente

Cada skill se ejecuta *inline* (rápido) y lanza un **SubAgent** en un hilo aparte, con su propio contexto de 4K, que resume el output y devuelve `{summary, key_findings, next_step}` al agente principal — **sin contaminación cruzada** y en paralelo.

```mermaid
flowchart LR
    K[Skill ejecutado] --> P[ProjectState + log]
    K --> SA[🤖 SubAgent · hilo propio]
    SA --> O[Ollama · contexto 4K]
    O --> C[resumen compacto]
    C --> M[Agente principal]
```

</div>

---

<div align="center">

## 📜 Licencia

**MIT** — para pentesting autorizado, CTFs, laboratorios y formación en ciberseguridad.

<br/>

<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=0,2,5,20,30&height=120&section=footer" width="100%"/>

<sub>Hecho para operar <b>100% local</b> · Powered by 🦙 Ollama · Úsalo con responsabilidad.</sub>

</div>
