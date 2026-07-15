"""
tool_manager.py — Auto-detección e instalación de herramientas de pentesting.
Escanea el sistema, verifica cada herramienta, y si falta, la instala automáticamente
usando apt, pip, go, cargo, curl, o git según corresponda.

Usa confs.json como fuente de verdad para rutas y comandos de instalación.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

HERE = Path(__file__).parent
CONFS_FILE = HERE / "confs.json"


# ── Tool definitions with install commands ─────────────────────────────────────
# Extends confs.json with more detailed install methods
TOOL_DEFS: dict[str, dict] = {
    "nmap": {
        "check": ["nmap", "--version"],
        "install": {
            "apt": "apt-get install -y nmap",
            "brew": "brew install nmap",
        },
        "min_version": "7.0",
        "category": "recon",
    },
    "gobuster": {
        "check": ["gobuster", "--version"],
        "install": {
            "apt": "apt-get install -y gobuster",
            "brew": "brew install gobuster",
            "go": "go install github.com/OJ/gobuster/v3@latest",
        },
        "category": "web",
    },
    "ffuf": {
        "check": ["ffuf", "-V"],
        "install": {
            "apt": "apt-get install -y ffuf",
            "brew": "brew install ffuf",
            "go": "go install github.com/ffuf/ffuf/v2@latest",
        },
        "category": "web",
    },
    "wfuzz": {
        "check": ["wfuzz", "--version"],
        "install": {
            "apt": "apt-get install -y wfuzz",
            "pip": "pip3 install wfuzz",
        },
        "category": "web",
    },
    "feroxbuster": {
        "check": ["feroxbuster", "--version"],
        "install": {
            "apt": "apt-get install -y feroxbuster",
            "curl": "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash",
        },
        "category": "web",
    },
    "dirsearch": {
        "check": ["dirsearch", "--version"],
        "install": {
            "apt": "apt-get install -y dirsearch",
            "pip": "pip3 install dirsearch",
        },
        "category": "web",
    },
    "nuclei": {
        "check": ["nuclei", "-version"],
        "install": {
            "apt": "apt-get install -y nuclei",
            "go": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "brew": "brew install nuclei",
        },
        "min_version": "3.0",
        "category": "vuln",
        "post_install": "nuclei -update-templates",
    },
    "subfinder": {
        "check": ["subfinder", "-version"],
        "install": {
            "apt": "apt-get install -y subfinder",
            "go": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "brew": "brew install subfinder",
        },
        "category": "recon",
    },
    "httpx": {
        "check": ["httpx", "-version"],
        "install": {
            "apt": "apt-get install -y httpx",
            "go": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        },
        "category": "recon",
    },
    "amass": {
        "check": ["amass", "-version"],
        "install": {
            "apt": "apt-get install -y amass",
            "go": "go install github.com/owasp-amass/amass/v4/...@master",
            "brew": "brew install amass",
        },
        "category": "recon",
    },
    "whatweb": {
        "check": ["whatweb", "--version"],
        "install": {"apt": "apt-get install -y whatweb"},
        "category": "recon",
    },
    "wafw00f": {
        "check": ["wafw00f", "--version"],
        "install": {
            "apt": "apt-get install -y wafw00f",
            "pip": "pip3 install wafw00f",
        },
        "category": "recon",
    },
    "wpscan": {
        "check": ["wpscan", "--version"],
        "install": {
            "apt": "apt-get install -y wpscan",
            "gem": "gem install wpscan",
            "brew": "brew install wpscan",
        },
        "category": "cms",
    },
    "sqlmap": {
        "check": ["sqlmap", "--version"],
        "install": {
            "apt": "apt-get install -y sqlmap",
            "pip": "pip3 install sqlmap",
            "brew": "brew install sqlmap",
        },
        "category": "web",
    },
    "searchsploit": {
        "check": ["searchsploit", "--version"],
        "install": {
            "apt": "apt-get install -y exploitdb",
        },
        "binary_name": "searchsploit",
        "category": "vuln",
    },
    "msfconsole": {
        "check": ["msfconsole", "--version"],
        "install": {
            "curl": "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && chmod +x /tmp/msfinstall && /tmp/msfinstall",
            "apt": "apt-get install -y metasploit-framework",
        },
        "category": "exploit",
    },
    "nikto": {
        "check": ["nikto", "-Version"],
        "install": {
            "apt": "apt-get install -y nikto",
            "brew": "brew install nikto",
        },
        "category": "vuln",
    },
    "hydra": {
        "check": ["hydra", "--version"],
        "install": {
            "apt": "apt-get install -y hydra",
            "brew": "brew install hydra",
        },
        "category": "attack",
    },
    "john": {
        "check": ["john", "--version"],
        "install": {
            "apt": "apt-get install -y john",
            "brew": "brew install john",
        },
        "category": "attack",
    },
    "enum4linux": {
        "check": ["enum4linux", "--version"],
        "install": {
            "apt": "apt-get install -y enum4linux",
        },
        "category": "ad",
    },
    "crackmapexec": {
        "check": ["crackmapexec", "--version"],
        "install": {
            "apt": "apt-get install -y crackmapexec",
            "pip": "pip3 install crackmapexec",
        },
        "category": "ad",
    },
    "netexec": {
        "check": ["netexec", "--version"],
        "install": {
            "pip": "pip3 install netexec",
        },
        "category": "ad",
    },
    "theharvester": {
        "check": ["theharvester", "--version"],
        "install": {
            "apt": "apt-get install -y theharvester",
            "pip": "pip3 install theharvester",
        },
        "category": "osint",
    },
    "dnsrecon": {
        "check": ["dnsrecon", "--version"],
        "install": {
            "apt": "apt-get install -y dnsrecon",
            "pip": "pip3 install dnsrecon",
        },
        "category": "osint",
    },
    "dnsx": {
        "check": ["dnsx", "-version"],
        "install": {
            "apt": "apt-get install -y dnsx",
            "go": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        },
        "category": "osint",
    },
    "sherlock": {
        "check": ["sherlock", "--version"],
        "install": {
            "pip": "pip3 install sherlock",
        },
        "binary_name": "sherlock",
        "category": "osint",
    },
    "holehe": {
        "check": ["holehe", "--version"],
        "install": {
            "pip": "pip3 install holehe",
        },
        "category": "osint",
    },
    "metagoofil": {
        "check": ["metagoofil", "--version"],
        "install": {
            "apt": "apt-get install -y metagoofil",
            "pip": "pip3 install metagoofil",
        },
        "category": "osint",
    },
    "exiftool": {
        "check": ["exiftool", "-ver"],
        "install": {
            "apt": "apt-get install -y exiftool",
            "brew": "brew install exiftool",
        },
        "category": "osint",
    },
    "phoneinfoga": {
        "check": ["phoneinfoga", "--version"],
        "install": {
            "go": "go install github.com/sundowndev/phoneinfoga/v2@latest",
            "curl": "curl -sL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install | bash",
        },
        "category": "osint",
        "binary_name": "phoneinfoga",
    },
    "sherlock_project": {
        "check": ["sherlock", "--version"],
        "install": {
            "pip": "pip3 install sherlock-project",
        },
        "binary_name": "sherlock",
        "category": "osint",
    },
    "maigret": {
        "check": ["maigret", "--version"],
        "install": {
            "pip": "pip3 install maigret",
        },
        "category": "osint",
    },
    # ── Python dependencies for skills ──────────────────────────────────────
    "ldap3": {
        "check": ["python3", "-c", "import ldap3; print(ldap3.__version__)"],
        "install": {"pip": "pip3 install ldap3"},
        "category": "ad",
    },
    "frida": {
        "check": ["frida", "--version"],
        "install": {
            "pip": "pip3 install frida-tools",
            "apt": "apt-get install -y frida-tools",
        },
        "category": "mobile",
    },
    "jadx": {
        "check": ["jadx", "--version"],
        "install": {
            "apt": "apt-get install -y jadx",
        },
        "category": "mobile",
    },
    "apktool": {
        "check": ["apktool", "--version"],
        "install": {
            "apt": "apt-get install -x apktool",
        },
        "category": "mobile",
    },
    "radare2": {
        "check": ["r2", "--version"],
        "install": {
            "apt": "apt-get install -y radare2",
            "brew": "brew install radare2",
        },
        "category": "re",
    },
}


# ── Cache de estado de herramientas ────────────────────────────────────────────
_TOOL_CACHE: dict[str, bool] = {}
_INSTALLING: set[str] = set()
_PROGRESS_CALLBACK: Callable | None = None


def set_progress_callback(cb: Callable | None):
    """Set a callback for install progress: cb(tool_name, status_msg)"""
    global _PROGRESS_CALLBACK
    _PROGRESS_CALLBACK = cb


def _log(msg: str):
    if _PROGRESS_CALLBACK:
        _PROGRESS_CALLBACK("system", msg)
    print(f"  [tool_manager] {msg}")


def _run(cmd: str, timeout: int = 60) -> tuple[str, str, int]:
    """Run a shell command and return (stdout, stderr, code)."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timeout ({timeout}s)", 1
    except Exception as e:
        return "", str(e), 1


def check_tool(tool_name: str) -> bool:
    """Check if a tool is installed and working. Returns bool."""
    if tool_name in _TOOL_CACHE:
        return _TOOL_CACHE[tool_name]

    confs = _load_confs()
    # Check confs.json first for custom paths
    for t in confs:
        if t.get("name", "").lower() == tool_name.lower():
            cmd = t.get("command", "").strip()
            if cmd and shutil.which(cmd.split()[0]):
                _TOOL_CACHE[tool_name] = True
                return True

    # Check tool defs
    td = TOOL_DEFS.get(tool_name)
    if not td:
        # Try shutil.which directly
        found = shutil.which(tool_name) is not None
        _TOOL_CACHE[tool_name] = found
        return found

    check_cmd = td.get("check", [tool_name, "--version"])
    binary = check_cmd[0]
    found = shutil.which(binary) is not None

    if found:
        # Verify it actually works
        so, _, code = _run(" ".join(check_cmd), timeout=10)
        if code == 0 and so:
            _TOOL_CACHE[tool_name] = True
            return True
        # Some tools return non-zero for --version
        if so and not so.startswith("command not found"):
            _TOOL_CACHE[tool_name] = True
            return True

    _TOOL_CACHE[tool_name] = False
    return False


def _load_confs() -> list:
    """Load tool configs from confs.json."""
    if not CONFS_FILE.exists():
        return []
    try:
        data = json.loads(CONFS_FILE.read_text(encoding="utf-8"))
        return data.get("tools", [])
    except Exception:
        return []


def get_install_command(tool_name: str) -> str:
    """Get the best install command for a tool based on available package managers."""
    td = TOOL_DEFS.get(tool_name)
    if not td:
        return ""

    install_methods = td.get("install", {})

    # Priority order of install methods
    priorities = []
    if shutil.which("apt-get"):
        priorities.append("apt")
    if shutil.which("brew"):
        priorities.append("brew")
    if shutil.which("go"):
        priorities.append("go")
    if shutil.which("pip3") or shutil.which("pip"):
        priorities.append("pip")
    if shutil.which("gem"):
        priorities.append("gem")
    if shutil.which("cargo"):
        priorities.append("cargo")

    # Always try curl as last resort
    priorities.append("curl")

    for method in priorities:
        if method in install_methods:
            return install_methods[method]

    # Fallback: return the first available method
    for method in ["apt", "brew", "pip", "go", "curl", "gem"]:
        if method in install_methods:
            return install_methods[method]

    return ""


def install_tool(tool_name: str, force: bool = False) -> bool:
    """
    Install a tool. Returns True if successful.
    If already installed and not force, returns True immediately.
    """
    if not force and check_tool(tool_name):
        return True

    if tool_name in _INSTALLING:
        _log(f"{tool_name} — ya está instalándose...")
        return False

    _INSTALLING.add(tool_name)
    _TOOL_CACHE.pop(tool_name, None)

    try:
        install_cmd = get_install_command(tool_name)
        if not install_cmd:
            _log(f"  ⚠ {tool_name}: no se encontró método de instalación")
            return False

        _log(f"  📦 Instalando {tool_name}...")

        # If it's a pip install, use --quiet
        if install_cmd.startswith("pip"):
            install_cmd = install_cmd.replace("pip3 install", "pip3 install -q --disable-pip-version-check")
            install_cmd = install_cmd.replace("pip install", "pip install -q --disable-pip-version-check")

        if install_cmd.startswith("go install"):
            # Go installs to GOPATH/bin, add to PATH
            install_cmd = f"export PATH=$PATH:$(go env GOPATH)/bin && {install_cmd}"

        stdout, stderr, code = _run(install_cmd, timeout=300)

        if code == 0:
            _log(f"  ✅ {tool_name} instalado correctamente")
            _TOOL_CACHE[tool_name] = True

            # Post-install steps (e.g., nuclei -update-templates)
            post = TOOL_DEFS.get(tool_name, {}).get("post_install", "")
            if post:
                _log(f"  ⚙  Ejecutando post-install: {post}")
                _run(post, timeout=120)

            return True
        else:
            _log(f"  ❌ {tool_name}: error de instalación:\n    {stderr[:500]}")
            _TOOL_CACHE[tool_name] = False
            return False
    except Exception as e:
        _log(f"  ❌ {tool_name}: excepción: {e}")
        _TOOL_CACHE[tool_name] = False
        return False
    finally:
        _INSTALLING.discard(tool_name)


def ensure_tools(tools: list[str], auto_install: bool = True) -> dict[str, bool]:
    """
    Ensure a list of tools are installed.
    Returns dict of {tool_name: installed_ok}.
    """
    results: dict[str, bool] = {}
    for tool in tools:
        ok = check_tool(tool)
        if not ok and auto_install:
            ok = install_tool(tool)
        results[tool] = ok
    return results


def ensure_python_package(package: str, import_name: str | None = None) -> bool:
    """Ensure a Python package is installed. Import name defaults to package name."""
    imp = import_name or package
    try:
        __import__(imp)
        return True
    except ImportError:
        pass

    _log(f"  📦 Instalando paquete Python: {package}...")
    cmd = f"{sys.executable} -m pip install -q --disable-pip-version-check {package}"
    _, _, code = _run(cmd, timeout=120)
    if code == 0:
        _log(f"  ✅ {package} instalado")
        return True
    _log(f"  ❌ {package}: error de instalación")
    return False


def scan_tools(category: str | None = None) -> dict[str, bool]:
    """
    Scan all known tools and return their installation status.
    If category is specified, only scan tools in that category.
    """
    results: dict[str, bool] = {}
    for tool_name, td in TOOL_DEFS.items():
        if category and td.get("category") != category:
            continue
        results[tool_name] = check_tool(tool_name)
    return results


def get_tool_status_table(category: str | None = None) -> str:
    """Get a formatted table of tool installation status."""
    results = scan_tools(category)

    if not results:
        return "  (sin herramientas definidas)"

    # ANSI colors
    R = "\033[0m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    DIM = "\033[2m"
    BOLD = "\033[1m"

    # Group by category
    by_cat: dict[str, list[tuple[str, bool]]] = {}
    for tool_name, ok in results.items():
        td = TOOL_DEFS.get(tool_name, {})
        cat = td.get("category", "other")
        by_cat.setdefault(cat, []).append((tool_name, ok))

    lines = [
        f"{BOLD}{'╔══ TOOL STATUS ═══════════════════════════════════╗'}{R}",
    ]

    CAT_LABELS = {
        "recon": "🔍 RECONOCIMIENTO",
        "web": "🌐 WEB / FUZZING",
        "vuln": "🎯 VULNERABILIDADES",
        "cms": "📝 CMS",
        "exploit": "💥 EXPLOIT",
        "attack": "⚔ ATAQUE",
        "ad": "🏢 ACTIVE DIRECTORY",
        "osint": "🕵 OSINT",
        "mobile": "📱 MÓVIL",
        "re": "🔬 ING. INVERSA",
        "other": "⚙ OTROS",
    }

    for cat in ["recon", "web", "vuln", "cms", "exploit", "attack", "ad", "osint", "mobile", "re", "other"]:
        items = by_cat.get(cat, [])
        if not items:
            continue
        label = CAT_LABELS.get(cat, cat.upper())
        lines.append(f"  {CYAN}{label}{R}")
        for name, ok in sorted(items):
            icon = f"{GREEN}✓{R}" if ok else f"{RED}✗{R}"
            lines.append(f"    {icon} {name}")
        lines.append("")

    lines.append(f"{BOLD}{'╚════════════════════════════════════════════╝'}{R}")
    return "\n".join(lines)


def install_missing_tools(category: str | None = None,
                           interactive: bool = False) -> dict[str, bool]:
    """Install all missing tools. Optionally filter by category."""
    results = scan_tools(category)
    missing = [name for name, ok in results.items() if not ok]

    if not missing:
        _log("  ✅ Todas las herramientas están instaladas")
        return {}

    _log(f"  📦 Herramientas faltantes ({len(missing)}): {', '.join(missing)}")
    installed: dict[str, bool] = {}

    for tool_name in missing:
        if interactive:
            ans = input(f"  ¿Instalar {tool_name}? [s/N]: ").strip().lower()
            if ans not in ("s", "si", "sí", "y", "yes"):
                continue
        ok = install_tool(tool_name)
        installed[tool_name] = ok

    return installed


def update_all_tools() -> dict[str, bool]:
    """Update nuclei templates and other updatable tools."""
    results: dict[str, bool] = {}

    # Update nuclei templates
    if check_tool("nuclei"):
        _log("  ⚙  Actualizando nuclei-templates...")
        so, se, code = _run("nuclei -update-templates", timeout=120)
        results["nuclei-templates"] = code == 0
        if code == 0:
            _log("  ✅ nuclei-templates actualizados")
        else:
            _log(f"  ⚠ nuclei-templates: {se[:200]}")

    return results


def get_tool_install_report() -> str:
    """Generate a full HTML report of tool status."""
    results = scan_tools()
    installed = sum(1 for v in results.values() if v)
    total = len(results)

    CAT_ICONS = {
        "recon": "🔍", "web": "🌐", "vuln": "🎯", "cms": "📝",
        "exploit": "💥", "attack": "⚔", "ad": "🏢",
        "osint": "🕵", "mobile": "📱", "re": "🔬", "other": "⚙",
    }

    by_cat: dict[str, list[tuple[str, bool]]] = {}
    for tool_name, ok in results.items():
        td = TOOL_DEFS.get(tool_name, {})
        cat = td.get("category", "other")
        by_cat.setdefault(cat, []).append((tool_name, ok))

    lines = [
        "<div class='tool-report'>",
        f"<h3>🔧 Estado de Herramientas ({installed}/{total})</h3>",
        "<div class='tool-grid'>",
    ]

    for cat in ["recon", "web", "vuln", "cms", "exploit", "attack", "ad", "osint", "mobile", "re", "other"]:
        items = by_cat.get(cat, [])
        if not items:
            continue
        icon = CAT_ICONS.get(cat, "⚙")
        lines.append(f"<div class='tool-cat'><div class='tool-cat-label'>{icon} {cat.upper()}</div>")
        for name, ok in sorted(items):
            status_icon = "✅" if ok else "❌"
            cls = "tool-ok" if ok else "tool-missing"
            lines.append(f"<span class='tool-item {cls}'>{status_icon} {name}</span>")
        lines.append("</div>")

    lines.append("</div></div>")
    return "\n".join(lines)
