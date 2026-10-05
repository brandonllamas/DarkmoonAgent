"""
tool_manager.py — Auto-detección e instalación de herramientas de pentesting.
Escanea el sistema, verifica cada herramienta, y si falta, la instala automáticamente
usando apt, pip, go, cargo, curl, o git según corresponda.

Usa confs.json como fuente de verdad para rutas y comandos de instalación.
"""
from __future__ import annotations

import json
import importlib.metadata
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import unicodedata
from pathlib import Path
from typing import Callable

HERE = Path(__file__).parent
CONFS_FILE = HERE / "confs.json"
REQUIREMENTS_FILE = HERE / "requirements.txt"

_DEPENDENCY_WORDS = re.compile(
    r"\b(?:dependencias?|requisitos?|herramientas?|tools?|todo\s+lo\s+necesario|"
    r"lo\s+que\s+necesit(?:e|es)|entorno\s+completo)\b",
    re.I,
)
_INSTALL_WORDS = re.compile(r"\b(?:instala(?:r|me|las?)?|instale|install|prepara(?:r)?)\b", re.I)


def is_dependency_install_request(message: str) -> bool:
    """Return True for explicit natural-language requests to install dependencies."""
    normalized = unicodedata.normalize("NFKD", str(message or ""))
    normalized = "".join(ch for ch in normalized if not unicodedata.combining(ch)).lower().strip()
    if re.search(r"\b(?:no|sin)\s+(?:instala(?:r|s)?|install)\b", normalized):
        return False
    return bool(_INSTALL_WORDS.search(normalized) and _DEPENDENCY_WORDS.search(normalized))


# ── Tool definitions with install commands ─────────────────────────────────────
# Extends confs.json with more detailed install methods
TOOL_DEFS: dict[str, dict] = {
    "curl": {
        "check": ["curl", "--version"],
        "install": {"apt": "apt-get install -y curl", "brew": "brew install curl"},
        "category": "recon",
    },
    "dig": {
        "check": ["dig", "-v"],
        "install": {"apt": "apt-get install -y dnsutils", "brew": "brew install bind"},
        "category": "recon",
    },
    "whois": {
        "check": ["whois", "--version"],
        "install": {"apt": "apt-get install -y whois", "brew": "brew install whois"},
        "category": "recon",
    },
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
        "check": [sys.executable, "-c", "import ldap3; print(ldap3.__version__)"],
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
            "apt": "apt-get install -y apktool",
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
_LAST_INSTALL_ERRORS: dict[str, str] = {}
_APT_PREFIX_CACHE: str | None = None


def set_progress_callback(cb: Callable | None):
    """Set a callback for install progress: cb(tool_name, status_msg)"""
    global _PROGRESS_CALLBACK
    _PROGRESS_CALLBACK = cb


def _log(msg: str, tool_name: str = "system"):
    if _PROGRESS_CALLBACK:
        _PROGRESS_CALLBACK(tool_name, msg)
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


def _run_args(args: list[str], timeout: int = 60) -> tuple[str, str, int]:
    """Run an argument vector without a shell (used for Python package installs)."""
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timeout ({timeout}s)", 1
    except Exception as exc:
        return "", str(exc), 1


def clear_tool_cache():
    """Forget cached checks so the next scan verifies the real environment."""
    _TOOL_CACHE.clear()


def _command_text(parts: list[str]) -> str:
    """Quote a command consistently for the current operating system."""
    return subprocess.list2cmdline([str(part) for part in parts])


def _add_go_bin_to_path():
    """Expose GOPATH/bin to this process after a successful `go install`."""
    if not shutil.which("go"):
        return
    stdout, _, code = _run("go env GOPATH", timeout=10)
    if code != 0 or not stdout.strip():
        return
    go_bin = str(Path(stdout.strip().splitlines()[-1]) / "bin")
    paths = os.environ.get("PATH", "").split(os.pathsep)
    if go_bin not in paths:
        os.environ["PATH"] = go_bin + os.pathsep + os.environ.get("PATH", "")


def _apt_prefix() -> str:
    """Return an apt command prefix that will not block waiting for a password."""
    global _APT_PREFIX_CACHE
    if _APT_PREFIX_CACHE is not None:
        return _APT_PREFIX_CACHE
    if not shutil.which("apt-get"):
        _APT_PREFIX_CACHE = ""
        return ""
    is_root = bool(hasattr(os, "geteuid") and os.geteuid() == 0)
    if is_root:
        _APT_PREFIX_CACHE = "apt-get"
        return _APT_PREFIX_CACHE
    if shutil.which("sudo"):
        _, _, code = _run("sudo -n true", timeout=8)
        if code == 0:
            _APT_PREFIX_CACHE = "sudo -n apt-get"
            return _APT_PREFIX_CACHE
    _APT_PREFIX_CACHE = ""
    return ""


def _prepare_install_command(method: str, raw_command: str) -> tuple[str, str]:
    """Adapt a declared install command to the current Python and privilege level."""
    command = str(raw_command or "").strip()
    if method == "apt":
        prefix = _apt_prefix()
        if not prefix:
            return "", "apt requiere ejecutar HackerAgent como root o sudo sin contraseña"
        command = re.sub(r"^apt-get\b", prefix, command)
    elif method == "pip":
        python = _command_text([sys.executable])
        command = re.sub(
            r"^(?:pip3?|py\s+-m\s+pip)\s+install\b",
            lambda _: f"{python} -m pip install",
            command,
        )
        command = command.replace(" -q ", " ")
        command = command.replace(
            " -m pip install ",
            " -m pip install --disable-pip-version-check ",
            1,
        )
    elif method == "curl" and os.name == "nt":
        return "", "el instalador por curl requiere un shell Unix"
    return command, ""


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

    check_cmd = [str(part) for part in td.get("check", [tool_name, "--version"])]
    binary = check_cmd[0]
    binary_is_current_python = Path(binary).resolve() == Path(sys.executable).resolve()
    found = binary_is_current_python or shutil.which(binary) is not None

    if found:
        # Verify it actually works
        so, se, code = _run(_command_text(check_cmd), timeout=10)
        if code == 0:
            _TOOL_CACHE[tool_name] = True
            return True
        # Some tools return non-zero for --version
        combined = (so or se).strip()
        if combined and "command not found" not in combined.lower() and "not recognized" not in combined.lower():
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


def get_install_candidates(tool_name: str) -> list[tuple[str, str]]:
    """Return usable install methods in priority order for the current host."""
    td = TOOL_DEFS.get(tool_name)
    if not td:
        return []

    install_methods = td.get("install", {})
    available = {
        "apt": bool(shutil.which("apt-get")),
        "brew": bool(shutil.which("brew")),
        "go": bool(shutil.which("go")),
        "pip": True,
        "gem": bool(shutil.which("gem")),
        "cargo": bool(shutil.which("cargo")),
        "winget": bool(shutil.which("winget")),
        "choco": bool(shutil.which("choco")),
        "scoop": bool(shutil.which("scoop")),
        "curl": bool(shutil.which("curl")) and os.name != "nt",
    }
    priorities = ["apt", "brew", "winget", "choco", "scoop", "go", "pip", "gem", "cargo", "curl"]
    candidates: list[tuple[str, str]] = []
    for method in priorities:
        if not available.get(method) or method not in install_methods:
            continue
        command, reason = _prepare_install_command(method, install_methods[method])
        if command:
            candidates.append((method, command))
        elif reason:
            _LAST_INSTALL_ERRORS[tool_name] = reason
    return candidates


def get_install_command(tool_name: str) -> str:
    """Get the best usable install command for compatibility with older callers."""
    candidates = get_install_candidates(tool_name)
    return candidates[0][1] if candidates else ""


def install_tool(tool_name: str, force: bool = False, progress: Callable | None = None) -> bool:
    """
    Install a tool. Returns True if successful.
    If already installed and not force, returns True immediately.
    """
    tool_name = str(tool_name or "").strip().lower()
    if not force and check_tool(tool_name):
        if progress:
            progress({"scope": "tool", "name": tool_name, "status": "already", "message": "Ya estaba instalada"})
        return True

    if tool_name in _INSTALLING:
        _log(f"{tool_name} — ya está instalándose...")
        return False

    _INSTALLING.add(tool_name)
    _TOOL_CACHE.pop(tool_name, None)

    try:
        candidates = get_install_candidates(tool_name)
        if not candidates:
            reason = _LAST_INSTALL_ERRORS.get(tool_name) or "no hay un método compatible con este sistema"
            _LAST_INSTALL_ERRORS[tool_name] = reason
            _log(f"  ⚠ {tool_name}: {reason}", tool_name)
            if progress:
                progress({"scope": "tool", "name": tool_name, "status": "unsupported", "message": reason})
            return False

        failures: list[str] = []
        for method, install_cmd in candidates:
            _log(f"  📦 Instalando {tool_name} con {method}...", tool_name)
            if progress:
                progress({"scope": "tool", "name": tool_name, "status": "installing", "method": method,
                          "message": f"Instalando con {method}"})
            stdout, stderr, code = _run(install_cmd, timeout=900)
            if method == "go":
                _add_go_bin_to_path()
            _TOOL_CACHE.pop(tool_name, None)
            verified = code == 0 and check_tool(tool_name)
            if verified:
                _LAST_INSTALL_ERRORS.pop(tool_name, None)
                _log(f"  ✅ {tool_name} instalado y verificado", tool_name)
                post = TOOL_DEFS.get(tool_name, {}).get("post_install", "")
                if post:
                    _log(f"  ⚙  Ejecutando post-install: {post}", tool_name)
                    _run(post, timeout=300)
                if progress:
                    progress({"scope": "tool", "name": tool_name, "status": "ready", "method": method,
                              "message": "Instalada y verificada"})
                return True
            detail = (stderr or stdout or f"exit {code}").strip().replace("\n", " ")[:300]
            failures.append(f"{method}: {detail}")

        reason = " | ".join(failures) or "la instalación no pudo verificarse"
        _LAST_INSTALL_ERRORS[tool_name] = reason
        _log(f"  ❌ {tool_name}: {reason[:500]}", tool_name)
        _TOOL_CACHE[tool_name] = False
        if progress:
            progress({"scope": "tool", "name": tool_name, "status": "failed", "message": reason[:300]})
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


def _requirement_names(requirements_file: Path = REQUIREMENTS_FILE) -> list[str]:
    """Extract distribution names from a regular requirements.txt file."""
    if not requirements_file.exists():
        return []
    names: list[str] = []
    for raw in requirements_file.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://")):
            continue
        match = re.match(r"([A-Za-z0-9_.-]+)", line)
        if match:
            names.append(match.group(1))
    return names


def python_dependency_status(requirements_file: Path = REQUIREMENTS_FILE) -> dict[str, bool]:
    """Check the Python distributions declared by requirements.txt."""
    status: dict[str, bool] = {}
    for name in _requirement_names(requirements_file):
        try:
            importlib.metadata.version(name)
            status[name] = True
        except importlib.metadata.PackageNotFoundError:
            status[name] = False
    return status


def install_python_dependencies(requirements_file: Path = REQUIREMENTS_FILE,
                                progress: Callable | None = None) -> dict:
    """Install and verify the application's Python runtime requirements."""
    before = python_dependency_status(requirements_file)
    missing = [name for name, ready in before.items() if not ready]
    result = {
        "total": len(before),
        "ready_before": sum(1 for ready in before.values() if ready),
        "installed": [],
        "failed": [],
        "success": True,
        "pip_check": "",
    }
    if progress:
        progress({"scope": "python", "name": "requirements.txt", "status": "installing",
                  "message": f"Verificando constraints; {len(missing)} paquete(s) faltante(s)"})
    if not requirements_file.exists():
        result.update({"failed": missing or ["requirements.txt"], "success": False})
        return result
    _, stderr, code = _run_args([
        sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
        "-r", str(requirements_file),
    ], timeout=1200)
    after = python_dependency_status(requirements_file)
    result["installed"] = [name for name in missing if after.get(name)]
    result["failed"] = [name for name in missing if not after.get(name)]
    _, pip_check_err, pip_check_code = _run_args(
        [sys.executable, "-m", "pip", "check"], timeout=120,
    )
    result["pip_check"] = pip_check_err[:500] if pip_check_code else "ok"
    result["success"] = code == 0 and not result["failed"] and pip_check_code == 0
    if progress:
        progress({
            "scope": "python", "name": "requirements.txt",
            "status": "ready" if result["success"] else "failed",
            "message": "Dependencias Python verificadas" if result["success"] else
                       (stderr or pip_check_err or "No se pudieron verificar todos los paquetes")[:300],
        })
    return result


def scan_tools(category: str | None = None, refresh: bool = False) -> dict[str, bool]:
    """
    Scan all known tools and return their installation status.
    If category is specified, only scan tools in that category.
    """
    if refresh:
        clear_tool_cache()
        _add_go_bin_to_path()
    results: dict[str, bool] = {}
    for tool_name, td in TOOL_DEFS.items():
        if category and td.get("category") != category:
            continue
        results[tool_name] = check_tool(tool_name)
    return results


def _emit_progress(callback: Callable | None, **event):
    if not callback:
        return
    try:
        callback(event)
    except Exception:
        pass


def install_all_dependencies(category: str | None = None,
                             progress: Callable | None = None) -> dict:
    """Install requirements.txt and every missing tool known by HackerAgent."""
    started = time.monotonic()
    _emit_progress(progress, scope="system", name="environment", status="scanning",
                   message="Comprobando Python y herramientas del sistema", current=0, total=1)
    before = scan_tools(category, refresh=True)
    missing = [name for name, ready in before.items() if not ready]
    total_steps = 1 + len(missing)
    _emit_progress(progress, scope="system", name="environment", status="start",
                   message=f"{len(missing)} herramienta(s) por preparar", current=0, total=total_steps)

    python_result = install_python_dependencies(progress=progress)
    _emit_progress(progress, scope="system", name="python", status="step_done",
                   message="Entorno Python comprobado", current=1, total=total_steps)

    installed: list[str] = []
    failed: list[str] = []
    unsupported: list[str] = []
    for index, tool_name in enumerate(missing, start=1):
        current = index

        def forward(event: dict, *, _current=current):
            payload = dict(event)
            payload.update({"current": _current, "total": total_steps})
            _emit_progress(progress, **payload)

        ok = install_tool(tool_name, progress=forward)
        if ok:
            installed.append(tool_name)
        else:
            reason = _LAST_INSTALL_ERRORS.get(tool_name, "instalación no verificada")
            if "no hay un método" in reason or "requiere ejecutar" in reason or "requiere un shell" in reason:
                unsupported.append(tool_name)
            else:
                failed.append(tool_name)
        _emit_progress(progress, scope="system", name=tool_name, status="step_done",
                       message=f"{tool_name}: {'lista' if ok else 'pendiente'}",
                       current=index + 1, total=total_steps)

    after = scan_tools(category, refresh=True)
    ready_after = [name for name, ready in after.items() if ready]
    still_missing = [name for name, ready in after.items() if not ready]
    # Verification is authoritative even if an installer returned an optimistic result.
    installed = [name for name in installed if after.get(name)]
    unsupported = [name for name in unsupported if name in still_missing]
    failed = [name for name in still_missing if name not in unsupported]
    error_details = {name: _LAST_INSTALL_ERRORS.get(name, "No se pudo verificar") for name in still_missing}
    report = {
        "schema_version": 1,
        "platform": {"system": platform.system(), "release": platform.release(), "python": sys.version.split()[0]},
        "success": bool(python_result.get("success")) and not still_missing,
        "duration_seconds": round(time.monotonic() - started, 2),
        "python": python_result,
        "tools": {
            "total": len(after),
            "ready_before": sum(1 for ready in before.values() if ready),
            "ready_after": len(ready_after),
            "already_ready": [name for name, ready in before.items() if ready],
            "installed": installed,
            "failed": failed,
            "unsupported": unsupported,
            "missing": still_missing,
            "errors": error_details,
        },
    }
    _emit_progress(progress, scope="system", name="environment",
                   status="complete" if report["success"] else "partial",
                   message="Instalación completa" if report["success"] else
                           f"Entorno parcial: {len(still_missing)} herramienta(s) pendiente(s)",
                   current=total_steps, total=total_steps)
    return report


def format_dependency_report(report: dict) -> str:
    """Create a concise Spanish summary suitable for CLI and chat history."""
    tools = report.get("tools", {})
    python_result = report.get("python", {})
    ready = int(tools.get("ready_after", 0))
    total = int(tools.get("total", 0))
    installed = list(tools.get("installed", []))
    missing = list(tools.get("missing", []))
    lines = [
        "✅ Entorno preparado y verificado." if report.get("success") else "⚠️ Instalación completada parcialmente.",
        f"Python: {python_result.get('total', 0) - len(python_result.get('failed', []))}/{python_result.get('total', 0)} dependencias listas.",
        f"Herramientas: {ready}/{total} disponibles.",
    ]
    if installed:
        lines.append(f"Instaladas ahora: {', '.join(installed)}.")
    if missing:
        lines.append(f"Pendientes: {', '.join(missing)}.")
        system = str(report.get("platform", {}).get("system", ""))
        if system == "Windows":
            lines.append("Las herramientas ofensivas sin instalador nativo deben ejecutarse desde Kali Linux o WSL.")
        elif any("requiere ejecutar" in str(value) for value in tools.get("errors", {}).values()):
            lines.append("Para completar paquetes del sistema, inicia HackerAgent con sudo/root y repite “instala dependencias”.")
    lines.append(f"Verificación terminada en {report.get('duration_seconds', 0)} s.")
    return "\n".join(lines)


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
