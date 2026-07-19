"""
Skill: model_advisor
Antes de desarrollar: recomienda el modelo de Ollama adecuado para la tarea Y
prepara el TOOLCHAIN del lenguaje elegido (instala compiladores, gestores de
paquetes, linters y formateadores). Para Python deja listo pipenv + herramientas
de buenas prácticas (black, flake8, pylint, mypy, isort, bandit, pytest).

Para desarrollo OFENSIVO conviene un modelo sin censura (dolphin*, *-uncensored);
para código general conviene un modelo "coder" o de razonamiento.
"""
import os
from skills.llm_client import available_models
import re
import shutil
import subprocess

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

META = {
    "name": "model_advisor",
    "category": "desarrollo",
    "description": (
        "Recomienda el modelo Ollama por tarea y PREPARA el toolchain del lenguaje "
        "(instala compiladores, linters, formateadores). Para Python deja pipenv + "
        "black/flake8/pylint/mypy/isort/bandit/pytest listos para código con buenas prácticas."
    ),
    "args": ["kind", "language", "setup"],
    "example": "SKILL:model_advisor kind=pentest language=python setup=true",
}

# ── Clasificación de modelos ──────────────────────────────────────────────────
_MODEL_TAGS = {
    "uncensored": ["dolphin", "uncensored", "wizard-vicuna", "nous-hermes", "hermes",
                   "mytho", "tiger", "abliterated", "abliter", "dark", "neural-chat",
                   "openhermes", "wizardlm"],
    "coder":      ["coder", "codellama", "code-llama", "codestral", "starcoder",
                   "granite-code", "deepseek-coder", "codeqwen", "qwen2.5-coder",
                   "stable-code", "codegemma", "magicoder", "wizardcoder"],
    "reasoning":  ["deepseek-r1", "-r1", "qwq", "marco-o1", "o1-", "reflection"],
    "general":    ["llama", "mistral", "mixtral", "qwen", "gemma", "phi", "yi",
                   "command-r", "solar", "vicuna", "orca"],
}

_OFFENSIVE_KINDS = {
    "malware", "c2", "payload", "persistence", "rootkit", "stealer", "keylogger",
    "ransomware", "evasion", "shellcode", "dropper", "loader", "rat", "backdoor",
    "obfuscation", "amsi", "edr",
}

# ── Toolchains por lenguaje ───────────────────────────────────────────────────
# check: binarios que indican que ya está listo | apt/pip: paquetes a instalar
_TOOLCHAINS = {
    "python": {
        "check": ["python3", "pip3"],
        "apt":   ["python3", "python3-pip", "python3-venv", "pipx"],
        "pip":   ["pipenv", "black", "flake8", "pylint", "mypy", "isort",
                  "bandit", "pytest", "autopep8"],
        "note":  "pipenv + linters/formateadores + bandit (SAST) para código con buenas prácticas",
    },
    "c":    {"check": ["gcc", "make"], "apt": ["build-essential", "clang", "cppcheck", "gdb", "valgrind"], "pip": []},
    "cpp":  {"check": ["g++", "make"], "apt": ["build-essential", "clang", "clang-tidy", "cppcheck", "gdb"], "pip": []},
    "go":   {"check": ["go"],   "apt": ["golang-go"],                 "pip": []},
    "rust": {"check": ["cargo"], "apt": [],                            "pip": [],
             "post": ["command -v cargo >/dev/null || (curl -sSf https://sh.rustup.rs | sh -s -- -y)"]},
    "bash": {"check": ["bash", "shellcheck"], "apt": ["shellcheck", "shfmt"], "pip": []},
    "powershell": {"check": ["pwsh"], "apt": ["powershell"], "pip": []},
    "ruby": {"check": ["ruby", "gem"], "apt": ["ruby", "ruby-dev"], "pip": [], "post": ["gem install rubocop 2>/dev/null || true"]},
    "php":  {"check": ["php"], "apt": ["php-cli", "composer"], "pip": []},
    "node": {"check": ["node", "npm"], "apt": ["nodejs", "npm"], "pip": [],
             "post": ["npm install -g eslint prettier 2>/dev/null || true"]},
    "java": {"check": ["javac"], "apt": ["default-jdk", "maven"], "pip": []},
}

_LANG_ALIAS = {
    "py": "python", "python3": "python", "c++": "cpp", "cxx": "cpp", "cc": "cpp",
    "golang": "go", "rs": "rust", "sh": "bash", "shell": "bash", "zsh": "bash",
    "ps1": "powershell", "pwsh": "powershell", "js": "node", "javascript": "node",
    "nodejs": "node", "rb": "ruby",
}


def _classify(name: str) -> list:
    n = name.lower()
    cats = [cat for cat, kws in _MODEL_TAGS.items() if any(k in n for k in kws)]
    return cats or ["general"]


def _size_b(name: str) -> float:
    m = re.search(r'(\d+(?:\.\d+)?)\s*[bB]\b', name)
    return float(m.group(1)) if m else 0.0


def list_ollama_models() -> tuple:
    # Kept under the historical name for callers, but now returns whichever
    # configured backend is active (Ollama, DeepSeek or LM Studio).
    backend, shared_models = available_models()
    if shared_models:
        return shared_models, backend
    if requests is None:
        return [], "módulo 'requests' no disponible"
    base = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")
    tags_url = base.split("/api/")[0] + "/api/tags"
    try:
        r = requests.get(tags_url, timeout=10)
        r.raise_for_status()
        return [m["name"] for m in r.json().get("models", [])], ""
    except Exception as e:
        return [], str(e)


def recommend(available: list, kind: str) -> list:
    offensive = kind.lower() in _OFFENSIVE_KINDS
    scored = []
    for mdl in available:
        cats = _classify(mdl)
        size = _size_b(mdl)
        score, reasons = 0.0, []
        if offensive:
            if "uncensored" in cats:
                score += 100; reasons.append("sin censura (no rechaza tareas ofensivas)")
            if "coder" in cats:
                score += 45; reasons.append("especializado en código")
            if "reasoning" in cats:
                score += 25; reasons.append("buen razonamiento")
        else:
            if "coder" in cats:
                score += 100; reasons.append("especializado en código")
            if "reasoning" in cats:
                score += 65; reasons.append("razonamiento profundo")
            if "uncensored" in cats:
                score += 30; reasons.append("sin censura")
        if "general" in cats and not reasons:
            reasons.append("propósito general")
        score += min(size, 70)
        if size:
            reasons.append(f"{size:g}B")
        scored.append({"model": mdl, "score": round(score, 1),
                       "cats": cats, "size": size, "reasons": reasons})
    scored.sort(key=lambda x: -x["score"])
    return scored


# ── Toolchain ─────────────────────────────────────────────────────────────────
def _lang_key(language: str) -> str:
    l = (language or "").strip().lower()
    return _LANG_ALIAS.get(l, l)


def _sh(cmd: str, tout: int = 600) -> tuple:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=tout)
        return ((r.stdout or "") + (r.stderr or "")).strip(), r.returncode
    except Exception as e:
        return str(e), 1


def check_toolchain(language: str) -> dict:
    key = _lang_key(language)
    tc = _TOOLCHAINS.get(key)
    if not tc:
        return {}
    present = [c for c in tc["check"] if shutil.which(c)]
    missing = [c for c in tc["check"] if not shutil.which(c)]
    return {"key": key, "present": present, "missing": missing, "tc": tc}


def install_toolchain(language: str) -> tuple:
    """Instala el toolchain del lenguaje. Retorna (log:list[(paso,code,out)], error)."""
    info = check_toolchain(language)
    if not info:
        return [], f"lenguaje '{language}' no soportado (usa: {', '.join(_TOOLCHAINS)})"
    tc = info["tc"]
    is_root = getattr(os, "geteuid", lambda: 1)() == 0
    sudo = "" if is_root else "sudo -n "
    log = []
    if tc.get("apt"):
        _sh(f"{sudo}apt-get update -y", 300)
        out, code = _sh(f"{sudo}DEBIAN_FRONTEND=noninteractive apt-get install -y {' '.join(tc['apt'])}", 900)
        log.append(("apt", code, out[-500:]))
    if tc.get("pip"):
        out, code = _sh(f"pip3 install --upgrade {' '.join(tc['pip'])} 2>&1 || "
                        f"pipx install {' '.join(tc['pip'][:1])} 2>&1", 900)
        log.append(("pip", code, out[-500:]))
    for post in tc.get("post", []):
        out, code = _sh(post, 900)
        log.append((post[:40], code, out[-300:]))
    return log, ""


def run(kind: str = "pentest", language: str = "", setup: str = "true", **kwargs) -> dict:
    kind = (kind or "pentest").strip().lower()
    language = (language or kwargs.get("lang") or "").strip()
    do_setup = str(setup).lower() in ("1", "true", "yes", "si", "sí", "y")
    offensive = kind in _OFFENSIVE_KINDS
    available, err = list_ollama_models()

    lines = [
        "╔═══ MODEL ADVISOR — modelo + toolchain de desarrollo ══╗",
        f"  Tarea    : {kind}   ({'OFENSIVA → sin censura' if offensive else 'código → coder/razonamiento'})",
        f"  Lenguaje : {language or '(no indicado)'}",
        "╚═══════════════════════════════════════════════════════╝",
        "",
    ]
    findings = []

    # ── 1. Recomendación de modelo ────────────────────────────────────────────
    recommended = ""
    if err or not available:
        lines.append(f"  ⚠ No pude listar modelos de Ollama: {err or 'sin modelos'}")
        lines.append(f"    Sugerencia: ollama pull {'dolphin-mixtral' if offensive else 'qwen2.5-coder:7b'}")
    else:
        ranked = recommend(available, kind)
        recommended = ranked[0]["model"] if ranked else ""
        lines.append(f"▶ MODELO — {len(available)} instalados. Recomendado: {recommended}")
        for i, r in enumerate(ranked[:5], 1):
            mark = "⭐" if i == 1 else f" {i}."
            lines.append(f"    {mark} {r['model']:<30} [{', '.join(r['reasons'])}]")
        if offensive and not any("uncensored" in r["cats"] for r in ranked):
            lines.append("    ⚠ Sin modelo SIN CENSURA → puede rechazar lo ofensivo. "
                         "ollama pull dolphin-mixtral")
            findings.append({"type": "model_warning", "severity": "medium",
                             "value": "sin modelo uncensored",
                             "description": "No hay modelo sin censura para tareas ofensivas"})
        if recommended:
            findings.append({"type": "model_recommendation", "severity": "info",
                             "value": recommended,
                             "description": f"Modelo recomendado para '{kind}': {recommended}"})

    # ── 2. Toolchain del lenguaje ─────────────────────────────────────────────
    toolchain_ready = None
    if not language:
        lines.append("\n▶ TOOLCHAIN — indica el lenguaje para prepararlo.")
        lines.append(f"    Soportados: {', '.join(_TOOLCHAINS)}")
        lines.append("    Ej: SKILL:model_advisor kind=pentest language=python setup=true")
    else:
        info = check_toolchain(language)
        if not info:
            lines.append(f"\n▶ TOOLCHAIN — lenguaje '{language}' no soportado para setup automático.")
            lines.append(f"    Soportados: {', '.join(_TOOLCHAINS)}")
        else:
            key = info["key"]
            lines.append(f"\n▶ TOOLCHAIN [{key}] — presentes: {info['present'] or '—'} · "
                         f"faltan: {info['missing'] or 'ninguno'}")
            if info["tc"].get("note"):
                lines.append(f"    ({info['tc']['note']})")
            if info["missing"] and do_setup:
                lines.append("    Instalando herramientas… (apt/pip, puede tardar)")
                log, ierr = install_toolchain(language)
                if ierr:
                    lines.append(f"    ✗ {ierr}")
                for step, code, out in log:
                    lines.append(f"      [{step}] {'✓' if code == 0 else '✗ (revisar)'}")
                info2 = check_toolchain(language)
                toolchain_ready = not info2["missing"]
                lines.append(f"    → toolchain {'✅ listo' if toolchain_ready else '⚠ incompleto (revisa permisos/root/red)'}")
            elif info["missing"] and not do_setup:
                lines.append("    setup=false → no instalo nada. Usa setup=true para instalar.")
            else:
                toolchain_ready = True
                lines.append("    ✅ toolchain ya listo")

            findings.append({
                "type": "toolchain", "severity": "info", "value": key,
                "description": f"Toolchain {key}: {'listo' if toolchain_ready else 'requiere instalación'}",
            })
            if key == "python":
                lines.append("    Python: se usará pipenv + black/flake8/mypy/bandit en el código (code_dev).")

    lines.append(f"\n  ▶ Siguiente paso:")
    lines.append(f"     SKILL:code_dev request=\"...\" kind={kind}"
                 + (f" language={language}" if language else "")
                 + (f" model={recommended}" if recommended else ""))

    return {
        "success": True,
        "output": "\n".join(lines),
        "findings": findings,
        "recommended_model": recommended,
        "language": _lang_key(language) if language else "",
        "toolchain_ready": toolchain_ready,
    }
