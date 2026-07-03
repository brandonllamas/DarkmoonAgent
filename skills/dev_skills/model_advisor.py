"""
Skill: model_advisor
Consulta los modelos instalados en Ollama y recomienda cuál usar según el tipo
de tarea de desarrollo (código de pentesting, malware/ofensivo, exploits, etc.).

Para desarrollo OFENSIVO conviene un modelo sin censura (dolphin*, *-uncensored,
*-abliterated); para código general de pentesting conviene un modelo "coder" o de
razonamiento. El skill puntúa los modelos disponibles y sugiere el mejor + alternativas.
"""
import os
import re

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

META = {
    "name": "model_advisor",
    "category": "desarrollo",
    "description": (
        "Lista los modelos de Ollama instalados y recomienda cuál usar para desarrollar "
        "(código de pentesting, malware/ofensivo, exploits). Sugiere modelos sin censura "
        "para tareas ofensivas y modelos coder/razonamiento para código general."
    ),
    "args": ["kind"],
    "example": "SKILL:model_advisor kind=malware",
}

# Palabras clave para clasificar los modelos por familia
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

# Tipos de tarea considerados "ofensivos" (modelos censurados suelen rechazarlos)
_OFFENSIVE_KINDS = {
    "malware", "c2", "payload", "persistence", "rootkit", "stealer", "keylogger",
    "ransomware", "evasion", "shellcode", "dropper", "loader", "rat", "backdoor",
    "obfuscation", "amsi", "edr",
}


def _classify(name: str) -> list:
    n = name.lower()
    cats = [cat for cat, kws in _MODEL_TAGS.items() if any(k in n for k in kws)]
    return cats or ["general"]


def _size_b(name: str) -> float:
    m = re.search(r'(\d+(?:\.\d+)?)\s*[bB]\b', name)
    return float(m.group(1)) if m else 0.0


def list_ollama_models() -> tuple:
    """Retorna (modelos:list[str], error:str)."""
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
    """Puntúa y ordena los modelos disponibles para el tipo de tarea. Retorna lista de dicts."""
    offensive = kind.lower() in _OFFENSIVE_KINDS
    scored = []
    for mdl in available:
        cats = _classify(mdl)
        size = _size_b(mdl)
        score = 0.0
        reasons = []
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
        score += min(size, 70)  # a mayor tamaño, mejor calidad (con tope)
        if size:
            reasons.append(f"{size:g}B")
        scored.append({"model": mdl, "score": round(score, 1),
                       "cats": cats, "size": size, "reasons": reasons})
    scored.sort(key=lambda x: -x["score"])
    return scored


def run(kind: str = "pentest", **kwargs) -> dict:
    kind = (kind or "pentest").strip().lower()
    offensive = kind in _OFFENSIVE_KINDS
    available, err = list_ollama_models()

    lines = [
        "╔═══ MODEL ADVISOR — recomendación de modelo Ollama ════╗",
        f"  Tarea   : {kind}   ({'OFENSIVA → prioriza sin censura' if offensive else 'código → prioriza coder/razonamiento'})",
        "╚═══════════════════════════════════════════════════════╝",
        "",
    ]
    findings = []

    if err or not available:
        lines.append(f"  ✗ No pude listar modelos de Ollama: {err or 'sin modelos'}")
        lines.append("  Verifica OLLAMA_URL en .env y que Ollama esté corriendo (ollama serve).")
        # sugerencias de instalación
        pull = ("dolphin-mixtral" if offensive else "qwen2.5-coder:7b")
        lines.append(f"\n  Sugerencia: instala un modelo adecuado →  ollama pull {pull}")
        return {"success": False, "output": "\n".join(lines), "findings": findings}

    ranked = recommend(available, kind)
    lines.append(f"  Modelos instalados: {len(available)}")
    lines.append("\n  RANKING PARA ESTA TAREA:")
    for i, r in enumerate(ranked[:8], 1):
        mark = "⭐" if i == 1 else f"{i}."
        lines.append(f"    {mark} {r['model']:<32} [{', '.join(r['reasons'])}]")

    best = ranked[0]
    lines.append(f"\n  ✅ RECOMENDADO: {best['model']}")
    if len(ranked) > 1:
        lines.append(f"     Alternativas: {', '.join(r['model'] for r in ranked[1:3])}")

    # advertencia si es ofensivo y no hay modelo sin censura
    has_uncensored = any("uncensored" in r["cats"] for r in ranked)
    if offensive and not has_uncensored:
        lines.append("\n  ⚠ No hay ningún modelo SIN CENSURA instalado. Un modelo censurado")
        lines.append("    puede rechazar el desarrollo ofensivo. Instala uno con:")
        lines.append("      ollama pull dolphin-mixtral   (o dolphin-mistral, más ligero)")
        findings.append({"type": "model_warning", "severity": "medium",
                         "value": "sin modelo uncensored",
                         "description": "No hay modelo sin censura para tareas ofensivas"})

    findings.append({
        "type": "model_recommendation", "severity": "info",
        "value": best["model"],
        "description": f"Modelo recomendado para '{kind}': {best['model']} "
                       f"({', '.join(best['reasons'])})",
    })

    lines.append(f"\n  ▶ Úsalo en el desarrollo:")
    lines.append(f"     SKILL:code_dev request=\"...\" kind={kind} model={best['model']}")

    return {
        "success": True,
        "output": "\n".join(lines),
        "findings": findings,
        "recommended_model": best["model"],
        "ranking": [r["model"] for r in ranked],
    }
