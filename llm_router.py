"""Enrutamiento determinista de modelos para HackerAgent.

Este módulo no hace llamadas de red. Recibe un catálogo de modelos disponibles,
clasifica la tarea y devuelve un ranking explicable. Así puede reutilizarse desde
``agent.py`` y desde los skills sin crear dependencias circulares.
"""
from __future__ import annotations

import os
import re
from typing import Any


BACKEND_NAMES = {
    "auto": "Auto IA",
    "ollama": "Ollama",
    "lmstudio": "LM Studio",
    "deepseek": "DeepSeek API",
    "openrouter": "OpenRouter",
}
LOCAL_BACKENDS = {"ollama", "lmstudio"}
BACKEND_ORDER = {"ollama": 0, "lmstudio": 1, "deepseek": 2, "openrouter": 3}
VALID_POLICIES = {"balanced", "quality", "local", "cost"}


def fallback_candidates(candidates: list[dict]) -> list[dict]:
    """Prueba primero un modelo de cada proveedor, conservando la elección inicial."""
    first, remaining, providers, seen = [], [], set(), set()
    for candidate in candidates:
        key = (candidate["backend"], candidate["model"])
        if key in seen:
            continue
        seen.add(key)
        if key[0] in providers:
            remaining.append(candidate)
        else:
            providers.add(key[0])
            first.append(candidate)
    return first + remaining


_PROFILE_RULES = [
    (
        "reverse_engineering",
        re.compile(
            r"\b(?:reverse|reversa|inversa|binari[oa]|assembly|asm|decompil|disassembl|"
            r"radare|ghidra|frida|apk|elf|pe32|firmware|bypass)\b",
            re.I,
        ),
        ("code", "reasoning", "long_context", "structured"),
        "ingeniería inversa: prioriza código, razonamiento y contexto amplio",
    ),
    (
        "coding",
        re.compile(
            r"\b(?:c[oó]digo|programa|implementa|refactor|debug|bug|python|javascript|"
            r"typescript|golang|rust|csharp|powershell|bash|api|desarrolla)\b",
            re.I,
        ),
        ("code", "reasoning", "structured"),
        "desarrollo: prioriza modelos especializados en código",
    ),
    (
        "report",
        re.compile(
            r"\b(?:reporte|informe|resumen ejecutivo|documenta|documentaci[oó]n|"
            r"redacta|explica|hallazgos)\b",
            re.I,
        ),
        ("writing", "long_context", "structured"),
        "reporte: prioriza redacción y contexto amplio",
    ),
    (
        "security_analysis",
        re.compile(
            r"\b(?:vulnerab|cve|exploit|pentest|audita|sqli|xss|rce|lfi|"
            r"metasploit|nuclei|clasifica|evidencia|riesgo)\b",
            re.I,
        ),
        ("reasoning", "security", "structured"),
        "análisis de seguridad: prioriza razonamiento y salida estructurada",
    ),
    (
        "research",
        re.compile(
            r"\b(?:osint|investiga|research|correlaciona|breach|wayback|metadata|"
            r"social|inteligencia|fuentes)\b",
            re.I,
        ),
        ("reasoning", "long_context", "structured"),
        "investigación: prioriza correlación y contexto amplio",
    ),
    (
        "tool_planning",
        re.compile(
            r"\b(?:recon|escanea|scan|enumera|subdominio|dns|puertos|nmap|"
            r"shodan|gobuster|httpx|whois)\b",
            re.I,
        ),
        ("fast", "structured", "security"),
        "planificación de herramientas: prioriza rapidez y JSON fiable",
    ),
]


def normalize_policy(policy: str = "") -> str:
    selected = (policy or os.environ.get("HACKERAGENT_ROUTER_POLICY", "balanced")).lower().strip()
    return selected if selected in VALID_POLICIES else "balanced"


def infer_task_profile(text: str) -> dict[str, Any]:
    """Clasifica una petición usando señales explícitas y reglas estables."""
    source = str(text or "")
    profile = "general"
    needs: tuple[str, ...] = ("reasoning", "structured")
    reason = "tarea general: equilibrio entre calidad, rapidez y JSON fiable"
    for candidate, pattern, candidate_needs, candidate_reason in _PROFILE_RULES:
        if pattern.search(source):
            profile, needs, reason = candidate, candidate_needs, candidate_reason
            break
    if len(source) > 12000 and "long_context" not in needs:
        needs = (*needs, "long_context")
        reason += "; entrada extensa"
    if re.search(r"\b(?:r[aá]pido|rapidez|quick|fast|baja latencia)\b", source, re.I):
        if "fast" not in needs:
            needs = (*needs, "fast")
        reason += "; el usuario pidió rapidez"
    return {"profile": profile, "needs": list(needs), "reason": reason}


def model_capabilities(model: str, backend: str = "") -> set[str]:
    name = str(model or "").lower()
    caps = {"general", "structured"}
    if any(k in name for k in ("coder", "codestral", "code-", "devstral", "starcoder", "codellama")):
        caps.update({"code", "security"})
    if any(k in name for k in (
        "reasoner", "deepseek-r1", "deepseek-r2", "qwq", "qwen3", "o1", "o3", "o4",
        "claude", "sonnet", "opus", "gpt-4", "gpt-5", "gemini-2", "command-r",
    )):
        caps.add("reasoning")
    if any(k in name for k in ("claude", "gemini", "gpt-4.1", "gpt-5", "qwen", "llama3.1", "command-r")):
        caps.add("long_context")
    if any(k in name for k in ("claude", "gpt", "gemini", "command-r", "mistral-large", "deepseek-chat")):
        caps.add("writing")
    if any(k in name for k in ("deepseek", "qwen", "coder", "llama", "mistral", "claude", "gpt", "gemini")):
        caps.add("security")
    is_mini_variant = bool(re.search(r"(?:^|[-_/])mini(?:$|[-_/])", name))
    if is_mini_variant or any(k in name for k in (
        "flash", "small", "nano", "haiku", ":3b", ":7b", ":8b", ":9b", ":12b", ":14b",
    )):
        caps.update({"fast", "cost"})
    size = re.search(r"(?:^|[:\-])(\d{1,3})b(?:$|[-_])", name)
    if size:
        billions = int(size.group(1))
        if billions >= 30:
            caps.update({"reasoning", "long_context"})
        elif billions <= 14:
            caps.update({"fast", "cost"})
    if backend in {"deepseek", "openrouter"}:
        caps.add("reliable_api")
    return caps


def model_quality(model: str) -> tuple[int, str]:
    """Puntuación base independiente del proveedor (0-100)."""
    name = str(model or "").lower()
    tiers = [
        (("gpt-5", "claude-sonnet-4", "claude-4", "gemini-2.5-pro", "o3", "deepseek-r2"), 96, "frontera"),
        (("gpt-4.1", "claude-3.7", "deepseek-reasoner", "deepseek-r1:32b", "qwen3-coder"), 92, "razonamiento avanzado"),
        (("deepseek-chat", "deepseek-v3", "qwen2.5-coder:32b", "codestral", "mistral-large", "command-r"), 86, "alta capacidad"),
        (("deepseek-r1:14b", "qwen2.5-coder", "llama-3.3", "llama3.3", "gemini-flash", "sonnet"), 82, "muy competente"),
        (("llama3.1", "llama3.2", "mistral", "qwen", "dolphin3"), 72, "general moderno"),
        (("codellama", "starcoder", "phi", "gemma"), 64, "especializado/ligero"),
    ]
    for keys, score, description in tiers:
        if any(key in name for key in keys):
            return score, description
    return 60, "modelo general"


def rank_candidates(
    catalog: list[dict[str, str]],
    task_text: str,
    *,
    policy: str = "",
    preferred_model: str = "",
    preferred_backend: str = "",
) -> dict[str, Any]:
    """Ordena modelos disponibles y explica la elección principal."""
    task = infer_task_profile(task_text)
    selected_policy = normalize_policy(policy)
    preferred_model = str(preferred_model or "").strip()
    preferred_backend = str(preferred_backend or "").strip().lower()
    if "::" in preferred_model:
        encoded_backend, encoded_model = preferred_model.split("::", 1)
        preferred_backend = encoded_backend
        preferred_model = encoded_model

    ranked: list[dict[str, Any]] = []
    for item in catalog:
        backend = str(item.get("backend", ""))
        model = str(item.get("model", ""))
        if not backend or not model:
            continue
        quality, quality_desc = model_quality(model)
        caps = model_capabilities(model, backend)
        score = float(quality)
        matched = [need for need in task["needs"] if need in caps]
        missing = [need for need in task["needs"] if need not in caps]
        score += len(matched) * 10
        score -= len(missing) * 4

        if selected_policy == "quality":
            score += quality * .25
            if backend not in LOCAL_BACKENDS:
                score += 4
        elif selected_policy == "local":
            score += 28 if backend in LOCAL_BACKENDS else -18
        elif selected_policy == "cost":
            score += 22 if backend in LOCAL_BACKENDS else 0
            score += 14 if "cost" in caps else -5
        else:  # balanced
            score += 7 if backend in LOCAL_BACKENDS else 2
            score += 4 if "fast" in caps else 0

        if "structured" in task["needs"] and "reliable_api" in caps:
            score += 4
        if preferred_backend and backend == preferred_backend:
            score += 120
        if preferred_model and (model == preferred_model or preferred_model.lower() in model.lower()):
            score += 1000

        ranked.append({
            "backend": backend,
            "backend_name": BACKEND_NAMES.get(backend, backend),
            "model": model,
            "score": round(score, 2),
            "quality": quality,
            "quality_desc": quality_desc,
            "capabilities": sorted(caps),
            "matched": matched,
            "missing": missing,
        })

    ranked.sort(key=lambda item: (
        -item["score"], BACKEND_ORDER.get(item["backend"], 99), item["model"].lower()
    ))
    choice = ranked[0] if ranked else None
    if choice:
        match_text = ", ".join(choice["matched"]) or "capacidad general"
        route_reason = (
            f"{task['reason']}; {choice['backend_name']}/{choice['model']} "
            f"coincide en {match_text} (política {selected_policy})"
        )
    else:
        route_reason = "no hay modelos disponibles"
    return {
        "profile": task["profile"],
        "needs": task["needs"],
        "policy": selected_policy,
        "reason": route_reason,
        "choice": choice,
        "candidates": ranked,
    }
