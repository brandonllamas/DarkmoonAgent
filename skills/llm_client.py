"""Cliente LLM compartido por skills con routing Ollama/LM Studio/cloud."""
from __future__ import annotations

import os
import time
import concurrent.futures
from typing import Any

import requests
from requests.adapters import HTTPAdapter

from llm_router import fallback_candidates, rank_candidates
from lmstudio_client import (
    check_lmstudio as _shared_check_lmstudio,
    lmstudio_chat_text,
    normalize_base_url as _normalize_lmstudio_url,
)


OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat")
LMSTUDIO_URL = _normalize_lmstudio_url(os.getenv("LMSTUDIO_URL"))
DEEPSEEK_API_URL = os.getenv("DEEPSEEK_API_URL", "https://api.deepseek.com/v1").rstrip("/")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
OPENROUTER_API_URL = os.getenv("OPENROUTER_API_URL", "https://openrouter.ai/api/v1").rstrip("/")
OPENROUTER_API_KEY = os.getenv("APIOPENROUTER", os.getenv("OPENROUTER_API_KEY", ""))
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "anthropic/claude-3.5-sonnet")

_HTTP = requests.Session()
_HTTP.mount("http://", HTTPAdapter(pool_connections=12, pool_maxsize=24))
_HTTP.mount("https://", HTTPAdapter(pool_connections=12, pool_maxsize=24))
_CATALOG_CACHE: dict[str, Any] = {"ts": 0.0, "value": None}


def _ollama_models() -> list[str]:
    base = OLLAMA_URL.rsplit("/api/chat", 1)[0].rsplit("/api/", 1)[0]
    try:
        data = _HTTP.get(f"{base}/api/tags", timeout=3).json()
        return [m["name"] for m in data.get("models", []) if m.get("name")]
    except Exception:
        return []


def _lmstudio_models() -> list[str]:
    ok, models = _shared_check_lmstudio()
    return models if ok else []


def _deepseek_models() -> list[str]:
    if not DEEPSEEK_API_KEY:
        return []
    try:
        response = _HTTP.get(
            f"{DEEPSEEK_API_URL}/models",
            headers={"Authorization": f"Bearer {DEEPSEEK_API_KEY}"}, timeout=(3, 8),
        )
        if response.ok:
            models = [m["id"] for m in response.json().get("data", []) if m.get("id")]
            return models or [DEEPSEEK_MODEL]
        if response.status_code in (401, 403):
            return []
    except Exception:
        pass
    return [DEEPSEEK_MODEL]


def _openrouter_models() -> list[str]:
    if not OPENROUTER_API_KEY:
        return []
    try:
        response = _HTTP.get(
            f"{OPENROUTER_API_URL}/models",
            headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}"}, timeout=(3, 10),
        )
        if response.ok:
            models = [m["id"] for m in response.json().get("data", []) if m.get("id")]
            unsupported = ("embedding", "moderation", "realtime", "audio", "image-generation", "text-to-speech")
            models = [m for m in models if not any(k in m.lower() for k in unsupported)]
            if len(models) > 200:
                useful = [m for m in models if any(k in m.lower() for k in (
                    "claude", "gpt", "deepseek", "qwen", "gemini", "mistral", "llama", "codestral"
                ))]
                models = useful or models[:100]
            return models or [OPENROUTER_MODEL]
        if response.status_code in (401, 403):
            return []
    except Exception:
        pass
    return [OPENROUTER_MODEL]


def _catalog(force: bool = False) -> list[dict[str, str]]:
    cached = _CATALOG_CACHE.get("value")
    ttl = max(5, int(os.getenv("HACKERAGENT_ROUTER_CACHE_TTL", "30")))
    if not force and cached is not None and time.time() - float(_CATALOG_CACHE["ts"]) < ttl:
        return [dict(item) for item in cached]

    providers = (
        ("ollama", _ollama_models), ("lmstudio", _lmstudio_models),
        ("deepseek", _deepseek_models), ("openrouter", _openrouter_models),
    )

    def _load(item):
        backend, loader = item
        return backend, loader()

    catalog: list[dict[str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(_load, providers))
    for backend, models in results:
        catalog.extend({"backend": backend, "model": model} for model in models)
    _CATALOG_CACHE.update(ts=time.time(), value=catalog)
    return [dict(item) for item in catalog]


def _desired_backend(preferred: str = "") -> str:
    desired = (preferred or os.getenv("HACKERAGENT_LLM_BACKEND", "auto")
               or os.getenv("LLM_BACKEND", "auto")).lower().strip()
    return desired if desired in {"auto", "ollama", "lmstudio", "deepseek", "openrouter"} else "auto"


def _catalog_for(desired: str) -> list[dict[str, str]]:
    if desired == "auto":
        return _catalog()
    loader = {
        "ollama": _ollama_models, "lmstudio": _lmstudio_models,
        "deepseek": _deepseek_models, "openrouter": _openrouter_models,
    }.get(desired)
    models = loader() if loader else []
    return [{"backend": desired, "model": model} for model in models]


def select_backend(model: str = "", preferred: str = "") -> str:
    """Elige backend para compatibilidad con skills antiguos."""
    desired = _desired_backend(preferred)
    if desired != "auto":
        return desired
    route = rank_candidates(_catalog_for(desired), "tarea general de skill", preferred_model=model)
    return route["choice"]["backend"] if route.get("choice") else "none"


def available_models(preferred: str = "") -> tuple[str, list[str]]:
    """Devuelve los modelos del proveedor recomendado para una tarea general."""
    desired = _desired_backend(preferred)
    catalog = _catalog_for(desired)
    route = rank_candidates(
        catalog, "tarea general de skill",
        preferred_backend="" if desired == "auto" else desired,
    )
    choice = route.get("choice")
    if not choice:
        return "none", []
    backend = choice["backend"]
    return backend, [item["model"] for item in route["candidates"] if item["backend"] == backend]


def _task_text(messages: list[dict[str, str]]) -> str:
    return "\n".join(
        str(message.get("content", "")) for message in messages[-8:]
        if message.get("role") == "user"
    )[-24000:]


def _sanitize_messages(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    """Consolida todos los mensajes system en uno solo al inicio de la lista."""
    system_parts = []
    other_messages = []
    for m in messages:
        if m.get("role") == "system":
            content = m.get("content", "").strip()
            if content:
                system_parts.append(content)
        else:
            other_messages.append(m)
    if not system_parts:
        return other_messages
    merged_system = {"role": "system", "content": "\n\n".join(system_parts)}
    return [merged_system] + other_messages


def _call_backend(backend: str, model: str, messages: list[dict[str, str]], *,
                  temperature: float, max_tokens: int, timeout: int, json_mode: bool) -> str:
    if backend == "lmstudio":
        return lmstudio_chat_text(
            model, messages, temperature=temperature, max_tokens=max_tokens,
            timeout=timeout, json_mode=json_mode,
        )
    if backend in {"deepseek", "openrouter"}:
        clean_msgs = messages
        payload: dict[str, Any] = {
            "model": model, "messages": clean_msgs, "temperature": temperature,
            "max_tokens": max_tokens, "stream": False,
        }
        headers = {"Content-Type": "application/json"}
        if backend == "deepseek":
            url = f"{DEEPSEEK_API_URL}/chat/completions"
            headers["Authorization"] = f"Bearer {DEEPSEEK_API_KEY}"
        elif backend == "openrouter":
            url = f"{OPENROUTER_API_URL}/chat/completions"
            headers.update({
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "HTTP-Referer": "https://github.com/HackerAgent", "X-Title": "HackerAgent",
            })
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        response = _HTTP.post(url, json=payload, headers=headers, timeout=(15, timeout))
        response.raise_for_status()
        response.encoding = "utf-8"
        return response.json()["choices"][0]["message"]["content"]

    payload = {
        "model": model, "messages": messages, "stream": False,
        "options": {"temperature": temperature, "num_ctx": max_tokens},
    }
    if json_mode:
        payload["format"] = "json"
    response = _HTTP.post(OLLAMA_URL, json=payload, timeout=timeout)
    response.raise_for_status()
    response.encoding = "utf-8"
    return response.json()["message"]["content"]


def chat_text(messages: list[dict[str, str]], model: str = "", *, temperature: float = .15,
              max_tokens: int = 4096, timeout: int = 180, json_mode: bool = False,
              backend: str = "") -> str:
    """Ejecuta chat con selección por tarea y fallback entre proveedores."""
    desired = _desired_backend(backend)
    catalog = _catalog_for(desired)
    route = rank_candidates(
        catalog, _task_text(messages),
        preferred_model=model,
        preferred_backend="" if desired == "auto" else desired,
    )
    candidates = route.get("candidates", [])
    if desired == "auto":
        candidates = fallback_candidates(candidates)
    if not candidates:
        raise RuntimeError(
            "No hay backend LLM disponible. Inicia Ollama/LM Studio o configura DeepSeek/OpenRouter."
        )
    try:
        configured_attempts = int(os.getenv("HACKERAGENT_ROUTER_FALLBACKS", "3"))
    except ValueError:
        configured_attempts = 3
    attempts = max(1, min(configured_attempts, 8))
    errors = []
    for candidate in candidates[:attempts]:
        try:
            return _call_backend(
                candidate["backend"], candidate["model"], messages,
                temperature=temperature, max_tokens=max_tokens,
                timeout=timeout, json_mode=json_mode,
            )
        except (requests.RequestException, KeyError, ValueError) as exc:
            errors.append(f"{candidate['backend']}/{candidate['model']}: {exc}")
            if desired != "auto":
                break
    raise RuntimeError("Todos los modelos seleccionados fallaron: " + "; ".join(errors))
