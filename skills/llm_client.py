"""Cliente LLM común para skills: Ollama, LM Studio y DeepSeek.

Los skills se cargan de forma dinámica, por lo que este módulo no expone META.
Cada skill puede usar ``chat_text`` sin conocer el formato específico de cada API.
"""
from __future__ import annotations

import os
from typing import Any

import requests
from requests.adapters import HTTPAdapter

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat")
LMSTUDIO_URL = os.getenv("LMSTUDIO_URL", "http://localhost:1234/v1").rstrip("/")
DEEPSEEK_API_URL = os.getenv("DEEPSEEK_API_URL", "https://api.deepseek.com/v1").rstrip("/")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

_HTTP = requests.Session()
_HTTP.mount("http://", HTTPAdapter(pool_connections=12, pool_maxsize=24))
_HTTP.mount("https://", HTTPAdapter(pool_connections=12, pool_maxsize=24))


def _ollama_models() -> list[str]:
    base = OLLAMA_URL.rsplit("/api/chat", 1)[0].rsplit("/api/", 1)[0]
    try:
        data = requests.get(f"{base}/api/tags", timeout=3).json()
        return [m["name"] for m in data.get("models", []) if m.get("name")]
    except Exception:
        return []


def select_backend(model: str = "", preferred: str = "") -> str:
    """Choose a configured backend, honoring explicit model/backend choices."""
    desired = (preferred or os.getenv("HACKERAGENT_LLM_BACKEND", "")
               or os.getenv("LLM_BACKEND", "")).lower().strip()
    if desired in {"ollama", "lmstudio", "deepseek"}:
        return desired
    if model.lower().startswith("deepseek") and DEEPSEEK_API_KEY:
        return "deepseek"
    if _ollama_models():
        return "ollama"
    if DEEPSEEK_API_KEY:
        return "deepseek"
    try:
        if requests.get(f"{LMSTUDIO_URL}/models", timeout=3).ok:
            return "lmstudio"
    except Exception:
        pass
    return "none"


def available_models(preferred: str = "") -> tuple[str, list[str]]:
    backend = select_backend(preferred=preferred)
    if backend == "ollama":
        return backend, _ollama_models()
    if backend == "deepseek":
        return backend, [DEEPSEEK_MODEL]
    if backend == "lmstudio":
        try:
            data = requests.get(f"{LMSTUDIO_URL}/models", timeout=5).json()
            return backend, [m["id"] for m in data.get("data", []) if m.get("id")]
        except Exception:
            return backend, []
    return backend, []


def chat_text(messages: list[dict[str, str]], model: str = "", *, temperature: float = .15,
              max_tokens: int = 4096, timeout: int = 180, json_mode: bool = False,
              backend: str = "") -> str:
    """Run a non-streaming chat request and return its text or raise RuntimeError."""
    selected = select_backend(model, backend)
    if selected == "none":
        raise RuntimeError("No hay backend LLM disponible. Configura Ollama, LM Studio o DEEPSEEK_API_KEY.")
    try:
        if selected == "deepseek":
            if not DEEPSEEK_API_KEY:
                raise RuntimeError("Falta DEEPSEEK_API_KEY")
            payload: dict[str, Any] = {"model": model or DEEPSEEK_MODEL, "messages": messages,
                                        "temperature": temperature, "max_tokens": max_tokens, "stream": False}
            if json_mode:
                payload["response_format"] = {"type": "json_object"}
            response = _HTTP.post(f"{DEEPSEEK_API_URL}/chat/completions", json=payload,
                                  headers={"Authorization": f"Bearer {DEEPSEEK_API_KEY}",
                                           "Content-Type": "application/json"},
                                  timeout=(15, timeout))
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        if selected == "lmstudio":
            payload = {"model": model or "local", "messages": messages, "temperature": temperature,
                       "max_tokens": max_tokens, "stream": False}
            response = _HTTP.post(f"{LMSTUDIO_URL}/chat/completions", json=payload, timeout=timeout)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        models = _ollama_models()
        chosen = model or (models[0] if models else "")
        if not chosen:
            raise RuntimeError("Ollama está disponible pero no tiene modelos instalados")
        payload = {"model": chosen, "messages": messages, "stream": False,
                   "options": {"temperature": temperature, "num_ctx": max_tokens}}
        if json_mode:
            payload["format"] = "json"
        response = _HTTP.post(OLLAMA_URL, json=payload, timeout=timeout)
        response.raise_for_status()
        return response.json()["message"]["content"]
    except requests.RequestException as exc:
        raise RuntimeError(f"{selected}: {exc}") from exc
