"""Cliente robusto y compartido para la API local de LM Studio.

Mantiene HackerAgent sobre los endpoints OpenAI-compatible para conservar el
historial completo, pero aprovecha ``/api/v1/models`` para el diagnóstico rico
cuando LM Studio 0.4+ está disponible.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter


AGENT_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "json_schema",
    "json_schema": {
        "name": "hackeragent_response",
        "schema": {
            "type": "object",
            "properties": {
                "thinking": {"type": "string"},
                "commands": {"type": "array", "items": {"type": "string"}},
                "message": {"type": "string"},
                "requires_confirmation": {"type": "boolean"},
                "task_complete": {"type": "boolean"},
                "risk_level": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                },
                "phase": {"type": "string"},
                "install_needed": {"type": "array", "items": {"type": "string"}},
                "needs_api_keys": {"type": "array", "items": {"type": "string"}},
                "open_browser": {"type": "string"},
                "fetch_url": {"type": "string"},
            },
            "required": [
                "thinking", "commands", "message", "requires_confirmation",
                "task_complete", "risk_level", "phase", "needs_api_keys",
                "open_browser", "fetch_url",
            ],
            "additionalProperties": True,
        },
    },
}

JSON_INSTRUCTION = (
    "Responde solamente con un objeto JSON válido que cumpla el esquema de "
    "HackerAgent. No uses bloques Markdown ni texto fuera del objeto."
)


class LMStudioError(RuntimeError):
    """Error de LM Studio con detalle accionable para CLI y Web UI."""

    def __init__(self, message: str, *, status: int | None = None, hint: str = ""):
        super().__init__(message)
        self.status = status
        self.hint = hint

    def __str__(self) -> str:
        message = super().__str__()
        return f"{message} — {self.hint}" if self.hint else message


def normalize_base_url(value: str | None = None) -> str:
    """Devuelve siempre la base OpenAI ``http(s)://host:port/v1``."""
    raw = str(value or os.getenv("LMSTUDIO_URL", "http://localhost:1234/v1")).strip()
    raw = raw.rstrip("/")
    if not raw:
        raw = "http://localhost:1234/v1"
    if not re.match(r"^https?://", raw, re.I):
        raw = "http://" + raw
    parts = urlsplit(raw)
    path = re.sub(r"/(?:chat/completions|models)$", "", parts.path.rstrip("/"))
    if path.endswith("/api/v1"):
        path = path[:-7] + "/v1"
    elif not path.endswith("/v1"):
        path += "/v1"
    path = re.sub(r"/{2,}", "/", path)
    return urlunsplit((parts.scheme, parts.netloc, path, "", "")).rstrip("/")


def server_root(base_url: str | None = None) -> str:
    base = normalize_base_url(base_url)
    return base[:-3] if base.endswith("/v1") else base


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                text = block.get("text") or block.get("content")
                if text:
                    parts.append(str(text))
        return "\n".join(parts)
    if content is None:
        return ""
    return str(content)


def normalize_messages(messages: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Normaliza historiales para plantillas Jinja estrictas de modelos locales.

    Fusiona mensajes ``system`` al inicio y mensajes consecutivos del mismo rol.
    Los resultados ``tool`` se convierten en contexto de usuario, ya que muchos
    modelos GGUF no aceptan ese rol sin una definición formal de herramientas.
    """
    system_parts: list[str] = []
    normalized: list[dict[str, str]] = []
    for raw in messages or []:
        if not isinstance(raw, dict):
            continue
        role = str(raw.get("role", "user")).lower().strip()
        content = _content_text(raw.get("content")).strip()
        if not content:
            continue
        if role == "system":
            system_parts.append(content)
            continue
        if role not in {"user", "assistant"}:
            content = f"[{role.upper()}]\n{content}"
            role = "user"
        if normalized and normalized[-1]["role"] == role:
            normalized[-1]["content"] += "\n\n" + content
        else:
            normalized.append({"role": role, "content": content})
    if system_parts:
        normalized.insert(0, {"role": "system", "content": "\n\n".join(system_parts)})
    return normalized


def with_json_instruction(messages: list[dict[str, Any]]) -> list[dict[str, str]]:
    prepared = normalize_messages(messages)
    if prepared and prepared[0]["role"] == "system":
        prepared[0] = dict(prepared[0])
        prepared[0]["content"] += "\n\n" + JSON_INSTRUCTION
    else:
        prepared.insert(0, {"role": "system", "content": JSON_INSTRUCTION})
    return prepared


def _balanced_json_object(text: str) -> str:
    """Extrae el primer objeto JSON balanceado sin romper llaves en strings."""
    start = text.find("{")
    while start >= 0:
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(text)):
            char = text[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return text[start:index + 1]
        start = text.find("{", start + 1)
    return ""


def parse_agent_json(content: str) -> dict[str, Any]:
    raw = str(content or "").strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.I)
    cleaned = re.sub(r"\s*```$", "", cleaned).strip()
    parsed: Any = None
    try:
        parsed = json.loads(cleaned)
    except (json.JSONDecodeError, TypeError):
        candidate = _balanced_json_object(cleaned)
        if candidate:
            try:
                parsed = json.loads(candidate)
            except (json.JSONDecodeError, TypeError):
                parsed = None
    if not isinstance(parsed, dict):
        return {
            "thinking": "", "commands": [], "message": raw,
            "requires_confirmation": False, "task_complete": True,
            "risk_level": "low", "phase": "response", "needs_api_keys": [],
            "open_browser": "", "fetch_url": "", "_json_parse_error": True,
        }

    result = dict(parsed)
    result["thinking"] = _content_text(result.get("thinking"))
    message = result.get("message")
    if not message:
        message = result.get("summary") or result.get("content") or result.get("response") or ""
    result["message"] = _content_text(message)
    commands = result.get("commands", [])
    if isinstance(commands, str):
        commands = [commands] if commands.strip() else []
    elif not isinstance(commands, list):
        commands = []
    result["commands"] = commands
    result["requires_confirmation"] = bool(result.get("requires_confirmation", False))
    result["task_complete"] = bool(result.get("task_complete", False))
    if result.get("risk_level") not in {"low", "medium", "high", "critical"}:
        result["risk_level"] = "low"
    result.setdefault("phase", "recon")
    for key in ("needs_api_keys", "install_needed"):
        value = result.get(key, [])
        result[key] = value if isinstance(value, list) else []
    result.setdefault("open_browser", "")
    result.setdefault("fetch_url", "")
    return result


class LMStudioClient:
    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        session: requests.Session | None = None,
    ):
        self.base_url = normalize_base_url(base_url)
        self.root_url = server_root(self.base_url)
        self.api_key = api_key if api_key is not None else (
            os.getenv("LMSTUDIO_API_KEY") or os.getenv("LM_API_TOKEN") or ""
        )
        self.session = session or requests.Session()
        if session is None:
            adapter = HTTPAdapter(pool_connections=12, pool_maxsize=24, max_retries=0)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)

    @property
    def headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _detail(self, response: Any) -> str:
        try:
            body = response.json()
            error = body.get("error", body) if isinstance(body, dict) else body
            if isinstance(error, dict):
                return str(error.get("message") or error.get("detail") or error)
            return str(error)
        except Exception:
            return str(getattr(response, "text", "") or "Error desconocido")[:600]

    def _raise_response(self, response: Any, operation: str) -> None:
        status = int(getattr(response, "status_code", 0) or 0)
        detail = self._detail(response)
        hint = ""
        if status in {401, 403}:
            hint = "configura LMSTUDIO_API_KEY con un token válido de LM Studio"
        elif status == 404:
            hint = f"verifica LMSTUDIO_URL; la base esperada es {self.base_url}"
        elif "model" in detail.lower() and any(word in detail.lower() for word in ("not found", "load", "invalid")):
            hint = "carga el modelo en Developer > Local Server o activa Just‑In‑Time loading"
        elif "context" in detail.lower() or "token" in detail.lower():
            hint = "reduce el historial o carga el modelo con mayor context length"
        raise LMStudioError(
            f"LM Studio no pudo {operation} (HTTP {status or '?' }): {detail}",
            status=status or None,
            hint=hint,
        )

    def _get(self, url: str, *, timeout: tuple[int, int] = (3, 8)) -> Any:
        try:
            return self.session.get(url, headers=self.headers, timeout=timeout)
        except requests.RequestException as exc:
            raise LMStudioError(
                f"No se pudo conectar con LM Studio en {self.root_url}",
                hint="inicia Local Server en LM Studio y habilita acceso de red si usas otra máquina",
            ) from exc

    def model_inventory(self) -> list[dict[str, Any]]:
        """Lista LLMs con metadata; usa OpenAI como fallback de compatibilidad."""
        native = self._get(f"{self.root_url}/api/v1/models")
        if getattr(native, "ok", False):
            try:
                data = native.json()
                result = []
                for item in data.get("models", []):
                    if item.get("type") == "embedding":
                        continue
                    instances = item.get("loaded_instances") or []
                    result.append({
                        "id": item.get("key") or item.get("id"),
                        "name": item.get("display_name") or item.get("key") or item.get("id"),
                        "loaded": bool(instances),
                        "loaded_instances": instances,
                        "context_length": (
                            ((instances[0].get("config") or {}).get("context_length"))
                            if instances else None
                        ),
                        "max_context_length": item.get("max_context_length"),
                        "params": item.get("params_string"),
                        "quantization": (item.get("quantization") or {}).get("name"),
                        "capabilities": item.get("capabilities") or {},
                    })
                return [item for item in result if item.get("id")]
            except (ValueError, TypeError, AttributeError) as exc:
                raise LMStudioError(f"LM Studio devolvió un inventario inválido: {exc}") from exc
        if getattr(native, "status_code", 0) not in {404, 405}:
            self._raise_response(native, "listar modelos")

        compat = self._get(f"{self.base_url}/models")
        if not getattr(compat, "ok", False):
            self._raise_response(compat, "listar modelos")
        try:
            return [
                {"id": item["id"], "name": item["id"], "loaded": None}
                for item in compat.json().get("data", [])
                if item.get("id") and str(item.get("type", "")).lower() != "embedding"
            ]
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise LMStudioError(f"LM Studio devolvió /v1/models inválido: {exc}") from exc

    def models(self) -> list[str]:
        return [item["id"] for item in self.model_inventory()]

    def diagnostics(self) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            inventory = self.model_inventory()
            return {
                "online": True,
                "url": self.base_url,
                "authenticated": bool(self.api_key),
                "latency_ms": round((time.perf_counter() - started) * 1000),
                "models": inventory,
                "model_count": len(inventory),
                "loaded_count": sum(item.get("loaded") is True for item in inventory),
                "error": "",
                "hint": "" if inventory else "Descarga o carga al menos un modelo de chat en LM Studio.",
            }
        except LMStudioError as exc:
            return {
                "online": False, "url": self.base_url, "authenticated": bool(self.api_key),
                "latency_ms": round((time.perf_counter() - started) * 1000),
                "models": [], "model_count": 0, "loaded_count": 0,
                "error": str(exc), "hint": exc.hint,
            }

    def _post(self, payload: dict[str, Any], *, stream: bool, read_timeout: int) -> Any:
        try:
            return self.session.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=self.headers,
                timeout=(15, read_timeout),
                stream=stream,
            )
        except requests.RequestException as exc:
            raise LMStudioError(
                "Se perdió la conexión con LM Studio durante la inferencia",
                hint="revisa que el servidor siga activo y que el modelo quepa en RAM/VRAM",
            ) from exc

    @staticmethod
    def _supports_schema_retry(response: Any) -> bool:
        status = int(getattr(response, "status_code", 0) or 0)
        if status not in {400, 422, 500}:
            return False
        try:
            text = json.dumps(response.json(), ensure_ascii=False).lower()
        except Exception:
            text = str(getattr(response, "text", "")).lower()
        return any(word in text for word in ("response_format", "json_schema", "grammar", "structured"))

    def _request(self, payload: dict[str, Any], *, stream: bool, read_timeout: int) -> Any:
        response = self._post(payload, stream=stream, read_timeout=read_timeout)
        if not getattr(response, "ok", False) and "response_format" in payload and self._supports_schema_retry(response):
            fallback = dict(payload)
            fallback.pop("response_format", None)
            response = self._post(fallback, stream=stream, read_timeout=read_timeout)
        if not getattr(response, "ok", False):
            self._raise_response(response, "generar la respuesta")
        return response

    def _payload(
        self,
        model: str,
        messages: list[dict[str, Any]],
        *,
        temperature: float,
        max_tokens: int | None,
        stream: bool,
        json_mode: bool,
    ) -> dict[str, Any]:
        token_limit = max_tokens or _env_int("LMSTUDIO_MAX_TOKENS", 4096, 256, 32768)
        payload: dict[str, Any] = {
            "model": model,
            "messages": with_json_instruction(messages) if json_mode else normalize_messages(messages),
            "temperature": max(0.0, min(float(temperature), 2.0)),
            "max_tokens": max(16, min(int(token_limit), 32768)),
            "stream": stream,
        }
        structured = os.getenv("LMSTUDIO_STRUCTURED_OUTPUT", "auto").lower().strip()
        if json_mode and structured not in {"off", "false", "0"}:
            payload["response_format"] = AGENT_RESPONSE_SCHEMA
        return payload

    @staticmethod
    def _choice(body: dict[str, Any]) -> tuple[str, str, dict[str, Any], str]:
        choices = body.get("choices") or []
        if not choices:
            raise LMStudioError("LM Studio devolvió una respuesta sin choices")
        choice = choices[0] or {}
        message = choice.get("message") or {}
        content = _content_text(message.get("content"))
        reasoning = _content_text(message.get("reasoning_content") or message.get("reasoning"))
        return content, reasoning, body.get("usage") or {}, str(choice.get("finish_reason") or "")

    def chat_json(
        self,
        model: str,
        messages: list[dict[str, Any]],
        *,
        on_delta: Callable[[str, str], None] | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        read_timeout = timeout or _env_int("LMSTUDIO_TIMEOUT", 600, 30, 3600)
        payload = self._payload(
            model, messages, temperature=.1, max_tokens=None,
            stream=on_delta is not None, json_mode=True,
        )
        response = self._request(payload, stream=on_delta is not None, read_timeout=read_timeout)
        if on_delta is None:
            try:
                body = response.json()
            except ValueError as exc:
                raise LMStudioError("LM Studio devolvió una respuesta HTTP que no es JSON") from exc
            content, reasoning, usage, finish = self._choice(body)
        else:
            content_parts: list[str] = []
            reasoning_parts: list[str] = []
            usage: dict[str, Any] = {}
            finish = ""
            # requests guesses ISO-8859-1 for text/event-stream when LM Studio
            # omits charset. Decode the wire bytes explicitly as UTF-8 so
            # Spanish text and emoji do not become mojibake in the Web UI.
            for raw_line in response.iter_lines(decode_unicode=False):
                if isinstance(raw_line, bytes):
                    raw_line = raw_line.decode("utf-8", errors="replace")
                line = str(raw_line or "").strip()
                if not line or line.startswith(":") or not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    chunk = json.loads(data)
                except json.JSONDecodeError:
                    continue
                if chunk.get("usage"):
                    usage = chunk["usage"]
                choices = chunk.get("choices") or []
                if not choices:
                    continue
                choice = choices[0] or {}
                finish = str(choice.get("finish_reason") or finish)
                delta = choice.get("delta") or {}
                reasoning_delta = _content_text(delta.get("reasoning_content") or delta.get("reasoning"))
                content_delta = _content_text(delta.get("content"))
                if reasoning_delta:
                    reasoning_parts.append(reasoning_delta)
                    on_delta("reasoning", reasoning_delta)
                if content_delta:
                    content_parts.append(content_delta)
                    on_delta("content", content_delta)
            content = "".join(content_parts)
            reasoning = "".join(reasoning_parts)
        if finish == "length":
            raise LMStudioError(
                "LM Studio alcanzó el límite de salida (finish_reason=length)",
                hint="aumenta LMSTUDIO_MAX_TOKENS o reduce el historial de la sesión",
            )
        result = parse_agent_json(content)
        result["_stream_raw"] = content
        result["_reasoning_content"] = reasoning
        result["_usage"] = usage
        return result

    def chat_text(
        self,
        model: str,
        messages: list[dict[str, Any]],
        *,
        temperature: float = .3,
        max_tokens: int | None = None,
        timeout: int | None = None,
        json_mode: bool = False,
    ) -> str:
        read_timeout = timeout or _env_int("LMSTUDIO_TIMEOUT", 600, 30, 3600)
        payload = self._payload(
            model, messages, temperature=temperature, max_tokens=max_tokens,
            stream=False, json_mode=json_mode,
        )
        response = self._request(payload, stream=False, read_timeout=read_timeout)
        try:
            content, _, _, finish = self._choice(response.json())
        except ValueError as exc:
            raise LMStudioError("LM Studio devolvió una respuesta HTTP que no es JSON") from exc
        if finish == "length":
            raise LMStudioError(
                "LM Studio alcanzó el límite de salida",
                hint="aumenta LMSTUDIO_MAX_TOKENS o solicita una respuesta más corta",
            )
        return content


_CLIENT: LMStudioClient | None = None
_CLIENT_SIGNATURE: tuple[str, str] | None = None
_DIAGNOSTIC_CACHE: dict[str, Any] = {"ts": 0.0, "signature": None, "value": None}
_DIAGNOSTIC_LOCK = threading.Lock()


def get_client(force: bool = False) -> LMStudioClient:
    global _CLIENT, _CLIENT_SIGNATURE
    url = normalize_base_url()
    token = os.getenv("LMSTUDIO_API_KEY") or os.getenv("LM_API_TOKEN") or ""
    signature = (url, token)
    if force or _CLIENT is None or _CLIENT_SIGNATURE != signature:
        _CLIENT = LMStudioClient(url, token)
        _CLIENT_SIGNATURE = signature
    return _CLIENT


def check_lmstudio() -> tuple[bool, list[str]]:
    diagnostic = lmstudio_diagnostics()
    return bool(diagnostic.get("online")), [
        item["id"] for item in diagnostic.get("models", []) if item.get("id")
    ]


def lmstudio_diagnostics(force: bool = False) -> dict[str, Any]:
    """Diagnóstico con caché breve para no duplicar timeouts desde la SPA."""
    signature = (
        normalize_base_url(),
        os.getenv("LMSTUDIO_API_KEY") or os.getenv("LM_API_TOKEN") or "",
    )
    cached = _DIAGNOSTIC_CACHE.get("value")
    if (
        not force and cached is not None
        and _DIAGNOSTIC_CACHE.get("signature") == signature
        and time.time() - float(_DIAGNOSTIC_CACHE.get("ts", 0)) < 5
    ):
        return dict(cached)
    with _DIAGNOSTIC_LOCK:
        cached = _DIAGNOSTIC_CACHE.get("value")
        if (
            not force and cached is not None
            and _DIAGNOSTIC_CACHE.get("signature") == signature
            and time.time() - float(_DIAGNOSTIC_CACHE.get("ts", 0)) < 5
        ):
            return dict(cached)
        result = get_client().diagnostics()
        _DIAGNOSTIC_CACHE.update(ts=time.time(), signature=signature, value=result)
        return dict(result)


def lmstudio_chat_json(
    model: str,
    messages: list[dict[str, Any]],
    on_delta: Callable[[str, str], None] | None = None,
) -> dict[str, Any]:
    return get_client().chat_json(model, messages, on_delta=on_delta)


def lmstudio_chat_text(
    model: str,
    messages: list[dict[str, Any]],
    *,
    temperature: float = .3,
    max_tokens: int | None = None,
    timeout: int | None = None,
    json_mode: bool = False,
) -> str:
    return get_client().chat_text(
        model, messages, temperature=temperature, max_tokens=max_tokens,
        timeout=timeout, json_mode=json_mode,
    )
