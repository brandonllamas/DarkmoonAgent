import json
import unittest

import requests

from lmstudio_client import (
    LMStudioClient,
    normalize_base_url,
    normalize_messages,
    parse_agent_json,
)


VALID_AGENT_RESPONSE = {
    "thinking": "listo",
    "commands": [],
    "message": "Respuesta correcta",
    "requires_confirmation": False,
    "task_complete": True,
    "risk_level": "low",
    "phase": "response",
    "needs_api_keys": [],
    "open_browser": "",
    "fetch_url": "",
}


class _Response:
    def __init__(self, status=200, payload=None, lines=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self._lines = lines or []
        self.text = json.dumps(self._payload)
        self.ok = 200 <= status < 300

    def json(self):
        return self._payload

    def iter_lines(self, decode_unicode=True):
        return iter(self._lines)


class _Session:
    def __init__(self, gets=None, posts=None):
        self.gets = list(gets or [])
        self.posts = list(posts or [])
        self.get_calls = []
        self.post_calls = []

    def get(self, url, **kwargs):
        self.get_calls.append((url, kwargs))
        response = self.gets.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def post(self, url, **kwargs):
        self.post_calls.append((url, kwargs))
        response = self.posts.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _chat_response(content=None, finish="stop"):
    return _Response(payload={
        "choices": [{
            "message": {"content": content or json.dumps(VALID_AGENT_RESPONSE)},
            "finish_reason": finish,
        }],
        "usage": {"total_tokens": 21},
    })


class LMStudioClientTest(unittest.TestCase):
    def test_normalizes_common_url_variants(self):
        self.assertEqual(normalize_base_url("localhost:1234"), "http://localhost:1234/v1")
        self.assertEqual(
            normalize_base_url("http://localhost:1234/v1/chat/completions"),
            "http://localhost:1234/v1",
        )
        self.assertEqual(
            normalize_base_url("http://localhost:1234/api/v1"),
            "http://localhost:1234/v1",
        )

    def test_message_normalization_handles_strict_chat_templates(self):
        messages = normalize_messages([
            {"role": "user", "content": "uno"},
            {"role": "system", "content": "sistema A"},
            {"role": "user", "content": "dos"},
            {"role": "tool", "content": "resultado"},
            {"role": "system", "content": "sistema B"},
        ])
        self.assertEqual(messages[0]["role"], "system")
        self.assertIn("sistema A\n\nsistema B", messages[0]["content"])
        self.assertEqual(messages[1]["role"], "user")
        self.assertIn("uno\n\ndos\n\n[TOOL]\nresultado", messages[1]["content"])

    def test_native_inventory_exposes_loaded_model_metadata_and_auth(self):
        session = _Session(gets=[_Response(payload={"models": [{
            "type": "llm", "key": "qwen/qwen3-8b", "display_name": "Qwen 3 8B",
            "params_string": "8B", "max_context_length": 32768,
            "quantization": {"name": "Q4_K_M"},
            "loaded_instances": [{"id": "qwen/qwen3-8b", "config": {"context_length": 16384}}],
            "capabilities": {"trained_for_tool_use": True},
        }]})])
        client = LMStudioClient("http://localhost:1234", api_key="test-token", session=session)

        inventory = client.model_inventory()

        self.assertEqual(inventory[0]["id"], "qwen/qwen3-8b")
        self.assertTrue(inventory[0]["loaded"])
        self.assertEqual(inventory[0]["context_length"], 16384)
        self.assertEqual(session.get_calls[0][1]["headers"]["Authorization"], "Bearer test-token")

    def test_falls_back_to_openai_models_endpoint_on_old_lmstudio(self):
        session = _Session(gets=[
            _Response(404, {"error": "not found"}),
            _Response(payload={"data": [{"id": "legacy-model", "object": "model"}]}),
        ])
        client = LMStudioClient(session=session)

        self.assertEqual(client.models(), ["legacy-model"])
        self.assertTrue(session.get_calls[1][0].endswith("/v1/models"))

    def test_json_schema_is_sent_with_positive_token_limit(self):
        session = _Session(posts=[_chat_response("```json\n" + json.dumps(VALID_AGENT_RESPONSE) + "\n```")])
        client = LMStudioClient(session=session)

        result = client.chat_json("qwen", [{"role": "user", "content": "hola"}])

        payload = session.post_calls[0][1]["json"]
        self.assertGreater(payload["max_tokens"], 0)
        self.assertEqual(payload["response_format"]["type"], "json_schema")
        self.assertEqual(result["message"], "Respuesta correcta")
        self.assertEqual(result["_usage"]["total_tokens"], 21)

    def test_structured_output_failure_retries_without_schema(self):
        session = _Session(posts=[
            _Response(400, {"error": {"message": "response_format json_schema unsupported"}}),
            _chat_response(),
        ])
        client = LMStudioClient(session=session)

        result = client.chat_json("small-model", [{"role": "user", "content": "hola"}])

        self.assertEqual(result["message"], "Respuesta correcta")
        self.assertEqual(len(session.post_calls), 2)
        self.assertIn("response_format", session.post_calls[0][1]["json"])
        self.assertNotIn("response_format", session.post_calls[1][1]["json"])

    def test_stream_accepts_sse_with_or_without_space_and_reasoning(self):
        first = {"choices": [{"delta": {"reasoning_content": "pienso "}}]}
        second = {"choices": [{"delta": {"content": json.dumps(VALID_AGENT_RESPONSE)}, "finish_reason": "stop"}]}
        usage = {"choices": [], "usage": {"total_tokens": 34}}
        response = _Response(lines=[
            ("data:" + json.dumps(first)).encode(),
            ("data: " + json.dumps(second)).encode(),
            ("data: " + json.dumps(usage)).encode(),
            b"data: [DONE]",
        ])
        session = _Session(posts=[response])
        client = LMStudioClient(session=session)
        deltas = []

        result = client.chat_json(
            "qwen", [{"role": "user", "content": "hola"}],
            on_delta=lambda channel, text: deltas.append((channel, text)),
        )

        self.assertEqual(result["message"], "Respuesta correcta")
        self.assertEqual(result["_reasoning_content"], "pienso ")
        self.assertEqual(result["_usage"]["total_tokens"], 34)
        self.assertEqual(deltas[0], ("reasoning", "pienso "))

    def test_stream_decodes_spanish_and_emoji_as_utf8(self):
        payload = dict(VALID_AGENT_RESPONSE)
        payload["message"] = "Investigación válida con solución 🔎"
        chunk = {"choices": [{"delta": {"content": json.dumps(payload, ensure_ascii=False)},
                               "finish_reason": "stop"}]}
        response = _Response(lines=[
            ("data: " + json.dumps(chunk, ensure_ascii=False)).encode("utf-8"),
            b"data: [DONE]",
        ])
        client = LMStudioClient(session=_Session(posts=[response]))

        result = client.chat_json(
            "qwen", [{"role": "user", "content": "investiga"}], on_delta=lambda *_: None,
        )

        self.assertEqual(result["message"], "Investigación válida con solución 🔎")
        self.assertIn("Investigación", result["_stream_raw"])

    def test_plain_text_is_preserved_as_terminal_compatible_response(self):
        result = parse_agent_json("La revisión terminó sin hallazgos.")

        self.assertTrue(result["_json_parse_error"])
        self.assertTrue(result["task_complete"])
        self.assertEqual(result["message"], "La revisión terminó sin hallazgos.")

    def test_diagnostics_explains_connection_failure(self):
        session = _Session(gets=[requests.ConnectionError("offline")])
        result = LMStudioClient(session=session).diagnostics()

        self.assertFalse(result["online"])
        self.assertIn("inicia Local Server", result["hint"])


if __name__ == "__main__":
    unittest.main()
