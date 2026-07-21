import json
import unittest

import agent


class _FakeResponse:
    ok = True
    status_code = 200
    text = ""

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def iter_lines(self, decode_unicode=True):
        chunks = [
            {"choices": [{"delta": {"reasoning_content": "pensando "}, "finish_reason": None}]},
            {"choices": [{"delta": {"content": '{"thinking":"ok",'}, "finish_reason": None}]},
            {"choices": [{"delta": {"content": '"commands":[],"message":"listo","task_complete":true}'}, "finish_reason": "stop"}]},
            {"choices": [], "usage": {"total_tokens": 42}},
        ]
        for chunk in chunks:
            yield ("data: " + json.dumps(chunk)).encode("utf-8")
        yield b"data: [DONE]"


class _FakeHttp:
    def post(self, *_args, **_kwargs):
        return _FakeResponse()


class DeepSeekStreamTest(unittest.TestCase):
    def test_stream_collects_reasoning_content_and_usage(self):
        original_http = agent._HTTP
        deltas = []
        try:
            agent._HTTP = _FakeHttp()
            result = agent.call_deepseek_stream(
                "deepseek-chat", [{"role": "user", "content": "hola"}],
                on_delta=lambda channel, text: deltas.append((channel, text)),
            )
        finally:
            agent._HTTP = original_http
        self.assertEqual(result["message"], "listo")
        self.assertTrue(result["task_complete"])
        self.assertEqual(result["_reasoning_content"], "pensando ")
        self.assertEqual(result["_usage"]["total_tokens"], 42)
        self.assertEqual(deltas[0], ("reasoning", "pensando "))
        self.assertIn('"message":"listo"', result["_stream_raw"])


if __name__ == "__main__":
    unittest.main()
