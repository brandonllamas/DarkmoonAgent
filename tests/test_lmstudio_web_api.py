import unittest
from unittest.mock import patch

import web_server


class LMStudioWebApiTest(unittest.TestCase):
    def setUp(self):
        self.client = web_server.app.test_client()

    def test_status_endpoint_forwards_forced_refresh(self):
        diagnostic = {
            "online": False, "url": "http://localhost:1234/v1",
            "models": [], "model_count": 0, "loaded_count": 0,
            "error": "offline", "hint": "inicia Local Server",
        }
        with patch.object(web_server, "lmstudio_diagnostics", return_value=diagnostic) as mocked:
            response = self.client.get("/api/lmstudio/status?force=1")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["hint"], "inicia Local Server")
        mocked.assert_called_once_with(force=True)

    def test_inference_test_uses_loaded_model(self):
        diagnostic = {
            "online": True, "url": "http://localhost:1234/v1",
            "models": [
                {"id": "downloaded", "loaded": False},
                {"id": "loaded-model", "loaded": True},
            ],
            "model_count": 2, "loaded_count": 1, "error": "", "hint": "",
        }
        with patch.object(web_server, "lmstudio_diagnostics", return_value=diagnostic), \
                patch("lmstudio_client.lmstudio_chat_text", return_value="OK") as chat:
            response = self.client.post("/api/lmstudio/test", json={"deep": True})

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["inference_ok"])
        self.assertEqual(body["model_tested"], "loaded-model")
        self.assertEqual(chat.call_args.args[0], "loaded-model")

    def test_inference_test_does_not_call_model_while_offline(self):
        diagnostic = {
            "online": False, "url": "http://localhost:1234/v1",
            "models": [], "model_count": 0, "loaded_count": 0,
            "error": "offline", "hint": "inicia Local Server",
        }
        with patch.object(web_server, "lmstudio_diagnostics", return_value=diagnostic), \
                patch("lmstudio_client.lmstudio_chat_text") as chat:
            response = self.client.post("/api/lmstudio/test", json={"deep": True})

        self.assertEqual(response.status_code, 503)
        chat.assert_not_called()


if __name__ == "__main__":
    unittest.main()
