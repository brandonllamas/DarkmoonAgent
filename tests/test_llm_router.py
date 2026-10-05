import unittest
import sqlite3
import tempfile
import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import agent
import web_server
from llm_router import infer_task_profile, model_capabilities, rank_candidates
from skills import llm_client
import database


CATALOG = [
    {"backend": "ollama", "model": "qwen2.5-coder:14b"},
    {"backend": "ollama", "model": "llama3.2:3b"},
    {"backend": "deepseek", "model": "deepseek-chat"},
    {"backend": "openrouter", "model": "anthropic/claude-sonnet-4"},
]


class RouterScoringTest(unittest.TestCase):
    def test_profiles_cover_reverse_recon_and_reports(self):
        self.assertEqual(
            infer_task_profile("decompila y analiza este binario ELF")["profile"],
            "reverse_engineering",
        )
        self.assertEqual(
            infer_task_profile("escanea subdominios rápido")["profile"],
            "tool_planning",
        )
        self.assertEqual(
            infer_task_profile("genera un reporte ejecutivo")["profile"],
            "report",
        )

    def test_local_policy_keeps_sensitive_work_on_local_model(self):
        route = rank_candidates(
            CATALOG,
            "implementa código Python para analizar un binario",
            policy="local",
        )
        self.assertEqual(route["choice"]["backend"], "ollama")
        self.assertEqual(route["choice"]["model"], "qwen2.5-coder:14b")

    def test_encoded_preference_pins_first_choice(self):
        route = rank_candidates(
            CATALOG,
            "analiza esta vulnerabilidad",
            preferred_model="deepseek::deepseek-chat",
        )
        self.assertEqual(route["choice"]["backend"], "deepseek")
        self.assertEqual(route["choice"]["model"], "deepseek-chat")

    def test_gemini_name_does_not_accidentally_match_mini(self):
        self.assertNotIn("fast", model_capabilities("google/gemini-2.5-pro", "openrouter"))
        self.assertIn("fast", model_capabilities("openai/gpt-4.1-mini", "openrouter"))


class AgentFallbackTest(unittest.TestCase):
    def test_provider_diversity_and_stream_failure_boundaries(self):
        candidates = [
            {"backend": "ollama", "model": f"local-{i}"} for i in range(4)
        ] + [{"backend": "lmstudio", "model": "loaded-model"}]
        route = {"candidates": candidates}
        for emitted in (False, True):
            with self.subTest(emitted=emitted), \
                    patch.object(agent, "LLM_BACKEND", "auto"), \
                    patch.object(agent, "select_llm_route", return_value=route), \
                    patch.dict(agent.os.environ, {"HACKERAGENT_ROUTER_FALLBACKS": "2"}):
                def dispatch(backend, model, messages, on_delta):
                    if backend == "ollama":
                        if emitted:
                            on_delta("content", "partial")
                        raise RuntimeError("offline")
                    return {"message": "ok"}
                with patch.object(agent, "_dispatch_llm_stream", side_effect=dispatch) as call:
                    if emitted:
                        with self.assertRaisesRegex(RuntimeError, "offline"):
                            agent.call_llm_stream("auto", [])
                        self.assertEqual(call.call_count, 1)
                    else:
                        result = agent.call_llm_stream("auto", [])
                        self.assertEqual(result["_routing"]["backend"], "lmstudio")
                        self.assertEqual(result["_routing"]["backend_name"], "LM Studio")
                        self.assertEqual(len(result["_routing"]["fallbacks"]), 1)

    def test_all_providers_fail_with_diagnostic(self):
        with patch.object(agent, "LLM_BACKEND", "auto"), \
                patch.object(agent, "select_llm_route", return_value={"candidates": CATALOG}), \
                patch.object(agent, "_dispatch_llm_json", side_effect=RuntimeError("offline")):
            with self.assertRaisesRegex(RuntimeError, "Todos los modelos seleccionados fallaron"):
                agent.call_llm("auto", [])

    def test_auto_mode_falls_back_to_second_provider(self):
        route = {
            "profile": "coding", "policy": "balanced", "reason": "test",
            "candidates": [
                {"backend": "ollama", "backend_name": "Ollama", "model": "coder-local"},
                {"backend": "deepseek", "backend_name": "DeepSeek API", "model": "deepseek-chat"},
            ],
        }
        original_backend = agent.LLM_BACKEND
        try:
            agent.LLM_BACKEND = "auto"
            with patch.object(agent, "select_llm_route", return_value=route), \
                    patch.object(agent, "call_ollama", side_effect=RuntimeError("offline")), \
                    patch.object(agent, "call_deepseek", return_value={"message": "ok"}):
                result = agent.call_llm("auto", [{"role": "user", "content": "programa esto"}])
        finally:
            agent.LLM_BACKEND = original_backend

        self.assertEqual(result["message"], "ok")
        self.assertEqual(result["_routing"]["backend"], "deepseek")
        self.assertEqual(len(result["_routing"]["fallbacks"]), 1)

    def test_shared_skill_client_also_falls_back(self):
        calls = []

        def fake_call(backend, model, *_args, **_kwargs):
            calls.append((backend, model))
            if backend == "ollama":
                raise llm_client.requests.ConnectionError("offline")
            return "respuesta"

        with patch.object(llm_client, "_catalog", return_value=CATALOG[:3]), \
                patch.object(llm_client, "_call_backend", side_effect=fake_call), \
                patch.dict(llm_client.os.environ, {"HACKERAGENT_LLM_BACKEND": "auto"}):
            result = llm_client.chat_text(
                [{"role": "user", "content": "implementa código"}],
                model="ollama::qwen2.5-coder:14b",
            )

        self.assertEqual(result, "respuesta")
        self.assertEqual(calls[0][0], "ollama")
        self.assertEqual(calls[-1][0], "deepseek")
        self.assertGreaterEqual(len(calls), 2)


class RouterApiTest(unittest.TestCase):
    def test_model_route_survives_database_reopen_and_web_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session.db"
            conn = sqlite3.connect(path)
            conn.row_factory = sqlite3.Row
            event = {"type": "model_route", "backend": "deepseek",
                     "backend_name": "DeepSeek API", "model": "deepseek-chat",
                     "profile": "coding", "policy": "balanced",
                     "reason": "fallback", "fallbacks": ["ollama/local: offline"]}
            try:
                with patch.object(database, "get_db", side_effect=lambda: conn):
                    database.init_db()
                    database.upsert_project("project", "Project", "", "full")
                    database.create_session("session", "project", "auto")
                    database.save_messages("session", [{"role": "user", "content": "hola"}])
                    streamer = web_server.EventStreamer("session", Path(tmp))
                    streamer.put(event)
                    streamer.put({"type": "done"})
                    conn.close()
                    conn = sqlite3.connect(path)
                    conn.row_factory = sqlite3.Row
                    client = web_server.app.test_client()
                    history = client.get("/api/projects/project/sessions/session/history").get_json()
                    replay = client.get("/api/projects/project/sessions/session/events").get_json()
                    self.assertEqual(history["model"], "auto")
                    self.assertEqual(replay["events"], [event])
                    if shutil.which("node"):
                        html = (Path(web_server.__file__).parent / "page" / "index.html").read_text(encoding="utf-8")
                        replay_js = html.split("async function loadEvents(", 1)[1].split("\nasync function deleteSession", 1)[0]
                        script = """
const assert = require('node:assert/strict');
const notices = [];
const appendEventNotice = (...args) => notices.push(args);
const renderFindingCounts = () => {};
const document = {querySelectorAll: () => []};
const fetch = async () => ({json: async () => (PAYLOAD)});
""".replace("PAYLOAD", json.dumps(replay))
                        script += "async function loadEvents(" + replay_js
                        script += """
loadEvents('project', 'session').then(() => {
  assert.equal(notices.length, 1);
  assert.match(notices[0][0], /DeepSeek API.*deepseek-chat.*coding.*1 fallback/);
  assert.equal(notices[0][1], 'warning');
  assert.equal(notices[0][2], 'Auto IA');
  assert.equal(notices[0][4], false);
}).catch(err => { console.error(err); process.exitCode = 1; });
"""
                        checked = subprocess.run(["node", "-e", script], capture_output=True, text=True)
                        self.assertEqual(checked.returncode, 0, checked.stderr)
                        self.assertEqual(checked.stderr, "")
            finally:
                conn.close()

    def test_models_endpoint_exposes_auto_and_explainable_route(self):
        route = rank_candidates(CATALOG, "tarea general del agente")
        original_backend = agent.LLM_BACKEND
        try:
            agent.LLM_BACKEND = "auto"
            with patch.object(web_server, "get_model_catalog", return_value=CATALOG), \
                    patch.object(web_server, "select_llm_route", return_value=route):
                response = web_server.app.test_client().get("/api/models")
        finally:
            agent.LLM_BACKEND = original_backend

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["available"])
        self.assertEqual(body["backend"], "auto")
        self.assertEqual(body["models"][0]["name"], "auto")
        self.assertEqual(body["router"]["providers"], 3)

    def test_router_policy_can_change_at_runtime(self):
        previous = web_server.os.environ.get("HACKERAGENT_ROUTER_POLICY")
        try:
            response = web_server.app.test_client().post(
                "/api/router/policy", json={"policy": "local"}
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["policy"], "local")
        finally:
            if previous is None:
                web_server.os.environ.pop("HACKERAGENT_ROUTER_POLICY", None)
            else:
                web_server.os.environ["HACKERAGENT_ROUTER_POLICY"] = previous


if __name__ == "__main__":
    unittest.main()
