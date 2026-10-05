import sys
from pathlib import Path
import unittest
from unittest.mock import patch

import tool_manager


class DependencyTriggerTest(unittest.TestCase):
    def test_explicit_spanish_requests_are_detected(self):
        positives = [
            "instala dependencias",
            "Instálame todas las herramientas",
            "prepara el entorno completo",
            "instala todo lo necesario para funcionar",
        ]
        for message in positives:
            with self.subTest(message=message):
                self.assertTrue(tool_manager.is_dependency_install_request(message))

    def test_negated_or_unrelated_requests_are_not_detected(self):
        for message in ("no instales dependencias", "lista las dependencias", "instala nuclei"):
            with self.subTest(message=message):
                self.assertFalse(tool_manager.is_dependency_install_request(message))


class DependencyInstallerTest(unittest.TestCase):
    def tearDown(self):
        tool_manager.clear_tool_cache()
        tool_manager._LAST_INSTALL_ERRORS.clear()

    def test_pip_commands_use_the_running_python(self):
        command, error = tool_manager._prepare_install_command("pip", "pip3 install ldap3")
        self.assertFalse(error)
        self.assertIn("-m pip install", command)
        self.assertIn(sys.executable, command)
        self.assertNotIn("pip3 install", command)

    @patch.object(tool_manager, "install_tool", return_value=True)
    @patch.object(tool_manager, "install_python_dependencies", return_value={
        "total": 4, "ready_before": 4, "installed": [], "failed": [], "success": True,
    })
    @patch.object(tool_manager, "scan_tools", side_effect=[
        {"nmap": True, "nuclei": False},
        {"nmap": True, "nuclei": True},
    ])
    def test_full_install_report_is_verified(self, _scan, _python, install_tool):
        events = []
        report = tool_manager.install_all_dependencies(progress=events.append)

        self.assertTrue(report["success"])
        self.assertEqual(report["tools"]["ready_after"], 2)
        self.assertEqual(report["tools"]["installed"], ["nuclei"])
        install_tool.assert_called_once()
        self.assertEqual(events[-1]["status"], "complete")

    @patch.object(tool_manager, "install_tool", return_value=False)
    @patch.object(tool_manager, "install_python_dependencies", return_value={
        "total": 4, "ready_before": 4, "installed": [], "failed": [], "success": True,
    })
    @patch.object(tool_manager, "scan_tools", side_effect=[
        {"nmap": False},
        {"nmap": False},
    ])
    def test_partial_install_never_claims_full_success(self, _scan, _python, _install):
        tool_manager._LAST_INSTALL_ERRORS["nmap"] = "no hay un método compatible con este sistema"
        report = tool_manager.install_all_dependencies()

        self.assertFalse(report["success"])
        self.assertEqual(report["tools"]["missing"], ["nmap"])
        self.assertEqual(report["tools"]["unsupported"], ["nmap"])
        self.assertIn("parcialmente", tool_manager.format_dependency_report(report))

    def test_install_all_api_returns_the_verified_report(self):
        import web_server

        expected = {
            "success": True,
            "python": {"total": 4, "failed": []},
            "tools": {"total": 40, "ready_after": 40, "missing": []},
        }
        with patch.object(tool_manager, "install_all_dependencies", return_value=expected):
            response = web_server.app.test_client().post("/api/tools/install-all", json={})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), expected)

    def test_web_chat_installs_without_calling_the_llm_backend(self):
        import web_server

        emitted = []

        class Sink:
            def put(self, event):
                emitted.append(event)

        report = {
            "success": True,
            "python": {"total": 4, "failed": []},
            "tools": {"total": 40, "ready_after": 40, "installed": ["nuclei"], "missing": []},
        }

        def fake_install(progress=None):
            progress({"scope": "tool", "name": "nuclei", "status": "ready", "current": 1, "total": 1})
            return report

        with (
            patch.object(web_server, "load_session_in_project", return_value=([{"role": "system", "content": "x"}], "m", None)),
            patch.object(web_server.database, "create_session"),
            patch.object(web_server, "save_session"),
            patch.object(web_server, "LogWriter"),
            patch.object(web_server, "check_backend") as check_backend,
            patch.object(tool_manager, "install_all_dependencies", side_effect=fake_install),
            patch.object(tool_manager, "format_dependency_report", return_value="Entorno listo"),
        ):
            web_server._process_chat_turn(
                project_dir=Path("unused"), session_name="session_test",
                user_message="instala dependencias", model="m", event_queue=Sink(),
            )

        check_backend.assert_not_called()
        event_types = [event["type"] for event in emitted]
        self.assertIn("dependency_start", event_types)
        self.assertIn("dependency_progress", event_types)
        self.assertIn("dependency_done", event_types)
        self.assertEqual(event_types[-1], "done")


if __name__ == "__main__":
    unittest.main()
