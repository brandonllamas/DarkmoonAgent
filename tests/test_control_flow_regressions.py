import tempfile
import unittest
from pathlib import Path

import agent
import web_server


class ControlFlowRegressionTest(unittest.TestCase):
    def test_re_target_ignores_stray_filesystem_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "sample-binary"
            target.touch()
            root = Path(target.anchor)

            resolved = agent._resolve_re_target(
                f"bypass el login de {root} {target}",
                temp_dir,
            )

            self.assertEqual(Path(resolved), target)

    def test_re_target_preserves_missing_absolute_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "missing-binary"

            resolved = agent._resolve_re_target(
                f"analiza {target}",
                temp_dir,
            )

            self.assertEqual(Path(resolved), target)

    def test_re_target_preserves_posix_path_on_windows_host(self):
        target = "/media/sf_share/missing-binary"

        resolved = agent._resolve_re_target(
            f"analiza {target}",
            str(Path.cwd()),
        )

        self.assertEqual(resolved, target)

    def test_model_error_is_visible_and_terminal(self):
        message, terminal = web_server._model_response_message({
            "error": "Cannot perform the requested operation.",
            "task_complete": False,
        })

        self.assertEqual(message, "Cannot perform the requested operation.")
        self.assertTrue(terminal)

    def test_normal_message_is_not_terminal_error(self):
        message, terminal = web_server._model_response_message({
            "message": "Análisis terminado.",
            "task_complete": True,
        })

        self.assertEqual(message, "Análisis terminado.")
        self.assertFalse(terminal)


if __name__ == "__main__":
    unittest.main()
