import os
import unittest
from unittest.mock import patch

import agent
from skills.pentest_skils import wpscan_run


class WPScanCommandNormalizationTest(unittest.TestCase):
    def test_raw_command_is_routed_through_skill_and_drops_api_flags(self):
        raw = (
            "wpscan --url https://example.com --enumerate vp,u "
            "--api-key $WPSCAN_API_KEY --api-token exposed-value --random-user-agent"
        )

        mapped = agent._map_raw_to_skill(raw)

        self.assertEqual(
            mapped,
            "SKILL:wpscan_run target=https://example.com enumerate=vp,u",
        )
        self.assertNotIn("--api-key", mapped)
        self.assertNotIn("exposed-value", mapped)

    def test_markdown_link_target_is_unwrapped(self):
        raw = "wpscan --url '[https://example.com](https://example.com)' -e vp,u"

        mapped = agent._map_raw_to_skill(raw)

        self.assertEqual(
            mapped,
            "SKILL:wpscan_run target=https://example.com enumerate=vp,u",
        )

    @patch.object(wpscan_run.subprocess, "run")
    def test_skill_uses_api_token_option_only(self, run_process):
        run_process.return_value.returncode = 0
        run_process.return_value.stdout = ""
        run_process.return_value.stderr = ""

        with patch.dict(os.environ, {"WPSCAN_API_KEY": "configured-token"}):
            result = wpscan_run.run("https://example.com", enumerate="vp,u")

        command = run_process.call_args.args[0]
        self.assertTrue(result["success"])
        self.assertIn("--api-token", command)
        self.assertNotIn("--api-key", command)
        self.assertEqual(command[command.index("--api-token") + 1], "configured-token")


if __name__ == "__main__":
    unittest.main()
