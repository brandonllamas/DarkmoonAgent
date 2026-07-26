import json
import tempfile
import unittest
from pathlib import Path

import web_server


class AssetApiTest(unittest.TestCase):
    def test_capture_tree_preview_and_path_guard(self):
        original_out = web_server.OUT_DIR
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                web_server.OUT_DIR = Path(temp_dir)
                capture = Path(temp_dir) / "project" / "web_assets" / "capture_one"
                (capture / "assets" / "site").mkdir(parents=True)
                (capture / "assets" / "site" / "app.js").write_text(
                    "fetch('/api/test')", encoding="utf-8")
                (capture / "manifest.json").write_text(json.dumps({
                    "target": "https://example.test", "created_at": "2026-01-01T00:00:00",
                    "stats": {"pages": 1, "assets": 1, "bytes": 18, "errors": 0},
                }), encoding="utf-8")

                client = web_server.app.test_client()
                captures = client.get("/api/projects/project/assets")
                self.assertEqual(captures.status_code, 200)
                self.assertEqual(captures.get_json()["captures"][0]["id"], "capture_one")

                tree = client.get("/api/projects/project/assets/tree?capture=capture_one")
                self.assertEqual(tree.status_code, 200)
                paths = {item["path"] for item in tree.get_json()["files"]}
                self.assertIn("assets/site/app.js", paths)

                preview = client.get(
                    "/api/projects/project/assets/file?capture=capture_one&path=assets%2Fsite%2Fapp.js")
                self.assertEqual(preview.status_code, 200)
                self.assertIn("/api/test", preview.get_json()["content"])

                analyzed = client.post(
                    "/api/projects/project/assets/analyze",
                    json={"capture": "capture_one", "max_files": 100, "verify_ai": False},
                )
                self.assertEqual(analyzed.status_code, 200, analyzed.get_data(as_text=True))
                analysis = analyzed.get_json()["analysis"]
                self.assertEqual(analysis["version"], 4)
                self.assertEqual(analysis["stats"]["api"], 1)
                self.assertEqual(analysis["stats"]["consumers"], 1)
                self.assertEqual(analysis["items"][0]["value"], "/api/test")
                self.assertEqual(analysis["items"][0]["declarations"][0]["kind"], "inline_literal")
                self.assertEqual(analysis["items"][0]["consumers"][0]["callee"], "fetch")

                fetched_analysis = client.get(
                    "/api/projects/project/assets/analysis?capture=capture_one")
                self.assertEqual(fetched_analysis.status_code, 200)
                self.assertEqual(fetched_analysis.get_json()["analysis"]["stats"]["api"], 1)

                escaped = client.get("/api/projects/project/assets/tree?capture=..")
                self.assertEqual(escaped.status_code, 403)
        finally:
            web_server.OUT_DIR = original_out


if __name__ == "__main__":
    unittest.main()
