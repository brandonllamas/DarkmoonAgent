import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from skills.pentest_skils import web_asset_mirror


class _FixtureHandler(BaseHTTPRequestHandler):
    ROUTES = {
        "/": ("text/html", b"""<!doctype html><html><head>
          <link rel='stylesheet' href='/app.css'><script src='/app.js'></script>
          </head><body><a href='/about'>About</a><img src='/img.png'></body></html>"""),
        "/about": ("text/html", b"<html><body>about</body></html>"),
        "/app.css": ("text/css", b"@font-face{src:url('/font.woff2')}"),
        "/app.js": ("application/javascript", b"fetch('/api/users');const routes=[{path:'/dashboard'}];\n//# sourceMappingURL=app.js.map"),
        "/app.js.map": ("application/json", b'{"version":3,"sources":["src/app.js"]}'),
        "/img.png": ("image/png", b"\x89PNG\r\n\x1a\nfixture"),
        "/font.woff2": ("font/woff2", b"woff2-fixture"),
    }

    def do_GET(self):
        route = self.path.split("?", 1)[0]
        if route not in self.ROUTES:
            self.send_error(404)
            return
        content_type, body = self.ROUTES[route]
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class WebAssetMirrorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_mirror_and_route_analysis(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = f"http://127.0.0.1:{self.server.server_port}/"
            result = web_asset_mirror.run(
                target=target, output_dir=temp_dir, depth="2", max_pages="10",
                max_assets="20", workers="4", allow_external="false",
            )
            self.assertTrue(result["success"], result["output"])
            self.assertGreaterEqual(result["stats"]["pages"], 2)
            self.assertGreaterEqual(result["stats"]["assets"], 5)
            manifest = json.loads(Path(result["manifest_file"]).read_text(encoding="utf-8"))
            urls = {item["url"] for item in manifest["files"]}
            self.assertIn(target + "app.js", urls)
            self.assertIn(target + "app.js.map", urls)
            self.assertIn(target + "font.woff2", urls)

            analyzed = web_asset_mirror.run(
                action="analyze", capture=result["artifact_root"], output_dir=temp_dir,
                query="rutas", ai="false",
            )
            self.assertTrue(analyzed["success"], analyzed["output"])
            self.assertIn("/api/users", analyzed["output"])
            self.assertIn("/dashboard", analyzed["output"])


if __name__ == "__main__":
    unittest.main()
