import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from skills.pentest_skils import web_asset_mirror


class _FixtureHandler(BaseHTTPRequestHandler):
    ROUTES = {
        "/": ("text/html", b"""<!doctype html><html><head>
          <link rel='stylesheet' href='/app.css'><script src='/app.js'></script>
          </head><body><a href='/about'>About</a><img src='/img.png'></body></html>"""),
        "/about": ("text/html", b"<html><body>about</body></html>"),
        "/app.css": ("text/css", b"@font-face{src:url('/font.woff2')}"),
        "/app.js": ("application/javascript", b"""fetch('/api/users?limit=10',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:user.name,email:user.email})}).then(r=>r.json());
          const routes=[{path:'/dashboard'}];
          const graphUrl='/graphql'; fetch(graphUrl);
          const operation=`query CurrentUser { viewer { id } }`;
          const firebaseConfig={projectId:'demo-project',authDomain:'demo.firebaseapp.com'};
          const usersCollection='users'; collection(db,usersCollection); new WebSocket('wss://socket.example/ws');
          const apiOrigin='https://api.example.test';
          const ordersUrl=apiOrigin + '/v2/orders'; axios.get(ordersUrl);
          const unusedUrl='https://unused.example.test/should-not-appear';
          const params=new URLSearchParams({page:1,sort:'name'});
          const polyfillExamples=['http://a','/a/b','/./']; function child(x){return x}
          //# sourceMappingURL=app.js.map"""),
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
            analysis_path = Path(result["analysis_file"])
            self.assertTrue(analysis_path.is_file())
            analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
            kinds = {item["kind"] for item in analysis["items"]}
            self.assertTrue({"api", "route", "server", "query_param", "firebase",
                             "graphql", "websocket"}.issubset(kinds))
            self.assertGreaterEqual(analysis["file_types"].get("css", 0), 1)
            self.assertTrue(any(item["method"] == "POST" and "/api/users" in item["value"]
                                for item in analysis["items"]))
            request = next(item for item in analysis["items"] if "/api/users" in item["value"])
            self.assertEqual(request["body"]["type"], "json")
            self.assertEqual(set(request["body"]["fields"]), {"name", "email"})
            self.assertEqual(request["headers"][0]["name"], "Content-Type")
            self.assertIn("JSON", request["response"]["formats"])
            self.assertTrue(any(item["kind"] == "query_param" and item["value"] == "limit"
                                for item in analysis["items"]))
            self.assertFalse(any(item["value"] in {"http://a", "/a/b", "/./"}
                                 for item in analysis["items"]))
            orders = next(item for item in analysis["items"] if item["value"].endswith("/v2/orders"))
            self.assertEqual(orders["value"], "https://api.example.test/v2/orders")
            self.assertEqual([item["symbol"] for item in orders["declarations"]],
                             ["ordersUrl", "apiOrigin"])
            self.assertEqual(orders["consumers"][0]["callee"], "axios.get")
            self.assertGreater(orders["consumers"][0]["offset"], orders["declarations"][0]["offset"])
            self.assertFalse(any("unused.example.test" in item["value"]
                                 for item in analysis["items"]))
            firebase_resource = next(item for item in analysis["items"]
                                     if item["kind"] == "firebase" and item["subtype"] == "resource")
            self.assertEqual(firebase_resource["value"], "collection: users")
            self.assertEqual(firebase_resource["declarations"][0]["symbol"], "usersCollection")
            self.assertEqual(firebase_resource["consumers"][0]["callee"], "firebase.collection")

            analyzed = web_asset_mirror.run(
                action="analyze", capture=result["artifact_root"], output_dir=temp_dir,
                query="rutas", ai="false",
            )
            self.assertTrue(analyzed["success"], analyzed["output"])
            self.assertIn("/api/users", analyzed["output"])
            self.assertIn("/dashboard", analyzed["output"])

    def test_secondary_ai_verifier_rejects_false_positives(self):
        candidates = [
            {"kind": "api", "subtype": "configured_endpoint", "value": "http://a",
             "method": "GET", "confidence": .8, "source": "polyfills.js", "line": 1,
             "evidence": "URL parser test http://a"},
            {"kind": "api", "subtype": "fetch", "value": "/api/orders", "method": "POST",
             "confidence": .95, "source": "app.js", "line": 4,
             "evidence": "fetch('/api/orders',{method:'POST',body:payload})"},
        ]
        verdict = json.dumps({"results": [
            {"id": 1, "verdict": "rejected", "confidence": .99,
             "reason": "URL de prueba del polyfill", "role": "framework"},
            {"id": 2, "verdict": "confirmed", "confidence": .98,
             "reason": "llamada fetch real", "role": "backend",
             "request_summary": "POST /api/orders", "response_summary": "no inferida"},
        ]})
        with patch.object(web_asset_mirror, "chat_text", return_value=verdict):
            accepted, rejected, verifier = web_asset_mirror._verify_inventory_with_ai(candidates, "test")
        self.assertEqual([item["value"] for item in accepted], ["/api/orders"])
        self.assertEqual([item["value"] for item in rejected], ["http://a"])
        self.assertEqual(verifier["status"], "complete")

    def test_cross_file_alias_and_configured_clients_are_traced(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = Path(temp_dir) / "capture"
            asset_dir = capture / "assets" / "example.test"
            asset_dir.mkdir(parents=True)
            (asset_dir / "config.js").write_text(
                "window.API_ORIGIN='https://backend.example.test/v3';\n"
                "const gqlOrigin='https://backend.example.test/graphql';\n",
                encoding="utf-8",
            )
            (asset_dir / "app.js").write_text(
                "const invoicesUrl=window.API_ORIGIN + '/invoices';\n"
                "fetch(invoicesUrl,{method:'GET'});\n"
                "axios.get(invoicesUrl);\n"
                "const billing=axios.create({baseURL:window.API_ORIGIN});\n"
                "billing.post('/payments',{amount,total});\n"
                "const graph=new GraphQLClient(gqlOrigin);\n"
                "graph.request(`query Viewer { viewer { id } }`);\n"
                "const documentation='https://docs.example.test/unused';\n",
                encoding="utf-8",
            )
            (capture / "manifest.json").write_text(json.dumps({
                "target": "https://example.test/", "files": [
                    {"local_path": "assets/example.test/config.js",
                     "url": "https://example.test/config.js", "kind": "asset"},
                    {"local_path": "assets/example.test/app.js",
                     "url": "https://example.test/app.js", "kind": "asset"},
                ], "stats": {"pages": 1, "assets": 2},
            }), encoding="utf-8")

            result = web_asset_mirror.run(
                action="analyze", capture=str(capture), output_dir=temp_dir,
                ai="false", max_files="100",
            )
            self.assertTrue(result["success"], result["output"])
            items = result["analysis"]["items"]
            invoices = next(item for item in items if item["value"].endswith("/v3/invoices"))
            self.assertEqual([definition["source"] for definition in invoices["declarations"]], [
                "assets/example.test/app.js", "assets/example.test/config.js",
            ])
            self.assertEqual([consumer["callee"] for consumer in invoices["consumers"]],
                             ["fetch", "axios.get"])
            payments = next(item for item in items if item["value"].endswith("/v3/payments"))
            self.assertEqual(payments["consumers"][0]["callee"], "billing.post")
            self.assertTrue(any(definition["kind"] == "http_client"
                                for definition in payments["declarations"]))
            graphql = next(item for item in items
                           if item["kind"] == "graphql" and item["subtype"] == "graphql_client")
            self.assertEqual(graphql["value"], "https://backend.example.test/graphql")
            self.assertEqual(graphql["consumers"][0]["callee"], "graph.request")
            self.assertFalse(any("docs.example.test" in item["value"] for item in items))


if __name__ == "__main__":
    unittest.main()
