"""Offline unit tests for atarus-webscan.

Modules run against a throwaway HTTP server bound to 127.0.0.1. Nothing
leaves the machine and no third-party test libraries are needed.
"""
import http.server
import os
import tempfile
import threading
import unittest
from unittest import mock

from atarus_webscan.models import ScanResult, Finding
from atarus_webscan.scope import ScopeValidator
from atarus_webscan.modules import discover, headers, methods, dangerous_files, technology, risk
from atarus_webscan.reports import html, json_export

INDEX = b"<html><head><title>lab</title></head><body>" + b"x" * 300 + b"<div id='__NEXT_DATA__'></div><script src='/_next/a.js'></script></body></html>"
FILES = {"/.env": b"DB_PASSWORD=lab-only-not-real\nAPI_KEY=lab-only-not-real\n" * 3}


class Handler(http.server.BaseHTTPRequestHandler):
    catch_all = False

    def log_message(self, *args):
        pass

    def _send(self, code, body=b"", extra=None):
        self.send_response(code)
        self.send_header("Server", "nginx/1.31.7")
        self.send_header("X-Powered-By", "Express 4.17.1")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            return self._send(200, INDEX, {"Content-Type": "text/html"})
        if self.path in FILES:
            return self._send(200, FILES[self.path])
        if self.catch_all:
            return self._send(200, b"<html>catch all page " + b"y" * 200 + b"</html>")
        return self._send(404, b"not found")

    do_HEAD = do_GET

    def do_PUT(self):
        self._send(201, b"created")

    def do_OPTIONS(self):
        self._send(200, b"", {"Allow": "GET, HEAD, PUT, OPTIONS"})

    def do_DELETE(self):
        self._send(405, b"no")

    do_POST = do_PATCH = do_TRACE = do_CONNECT = do_DELETE


class LabServer:
    def __init__(self, catch_all=False):
        handler = type("H", (Handler,), {"catch_all": catch_all})
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class ScopeTests(unittest.TestCase):
    def test_normalize(self):
        s = ScopeValidator("HTTP://Lab.Example.com:8443/path")
        self.assertEqual(s.target, "lab.example.com")
        self.assertEqual(s.normalize_target(), "http://lab.example.com")
        self.assertTrue(s.is_in_scope("https://api.lab.example.com/x"))
        self.assertFalse(s.is_in_scope("https://lab.example.com.evil.net"))

    def test_rejects_bare_names(self):
        with self.assertRaises(ValueError):
            ScopeValidator("localhost")


class ModuleTests(unittest.TestCase):
    def setUp(self):
        self.srv = LabServer()

    def tearDown(self):
        self.srv.close()

    def test_discover_headers_methods_files(self):
        r = ScanResult(target="lab.test")
        self.assertTrue(discover.run(r, self.srv.url).success)
        self.assertEqual(r.framework, "Next.js")
        self.assertEqual(r.site_type, "spa")

        headers.run(r, self.srv.url)
        missing = {f.title for f in r.findings if f.category == "headers"}
        self.assertIn("Missing Content-Security-Policy header", missing)
        self.assertIn("Version disclosure via server header", missing)

        methods.run(r, self.srv.url)
        self.assertIn("PUT", r.methods_allowed)
        self.assertTrue(any(f.title == "PUT method enabled" for f in r.findings))

        dangerous_files.run(r, self.srv.url)
        exposed = [f for f in r.findings if f.category == "dangerous_files"]
        self.assertEqual([f.title for f in exposed], ["Environment file exposed"])

        risk.run(r, self.srv.url)
        self.assertGreater(r.risk_score, 0)

    def test_catch_all_responses_are_filtered(self):
        self.srv.close()
        self.srv = LabServer(catch_all=True)
        r = ScanResult(target="lab.test")
        res = dangerous_files.run(r, self.srv.url)
        titles = [f.title for f in r.findings]
        self.assertEqual(titles, ["Environment file exposed"])
        self.assertIn("false positives filtered", res.message)

    def test_technology_without_nuclei(self):
        with mock.patch.object(technology, "_find_nuclei", return_value=""):
            res = technology.run(ScanResult(target="lab.test"), self.srv.url)
        self.assertFalse(res.success)
        self.assertIn("nuclei not found", res.message)


class RiskTests(unittest.TestCase):
    def test_levels(self):
        r = ScanResult(target="lab.test", findings=[Finding(title="a", severity="critical", description="")] * 3)
        risk.run(r, "")
        self.assertEqual((r.risk_score, r.risk_level), (75, "critical"))
        r = ScanResult(target="lab.test")
        risk.run(r, "")
        self.assertEqual(r.risk_level, "clean")


class ReportTests(unittest.TestCase):
    def test_html_and_json(self):
        r = ScanResult(target="lab.test", risk_level="high", risk_score=50)
        r.findings.append(Finding(title="<script>alert(1)</script>", severity="high", description="d", evidence="e"))
        with tempfile.TemporaryDirectory() as d:
            with open(html.generate(r, d)) as f:
                content = f.read()
            self.assertIn("atarus-webscan | lab.test", content)
            self.assertNotIn("<script>alert(1)</script>", content)
            self.assertIn("&lt;script&gt;", content)
            self.assertTrue(os.path.exists(json_export.generate(r, d)))

    def test_template_ships_inside_package(self):
        import atarus_webscan
        pkg = os.path.dirname(atarus_webscan.__file__)
        self.assertTrue(os.path.exists(os.path.join(pkg, "templates", "report.html")))


if __name__ == "__main__":
    unittest.main()
