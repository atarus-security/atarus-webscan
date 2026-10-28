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
from atarus_webscan.transport import Client
from atarus_webscan.modules import discover, headers, methods, dangerous_files, write_methods, technology, risk
from atarus_webscan.reports import html, json_export

INDEX = b"<html><head><title>lab</title></head><body>" + b"x" * 300 + b"<div id='__NEXT_DATA__'></div><script src='/_next/a.js'></script></body></html>"
FILES = {"/.env": b"DB_PASSWORD=lab-only-not-real\nAPI_KEY=lab-only-not-real\n" * 3}


class Handler(http.server.BaseHTTPRequestHandler):
    catch_all = False
    seen = None  # set per server: list of (method, path, range header)

    def log_message(self, *args):
        pass

    def _record(self):
        if self.seen is not None:
            self.seen.append((self.command, self.path, self.headers.get("Range")))

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
        self._record()
        if self.path == "/":
            return self._send(200, INDEX, {"Content-Type": "text/html"})
        if self.path in FILES:
            return self._send(200, FILES[self.path])
        if self.catch_all:
            return self._send(200, b"<html>catch all page " + b"y" * 200 + b"</html>")
        return self._send(404, b"not found")

    do_HEAD = do_GET

    def do_PUT(self):
        self._record()
        self._send(201, b"created")

    def do_OPTIONS(self):
        self._record()
        self._send(200, b"", {"Allow": "GET, HEAD, PUT, OPTIONS"})

    def do_DELETE(self):
        self._record()
        self._send(405, b"no")

    do_POST = do_PATCH = do_TRACE = do_CONNECT = do_DELETE


class LabServer:
    def __init__(self, catch_all=False):
        self.seen = []
        handler = type("H", (Handler,), {"catch_all": catch_all, "seen": self.seen})
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def client(self):
        return Client(ScopeValidator(self.url), rate_limit=0)

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class ScopeTests(unittest.TestCase):
    def test_keeps_scheme_host_port_and_path(self):
        s = ScopeValidator("HTTP://Lab.Example.com:8443/path/")
        self.assertEqual(s.target, "lab.example.com:8443")
        self.assertEqual(s.normalize_target(), "http://lab.example.com:8443/path")
        self.assertEqual(s.origin, "http://lab.example.com:8443")
        self.assertTrue(s.same_origin("http://lab.example.com:8443/other"))
        self.assertFalse(s.same_origin("http://lab.example.com/other"), "a different port is a different origin")
        self.assertFalse(s.same_origin("https://lab.example.com:8443/other"), "a different scheme is a different origin")
        self.assertFalse(s.same_origin("http://api.lab.example.com:8443/x"), "subdomains are not the named host")
        self.assertFalse(s.is_in_scope("https://lab.example.com.evil.net"))

    def test_default_scheme_and_port(self):
        s = ScopeValidator("lab.example.com")
        self.assertEqual(s.normalize_target(), "https://lab.example.com")
        self.assertEqual(s.target, "lab.example.com")
        self.assertTrue(s.same_origin("https://lab.example.com:443/"), "an explicit default port is the same origin")

    def test_rejects_bare_names(self):
        with self.assertRaises(ValueError):
            ScopeValidator("localhost")
        with self.assertRaises(ValueError):
            ScopeValidator("ftp://lab.example.com")


class ModuleTests(unittest.TestCase):
    def setUp(self):
        self.srv = LabServer()
        self.client = self.srv.client()

    def tearDown(self):
        self.srv.close()

    def test_discover_headers_methods_files(self):
        r = ScanResult(target="lab.test")
        self.assertTrue(discover.run(r, self.client).success)
        self.assertEqual(r.framework, "Next.js")
        self.assertEqual(r.site_type, "spa")

        headers.run(r, self.client)
        missing = {f.title for f in r.findings if f.category == "headers"}
        self.assertIn("Missing Content-Security-Policy header", missing)
        self.assertIn("Version disclosure via server header", missing)
        self.assertEqual([m for m, _, _ in self.srv.seen if m == "GET"], ["GET"], "discover and headers share one GET")

        methods.run(r, self.client)
        self.assertEqual(r.methods_allowed, ["GET", "HEAD", "OPTIONS"])
        self.assertIn("PUT", r.methods_announced)
        self.assertTrue(any(f.title == "PUT method announced via OPTIONS" for f in r.findings))
        self.assertFalse(any(f.title == "PUT method enabled" for f in r.findings), "nothing state-changing was sent")

        dangerous_files.run(r, self.client)
        exposed = [f for f in r.findings if f.category == "dangerous_files"]
        self.assertEqual([f.title for f in exposed], ["Environment file exposed"])
        self.assertNotIn("lab-only-not-real", exposed[0].evidence)
        self.assertIn(f"{len(FILES['/.env'])} bytes", exposed[0].evidence)

        risk.run(r, self.client)
        self.assertGreater(r.risk_score, 0)

    def test_write_methods_only_hit_named_paths(self):
        r = ScanResult(target="lab.test", probe_paths=["/upload"])
        methods.run(r, self.client)
        res = write_methods.run(r, self.client)
        self.assertTrue(res.success)
        self.assertTrue(any(f.title == "PUT method enabled" for f in r.findings))
        self.assertFalse(any(f.title == "PUT method announced via OPTIONS" for f in r.findings), "confirmed supersedes announced")
        write_paths = {p for m, p, _ in self.srv.seen if m in ("POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT")}
        self.assertEqual(write_paths, {"/upload"})

    def test_write_methods_need_a_named_path(self):
        r = ScanResult(target="lab.test")
        res = write_methods.run(r, self.client)
        self.assertFalse(res.success)
        self.assertIn("--probe-path", res.message)
        self.assertEqual(self.srv.seen, [])

    def test_catch_all_responses_are_filtered(self):
        self.srv.close()
        self.srv = LabServer(catch_all=True)
        r = ScanResult(target="lab.test")
        res = dangerous_files.run(r, self.srv.client())
        titles = [f.title for f in r.findings]
        self.assertEqual(titles, ["Environment file exposed"])
        self.assertIn("false positives filtered", res.message)

    def test_technology_without_nuclei(self):
        with mock.patch.object(technology, "_find_nuclei", return_value=""):
            res = technology.run(ScanResult(target="lab.test"), self.client)
        self.assertFalse(res.success)
        self.assertIn("nuclei not found", res.message)
        self.assertEqual(self.srv.seen, [])


class RiskTests(unittest.TestCase):
    def test_levels(self):
        r = ScanResult(target="lab.test", findings=[Finding(title="a", severity="critical", description="")] * 3)
        risk.run(r)
        self.assertEqual((r.risk_score, r.risk_level), (75, "critical"))
        r = ScanResult(target="lab.test")
        risk.run(r)
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
