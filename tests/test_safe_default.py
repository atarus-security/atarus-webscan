"""Tests for the passive default, target fidelity, the scope lock and the confirmation gate.

Standard library plus click's own CliRunner. The HTTP layer is replaced by a
fake transport that serves canned responses and records every request; the
socket layer is additionally guarded so that no test can reach a real host
by accident.
"""
import contextlib
import io
import json
import os
import select
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from click.testing import CliRunner
from rich.console import Console

from atarus_webscan import cli, scope as scope_module, runner as runner_module
from atarus_webscan.models import ScanResult
from atarus_webscan.modules import technology, dangerous_files, discover, headers
from atarus_webscan.runner import ModuleRunner, ModuleResult
from atarus_webscan.scope import ActiveScope, ScopeValidator
from atarus_webscan.transport import Client, OffOriginError, PROBE_READ_LIMIT, PAGE_READ_LIMIT, READ_CHUNK
from atarus_webscan.reports import html


EXPECTED_ACTIVE = ["dangerous_files", "write_methods", "technology"]
EXPECTED_PASSIVE = ["discover", "headers", "methods", "risk"]

NAMED = "https://lab.test:8443/app"
ORIGIN = "https://lab.test:8443"
PAGE = b"<html><head><title>lab</title></head><body>" + b"x" * 300 + b"<div id='__NEXT_DATA__'></div></body></html>"
SECRET = b"DB_PASSWORD=lab-only-not-real\n" * 700  # about 20 KB


def _network_refused(*args, **kwargs):
    raise AssertionError("a real network call was attempted")


def _quiet_console():
    return Console(file=io.StringIO(), width=120)


class _NetworkGuard:
    """Patches the socket layer so any unmocked connection fails loudly."""

    def __init__(self):
        self._patches = [
            mock.patch.object(socket.socket, "connect", side_effect=_network_refused),
            mock.patch.object(socket.socket, "connect_ex", side_effect=_network_refused),
            mock.patch.object(socket, "create_connection", side_effect=_network_refused),
            mock.patch.object(socket, "getaddrinfo", side_effect=_network_refused),
        ]

    def __enter__(self):
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._patches):
            p.stop()
        return False


class _FakeRaw:
    """Stands in for urllib3's response body. Records how much was asked for."""

    def __init__(self, body, reads):
        self._body = body
        self._reads = reads
        self._wire = 0

    def read(self, amt=None, decode_content=None):
        self._reads.append(amt)
        if amt is None:
            raise AssertionError("an unbounded read was attempted")
        chunk, self._body = self._body[:amt], self._body[amt:]
        self._wire += len(chunk)
        return chunk

    def tell(self):
        # urllib3 reports the bytes pulled off the wire; here nothing is encoded.
        return self._wire


class _ExpandingRaw(_FakeRaw):
    """A body that decodes to many times what came off the wire, like a gzip bomb."""

    # 8 KiB off the wire becomes 512 KiB, so the 2 MiB cap takes several reads.
    RATIO = 64

    def read(self, amt=None, decode_content=None):
        self._reads.append(amt)
        if amt is None:
            raise AssertionError("an unbounded read was attempted")
        self._wire += amt
        return b"\0" * (amt * self.RATIO)


class _FakeResponse:
    def __init__(self, status, headers, body, reads):
        from requests.structures import CaseInsensitiveDict
        self.status_code = status
        self.headers = CaseInsensitiveDict(headers)
        self.cookies = {}
        self.raw = _FakeRaw(body, reads)
        self.closed = False

    def close(self):
        self.closed = True


class FakeTransport:
    """Canned responses keyed by (METHOD, url). Records (method, url, headers) of every request.

    A route value is (status, headers, body). A missing route is a 404.
    The `*` method matches any method.
    """

    def __init__(self, routes):
        self.routes = routes
        self.sent = []
        self.reads = []

    def __call__(self, method, url, headers):
        self.sent.append((method, url, dict(headers)))
        route = self.routes.get((method, url)) or self.routes.get(("*", url))
        if route is None:
            return _FakeResponse(404, {"Content-Length": "9"}, b"not found", self.reads)
        status, hdrs, body = route
        hdrs = dict(hdrs)
        rng = headers.get("Range")
        if rng and status == 200 and body:
            end = int(rng.split("-")[1])
            part = body[: end + 1]
            hdrs["Content-Range"] = f"bytes 0-{len(part) - 1}/{len(body)}"
            hdrs["Content-Length"] = str(len(part))
            return _FakeResponse(206, hdrs, part, self.reads)
        hdrs.setdefault("Content-Length", str(len(body)))
        return _FakeResponse(status, hdrs, b"" if method == "HEAD" else body, self.reads)

    def methods(self):
        return sorted({m for m, _, _ in self.sent})

    def urls(self):
        return [u for _, u, _ in self.sent]


def _lab_routes(base=NAMED):
    return {
        ("GET", base): (200, {"Content-Type": "text/html", "Server": "nginx/1.31.7"}, PAGE),
        ("HEAD", base): (200, {"Server": "nginx/1.31.7"}, b""),
        ("OPTIONS", base): (200, {"Allow": "GET, HEAD, PUT, OPTIONS"}, b""),
        ("*", f"{base}/.env"): (200, {"Content-Type": "text/plain"}, SECRET),
        ("*", f"{ORIGIN}/upload"): (201, {}, b"created"),
    }


@contextlib.contextmanager
def _patched_transport(transport, resolved=("203.0.113.5",)):
    with mock.patch.object(Client, "_transport", transport), \
         mock.patch.object(runner_module, "resolve_host", return_value=list(resolved)), \
         _NetworkGuard():
        yield


def _invoke(args, transport, resolved=("203.0.113.5",)):
    with _patched_transport(transport, resolved), tempfile.TemporaryDirectory() as out:
        result = CliRunner().invoke(cli.main, ["--format", "json", "-o", out, "-r", "0"] + args)
        data = None
        for name in os.listdir(out):
            if name.endswith(".json"):
                with open(os.path.join(out, name)) as f:
                    data = json.load(f)
    return result, data


class ModuleClassificationTests(unittest.TestCase):
    def test_registry_marks_modules_that_send_more_than_the_safe_requests_active(self):
        self.assertEqual(cli.ACTIVE_MODULES, EXPECTED_ACTIVE)
        self.assertEqual(cli.PASSIVE_MODULES, EXPECTED_PASSIVE)


class PassiveDefaultTests(unittest.TestCase):
    def test_default_run_sends_only_get_head_and_options_to_the_named_url(self):
        transport = FakeTransport(_lab_routes())
        result, data = _invoke(["-t", NAMED + "/"], transport)
        self.assertEqual(result.exit_code, 0, result.output)

        self.assertEqual(transport.methods(), ["GET", "HEAD", "OPTIONS"])
        self.assertEqual(transport.urls(), [NAMED, NAMED, NAMED], "every request went to the named URL, once per method")
        self.assertEqual(data["mode"], "passive")
        self.assertEqual(data["named_url"], NAMED)
        self.assertEqual(data["requests_sent"], {"GET": 1, "HEAD": 1, "OPTIONS": 1})
        self.assertEqual(data["confirmation"], "")
        self.assertFalse(data["insecure"])
        self.assertEqual([m["module"] for m in data["modules_not_run"]], EXPECTED_ACTIVE)
        for m in data["modules_not_run"]:
            self.assertIn("passive mode", m["reason"])
        # The passive modules still did their job.
        self.assertEqual(data["framework"], "Next.js")
        self.assertEqual(data["methods_allowed"], ["GET", "HEAD", "OPTIONS"])
        self.assertIn("PUT", data["methods_announced"])
        self.assertTrue(any(f["title"] == "PUT method announced via OPTIONS" for f in data["findings"]))
        self.assertFalse(any(f["title"] == "PUT method enabled" for f in data["findings"]))
        self.assertIn("Modules not run: dangerous_files, write_methods, technology", result.output)

    def test_port_and_path_are_preserved(self):
        transport = FakeTransport(_lab_routes())
        result, data = _invoke(["-t", "HTTPS://Lab.Test:8443/app/"], transport)
        self.assertEqual(result.exit_code, 0, result.output)
        for url in transport.urls():
            self.assertTrue(url.startswith(ORIGIN + "/"), url)
        self.assertEqual(data["target"], "lab.test:8443")
        self.assertEqual(data["named_url"], NAMED)

    def test_tls_verification_is_on_by_default_and_insecure_is_recorded(self):
        captured = []
        original = Client._transport

        def spy(self, method, url, headers):
            captured.append(self.insecure)
            raise AssertionError("stop before the network")

        with mock.patch.object(Client, "_transport", spy), _NetworkGuard(), tempfile.TemporaryDirectory() as out:
            CliRunner().invoke(cli.main, ["-t", NAMED, "--format", "json", "-o", out, "-r", "0"])
        self.assertTrue(captured and not any(captured), "verify=True by default")

        transport = FakeTransport(_lab_routes())
        result, data = _invoke(["-t", NAMED, "--insecure"], transport)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(data["insecure"])
        self.assertIn("TLS verification: OFF (--insecure)", result.output)
        self.assertIs(Client._transport, original)

    def test_real_transport_passes_verify_from_the_insecure_flag(self):
        for insecure in (False, True):
            client = Client(ScopeValidator(NAMED), insecure=insecure, rate_limit=0)
            with mock.patch.object(client._session, "request") as req:
                client._transport("GET", NAMED, {})
            self.assertEqual(req.call_args.kwargs["verify"], not insecure)
            self.assertFalse(req.call_args.kwargs["allow_redirects"], "the HTTP library never follows redirects itself")
            self.assertTrue(req.call_args.kwargs["stream"], "bodies are read only up to the caller's limit")


class UsageErrorTests(unittest.TestCase):
    def _usage(self, args):
        with mock.patch.object(ModuleRunner, "run", side_effect=AssertionError("runner must not start")), _NetworkGuard():
            return CliRunner().invoke(cli.main, ["-t", NAMED] + args)

    def test_active_without_scope_exits_with_an_error(self):
        result = self._usage(["--active"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("--scope", result.output)

    def test_yes_without_scope_exits_with_an_error(self):
        result = self._usage(["--yes"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("--scope", result.output)

    def test_only_with_active_module_needs_active_flag(self):
        result = self._usage(["--only", "headers,dangerous_files"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("dangerous_files", result.output)
        self.assertIn("--active", result.output)

    def test_probe_path_needs_active(self):
        result = self._usage(["--probe-path", "/upload"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("--probe-path", result.output)

    def test_probe_path_off_origin_is_refused(self):
        result = self._usage(["--active", "--scope", "lab.test", "--yes", "--probe-path", "https://other.test/upload"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("not on the named origin", result.output)

    def test_active_without_terminal_or_yes_exits_with_an_error(self):
        with mock.patch.object(cli, "tty_available", return_value=False):
            result = self._usage(["--active", "--scope", "lab.test"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("terminal", result.output)

    def test_bad_scope_entry_exits_with_an_error(self):
        result = self._usage(["--active", "--yes", "--scope", "not a host"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("not a host", result.output)

    def test_invalid_target_exits_with_an_error(self):
        result = self._usage([])
        self.assertNotEqual(result.exit_code, 2, "a valid target reaches the runner")
        for bad in ("localhost", "ftp://lab.test", "https://lab.test:99999/"):
            with mock.patch.object(ModuleRunner, "run", side_effect=AssertionError("runner must not start")):
                result = CliRunner().invoke(cli.main, ["-t", bad])
            self.assertEqual(result.exit_code, 2, bad)


class RedirectTests(unittest.TestCase):
    def test_off_origin_redirect_is_refused_and_reported(self):
        routes = _lab_routes()
        routes[("GET", NAMED)] = (301, {"Location": "https://other.test/app"}, b"")
        transport = FakeTransport(routes)
        result, data = _invoke(["-t", NAMED], transport)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(any("other.test" in u for u in transport.urls()), transport.urls())
        self.assertEqual(data["refused_redirects"], [{"from": NAMED, "to": "https://other.test/app", "status": 301}])
        not_run = {m["module"]: m["reason"] for m in data["modules_not_run"]}
        self.assertIn("off-origin", not_run["discover"])
        self.assertIn("off-origin", not_run["headers"])
        self.assertIn("Redirects refused (off-origin): 1", result.output)

    def test_scheme_and_port_changes_count_as_off_origin(self):
        for location in ("http://lab.test:8443/app", "https://lab.test/app", "https://lab.test:9443/app"):
            routes = {("GET", NAMED): (302, {"Location": location}, b"")}
            transport = FakeTransport(routes)
            client = Client(ScopeValidator(NAMED), rate_limit=0)
            with _patched_transport(transport):
                fetched = client.fetch_named()
            self.assertTrue(fetched.redirect_refused, location)
            self.assertEqual(transport.urls(), [NAMED], location)
            self.assertEqual(client.refused_redirects[0]["to"], location)

    def test_same_origin_redirect_is_followed_with_a_hop_limit(self):
        routes = _lab_routes()
        routes[("GET", NAMED)] = (301, {"Location": "/app/"}, b"")
        routes[("GET", NAMED + "/")] = (200, {"Content-Type": "text/html"}, PAGE)
        transport = FakeTransport(routes)
        client = Client(ScopeValidator(NAMED), rate_limit=0)
        with _patched_transport(transport):
            fetched = client.fetch_named()
        self.assertEqual(fetched.status, 200)
        self.assertEqual(transport.urls(), [NAMED, NAMED + "/"])
        self.assertEqual(client.refused_redirects, [])

        loop = {("GET", NAMED): (302, {"Location": NAMED}, b"")}
        transport = FakeTransport(loop)
        client = Client(ScopeValidator(NAMED), rate_limit=0)
        with _patched_transport(transport):
            fetched = client.fetch_named()
        self.assertEqual(fetched.status, 302)
        self.assertLessEqual(len(transport.sent), 6)

    def test_client_refuses_to_build_off_origin_requests(self):
        client = Client(ScopeValidator(NAMED), rate_limit=0)
        with _patched_transport(FakeTransport({})):
            for url in ("https://other.test/", "http://lab.test:8443/", "https://lab.test/", "https://cdn.lab.test:8443/"):
                with self.assertRaises(OffOriginError, msg=url):
                    client.send("GET", url)


class SensitiveFileTests(unittest.TestCase):
    def _run_active(self, routes):
        transport = FakeTransport(routes)
        r = ScanResult(target="lab.test:8443")
        client = Client(ScopeValidator(NAMED), rate_limit=0)
        with _patched_transport(transport):
            res = dangerous_files.run(r, client)
        return res, r, transport

    def test_head_first_then_a_capped_range_get(self):
        res, r, transport = self._run_active(_lab_routes())
        self.assertTrue(res.success, res.message)

        env_requests = [(m, h) for m, u, h in transport.sent if u == NAMED + "/.env"]
        self.assertEqual([m for m, _ in env_requests], ["HEAD", "GET"], "HEAD first, then one GET")
        self.assertEqual(env_requests[1][1].get("Range"), f"bytes=0-{PROBE_READ_LIMIT - 1}")

        # Every GET in the module is capped: the random baseline path and the candidate.
        gets = [h for m, u, h in transport.sent if m == "GET"]
        self.assertEqual(len(gets), 2)
        self.assertTrue(all(h.get("Range") == f"bytes=0-{PROBE_READ_LIMIT - 1}" for h in gets))
        # Absent paths cost one HEAD and no GET.
        self.assertEqual(len([1 for m, _, _ in transport.sent if m == "HEAD"]), len(dangerous_files.SENSITIVE_PATHS))

    def test_read_never_exceeds_512_bytes_and_content_is_not_reported(self):
        res, r, transport = self._run_active(_lab_routes())
        self.assertTrue(transport.reads, "the body was read through the capped reader")
        self.assertTrue(all(amt is not None and amt <= 512 for amt in transport.reads), transport.reads)

        exposed = [f for f in r.findings if f.category == "dangerous_files"]
        self.assertEqual([f.title for f in exposed], ["Environment file exposed"])
        self.assertIn(f"{len(SECRET)} bytes", exposed[0].evidence, "size comes from Content-Range")
        self.assertNotIn("lab-only-not-real", exposed[0].evidence)
        dumped = json.dumps([f.__dict__ for f in r.findings])
        self.assertNotIn("DB_PASSWORD", dumped)

    def test_server_ignoring_range_is_still_capped(self):
        routes = _lab_routes()
        # This route answers 200 with the whole file regardless of Range.
        big = SECRET

        class IgnoresRange(FakeTransport):
            def __call__(self, method, url, headers):
                if url == NAMED + "/.env" and method == "GET":
                    self.sent.append((method, url, dict(headers)))
                    return _FakeResponse(200, {"Content-Length": str(len(big))}, big, self.reads)
                return super().__call__(method, url, headers)

        transport = IgnoresRange(routes)
        r = ScanResult(target="lab.test:8443")
        client = Client(ScopeValidator(NAMED), rate_limit=0)
        with _patched_transport(transport):
            dangerous_files.run(r, client)
        self.assertTrue(all(amt <= 512 for amt in transport.reads))
        exposed = [f for f in r.findings if f.category == "dangerous_files"]
        self.assertEqual(len(exposed), 1)
        self.assertIn(f"{len(big)} bytes", exposed[0].evidence)

    def test_auth_protected_path_gets_no_get(self):
        routes = _lab_routes()
        routes[("*", NAMED + "/.env")] = (403, {}, b"forbidden")
        res, r, transport = self._run_active(routes)
        self.assertEqual([m for m, u, _ in transport.sent if u == NAMED + "/.env"], ["HEAD"])
        self.assertEqual([f.title for f in r.findings], ["Environment file exposed (auth-protected)"])


class DecodedCapTests(unittest.TestCase):
    """The page cap is on decoded bytes: an expanding body is cut at the cap."""

    def test_expanding_body_is_cut_at_the_decoded_cap_and_read_in_chunks(self):
        reads = []

        class Bomb(FakeTransport):
            def __call__(self, method, url, headers):
                self.sent.append((method, url, dict(headers)))
                resp = _FakeResponse(200, {"Content-Encoding": "gzip", "Content-Length": "4096"}, b"", reads)
                resp.raw = _ExpandingRaw(b"", reads)
                return resp

        client = Client(ScopeValidator(NAMED), rate_limit=0)
        with _patched_transport(Bomb({})):
            fetched = client.get(NAMED)
        self.assertEqual(len(fetched.body), PAGE_READ_LIMIT)
        self.assertTrue(fetched.truncated)
        self.assertTrue(all(amt <= READ_CHUNK for amt in reads), reads)
        self.assertEqual(len(reads), PAGE_READ_LIMIT // (READ_CHUNK * _ExpandingRaw.RATIO),
                         "the body is read chunk by chunk until the decoded cap is reached")

    def test_short_body_is_not_marked_truncated(self):
        transport = FakeTransport({("GET", NAMED): (200, {"Content-Type": "text/html"}, PAGE)})
        client = Client(ScopeValidator(NAMED), rate_limit=0)
        with _patched_transport(transport):
            fetched = client.get(NAMED)
        self.assertEqual(fetched.body, PAGE)
        self.assertFalse(fetched.truncated)


class TerminalEscapeTests(unittest.TestCase):
    """Text that came from the target is inert on the terminal and in the report."""

    def test_off_origin_location_cannot_drive_the_terminal(self):
        hostile = "https://other.test/[bold red]owned[/]\x1b]0;pwned\x07"
        transport = FakeTransport({("GET", NAMED): (302, {"Location": hostile}, b"")})
        result = ScanResult(target="lab.test:8443", named_url=NAMED)
        client = Client(ScopeValidator(NAMED), rate_limit=0)
        console = _quiet_console()
        runner = ModuleRunner(console, result, client)
        runner.register("Discovery", "discover", discover.run, active=False)
        runner.register("Headers", "headers", headers.run, active=False)
        with _patched_transport(transport):
            runner.run()
        text = console.file.getvalue()
        self.assertIn("[bold red]owned[/]", text, "markup from the target is shown, not interpreted")
        self.assertIn("\\x1b]0;pwned\\x07", text, "control characters are shown as escapes")
        for ch in text:
            self.assertTrue(ord(ch) >= 0x20 or ch == "\n", f"control character reached the terminal: {ch!r}")
        reasons = [m["reason"] for m in result.modules_not_run]
        self.assertEqual(len(reasons), 2)
        for reason in reasons:
            self.assertIn("\\x1b]0;pwned\\x07", reason, "the report carries the inert form too")

    def test_safe_text_matches_the_vendored_behaviour(self):
        self.assertEqual(scope_module.safe_text("nginx\x1b[2J\x1b]0;owned\x07"), "nginx\\x1b[2J\\x1b]0;owned\\x07")
        self.assertEqual(scope_module.safe_text("a\r\nb\tc"), "a b c")
        self.assertEqual(scope_module.safe_text("x\x7fy\x9bz"), "x\\x7fy\\x9bz")
        self.assertEqual(scope_module.safe_text("abcdefghij", 5), "abcde [cut]")
        self.assertEqual(scope_module.safe_text(None), "")


class ActiveScopeTests(unittest.TestCase):
    def test_entry_forms(self):
        s = ActiveScope(["app.lab.test", "*.corp.test", "203.0.113.7", "198.51.100.0/24", "https://Portal.lab.test:8443/x"])
        self.assertEqual(s.entries, ["app.lab.test", "*.corp.test", "203.0.113.7", "198.51.100.0/24", "portal.lab.test"])
        self.assertTrue(s.covers("app.lab.test", ["192.0.2.1"]))
        self.assertTrue(s.covers("APP.lab.test.", []))
        self.assertFalse(s.covers("www.app.lab.test", ["192.0.2.1"]), "a host entry is exact")
        self.assertTrue(s.covers("a.b.corp.test", []), "a domain entry covers any depth")
        self.assertFalse(s.covers("corp.test", []), "a domain entry does not cover the apex")
        self.assertTrue(s.covers("anything.example", ["203.0.113.7"]))
        self.assertTrue(s.covers("anything.example", ["198.51.100.200", "198.51.100.201"]))
        self.assertFalse(s.covers("anything.example", ["198.51.100.200", "192.0.2.9"]), "every address must be inside")
        self.assertFalse(s.covers("anything.example", []), "unresolved is not covered")
        self.assertFalse(s.covers("anything.example", ["not-an-ip"]))

    def test_scope_file_with_comments(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# client scope\n\n*.lab.test\n203.0.113.0/24  # office range\n")
            path = f.name
        try:
            s = ActiveScope.from_option(path)
        finally:
            os.unlink(path)
        self.assertEqual(s.entries, ["*.lab.test", "203.0.113.0/24"])

    def test_list_form_and_errors(self):
        self.assertEqual(ActiveScope.from_option("lab.test, *.lab.test").entries, ["lab.test", "*.lab.test"])
        with self.assertRaises(ValueError):
            ActiveScope.from_option("")
        with self.assertRaises(ValueError):
            ActiveScope.from_option("lab.test,bad_label.test")
        with self.assertRaises(ValueError):
            ActiveScope.from_option("localhost")


class _Probe:
    """An active stub module that records each call."""
    def __init__(self):
        self.calls = 0

    def run(self, result, client, verbose=False):
        self.calls += 1
        return ModuleResult(success=True, message="probed")


def _make_runner(active, assume_yes, scope_entries=("203.0.113.0/24",), probe_paths=()):
    result = ScanResult(target="lab.test:8443", named_url=NAMED, probe_paths=list(probe_paths))
    client = Client(ScopeValidator(NAMED), rate_limit=0)
    runner = ModuleRunner(
        _quiet_console(), result, client, active=active,
        active_scope=ActiveScope(list(scope_entries)) if active else None,
        assume_yes=assume_yes,
    )
    probe = _Probe()
    runner.register("Passive stub", "stub", lambda r, c, v=False: ModuleResult(True, "ok"), active=False)
    runner.register("Probe", "probe", probe.run, active=True)
    runner.register("Second probe", "probe2", probe.run, active=True)
    return runner, probe


class ScopeEnforcementTests(unittest.TestCase):
    def test_host_outside_scope_is_not_probed_and_reported(self):
        runner, probe = _make_runner(active=True, assume_yes=True, scope_entries=("192.0.2.0/24",))
        with _patched_transport(FakeTransport({}), resolved=("203.0.113.5",)):
            result = runner.run()
        self.assertEqual(probe.calls, 0)
        self.assertEqual(result.out_of_scope, [{"hostname": "lab.test", "ip": "203.0.113.5"}])
        self.assertEqual([m["module"] for m in result.modules_not_run], ["probe", "probe2"])
        self.assertIn("outside --scope", result.modules_not_run[0]["reason"])
        self.assertEqual(result.confirmation, "")

    def test_host_covered_by_name_or_address(self):
        for entries in (("lab.test",), ("203.0.113.0/24",), ("203.0.113.5",), ("lab.test", "192.0.2.0/24")):
            runner, probe = _make_runner(active=True, assume_yes=True, scope_entries=entries)
            with _patched_transport(FakeTransport({})):
                result = runner.run()
            self.assertEqual(probe.calls, 2, entries)
            self.assertEqual(result.mode, "active")
            self.assertEqual(result.active_scope, list(entries))
            self.assertIn("--yes", result.confirmation)
            self.assertEqual(result.modules_not_run, [])

    def test_unresolved_host_is_not_probed(self):
        runner, probe = _make_runner(active=True, assume_yes=True)
        with _patched_transport(FakeTransport({}), resolved=()):
            result = runner.run()
        self.assertEqual(probe.calls, 0)
        self.assertIn("did not resolve", result.modules_not_run[0]["reason"])

    def test_passive_runner_never_calls_active_modules(self):
        runner, probe = _make_runner(active=False, assume_yes=False)
        with _patched_transport(FakeTransport({})):
            result = runner.run()
        self.assertEqual(probe.calls, 0)
        self.assertEqual(result.mode, "passive")
        self.assertEqual([m["module"] for m in result.modules_not_run], ["probe", "probe2"])

    def test_skipped_and_failed_modules_are_recorded_as_not_run(self):
        runner, probe = _make_runner(active=True, assume_yes=True)
        runner.skip = ["probe2"]
        runner.register("Broken", "broken", lambda r, c, v=False: ModuleResult(False, "nuclei not found"), active=False)
        with _patched_transport(FakeTransport({})):
            result = runner.run()
        self.assertEqual(probe.calls, 1)
        self.assertEqual(result.modules_not_run, [
            {"module": "broken", "name": "Broken", "reason": "nuclei not found"},
            {"module": "probe2", "name": "Second probe", "reason": "skipped with --skip or --only"},
        ])

    def test_active_runner_requires_a_scope(self):
        with self.assertRaises(ValueError):
            ModuleRunner(_quiet_console(), ScanResult(target="lab.test"), Client(ScopeValidator(NAMED), rate_limit=0), active=True)


class ConfirmationGateTests(unittest.TestCase):
    def _run_with_answer(self, answer):
        runner, probe = _make_runner(active=True, assume_yes=False)
        with _patched_transport(FakeTransport({})), \
             mock.patch.object(runner_module, "read_tty_line", return_value=answer) as reader:
            result = runner.run()
        return result, probe, reader

    def test_gate_blocks_when_the_word_is_not_yes(self):
        for answer in ("", "no", "y", "YES please", "yes\x00"):
            result, probe, reader = self._run_with_answer(answer)
            self.assertEqual(probe.calls, 0, f"probe ran after answer {answer!r}")
            self.assertEqual(reader.call_count, 1, "the gate asks once, not once per module")
            self.assertEqual([m["module"] for m in result.modules_not_run], ["probe", "probe2"])
            self.assertIn("confirmation not given", result.modules_not_run[0]["reason"])
            self.assertEqual(result.confirmation, "")

    def test_gate_blocks_without_a_terminal(self):
        result, probe, _ = self._run_with_answer(None)
        self.assertEqual(probe.calls, 0)
        self.assertIn("no terminal", result.modules_not_run[0]["reason"])

    def test_gate_opens_on_yes(self):
        result, probe, reader = self._run_with_answer("yes")
        self.assertEqual(probe.calls, 2)
        self.assertEqual(result.confirmation, "typed yes on the terminal")
        prompt = reader.call_args[0][0]
        self.assertIn("203.0.113.0/24", prompt)
        self.assertIn(ORIGIN, prompt)

    def test_environment_cannot_open_the_gate(self):
        env = {"ATARUS_YES": "1", "ATARUS_WEBSCAN_YES": "yes", "ATARUS_WEBSCAN_ACTIVE": "1", "CI": "true", "YES": "yes"}
        with mock.patch.dict(os.environ, env):
            result, probe, _ = self._run_with_answer("no")
        self.assertEqual(probe.calls, 0)
        self.assertEqual(result.confirmation, "")
        # The CLI reads no environment variable for these options either.
        with mock.patch.dict(os.environ, env), mock.patch.object(ModuleRunner, "run", side_effect=AssertionError("runner must not start")):
            result = CliRunner().invoke(cli.main, ["-t", NAMED, "--active"])
        self.assertEqual(result.exit_code, 2)

    def test_read_tty_line_never_reads_stdin(self):
        with mock.patch.object(scope_module, "TTY_PATH", os.path.join(tempfile.gettempdir(), "atarus-no-such-tty")), \
             mock.patch.object(sys, "stdin", io.StringIO("yes\n")):
            self.assertIsNone(scope_module.read_tty_line("confirm: "))
            self.assertFalse(scope_module.tty_available())

    def test_read_tty_line_reads_the_terminal_device(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("yes\n")
            path = f.name
        try:
            with mock.patch.object(scope_module, "TTY_PATH", path):
                self.assertTrue(scope_module.tty_available())
                self.assertEqual(scope_module.read_tty_line(""), "yes")
        finally:
            os.unlink(path)


class ActiveRunTests(unittest.TestCase):
    def test_write_methods_go_only_to_named_paths(self):
        transport = FakeTransport(_lab_routes())
        with mock.patch.object(technology, "_find_nuclei", return_value=""):
            result, data = _invoke(["-t", NAMED, "--active", "--scope", "203.0.113.0/24", "--yes", "--probe-path", "/upload"], transport)
        self.assertEqual(result.exit_code, 0, result.output)
        write = [(m, u) for m, u, _ in transport.sent if m in ("POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT")]
        self.assertEqual({u for _, u in write}, {ORIGIN + "/upload"})
        self.assertEqual(len(write), 6)
        self.assertEqual(data["probe_paths"], ["/upload"])
        self.assertEqual(data["mode"], "active")
        self.assertIn("--yes", data["confirmation"])
        self.assertTrue(any(f["title"] == "PUT method enabled" for f in data["findings"]))
        self.assertEqual([m["module"] for m in data["modules_not_run"]], ["technology"])
        self.assertIn("nuclei not found", data["modules_not_run"][0]["reason"])

    def test_active_without_probe_path_sends_no_write_methods(self):
        transport = FakeTransport(_lab_routes())
        with mock.patch.object(technology, "_find_nuclei", return_value=""):
            result, data = _invoke(["-t", NAMED, "--active", "--scope", "lab.test", "--yes"], transport)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(transport.methods(), ["GET", "HEAD", "OPTIONS"])
        not_run = {m["module"]: m["reason"] for m in data["modules_not_run"]}
        self.assertIn("--probe-path", not_run["write_methods"])


class NucleiTests(unittest.TestCase):
    def _run(self, returncode, stderr="", output_lines=None):
        calls = []

        def fake_run(cmd, *args, **kwargs):
            calls.append(cmd)
            out = cmd[cmd.index("-o") + 1]
            with open(out, "w") as f:
                for line in output_lines or []:
                    f.write(json.dumps(line) + "\n")
            return mock.Mock(returncode=returncode, stdout="", stderr=stderr)

        r = ScanResult(target="lab.test:8443")
        client = Client(ScopeValidator(NAMED), rate_limit=0)
        with mock.patch.object(technology, "_find_nuclei", return_value="/opt/bin/nuclei"), \
             mock.patch.object(subprocess, "run", side_effect=fake_run), _NetworkGuard():
            res = technology.run(r, client)
        return res, r, calls[0]

    def test_flags_and_success(self):
        record = {"template-id": "tech-detect", "info": {"name": "nginx", "severity": "info", "tags": ["tech"]}, "extracted-results": ["nginx/1.31.7"]}
        res, r, cmd = self._run(0, output_lines=[record])
        self.assertTrue(res.success, res.message)
        self.assertIn("-ni", cmd)
        self.assertIn("-disable-redirects", cmd)
        self.assertEqual(cmd[0], "/opt/bin/nuclei")
        self.assertEqual([t.name for t in r.technologies], ["nginx"])

    def test_non_zero_exit_is_not_run(self):
        res, r, _ = self._run(1, stderr="flag provided but not defined: -nope")
        self.assertFalse(res.success)
        self.assertIn("exited with code 1", res.message)
        self.assertIn("-nope", res.message)
        self.assertEqual(r.findings, [])

    def test_stderr_tail_is_made_inert(self):
        res, _, _ = self._run(1, stderr="[FTL] target said [red]hi[/]\x1b[2J\nsecond line")
        self.assertFalse(res.success)
        self.assertIn("[red]hi[/]\\x1b[2J second line", res.message)
        for ch in res.message:
            self.assertGreaterEqual(ord(ch), 0x20)

    def test_absent_nuclei_is_recorded_in_the_report(self):
        transport = FakeTransport(_lab_routes())
        with mock.patch.object(technology, "_find_nuclei", return_value=""):
            result, data = _invoke(["-t", NAMED, "--active", "--scope", "lab.test", "--yes", "--only", "technology"], transport)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(transport.sent, [], "nothing was sent when nuclei is absent")
        reasons = {m["module"]: m["reason"] for m in data["modules_not_run"]}
        self.assertIn("nuclei not found", reasons["technology"])


class PassiveReportTests(unittest.TestCase):
    def test_passive_report_does_not_read_as_clean(self):
        result = ScanResult(target="lab.test:8443", named_url=NAMED, insecure=True)
        result.requests_sent = {"GET": 1, "HEAD": 1, "OPTIONS": 1}
        result.modules_not_run.append({"module": "technology", "name": "Technology + CVE scan (nuclei)",
                                       "reason": "passive mode; add --active and --scope to run it"})
        result.refused_redirects.append({"from": NAMED, "to": "https://other.test/", "status": 301})
        result.out_of_scope.append({"hostname": "lab.test", "ip": "203.0.113.5"})
        with tempfile.TemporaryDirectory() as d:
            with open(html.generate(result, d)) as f:
                content = f.read()
        self.assertIn("passive", content)
        self.assertIn("nothing else was sent", content)
        self.assertIn("Checks not made", content)
        self.assertIn("Technology + CVE scan (nuclei)", content)
        self.assertIn("Do not read this report as clean", content)
        self.assertIn("Redirects refused", content)
        self.assertIn("https://other.test/", content)
        self.assertIn("off (--insecure)", content)
        self.assertIn("Out of scope, not probed", content)
        self.assertIn("GET 1, HEAD 1, OPTIONS 1", content)
        self.assertIn("atarus-webscan v0.2.0", content)
        self.assertNotIn("No findings recorded.", content)


def _pty_supported():
    try:
        import pty  # noqa: F401
    except ImportError:
        return False
    return hasattr(os, "fork") and sys.platform != "win32"


class PseudoTerminalGateTests(unittest.TestCase):
    """The gate on a real terminal. The child of pty.fork has the pseudo-terminal
    as its controlling terminal, so /dev/tty is the real path here, not a file
    standing in for it; a regression in how the terminal is opened (the
    0.2.0 r+ bug) fails these tests."""

    PROMPT_MARK = b"Type yes to"
    DEADLINE = 30

    def _in_pty(self, child, answer):
        """Run child() in a pty.fork child, answer the prompt, return (output, exit code).

        child() returns the text the child prints after the prompt was answered."""
        import pty
        try:
            pid, fd = pty.fork()
        except OSError as e:
            self.skipTest(f"pseudo-terminal not available: {e}")
        if pid == 0:
            code = 3
            try:
                text = child()
                os.write(1, ("\nRESULT=" + text + "\n").encode("utf-8", "replace"))
                code = 0
            except BaseException as e:  # noqa: BLE001
                try:
                    os.write(1, f"\nCHILD ERROR {e!r}\n".encode("utf-8", "replace"))
                except OSError:
                    pass
            finally:
                os._exit(code)

        out = b""
        answered = False
        status = None
        deadline = time.time() + self.DEADLINE
        try:
            while time.time() < deadline:
                ready, _, _ = select.select([fd], [], [], 0.2)
                if ready:
                    try:
                        chunk = os.read(fd, 4096)
                    except OSError:
                        break  # EIO once the child has closed its side (Linux)
                    if not chunk:
                        break  # EOF (macOS)
                    out += chunk
                    if not answered and self.PROMPT_MARK in out:
                        os.write(fd, answer.encode() + b"\n")
                        answered = True
                    continue
                done, st = os.waitpid(pid, os.WNOHANG)
                if done:
                    status = st
                    while True:
                        ready, _, _ = select.select([fd], [], [], 0.2)
                        if not ready:
                            break
                        try:
                            chunk = os.read(fd, 4096)
                        except OSError:
                            break
                        if not chunk:
                            break
                        out += chunk
                    break
            else:
                os.kill(pid, 9)
                self.fail(f"child did not finish in {self.DEADLINE}s; output so far: {out!r}")
            if status is None:
                _, status = os.waitpid(pid, 0)
        finally:
            os.close(fd)
        return out.decode("utf-8", "replace"), os.waitstatus_to_exitcode(status)

    @unittest.skipUnless(_pty_supported(), "needs a POSIX pseudo-terminal")
    def test_read_tty_line_reads_from_the_real_controlling_terminal(self):
        def child():
            available = scope_module.tty_available()
            line = scope_module.read_tty_line("Type yes to continue: ")
            return f"available={available} line={line!r}"

        for answer in ("yes", "no"):
            out, code = self._in_pty(child, answer)
            self.assertEqual(code, 0, out)
            self.assertIn("Type yes to continue:", out, "the prompt must be written to the terminal")
            self.assertIn(f"RESULT=available=True line={answer!r}", out)

    @unittest.skipUnless(_pty_supported(), "needs a POSIX pseudo-terminal")
    def test_gate_opens_on_yes_and_blocks_on_no_typed_on_a_terminal(self):
        def child():
            runner, probe = _make_runner(active=True, assume_yes=False)
            with _patched_transport(FakeTransport({})):
                result = runner.run()
            return f"confirmation={result.confirmation!r} probed={probe.calls} not_run={[m['module'] for m in result.modules_not_run]!r}"

        out, code = self._in_pty(child, "yes")
        self.assertEqual(code, 0, out)
        self.assertIn("RESULT=confirmation='typed yes on the terminal' probed=2 not_run=[]", out)

        out, code = self._in_pty(child, "no")
        self.assertEqual(code, 0, out)
        self.assertIn("RESULT=confirmation='' probed=0 not_run=['probe', 'probe2']", out)


if __name__ == "__main__":
    unittest.main()
