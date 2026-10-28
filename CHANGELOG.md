# Changelog

All notable changes to atarus-webscan. v0.1.0 is tagged in git but was never published as a GitHub release.

## 0.2.0 (unreleased, refresh-2026-10 and safe-default)

### Security

- **Passive by default; active checks need `--active`, `--scope` and a typed confirmation.**

  What was wrong: a bare `atarus-webscan -t https://example.com` sent about sixty requests to the target with no question asked, including a GET to a random path, GETs to 46 guessed sensitive paths and one request for each of nine HTTP methods, among them POST, PUT, PATCH, DELETE, TRACE and CONNECT. On an application that honours PUT or DELETE, a scan could create or remove a resource. The project's own rule, that a tool observes and reports by default and probes a live system only inside a scope the user set and confirmed, was not true of this tool.

  What changed, in plain terms: a plain run now sends exactly three safe requests to the URL you named, one GET, one HEAD and one OPTIONS, and nothing to any other path. To probe, you pass `--active` and a `--scope` listing the hosts, networks or domains you are authorized to touch; the tool shows you the named URL, the addresses it resolves to, the scope, the active modules and whether TLS verification is on, then waits for you to type `yes` on the terminal. If the named host is outside the scope, the active modules do not run and the host is listed as out of scope. The report records the mode, the scope, how the run was confirmed, how many requests of each method were sent, and every module that did not run and why, so a passive report cannot be mistaken for a clean active one.

  Technically: `cli.MODULE_REGISTRY` carries an `active` flag per module (`dangerous_files`, `write_methods` and `technology` are active; `discover`, `headers`, `methods` and `risk` are passive). `ModuleRunner` refuses active modules unless constructed with `active=True` and an `ActiveScope`, runs the confirmation gate once before the first active module, and records any module that was skipped, blocked or did not complete in `ScanResult.modules_not_run`. `scope.ActiveScope` parses `--scope` (file or list) into exact hosts, `*.domain` wildcards, addresses and CIDR networks; `covers(name, ips)` matches by name, or requires every resolved address to fall inside a listed network. The confirmation is read from `/dev/tty` by `scope.read_tty_line`; stdin, environment variables and configuration files are not consulted, and click's environment-variable support is not enabled. `--yes` is accepted only with `--scope`, is printed at the start of the run and is stored in `ScanResult.confirmation`. `--active` without `--scope`, `--yes` without `--scope`, `--only` naming an active module without `--active`, `--probe-path` without `--active`, and `--active` with neither a terminal nor `--yes` exit with a usage error (code 2) before any module runs. `discover` and `headers` share one GET through `Client.fetch_named()`.

- **HTTP methods: OPTIONS and HEAD only by default; state-changing methods only against a path you name.**

  What was wrong: the `methods` module sent GET, POST, PUT, DELETE, PATCH, OPTIONS, TRACE, CONNECT and HEAD to the named URL on every run.

  What changed: the `methods` module (passive) sends one HEAD and one OPTIONS and reads the `Allow` header; a dangerous method announced there is reported as "announced via OPTIONS", not as confirmed. The new `write_methods` module (active) sends POST, PUT, PATCH, DELETE, TRACE and CONNECT, each without a body, only to the paths named with the repeatable `--probe-path` option (an absolute path on the named origin, or a URL on that origin), never to the named URL by default and never to a path another module discovered. Without `--probe-path` it is recorded as not run. A method it confirms replaces the "announced" finding for that method. `ScanResult.methods_allowed` now holds confirmed methods and the new `methods_announced` holds the `Allow` list.

- **Sensitive-file checks: HEAD first, then a GET capped at 512 bytes; presence and size reported, never content.**

  What was wrong: `dangerous_files` fetched each of the 46 candidate paths with a plain GET and read the whole body, so a scan downloaded any exposed `.env`, backup archive or database dump in full. The response size went into the report, but the content sat in memory and could be as large as the server cared to send.

  What changed: each candidate gets a HEAD request first. Only when the server says the path exists (2xx, or 405/501 for servers that refuse HEAD) does a GET follow, carrying `Range: bytes=0-511`, and the client reads at most 512 bytes from the socket before closing the connection, whether or not the server honoured the range. A 401 or 403 is recorded from the HEAD alone. The 404 baseline is calibrated with the same capped GET and compares status, declared length and the hash of the first 512 bytes. The finding's evidence records the HTTP status and the size from `Content-Range` or `Content-Length`, and says that no content was stored. The module also no longer sends a separate reachability GET; the baseline request is the reachability check.

- **Target fidelity: exact scheme, host, port and path; no off-origin redirects; TLS verification on by default.**

  What was wrong: the target was reduced to a hostname, so `https://example.com:8443/app` was scanned as `https://example.com/`, a different service. Every request was sent with `verify=False` and the library followed redirects wherever they pointed, so a target that redirected to another host caused requests to that host.

  What changed: `scope.ScopeValidator` keeps the scheme, host, port and path exactly as named (`base_url`, `origin`, `same_origin(url)`); the report file name includes the port when one was named. All requests go through the new `transport.Client`, which refuses to send to any URL that is not on the named origin (same scheme, host and port), never lets the HTTP library follow redirects, follows a same-origin redirect of the named URL itself for up to five hops, and records an off-origin redirect in `ScanResult.refused_redirects` without following it; `discover` and `headers` then report the named URL as redirecting off-origin and are listed as not run. TLS certificates are verified unless `--insecure` is passed; the flag is printed at the start of the run and stored in `ScanResult.insecure`, which the HTML report shows. `urllib3` warnings are silenced only when `--insecure` is in effect. The client also paces requests to `--rate-limit`, which was previously accepted and ignored, and records every request so the report can state how many of each method were sent (`requests_sent`).

- **nuclei: return code checked, no interactsh, no redirects, "not run" recorded when absent.**

  What was wrong: the module ignored nuclei's exit status, so a nuclei that refused to start reported "0 technologies detected, 0 vulnerabilities", and a missing binary surfaced only as a console warning that the report did not carry.

  What changed: nuclei runs with `-ni` (no out-of-band callbacks through interactsh) and `-disable-redirects` (stay on the named origin). A missing binary, a start failure, a timeout, a non-zero exit (with the tail of stderr) or a missing output file is returned as a failure, which the runner records in `modules_not_run`, so the HTML report shows the check under "Checks not made" instead of an empty technologies section.

### Fixed
- HTML and PDF reports failed on every scan ("Could not find templates/report.html") because the template was never committed: the `.gitignore` rule `*.html` was only re-included for a root `templates/` directory. Added `src/atarus_webscan/templates/report.html` and fixed `.gitignore`.
- WeasyPrint is imported only for PDF export, so the CLI starts on hosts without the Pango system libraries.
- The nuclei timeout message said 240 seconds; the timeout is 90 seconds.
- `dangerous_files` sent its reachability probe twice.

### Added
- MIT LICENSE file (README and pyproject.toml already declared MIT).
- Offline unit tests (`tests/`), GitHub Actions workflow, `constraints.txt`, SECURITY.md and this changelog. `tests/test_safe_default.py` replaces the HTTP layer with a recording fake and guards the socket layer; it covers the passive default (only GET, HEAD and OPTIONS leave, each once, to the named URL), the 512-byte read cap, refused and followed redirects, port and path preservation, the usage errors, the scope lock, the confirmation gate (blocks without `yes`, cannot be opened from the environment, never reads stdin), `write_methods` reaching only named paths, and the nuclei flags and return-code handling.
- `--list-modules`, `--active`, `--scope`, `--yes`, `--probe-path` and `--insecure` options. `ScanResult` gained `named_url`, `methods_announced`, `mode`, `active_scope`, `confirmation`, `insecure`, `probe_paths`, `modules_not_run`, `out_of_scope`, `refused_redirects` and `requests_sent`; the HTML report shows them, with "Checks not made", "Out of scope, not probed" and "Redirects refused" sections.
- `install-deps.sh` installs Pango for PDF export.

### Changed
- Module functions now take `(result, client, verbose)` instead of `(result, base_url, verbose)`; the client carries the named URL and is the only way a module can send a request.
- The User-Agent string follows `atarus_webscan.__version__` instead of a hard-coded `0.1.0`.

### Docs
- README: passive default, how to run active checks, the scope and confirmation rules, the HTTP method policy, the sensitive-file read cap, target fidelity and the `--insecure` note, a per-module table of what is sent over the network, Known issues. Earlier corrections: framework count (17), what the 404 baseline does, Pango requirement, suite description. SECURITY.md "Using this tool" rewritten to match.

## 0.1.0 (2026-04-29)
- Initial release: discover, headers, methods, dangerous_files, technology (nuclei) and risk modules; smart 404 baseline; HTML, PDF and JSON output.
