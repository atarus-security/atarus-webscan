# atarus-webscan

Web application security scanner by [Atarus Offensive Security](https://atarussecurity.com).

A modern, focused web app scanner. Built as a smart replacement for legacy tools like Nikto: fewer false positives, modern framework awareness, clean reports.

Passive by default. A plain run sends exactly three safe requests to the URL you named, one GET, one HEAD and one OPTIONS, and nothing to any other path, host or port. The modules that send more (sensitive-file probing, state-changing HTTP methods, nuclei) run only behind `--active`, only when the named host is inside a `--scope` you provide, and only after you type `yes` on the terminal. See [Passive by default, active on request](#passive-by-default-active-on-request).

```bash
atarus-webscan -t https://example.com
```

That single command produces:

- `atarus-webscan-example.com.html` - Atarus dark-theme report
- `atarus-webscan-example.com.pdf` - branded PDF export (needs the Pango system libraries, see Quick start)
- `atarus-webscan-example.com.json` - machine-readable output, including `mode`, `requests_sent`, `modules_not_run`, `refused_redirects`, `confirmation` and `insecure`

A passive report has no sensitive-file results, no confirmed state-changing methods and no nuclei findings. It says so: the report lists the active modules under "Checks not made" rather than showing an empty, clean-looking section.

## What it does

| Module | Mode | Description | External tool |
|---|---|---|---|
| `discover` | passive | Site type and framework detection (17 frameworks and platforms) from the single GET | None |
| `headers` | passive | Security header analysis of that same response, with a grade for each header | None |
| `methods` | passive | One HEAD and one OPTIONS to the named URL; dangerous methods the `Allow` header announces are reported as announced | None |
| `dangerous_files` | active | Exposed sensitive file detection (.git, .env, backups, admin panels): HEAD first, then a 512-byte capped GET | None |
| `write_methods` | active | POST, PUT, PATCH, DELETE, TRACE and CONNECT, sent only to the paths you name with `--probe-path` | None |
| `technology` | active | Framework fingerprinting and CVE matching | nuclei |
| `risk` | passive | Per-finding severity scoring and target risk rating, computed offline | None |

`atarus-webscan --list-modules` prints this table. Active modules need `--active` and `--scope`; `--only dangerous_files` without them is an error, not a silent scan.

## Smart 404 detection

Every `dangerous_files` probe is filtered against a calibrated 404 baseline. The module fetches one random, nonexistent path, hashes the first 512 bytes of the answer, and discards any probed path whose response matches that signature, even if the HTTP status is 200. This eliminates the most common false positives in legacy web scanners. The calibration request is part of the active module, so a passive run does not make it.

## Modern framework awareness

`discover` identifies these frameworks via response markers:

Next.js, Nuxt.js, React, Vue.js, Angular, Django, Rails, Laravel, WordPress, Drupal, Express.js, ASP.NET, Spring Boot, Flask, Vercel, Cloudflare Pages, Netlify

This drives smarter probing, fewer false positives, and accurate technology fingerprinting in the report.

## Quick start

```bash
git clone https://github.com/atarus-security/atarus-webscan.git
cd atarus-webscan

# Python deps (Python 3.10 or newer)
python3 -m venv venv
source venv/bin/activate
pip install -e .

# External tools (nuclei v3) and the Pango libraries WeasyPrint needs for PDF
./install-deps.sh

# Add Go binaries to PATH (one-time)
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
source ~/.bashrc

# Passive run (default): one GET, one HEAD, one OPTIONS to the named URL
atarus-webscan -t https://example.com

# Active run: sensitive-file probing and nuclei against the host you place in
# scope. Prints the named URL, its addresses and the scope, then waits for
# you to type yes on the terminal.
atarus-webscan -t https://example.com --active --scope example.com
```

## Usage

Passive scan (default):
```bash
atarus-webscan -t https://example.com
```

Active scan, interactive confirmation:
```bash
atarus-webscan -t https://example.com --active --scope example.com
```

Active scan including state-changing method probes against a path you name:
```bash
atarus-webscan -t https://example.com --active --scope example.com --probe-path /uploads/
```

Non-interactive active scan (CI, cron): `--yes` stands in for the typed word, is only accepted together with `--scope`, and is recorded in the report:
```bash
atarus-webscan -t https://example.com --active --scope ./scope.txt --yes
```

A service on a non-standard port or under a path prefix. The scheme, host, port and path are kept exactly as named:
```bash
atarus-webscan -t https://example.com:8443/app
```

A host with a self-signed or otherwise untrusted certificate. Verification is on by default; `--insecure` turns it off and the report says so:
```bash
atarus-webscan -t https://10.0.0.5:8443 --insecure
```

Specific format:
```bash
atarus-webscan -t https://example.com --format json
```

Skip modules:
```bash
atarus-webscan -t https://example.com --skip technology
```

Run only specific modules:
```bash
atarus-webscan -t https://example.com --only headers,methods,dangerous_files
```

Verbose output:
```bash
atarus-webscan -t https://example.com -v
```

Notes:
- The target is a URL. Scheme, host, port and path are used exactly as given; the query string and fragment are not. The report file name includes the port when one was named.
- `--rate-limit` paces every request the tool sends itself (default 10 per second). nuclei runs with its own limit of 60 requests per second and a 90 second timeout.
- Without the Pango system libraries (`sudo apt install libpango-1.0-0 libpangoft2-1.0-0` on Debian or Kali) the scan, HTML and JSON reports work and the PDF step prints an error.

## Passive by default, active on request

atarus-webscan follows one rule: it observes and reports by default, and it probes a live system only when you placed that system in scope and confirmed it yourself.

### Passive mode (default)

Without `--active`, only the passive modules run: `discover`, `headers`, `methods` and `risk`. Together they send one GET, one HEAD and one OPTIONS to the URL you named, all safe methods, and nothing to any other path. `discover` and `headers` share the same GET response. The three active modules are listed in the terminal and in the report as not run, with the reason, so a passive report never reads as a clean active scan.

### Active mode

`--active` enables `dangerous_files`, `write_methods` and `technology`. It needs two more things:

1. **A scope lock.** `--scope` takes a file (one entry per line, `#` comments allowed) or a comma-separated list. Four entry forms:

   | Entry | Covers |
   |---|---|
   | `app.example.com` | exactly that host |
   | `*.example.com` | every name under `example.com`, at any depth, but not the apex |
   | `203.0.113.7` | that address |
   | `203.0.113.0/24` | every address in that network |

   The named host is covered when its name matches a host or domain entry, or when every address it resolves to falls inside a network entry. If it is not covered, the active modules do not run, the host is listed as out of scope in the terminal, the HTML report and the JSON (`out_of_scope`), and the passive results are still written.

2. **A confirmation the software cannot give for you.** Before the first active request, the tool prints the named URL, the origin it resolves to, the exact scope, the active modules, the paths named for state-changing methods and whether TLS verification is on, then waits for you to type the word `yes` on the controlling terminal (`/dev/tty`). Anything else, end of file, or no terminal at all means the active modules do not run; the passive results and the report are still written.

   For non-interactive runs, `--yes` stands in for the typed word. It is accepted only together with `--scope`, it is printed at the start of the run, and it is recorded in the report (`confirmation`). No environment variable and no configuration file can stand in for the confirmation: the tool reads neither for these options. An automation or AI agent driving the CLI can pass flags, but it cannot answer `/dev/tty`, which is the point.

   `--active` without `--scope`, `--yes` without `--scope`, `--only` naming an active module without `--active`, `--probe-path` without `--active`, and `--active` with neither a terminal nor `--yes` all stop with a usage error before anything runs.

### HTTP method policy

- By default the method check sends OPTIONS and HEAD only. A dangerous method (PUT, DELETE, PATCH, TRACE, CONNECT) that the server's `Allow` header announces is reported as "announced via OPTIONS", not as confirmed.
- POST, PUT, PATCH, DELETE, TRACE and CONNECT are sent by the `write_methods` module only, which needs `--active`, and even then only to the paths you name with `--probe-path` (repeatable; an absolute path on the named origin, or a URL on that origin). They are never sent to the named URL by default and never to a path another module discovered. Without `--probe-path`, `write_methods` is recorded as not run.
- Each probe is sent without a body.

### Sensitive-file checks

For each candidate path, `dangerous_files` sends a HEAD request first. Only when the server says the path is there (2xx, or 405/501 for servers that refuse HEAD) does a GET follow, and that GET asks for the first 512 bytes with a `Range: bytes=0-511` header and reads no more than 512 bytes before closing the connection, whether or not the server honours the range. A 401 or 403 is recorded from the HEAD alone. The report records presence and size (from `Content-Range` or `Content-Length`), never content, so a scan does not leave a copy of someone's `.env` in your output directory.

### Target fidelity

- The scanner requests exactly the scheme, host, port and path you named. It never switches ports (`https://example.com:8443/app` is scanned on 8443 under `/app`) and never scans a sibling host.
- Redirects are never followed by the HTTP library. A redirect to the same origin (same scheme, host and port) is followed for the named URL only, up to five hops. A redirect anywhere else, including `http` to `https` on the same host or the same host on another port, is refused: the request is not made, and the redirect is listed in the terminal and the report (`refused_redirects`). Rerun with the new URL if it is in scope.
- TLS certificate verification is on by default. `--insecure` turns it off for hosts with self-signed or otherwise untrusted certificates; the flag is printed at the start of the run and recorded in the report (`insecure`). nuclei does not verify certificates on its own.

### What this tool sends over the network

| Module | Mode | Destination | What is sent | When |
|---|---|---|---|---|
| discover | passive | the named URL | one GET; same-origin redirects followed up to five hops; at most 2 MiB of the decoded body is read, in 8 KiB chunks, and a compressed body that would expand past that is cut there and marked truncated | every run |
| headers | passive | nothing of its own | reuses the discover response (one GET in total when both run; one GET of its own with `--only headers`) | every run |
| methods | passive | the named URL | one HEAD and one OPTIONS | every run |
| risk | passive | nothing | nothing, computed offline | every run |
| dangerous_files | active | the named origin, under the named path | one GET of a random path for the 404 baseline, then one HEAD per candidate path (46 paths) and, for paths the server says exist, one GET asking for the first 512 bytes | `--active` only, after confirmation |
| write_methods | active | the paths named with `--probe-path`, on the named origin | POST, PUT, PATCH, DELETE, TRACE and CONNECT, one each per path, no body | `--active` with `--probe-path`, after confirmation |
| technology | active | the named URL | nuclei templates tagged `tech` and `exposure` at low severity and above: many HTTP requests, redirects disabled (`-disable-redirects`), no interactsh callbacks (`-ni`), no certificate verification | `--active` only, after confirmation, when nuclei is installed |

Besides resolving the named host through your system's DNS resolver (needed to connect at all, and repeated before the active confirmation to check the scope), the tool contacts no third party. There are no update checks, no telemetry and no out-of-band callback servers.

The HTTP session ignores the environment: `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` and `~/.netrc` are not consulted (`trust_env` is off on the `requests` session), so a request cannot leave through a proxy you did not name and no stored credential for the named host is sent silently. There is no proxy option; if a run has to go through one, that is a feature to ask for, not something the environment can switch on without a word in the output.

Text that came from the target (a `Location` header, a server banner, nuclei's stderr) is made inert before it is printed: control and format characters are shown as escapes and rich markup is shown literally, so a hostile response cannot style, clear or retitle your terminal. The HTML and JSON reports escape it as well.

### Known issues

- The scope check is by name or by resolved address; it does not yet show the owner of each address (CNAME target, ASN) at the confirmation prompt. Check the printed addresses against your authorization before typing yes.
- `install-deps.sh` downloads the latest nuclei release without a pinned version or checksum.

## What it is NOT

atarus-webscan is a **fast, signature-based, unauthenticated web app scanner**. It is not a replacement for:

- **Burp Suite or ZAP active scanning** (for SQL injection, XSS, CSRF testing)
- **Authenticated testing** (login flows, session handling)
- **Manual pentesting** (business logic flaws, IDOR, race conditions)
- **API security testing** (planned for v0.2)

For active injection testing, use Burp Suite or OWASP ZAP after running atarus-webscan.

## Roadmap

**Later:**
- ZAP baseline integration via `--deep` flag
- Authenticated scanning support
- API discovery (Swagger, GraphQL introspection)
- SPA rendering via Playwright
- Authentication module (session/JWT/CSRF testing)
- Misconfiguration scanner (cloud/SaaS leakage in JS bundles)
- Custom signature database

## Suite integration

atarus-webscan is part of the [Atarus offensive security tool suite](https://github.com/atarus-security):

- [atarus-recon](https://github.com/atarus-security/atarus-recon) - external attack surface reconnaissance
- [atarus-cloud](https://github.com/atarus-security/atarus-cloud) - AWS and Azure configuration auditor
- [atarus-phishcheck](https://github.com/atarus-security/atarus-phishcheck) - email security analyzer
- [atarus-report-kit](https://github.com/atarus-security/atarus-report-kit) - pentest report generator
- **atarus-webscan** - web application security scanner

The Python tools share the same CLI conventions (`--only`, `--skip`, `--format`) and report styling.

## Testing

```bash
python -m unittest discover -s tests -v
```

The tests are offline and use only the standard library. `tests/test_core.py` runs the modules against a throwaway HTTP server on 127.0.0.1; `tests/test_safe_default.py` replaces the HTTP layer with a recording fake and guards the socket layer, and covers the passive default (only GET, HEAD and OPTIONS leave), the 512-byte cap, the 2 MiB decoded cap against a gzip body that expands past it, the proxy and netrc environment being ignored, terminal escaping, refused redirects, the confirmation gate on a real pseudo-terminal, port preservation, the `--active` and `--yes` usage errors and the confirmation gate. GitHub Actions runs them on every push. `constraints.txt` records the dependency versions they last passed with.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability. The default run is passive. Only use `--active` against applications you own or are authorized in writing to test, and put exactly those hosts in `--scope`.

## License

MIT. See [LICENSE](LICENSE).

## About Atarus

[Atarus Offensive Security](https://atarussecurity.com) is a boutique offensive security firm. We build tools by practitioners, for practitioners.
