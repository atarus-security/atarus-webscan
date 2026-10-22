# atarus-webscan

Web application security scanner by [Atarus Offensive Security](https://atarussecurity.com).

A modern, focused web app scanner. Built as a smart replacement for legacy tools like Nikto: fewer false positives, modern framework awareness, clean reports.

```bash
atarus-webscan -t https://example.com
```

That single command produces:

- `atarus-webscan-example.com.html` - Atarus dark-theme report
- `atarus-webscan-example.com.pdf` - branded PDF export (needs the Pango system libraries, see Quick start)
- `atarus-webscan-example.com.json` - machine-readable output

## What it does

| Module | Description | External tool |
|---|---|---|
| `discover` | Site type and framework detection (17 frameworks and platforms) | None |
| `headers` | Security header analysis with grade for each | None |
| `methods` | Dangerous HTTP method detection (PUT, DELETE, TRACE, etc) | None |
| `dangerous_files` | Exposed sensitive file detection (.git, .env, backups, admin panels) | None |
| `technology` | Framework fingerprinting and CVE matching | nuclei |
| `risk` | Per-finding severity scoring and target risk rating | None |

## Smart 404 detection

Every probe is filtered against a calibrated 404 baseline. If a probed path returns a response that matches the catch-all 404 hash, it's discarded, even if the HTTP status is 200. This eliminates the most common false positives in legacy web scanners.

The `dangerous_files` module recalibrates its own baseline immediately before probing, to handle sites that cache or rate-limit differently over the course of a scan.

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

# Run a scan
atarus-webscan -t https://example.com
```

## Usage

Standard scan:
```bash
atarus-webscan -t https://example.com
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
- The target is a hostname. Any port in the URL is dropped, so a service on a non-standard port cannot be scanned yet.
- `--rate-limit` is accepted but not yet applied to requests. Each module sends its probes sequentially; nuclei runs with its own limit of 60 requests per second and a 90 second timeout.
- Without the Pango system libraries (`sudo apt install libpango-1.0-0 libpangoft2-1.0-0` on Debian or Kali) the scan, HTML and JSON reports work and the PDF step prints an error.

## What it is NOT

atarus-webscan is a **fast, signature-based, unauthenticated web app scanner**. It is not a replacement for:

- **Burp Suite or ZAP active scanning** (for SQL injection, XSS, CSRF testing)
- **Authenticated testing** (login flows, session handling)
- **Manual pentesting** (business logic flaws, IDOR, race conditions)
- **API security testing** (planned for v0.2)

For active injection testing, use Burp Suite or OWASP ZAP after running atarus-webscan.

## Roadmap

**v0.2 (next):**
- ZAP baseline integration via `--deep` flag
- Authenticated scanning support
- API discovery (Swagger, GraphQL introspection)
- SPA rendering via Playwright

**v0.3:**
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

The tests run the modules against a throwaway HTTP server on 127.0.0.1 and use only the standard library. GitHub Actions runs them on every push. `constraints.txt` records the dependency versions they last passed with.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability. Only scan applications you own or are authorized in writing to test.

## License

MIT. See [LICENSE](LICENSE).

## About Atarus

[Atarus Offensive Security](https://atarussecurity.com) is a boutique offensive security firm. We build tools by practitioners, for practitioners.
