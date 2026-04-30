# atarus-webscan

Web application security scanner by [Atarus Offensive Security](https://atarussecurity.com).

A modern, focused web app scanner. Built as a smart replacement for legacy tools like Nikto: fewer false positives, modern framework awareness, clean reports.

```bash
atarus-webscan -t https://example.com
```

That single command produces:

- `atarus-webscan-example.com.html` — Atarus dark-theme tabbed report
- `atarus-webscan-example.com.pdf` — branded PDF export
- `atarus-webscan-example.com.json` — machine-readable output

## What it does

| Module | Description | External tool |
|---|---|---|
| `discover` | Site type and framework detection (16 frameworks) | None |
| `headers` | Security header analysis with grade for each | None |
| `methods` | Dangerous HTTP method detection (PUT, DELETE, TRACE, etc) | None |
| `dangerous_files` | Exposed sensitive file detection (.git, .env, backups, admin panels) | None |
| `technology` | Framework fingerprinting and CVE matching | nuclei |
| `risk` | Per-finding severity scoring and target risk rating | None |

## Smart 404 detection

Every probe is filtered against a calibrated 404 baseline. If a probed path returns a response that matches the catch-all 404 hash, it's discarded, even if the HTTP status is 200. This eliminates the most common false positives in legacy web scanners.

The baseline is recalibrated per-module to handle sites that cache or rate-limit differently across paths.

## Modern framework awareness

`discover` identifies these frameworks via response markers:

Next.js, Nuxt.js, React, Vue.js, Angular, Django, Rails, Laravel, WordPress, Drupal, Express.js, ASP.NET, Spring Boot, Flask, Vercel, Cloudflare Pages, Netlify

This drives smarter probing, fewer false positives, and accurate technology fingerprinting in the report.

## Quick start

```bash
git clone https://github.com/atarus-security/atarus-webscan.git
cd atarus-webscan

# Python deps
python3 -m venv venv
source venv/bin/activate
pip install -e .

# External tools (nuclei)
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

- [atarus-recon](https://github.com/atarus-security/atarus-recon) — external attack surface reconnaissance
- [atarus-cloud](https://github.com/atarus-security/atarus-cloud) — AWS and Azure configuration auditor
- [atarus-phishcheck](https://github.com/atarus-security/atarus-phishcheck) — email security analyzer
- [atarus-report-kit](https://github.com/atarus-security/atarus-report-kit) — pentest report generator
- **atarus-webscan** — web application security scanner

All tools share the same scope validator, output format, and report styling.

## License

MIT

## About Atarus

[Atarus Offensive Security](https://atarussecurity.com) is a boutique offensive security firm. We build tools by practitioners, for practitioners.
