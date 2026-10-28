"""Detection of exposed sensitive files.

Active module: it sends a request per candidate path, so it runs only behind
--active, inside --scope and after the confirmation gate.

Each candidate gets a HEAD request first. Only when the server says the path
is there does a GET follow, and that GET asks for the first 512 bytes with a
Range header and reads no more than that before closing the connection. A
candidate secret is never downloaded whole, and the report records that the
file is present and how large it is, never its content. A smart 404 baseline
(one capped GET of a random path) filters catch-all routes.
"""
from atarus_webscan.models import ScanResult, Finding
from atarus_webscan.runner import ModuleResult
from atarus_webscan.baseline import BaselineDetector
from atarus_webscan.transport import TransportError, PROBE_READ_LIMIT


SENSITIVE_PATHS = [
    (".git/config", "critical", "Git configuration exposed", "Source code likely accessible via .git directory"),
    (".git/HEAD", "critical", "Git HEAD exposed", "Repository metadata accessible"),
    (".env", "critical", "Environment file exposed", "Likely contains secrets, API keys, database credentials"),
    (".env.local", "critical", "Local environment file exposed", "Likely contains secrets"),
    (".env.production", "critical", "Production environment file exposed", "Likely contains production secrets"),
    (".aws/credentials", "critical", "AWS credentials file exposed", "Cloud credentials likely accessible"),
    (".ssh/id_rsa", "critical", "SSH private key exposed", "Server access compromised"),
    (".npmrc", "high", ".npmrc exposed", "May contain npm auth tokens"),
    (".dockercfg", "high", ".dockercfg exposed", "May contain Docker registry credentials"),
    ("docker-compose.yml", "medium", "docker-compose.yml exposed", "Reveals service architecture and possible credentials"),
    ("config.json", "medium", "config.json exposed", "May contain application configuration"),
    ("config.yaml", "medium", "config.yaml exposed", "May contain application configuration"),
    ("config.yml", "medium", "config.yml exposed", "May contain application configuration"),
    ("settings.py", "medium", "Django settings.py exposed", "May reveal SECRET_KEY and database credentials"),
    ("web.config", "medium", "IIS web.config exposed", "May reveal server configuration"),
    ("phpinfo.php", "high", "phpinfo() exposed", "Reveals server configuration, paths, environment"),
    ("info.php", "high", "info.php exposed", "Likely phpinfo() output"),
    ("test.php", "low", "test.php exposed", "Often left over from debugging"),
    ("backup.sql", "high", "Database backup exposed", "Full database content accessible"),
    ("backup.zip", "high", "Backup archive exposed", "Site backup accessible"),
    ("backup.tar.gz", "high", "Backup tarball exposed", "Site backup accessible"),
    ("dump.sql", "high", "Database dump exposed", "Full database content accessible"),
    (".DS_Store", "low", ".DS_Store exposed", "macOS metadata reveals directory structure"),
    ("crossdomain.xml", "low", "crossdomain.xml exposed", "Adobe Flash policy file, often overly permissive"),
    ("clientaccesspolicy.xml", "low", "clientaccesspolicy.xml exposed", "Silverlight policy file"),
    ("robots.txt", "info", "robots.txt present", "Reveals paths the operator wants to hide from search engines"),
    ("sitemap.xml", "info", "sitemap.xml present", "Lists site URLs for crawlers"),
    ("server-status", "high", "Apache server-status exposed", "Reveals server activity, requests, and IPs"),
    ("server-info", "high", "Apache server-info exposed", "Reveals server configuration"),
    (".well-known/security.txt", "info", "security.txt present", "Vulnerability disclosure contact info"),
    ("admin/", "medium", "admin path returns content", "Possible admin interface, requires manual verification"),
    ("administrator/", "medium", "administrator path returns content", "Possible Joomla admin"),
    ("phpmyadmin/", "high", "phpMyAdmin exposed", "Database admin interface accessible"),
    ("wp-admin/", "medium", "WordPress admin exposed", "Admin interface accessible, brute-force target"),
    ("wp-login.php", "low", "WordPress login exposed", "Login page accessible"),
    ("api/swagger", "low", "Swagger UI exposed", "API documentation reveals endpoints"),
    ("swagger.json", "low", "swagger.json exposed", "API spec reveals all endpoints and schemas"),
    ("swagger-ui.html", "low", "Swagger UI exposed", "API documentation accessible"),
    ("openapi.json", "low", "openapi.json exposed", "API spec accessible"),
    ("graphql", "info", "GraphQL endpoint reachable", "May allow introspection queries"),
    ("composer.json", "low", "composer.json exposed", "Reveals PHP dependency versions"),
    ("composer.lock", "low", "composer.lock exposed", "Reveals exact PHP dependency versions"),
    ("package.json", "low", "package.json exposed", "Reveals Node dependency versions"),
    ("package-lock.json", "low", "package-lock.json exposed", "Reveals exact Node dependency versions"),
    ("Gemfile", "low", "Gemfile exposed", "Reveals Ruby dependency versions"),
    ("Gemfile.lock", "low", "Gemfile.lock exposed", "Reveals exact Ruby dependency versions"),
]


def run(result: ScanResult, client, verbose: bool = False) -> ModuleResult:
    """Probe for exposed sensitive files: HEAD first, then a capped GET"""

    base_url = client.base_url

    baseline = BaselineDetector(client)
    if not baseline.calibrate(verbose=verbose):
        return ModuleResult(success=False, message="target unreachable: the baseline request failed")
    result.baseline_404_hash = baseline.baseline_hash[:16] if baseline.baseline_hash else ""
    result.baseline_404_status = baseline.baseline_status

    found = 0
    filtered = 0
    heads = 0
    gets = 0

    for path, severity, title, description in SENSITIVE_PATHS:
        url = f"{base_url}/{path}"

        try:
            head = client.head(url)
        except TransportError:
            continue
        heads += 1

        # Absent, or a redirect (typically to a login or marketing page). Not followed.
        if head.status == 404 or head.is_redirect:
            continue

        if head.status in (401, 403):
            # Auth-protected paths still indicate the file exists. No GET is sent.
            if severity in ("critical", "high"):
                result.findings.append(Finding(
                    title=f"{title} (auth-protected)",
                    severity="low",
                    description=f"{description}. The file appears to exist but requires authentication.",
                    url=url,
                    evidence=f"HTTP {head.status} to HEAD",
                    remediation=f"Confirm /{path} is intentionally exposed and access controls are correct",
                    category="dangerous_files",
                    owasp_mapping="A05:2021 Security Misconfiguration",
                ))
            continue

        # HEAD said 2xx (or the server does not take HEAD: 405, 501). Ask for
        # the first bytes only, enough to tell the file from the 404 page.
        if not (200 <= head.status < 300 or head.status in (405, 501)):
            continue

        try:
            resp = client.get_capped(url)
        except TransportError:
            continue
        gets += 1

        if resp.status == 404 or resp.is_redirect:
            continue

        if resp.status in (401, 403):
            continue

        if resp.status not in (200, 206):
            continue

        if baseline.matches_baseline(resp):
            filtered += 1
            continue

        # Some servers answer 200 with no body for unknown routes.
        size = resp.declared_length if resp.declared_length is not None else len(resp.body)
        if size < 50:
            continue

        found += 1
        result.findings.append(Finding(
            title=title,
            severity=severity,
            description=description,
            url=url,
            evidence=(
                f"HTTP {resp.status}, {resp.size_text()}. Presence and size only: the scanner asked for the "
                f"first {PROBE_READ_LIMIT} bytes (Range) and stored none of the content."
            ),
            remediation=f"Restrict public access to /{path}",
            category="dangerous_files",
            owasp_mapping="A05:2021 Security Misconfiguration",
        ))

    msg = f"{found} sensitive paths exposed, {filtered} false positives filtered ({heads} HEAD, {gets} capped GET)"
    return ModuleResult(success=True, message=msg)
