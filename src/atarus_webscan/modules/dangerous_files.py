"""Detection of exposed sensitive files.

Probes for common sensitive paths with smart 404 baseline filtering to
eliminate false positives from catch-all routes.
"""
import requests
from atarus_webscan.models import ScanResult, Finding
from atarus_webscan.runner import ModuleResult
from atarus_webscan.baseline import BaselineDetector


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


def run(result: ScanResult, base_url: str, verbose: bool = False) -> ModuleResult:
    """Probe for exposed sensitive files using baseline filtering"""

    # Quick reachability check
    try:
        probe = requests.get(
            base_url,
            timeout=4,
            allow_redirects=False,
            headers={"User-Agent": "atarus-webscan/0.1.0"},
            verify=False,
        )
    except requests.RequestException as e:
        return ModuleResult(success=False, message=f"target unreachable: {type(e).__name__}")

    # Quick reachability check
    try:
        probe = requests.get(
            base_url,
            timeout=4,
            allow_redirects=False,
            headers={"User-Agent": "atarus-webscan/0.1.0"},
            verify=False,
        )
    except requests.RequestException as e:
        return ModuleResult(success=False, message=f"target unreachable: {type(e).__name__}")

    baseline = BaselineDetector(base_url)
    baseline.calibrate(verbose=verbose)

    found = 0
    filtered = 0

    for path, severity, title, description in SENSITIVE_PATHS:
        url = f"{base_url}/{path}"

        try:
            resp = requests.get(
                url,
                timeout=5,
                allow_redirects=False,
                headers={"User-Agent": "atarus-webscan/0.1.0"},
                verify=False,
            )
        except requests.RequestException:
            continue

        # Skip 404s
        if resp.status_code == 404:
            continue

        # Skip baseline matches (catch-all 200s)
        if baseline.matches_baseline(resp):
            filtered += 1
            continue

        # Skip redirects to login/marketing pages (typically 302 to the homepage)
        if resp.status_code in (301, 302, 303, 307, 308):
            continue

        # Skip empty responses (some servers 200 with no body for unknown routes)
        if resp.status_code == 200 and len(resp.content) < 50:
            continue

        if resp.status_code == 200:
            found += 1
            result.findings.append(Finding(
                title=title,
                severity=severity,
                description=description,
                url=url,
                evidence=f"HTTP {resp.status_code}, {len(resp.content)} bytes",
                remediation=f"Restrict public access to /{path}",
                category="dangerous_files",
                owasp_mapping="A05:2021 Security Misconfiguration",
            ))

        elif resp.status_code in (401, 403):
            # Auth-protected paths still indicate the file exists
            if severity in ("critical", "high"):
                result.findings.append(Finding(
                    title=f"{title} (auth-protected)",
                    severity="low",
                    description=f"{description}. The file appears to exist but requires authentication.",
                    url=url,
                    evidence=f"HTTP {resp.status_code}",
                    remediation=f"Confirm /{path} is intentionally exposed and access controls are correct",
                    category="dangerous_files",
                    owasp_mapping="A05:2021 Security Misconfiguration",
                ))

    msg = f"{found} sensitive paths exposed, {filtered} false positives filtered"
    return ModuleResult(success=True, message=msg)
