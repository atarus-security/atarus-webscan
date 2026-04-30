"""Site type and framework detection.

Identifies whether the target is an SPA, server-rendered, static, or API,
and detects the underlying framework via response headers and HTML markers.
"""
import re
import requests
from atarus_webscan.models import ScanResult, Technology
from atarus_webscan.runner import ModuleResult


FRAMEWORK_SIGNATURES = {
    "Next.js": [
        ("html", r'__NEXT_DATA__'),
        ("html", r'/_next/'),
        ("header", "x-powered-by", "next.js"),
    ],
    "Nuxt.js": [
        ("html", r'__NUXT__'),
        ("html", r'/_nuxt/'),
    ],
    "React": [
        ("html", r'<div id="root"'),
        ("html", r'react-dom'),
    ],
    "Vue.js": [
        ("html", r'data-v-app'),
        ("html", r'__vue__'),
    ],
    "Angular": [
        ("html", r'ng-version'),
        ("html", r'_ngcontent'),
    ],
    "Django": [
        ("header", "x-powered-by", "django"),
        ("html", r'csrfmiddlewaretoken'),
    ],
    "Rails": [
        ("header", "x-powered-by", "rails"),
        ("html", r'csrf-param.*authenticity_token'),
    ],
    "Laravel": [
        ("cookie", "laravel_session"),
        ("cookie", "XSRF-TOKEN"),
    ],
    "WordPress": [
        ("html", r'wp-content/'),
        ("html", r'wp-includes/'),
        ("header", "x-powered-by", "wordpress"),
    ],
    "Drupal": [
        ("html", r'Drupal\.settings'),
        ("header", "x-generator", "drupal"),
    ],
    "Express.js": [
        ("header", "x-powered-by", "express"),
    ],
    "ASP.NET": [
        ("header", "x-powered-by", "asp.net"),
        ("header", "x-aspnet-version", ""),
    ],
    "Spring Boot": [
        ("header", "x-application-context", ""),
    ],
    "Flask": [
        ("header", "server", "werkzeug"),
    ],
    "Vercel": [
        ("header", "server", "vercel"),
        ("header", "x-vercel-id", ""),
    ],
    "Cloudflare Pages": [
        ("header", "server", "cloudflare"),
        ("header", "cf-ray", ""),
    ],
    "Netlify": [
        ("header", "server", "netlify"),
        ("header", "x-nf-request-id", ""),
    ],
}


def run(result: ScanResult, base_url: str, verbose: bool = False) -> ModuleResult:
    """Detect site type and framework"""

    try:
        resp = requests.get(
            base_url,
            timeout=15,
            allow_redirects=True,
            headers={"User-Agent": "atarus-webscan/0.1.0"},
            verify=False,
        )
    except requests.RequestException as e:
        return ModuleResult(success=False, message=f"could not reach target: {type(e).__name__}")

    html = resp.text or ""
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    # Server detection
    if "server" in headers_lower:
        result.server = headers_lower["server"]

    # Site type detection
    result.site_type = _detect_site_type(html, headers_lower, resp)

    # Framework detection
    detected = []
    for fw_name, signatures in FRAMEWORK_SIGNATURES.items():
        for sig in signatures:
            if _matches_signature(sig, html, headers_lower, resp.cookies):
                if fw_name not in detected:
                    detected.append(fw_name)
                break

    if detected:
        result.framework = detected[0]
        for fw in detected:
            result.technologies.append(Technology(
                name=fw,
                category="framework",
                confidence="high",
            ))

    if result.server:
        result.technologies.append(Technology(
            name=result.server.split("/")[0].split(" ")[0],
            version=_extract_version(result.server),
            category="server",
            confidence="high",
        ))

    msg = f"site type: {result.site_type}"
    if detected:
        msg += f", framework: {', '.join(detected)}"
    if result.server:
        msg += f", server: {result.server}"

    return ModuleResult(success=True, message=msg)


def _detect_site_type(html: str, headers: dict, resp) -> str:
    """Classify the site as spa, server-rendered, static, or api"""
    content_type = headers.get("content-type", "").lower()

    if "json" in content_type:
        return "api"

    if not html or len(html) < 200:
        return "minimal"

    spa_markers = [
        r'<div id="root"',
        r'<div id="app"',
        r'__NEXT_DATA__',
        r'__NUXT__',
        r'ng-version',
        r'data-v-app',
    ]
    spa_count = sum(1 for m in spa_markers if re.search(m, html, re.IGNORECASE))

    if spa_count >= 1 and len(html) < 50000:
        return "spa"

    server_markers = [
        r'csrfmiddlewaretoken',
        r'authenticity_token',
        r'wp-content',
        r'jsessionid',
    ]
    if any(re.search(m, html, re.IGNORECASE) for m in server_markers):
        return "server-rendered"

    if "set-cookie" not in headers and "cache-control" in headers:
        if "max-age" in headers.get("cache-control", "").lower():
            return "static"

    return "server-rendered"


def _matches_signature(sig: tuple, html: str, headers: dict, cookies) -> bool:
    """Check if a single signature matches the response"""
    sig_type = sig[0]

    if sig_type == "html":
        pattern = sig[1]
        return bool(re.search(pattern, html, re.IGNORECASE))

    if sig_type == "header":
        header_name = sig[1].lower()
        expected = sig[2].lower() if sig[2] else ""
        if header_name not in headers:
            return False
        if not expected:
            return True
        return expected in headers[header_name].lower()

    if sig_type == "cookie":
        cookie_name = sig[1]
        return cookie_name in cookies

    return False


def _extract_version(server_string: str) -> str:
    """Pull a version number from a server header value"""
    m = re.search(r'(\d+(?:\.\d+)+)', server_string)
    return m.group(1) if m else ""
