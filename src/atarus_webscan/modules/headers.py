"""Security header analysis.

Probes the target for security headers and grades each one.
"""
from atarus_webscan.models import ScanResult, Finding, HeaderAnalysis
from atarus_webscan.runner import ModuleResult
from atarus_webscan.transport import TransportError
from atarus_webscan.scope import safe_text


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "high",
        "description": "CSP prevents XSS and data injection attacks",
        "owasp": "A05:2021 Security Misconfiguration",
    },
    "Strict-Transport-Security": {
        "severity": "high",
        "description": "HSTS prevents protocol downgrade attacks and cookie hijacking",
        "owasp": "A02:2021 Cryptographic Failures",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "Prevents clickjacking via iframe embedding",
        "owasp": "A05:2021 Security Misconfiguration",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "description": "Prevents MIME-sniffing attacks",
        "owasp": "A05:2021 Security Misconfiguration",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Controls referrer information leakage",
        "owasp": "A01:2021 Broken Access Control",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Controls browser feature access (camera, mic, geolocation)",
        "owasp": "A05:2021 Security Misconfiguration",
    },
}


VERSION_DISCLOSING_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
]


def run(result: ScanResult, client, verbose: bool = False) -> ModuleResult:
    """Analyze the security headers of the single GET of the named URL.

    Passive module. Sends no request of its own when discover has already
    fetched the named URL; the response is shared through the client.
    """

    try:
        resp = client.fetch_named()
    except TransportError as e:
        return ModuleResult(success=False, message=f"could not fetch headers: {e}")

    if resp.redirect_refused:
        return ModuleResult(
            success=False,
            message=f"the named URL redirects off-origin to {safe_text(resp.redirect_to, 300)}; headers not analyzed",
        )

    base_url = resp.url
    headers_lower = resp.headers_lower()

    missing = 0
    present = 0
    weak = 0

    for header_name, meta in SECURITY_HEADERS.items():
        h_lower = header_name.lower()

        if h_lower not in headers_lower:
            result.headers.append(HeaderAnalysis(
                header=header_name,
                present=False,
                issue=f"Missing {header_name}",
                severity=meta["severity"],
            ))
            result.findings.append(Finding(
                title=f"Missing {header_name} header",
                severity=meta["severity"],
                description=meta["description"],
                url=base_url,
                evidence=f"Response headers do not include {header_name}",
                remediation=f"Add {header_name} to all HTTP responses with appropriate values",
                category="headers",
                owasp_mapping=meta["owasp"],
            ))
            missing += 1
        else:
            value = headers_lower[h_lower]
            issue = _grade_header(header_name, value)
            result.headers.append(HeaderAnalysis(
                header=header_name,
                present=True,
                value=value,
                issue=issue,
                severity=meta["severity"] if issue else "",
            ))
            if issue:
                result.findings.append(Finding(
                    title=f"Weak {header_name} configuration",
                    severity=meta["severity"],
                    description=issue,
                    url=base_url,
                    evidence=f"{header_name}: {value}",
                    remediation=f"Strengthen {header_name} per OWASP guidance",
                    category="headers",
                    owasp_mapping=meta["owasp"],
                ))
                weak += 1
            else:
                present += 1

    # Version disclosure check
    for vh in VERSION_DISCLOSING_HEADERS:
        if vh in headers_lower:
            value = headers_lower[vh]
            if any(c.isdigit() for c in value):
                result.findings.append(Finding(
                    title=f"Version disclosure via {vh} header",
                    severity="low",
                    description=f"The {vh} header reveals software version, helping attackers find known CVEs",
                    url=base_url,
                    evidence=f"{vh}: {value}",
                    remediation=f"Remove or obfuscate the {vh} header",
                    category="headers",
                    owasp_mapping="A05:2021 Security Misconfiguration",
                ))

    msg = f"{present} present, {missing} missing, {weak} weak"
    return ModuleResult(success=True, message=msg)


def _grade_header(header_name: str, value: str) -> str:
    """Return an issue string if header is weak, empty if OK"""
    v = value.lower()

    if header_name == "Content-Security-Policy":
        if "unsafe-inline" in v:
            return "CSP contains unsafe-inline which permits inline scripts"
        if "unsafe-eval" in v:
            return "CSP contains unsafe-eval which permits dynamic code execution"
        if "*" in v and "default-src" in v:
            return "CSP uses wildcard default-src which is overly permissive"

    if header_name == "Strict-Transport-Security":
        if "max-age=0" in v:
            return "HSTS max-age is 0, effectively disabled"
        if "max-age=" in v:
            try:
                max_age = int(v.split("max-age=")[1].split(";")[0].split(",")[0].strip())
                if max_age < 15768000:
                    return f"HSTS max-age ({max_age}) below recommended 6 months"
            except (ValueError, IndexError):
                pass

    if header_name == "X-Frame-Options":
        if v not in ("deny", "sameorigin"):
            return f"X-Frame-Options value '{value}' is not DENY or SAMEORIGIN"

    if header_name == "X-Content-Type-Options":
        if v != "nosniff":
            return f"X-Content-Type-Options should be 'nosniff', got '{value}'"

    if header_name == "Referrer-Policy":
        weak_policies = ["unsafe-url", "no-referrer-when-downgrade", ""]
        if v in weak_policies:
            return f"Referrer-Policy '{value}' leaks referrer to third parties"

    return ""
