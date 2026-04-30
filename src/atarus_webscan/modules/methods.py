"""Dangerous HTTP method detection.

Probes the target with each HTTP method and flags methods that should not
be exposed in production.
"""
import requests
from atarus_webscan.models import ScanResult, Finding
from atarus_webscan.runner import ModuleResult


METHODS_TO_TEST = [
    "GET", "POST", "PUT", "DELETE", "PATCH",
    "OPTIONS", "TRACE", "CONNECT", "HEAD",
]


DANGEROUS_METHODS = {
    "PUT": ("high", "PUT allows file upload to arbitrary paths"),
    "DELETE": ("high", "DELETE allows resource deletion"),
    "TRACE": ("medium", "TRACE enables Cross-Site Tracing (XST) attacks"),
    "CONNECT": ("high", "CONNECT enables proxy tunnel abuse"),
    "PATCH": ("medium", "PATCH allows resource modification, often unintended"),
}


def run(result: ScanResult, base_url: str, verbose: bool = False) -> ModuleResult:
    """Probe each HTTP method against the target"""

    allowed = []

    # Quick reachability check before iterating methods
    try:
        probe = requests.get(
            base_url,
            timeout=4,
            allow_redirects=False,
            headers={"User-Agent": "atarus-webscan/0.1.0"},
            verify=False,
        )
        if probe.status_code == 0:
            return ModuleResult(success=False, message="target unreachable")
    except requests.RequestException as e:
        return ModuleResult(success=False, message=f"target unreachable: {type(e).__name__}")

    for method in METHODS_TO_TEST:
        try:
            resp = requests.request(
                method,
                base_url,
                timeout=4,
                allow_redirects=False,
                headers={"User-Agent": "atarus-webscan/0.1.0"},
                verify=False,
            )

            if resp.status_code < 400 or resp.status_code in (401, 403):
                allowed.append(method)

                if method in DANGEROUS_METHODS:
                    severity, desc = DANGEROUS_METHODS[method]
                    result.findings.append(Finding(
                        title=f"{method} method enabled",
                        severity=severity,
                        description=desc,
                        url=base_url,
                        evidence=f"Server returned HTTP {resp.status_code} for {method}",
                        remediation=f"Disable {method} method on the server unless explicitly required",
                        category="methods",
                        owasp_mapping="A05:2021 Security Misconfiguration",
                    ))

        except requests.RequestException:
            continue

    # OPTIONS Allow header check
    try:
        opts_resp = requests.options(
            base_url,
            timeout=4,
            headers={"User-Agent": "atarus-webscan/0.1.0"},
            verify=False,
        )
        allow_header = opts_resp.headers.get("Allow", "") or opts_resp.headers.get("allow", "")
        if allow_header:
            announced = [m.strip().upper() for m in allow_header.split(",")]
            for method in announced:
                if method in DANGEROUS_METHODS and method not in allowed:
                    severity, desc = DANGEROUS_METHODS[method]
                    result.findings.append(Finding(
                        title=f"{method} method announced via OPTIONS",
                        severity=severity,
                        description=f"{desc}. Server's OPTIONS Allow header announces {method} is supported.",
                        url=base_url,
                        evidence=f"Allow: {allow_header}",
                        remediation=f"Either disable {method} or remove it from OPTIONS Allow",
                        category="methods",
                        owasp_mapping="A05:2021 Security Misconfiguration",
                    ))
    except requests.RequestException:
        pass

    result.methods_allowed = allowed

    return ModuleResult(success=True, message=f"{len(allowed)} methods allowed: {', '.join(allowed)}")
