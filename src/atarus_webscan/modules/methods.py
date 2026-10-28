"""HTTP method checks with safe methods only.

Passive module. Sends one HEAD and one OPTIONS request to the URL the user
named, confirms those two methods and reads the OPTIONS Allow header. A
dangerous method that the server announces there is reported as announced,
not confirmed. Nothing state-changing is sent here: POST, PUT, PATCH,
DELETE, TRACE and CONNECT belong to the active write_methods module, which
only sends them to a path the user named with --probe-path.
"""
from atarus_webscan.models import ScanResult, Finding
from atarus_webscan.runner import ModuleResult
from atarus_webscan.transport import TransportError


SAFE_METHODS = ["HEAD", "OPTIONS"]


DANGEROUS_METHODS = {
    "PUT": ("high", "PUT allows file upload to arbitrary paths"),
    "DELETE": ("high", "DELETE allows resource deletion"),
    "TRACE": ("medium", "TRACE enables Cross-Site Tracing (XST) attacks"),
    "CONNECT": ("high", "CONNECT enables proxy tunnel abuse"),
    "PATCH": ("medium", "PATCH allows resource modification, often unintended"),
}


def _accepted(status: int) -> bool:
    """A method counts as accepted when the server did not reject it as a method.
    401 and 403 mean the route exists behind auth, which still tells us the method is routed."""
    return status < 400 or status in (401, 403)


def run(result: ScanResult, client, verbose: bool = False) -> ModuleResult:
    """Send HEAD and OPTIONS to the named URL and read the Allow header"""

    base_url = client.base_url
    confirmed = []

    named = client.named_cached()
    if named is not None and not named.redirect_refused and _accepted(named.status):
        confirmed.append("GET")

    responses = {}
    for method in SAFE_METHODS:
        try:
            responses[method] = client.send(method, base_url)
        except TransportError as e:
            if not responses and method == SAFE_METHODS[0]:
                return ModuleResult(success=False, message=f"target unreachable: {e}")
            continue
        if _accepted(responses[method].status):
            confirmed.append(method)

    announced = []
    opts = responses.get("OPTIONS")
    if opts is not None:
        allow_header = opts.headers.get("Allow", "")
        if allow_header:
            announced = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
            for method in announced:
                if method in DANGEROUS_METHODS:
                    severity, desc = DANGEROUS_METHODS[method]
                    result.findings.append(Finding(
                        title=f"{method} method announced via OPTIONS",
                        severity=severity,
                        description=(
                            f"{desc}. The server's OPTIONS Allow header announces {method}. "
                            f"It was announced, not probed: run with --active and --probe-path to confirm it."
                        ),
                        url=base_url,
                        evidence=f"Allow: {allow_header}",
                        remediation=f"Either disable {method} or remove it from OPTIONS Allow",
                        category="methods",
                        owasp_mapping="A05:2021 Security Misconfiguration",
                    ))

    for m in confirmed:
        if m not in result.methods_allowed:
            result.methods_allowed.append(m)
    result.methods_announced = announced

    msg = f"{len(confirmed)} safe methods confirmed: {', '.join(confirmed) or 'none'}"
    if announced:
        msg += f"; OPTIONS announces: {', '.join(announced)}"
    return ModuleResult(success=True, message=msg)
