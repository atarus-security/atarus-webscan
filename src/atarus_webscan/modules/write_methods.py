"""State-changing HTTP method probes.

Active module. Sends POST, PUT, PATCH, DELETE, TRACE and CONNECT, each
without a body, to the paths the user named with --probe-path and to no
other path: never to the named URL by default and never to a path another
module discovered. Runs only behind --active, inside --scope and after the
confirmation gate. Without --probe-path it does not run and says so.
"""
from atarus_webscan.models import ScanResult, Finding
from atarus_webscan.runner import ModuleResult
from atarus_webscan.transport import TransportError
from atarus_webscan.modules.methods import DANGEROUS_METHODS, _accepted


WRITE_METHODS = ["POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"]


def run(result: ScanResult, client, verbose: bool = False) -> ModuleResult:
    """Probe each state-changing method against each user-named path"""

    if not result.probe_paths:
        return ModuleResult(
            success=False,
            message="no --probe-path named; state-changing methods are only sent to a path you name",
        )

    confirmed = []
    probed = 0
    for path in result.probe_paths:
        url = client.target.url_for(path)
        for method in WRITE_METHODS:
            try:
                resp = client.send(method, url)
            except TransportError:
                continue
            probed += 1
            if not _accepted(resp.status):
                continue
            label = f"{method} {path}"
            confirmed.append(label)
            if method not in result.methods_allowed:
                result.methods_allowed.append(method)
            if method in DANGEROUS_METHODS:
                severity, desc = DANGEROUS_METHODS[method]
                result.findings.append(Finding(
                    title=f"{method} method enabled",
                    severity=severity,
                    description=desc,
                    url=url,
                    evidence=f"Server returned HTTP {resp.status} for {method} {path}",
                    remediation=f"Disable {method} on the server unless explicitly required",
                    category="methods",
                    owasp_mapping="A05:2021 Security Misconfiguration",
                ))

    if probed == 0:
        return ModuleResult(success=False, message="no probe reached the target")

    # A method confirmed here supersedes the "announced via OPTIONS" note for it.
    confirmed_methods = {label.split(" ", 1)[0] for label in confirmed}
    result.findings[:] = [
        f for f in result.findings
        if not (f.category == "methods" and f.title.endswith("announced via OPTIONS")
                and f.title.split(" ", 1)[0] in confirmed_methods)
    ]

    return ModuleResult(
        success=True,
        message=f"{probed} probes sent to {len(result.probe_paths)} path(s); accepted: {', '.join(confirmed) or 'none'}",
    )
