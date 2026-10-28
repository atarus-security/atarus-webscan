"""Technology fingerprinting and CVE matching via nuclei.

Active module: nuclei sends many requests to the named URL, so it runs only
behind --active, inside --scope and after the confirmation gate.

Wraps the nuclei binary to run technology-detection and CVE templates and
parses results into Atarus Finding objects. nuclei is given the named URL
only, with redirects and interactsh (out-of-band callbacks to a third-party
server) disabled. A missing binary, a non-zero exit or a timeout is
reported as the check not having run, never as a clean result.
"""
import json
import os
import shutil
import subprocess
import tempfile
from atarus_webscan.models import ScanResult, Finding, Technology
from atarus_webscan.runner import ModuleResult


# How much of nuclei's stderr is kept for the not-run reason.
STDERR_TAIL = 200


def run(result: ScanResult, client, verbose: bool = False) -> ModuleResult:
    """Run nuclei technology and CVE detection against the named URL"""

    base_url = client.base_url
    nuclei_path = _find_nuclei()
    if not nuclei_path:
        return ModuleResult(
            success=False,
            message="nuclei not found. Install: ./install-deps.sh or go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        )

    if verbose:
        print(f"  using nuclei binary: {nuclei_path}")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as target_file:
        target_file.write(base_url + "\n")
        target_path = target_file.name

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as output_file:
        output_path = output_file.name

    try:
        cmd = [
            nuclei_path,
            "-list", target_path,
            "-tags", "tech,exposure",
            "-severity", "low,medium,high,critical",
            "-jsonl",
            "-o", output_path,
            "-silent",
            "-disable-update-check",
            "-max-host-error", "3",
            "-timeout", "8",
            "-rate-limit", "60",
            # No interactsh: no out-of-band callbacks through a third-party server.
            "-ni",
            # Stay on the named origin: nuclei must not follow redirects elsewhere.
            "-disable-redirects",
        ]

        if not verbose:
            cmd.extend(["-no-color"])

        try:
            proc = subprocess.run(
                cmd,
                timeout=90,
                capture_output=True,
                text=True,
            )
        except subprocess.TimeoutExpired:
            return ModuleResult(success=False, message="nuclei timed out after 90 seconds; check not completed")
        except OSError as e:
            return ModuleResult(success=False, message=f"nuclei could not be started: {type(e).__name__}")

        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout or "").strip().replace("\n", " ")[-STDERR_TAIL:]
            return ModuleResult(
                success=False,
                message=f"nuclei exited with code {proc.returncode}; check not completed. {tail}".strip(),
            )

        techs = 0
        vulns = 0

        try:
            with open(output_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    info = record.get("info", {})
                    template_id = record.get("template-id", "")
                    severity = (info.get("severity") or "info").lower()
                    name = info.get("name", "").strip()
                    tags = info.get("tags", []) or []

                    if "tech" in tags:
                        result.technologies.append(Technology(
                            name=name,
                            version=_extract_matched_version(record),
                            category="library",
                            confidence="high",
                        ))
                        techs += 1
                        continue

                    if severity == "info":
                        continue

                    cve = ""
                    classification = info.get("classification") or {}
                    cve_list = classification.get("cve-id") or []
                    if isinstance(cve_list, list) and cve_list:
                        cve = cve_list[0]
                    elif isinstance(cve_list, str):
                        cve = cve_list

                    description = info.get("description", "").strip() or "Vulnerability detected by nuclei template"
                    matched_at = record.get("matched-at", base_url)
                    extracted = record.get("extracted-results", []) or []
                    evidence = ", ".join(extracted[:3]) if extracted else f"matched {template_id}"

                    result.findings.append(Finding(
                        title=name or template_id,
                        severity=severity,
                        description=description[:500],
                        url=matched_at,
                        evidence=evidence[:300],
                        remediation=info.get("remediation", "")[:300],
                        category="technology",
                        owasp_mapping=_classify_owasp(tags, severity),
                        cve=cve,
                    ))
                    vulns += 1

        except FileNotFoundError:
            return ModuleResult(success=False, message="nuclei wrote no output file; check not completed")

        msg = f"{techs} technologies detected, {vulns} vulnerabilities"
        return ModuleResult(success=True, message=msg)

    finally:
        for path in (target_path, output_path):
            try:
                os.unlink(path)
            except OSError:
                pass


def _find_nuclei() -> str:
    """Locate the nuclei binary"""
    candidates = [
        os.path.expanduser("~/go/bin/nuclei"),
        "/usr/local/bin/nuclei",
        "/usr/bin/nuclei",
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c

    return shutil.which("nuclei") or ""


def _extract_matched_version(record: dict) -> str:
    """Pull a version string from nuclei extracted results if present"""
    extracted = record.get("extracted-results", [])
    if not extracted:
        return ""
    for item in extracted:
        if isinstance(item, str):
            import re
            m = re.search(r'\d+\.\d+(?:\.\d+)?', item)
            if m:
                return m.group(0)
    return ""


def _classify_owasp(tags: list, severity: str) -> str:
    """Map nuclei tags to OWASP Top 10 categories"""
    tags_lower = {t.lower() for t in tags}

    if "exposure" in tags_lower or "misconfig" in tags_lower:
        return "A05:2021 Security Misconfiguration"
    if "cve" in tags_lower:
        return "A06:2021 Vulnerable and Outdated Components"
    if "injection" in tags_lower or "sqli" in tags_lower:
        return "A03:2021 Injection"
    if "auth" in tags_lower:
        return "A07:2021 Identification and Authentication Failures"
    if "ssrf" in tags_lower:
        return "A10:2021 Server-Side Request Forgery"

    return "A05:2021 Security Misconfiguration"
