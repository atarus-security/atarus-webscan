"""Per-target risk scoring.

Aggregates findings into a single 0-100 risk score and rating.
"""
from atarus_webscan.models import ScanResult
from atarus_webscan.runner import ModuleResult


SEVERITY_POINTS = {
    "critical": 25,
    "high": 12,
    "medium": 5,
    "low": 2,
    "info": 0,
}


def run(result: ScanResult, base_url: str, verbose: bool = False) -> ModuleResult:
    """Compute a risk score from accumulated findings"""

    score = 0
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for finding in result.findings:
        sev = (finding.severity or "info").lower()
        score += SEVERITY_POINTS.get(sev, 0)
        if sev in counts:
            counts[sev] += 1

    score = min(100, score)
    result.risk_score = score

    if score >= 70:
        result.risk_level = "critical"
    elif score >= 40:
        result.risk_level = "high"
    elif score >= 20:
        result.risk_level = "medium"
    elif score > 0:
        result.risk_level = "low"
    else:
        result.risk_level = "clean"

    msg = (
        f"risk: {result.risk_level} ({score}/100), "
        f"{counts['critical']}c {counts['high']}h {counts['medium']}m "
        f"{counts['low']}l {counts['info']}i"
    )
    return ModuleResult(success=True, message=msg)
