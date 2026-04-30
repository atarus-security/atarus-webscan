"""JSON report generation"""
import json
import os
from dataclasses import asdict
from atarus_webscan.models import ScanResult
from atarus_webscan.scope import ScopeValidator


def generate(result: ScanResult, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)

    data = asdict(result)

    safe_target = ScopeValidator.sanitize_filename(result.target)
    output_path = os.path.join(output_dir, f"atarus-webscan-{safe_target}.json")

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    return output_path
