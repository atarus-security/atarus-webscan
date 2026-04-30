"""Smart 404 baseline detection.

Sites with catch-all routes return HTTP 200 for nonexistent paths. Without
baseline detection, every dangerous_files probe would false-positive. We
fetch a known-bad path first, hash the response, and use that hash to
filter subsequent probes.
"""
import hashlib
import secrets
import requests


class BaselineDetector:
    """Detects catch-all 200 responses by hashing a known-bad path"""

    def __init__(self, base_url: str, timeout: int = 6):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.baseline_hash = ""
        self.baseline_status = 0
        self.baseline_length = 0

    def calibrate(self, verbose: bool = False) -> bool:
        """Fetch a random nonexistent path and capture its response signature."""
        random_path = secrets.token_urlsafe(24)
        probe_url = f"{self.base_url}/{random_path}"

        try:
            resp = requests.get(
                probe_url,
                timeout=self.timeout,
                allow_redirects=False,
                headers={"User-Agent": "atarus-webscan/0.1.0"},
                verify=False,
            )
        except requests.RequestException:
            return False

        self.baseline_status = resp.status_code
        self.baseline_length = len(resp.content)
        self.baseline_hash = hashlib.sha256(resp.content).hexdigest()
        return True

    def matches_baseline(self, response: requests.Response) -> bool:
        """True if a response is indistinguishable from the catch-all."""
        if not self.baseline_hash:
            return False

        if response.status_code != self.baseline_status:
            return False

        # Length within 5% of baseline
        if abs(len(response.content) - self.baseline_length) > max(50, self.baseline_length * 0.05):
            return False

        # Exact content hash match
        if hashlib.sha256(response.content).hexdigest() == self.baseline_hash:
            return True

        return False
