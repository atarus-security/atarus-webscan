"""Smart 404 baseline detection.

Sites with catch-all routes return HTTP 200 for nonexistent paths. Without
baseline detection, every dangerous_files probe would false-positive. We
fetch a known-bad path first, hash the first bytes of the response, and use
that signature to filter subsequent probes.

The calibration request is a GET to a random path on the target, so it is
only made by the active dangerous_files module, never in a passive run.
"""
import hashlib
import secrets

from atarus_webscan.transport import Fetched, TransportError


class BaselineDetector:
    """Detects catch-all responses by hashing the capped body of a known-bad path"""

    def __init__(self, client):
        self.client = client
        self.base_url = client.base_url
        self.baseline_hash = ""
        self.baseline_status = 0
        self.baseline_length = 0

    def calibrate(self, verbose: bool = False) -> bool:
        """Fetch a random nonexistent path (capped read) and capture its signature."""
        probe_url = f"{self.base_url}/{secrets.token_urlsafe(24)}"
        try:
            fetched = self.client.get_capped(probe_url)
        except TransportError:
            return False
        self.baseline_status = fetched.status
        self.baseline_length = fetched.declared_length if fetched.declared_length is not None else len(fetched.body)
        self.baseline_hash = hashlib.sha256(fetched.body).hexdigest()
        return True

    def matches_baseline(self, fetched: Fetched) -> bool:
        """True if a response is indistinguishable from the catch-all."""
        if not self.baseline_hash:
            return False
        if fetched.status != self.baseline_status:
            return False
        length = fetched.declared_length if fetched.declared_length is not None else len(fetched.body)
        if abs(length - self.baseline_length) > max(50, self.baseline_length * 0.05):
            return False
        return hashlib.sha256(fetched.body).hexdigest() == self.baseline_hash
