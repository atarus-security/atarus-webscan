"""Scope validation for target URLs"""
import re
from urllib.parse import urlparse


class ScopeValidator:
    def __init__(self, target: str):
        target = target.strip()

        # Capture user-provided scheme if present
        scheme_match = re.match(r"^(https?)://", target, re.IGNORECASE)
        self.scheme = scheme_match.group(1).lower() if scheme_match else "https"

        target = target.lower()
        target = re.sub(r"^https?://", "", target)
        target = target.rstrip("/")
        target = target.split("/")[0]
        target = target.split(":")[0]

        try:
            target = target.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError):
            pass

        if not target or "." not in target:
            raise ValueError(f"Invalid target: {target}")

        self.target = target

    def is_in_scope(self, url: str) -> bool:
        try:
            parsed = urlparse(url if "://" in url else f"https://{url}")
            host = parsed.hostname
            if not host:
                return False
            host = host.lower()
            return host == self.target or host.endswith(f".{self.target}")
        except Exception:
            return False

    def normalize_target(self, scheme: str = None) -> str:
        if scheme is None:
            scheme = self.scheme
        return f"{scheme}://{self.target}"

    @staticmethod
    def sanitize_filename(name: str) -> str:
        return re.sub(r"[^a-zA-Z0-9._-]", "_", name)
