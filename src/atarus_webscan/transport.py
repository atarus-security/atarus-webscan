"""The one place requests leave the scanner.

Every module sends through a Client. The Client:

- refuses to send to any URL that is not on the named origin (same scheme,
  host and port), so a module cannot wander off the target by mistake;
- never lets the HTTP library follow a redirect; same-origin redirects are
  followed only when the caller asks, up to MAX_REDIRECTS hops, and an
  off-origin redirect is recorded and returned as is;
- reads bodies only up to a caller-given limit and closes the connection,
  so a candidate secret is never downloaded whole;
- verifies TLS certificates unless the user passed --insecure;
- keeps a record of every request sent, for the report and the tests.
"""
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests
from requests.structures import CaseInsensitiveDict

from atarus_webscan import __version__


USER_AGENT = f"atarus-webscan/{__version__}"

# How much of a page is read for framework detection and header analysis.
PAGE_READ_LIMIT = 512 * 1024

# How much of a candidate sensitive file is read: enough to tell it from the
# 404 page, never enough to be a copy of a secret.
PROBE_READ_LIMIT = 512

MAX_REDIRECTS = 5


class TransportError(Exception):
    """A request could not be completed. The message is safe to show."""


class OffOriginError(Exception):
    """A module asked for a URL outside the named origin. This is a bug guard."""


def describe_error(exc: Exception) -> str:
    if isinstance(exc, requests.exceptions.SSLError):
        return ("TLS certificate verification failed; pass --insecure to scan a host "
                "with an untrusted certificate (the flag is recorded in the report)")
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "connection timed out"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "read timed out"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return f"connection failed: {type(exc).__name__}"
    return type(exc).__name__


@dataclass
class Fetched:
    """What came back from one request, with at most read_limit bytes of body."""
    method: str
    url: str
    status: int
    headers: CaseInsensitiveDict = field(default_factory=CaseInsensitiveDict)
    cookie_names: set = field(default_factory=set)
    body: bytes = b""
    read_limit: int = 0
    truncated: bool = False
    declared_length: int = None
    redirect_to: str = ""
    redirect_refused: bool = False

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status < 400 and bool(self.redirect_to)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def headers_lower(self) -> dict:
        return {k.lower(): v for k, v in self.headers.items()}

    def size_text(self) -> str:
        """The size to report: declared by the server, else what was read."""
        if self.declared_length is not None:
            return f"{self.declared_length} bytes"
        if self.truncated:
            return f"at least {len(self.body)} bytes"
        return f"{len(self.body)} bytes"


def _declared_length(headers) -> int:
    """Total size from Content-Range (bytes 0-511/12345), else Content-Length."""
    content_range = headers.get("Content-Range", "")
    if "/" in content_range:
        total = content_range.rsplit("/", 1)[1].strip()
        if total.isdigit():
            return int(total)
    content_length = (headers.get("Content-Length") or "").strip()
    if content_length.isdigit():
        return int(content_length)
    return None


class Client:
    """Sends requests to the named origin and nowhere else."""

    def __init__(self, target, insecure: bool = False, timeout: float = 10.0, rate_limit: int = 10):
        self.target = target
        self.base_url = target.base_url
        self.origin = target.origin
        self.insecure = bool(insecure)
        self.timeout = timeout
        self.min_interval = 1.0 / rate_limit if rate_limit and rate_limit > 0 else 0.0
        self.requests_sent = []
        self.refused_redirects = []
        self._session = requests.Session()
        self._named = None
        self._next_send_at = 0.0

    # The single call into the HTTP library. Tests replace this method.
    def _transport(self, method: str, url: str, headers: dict):
        return self._session.request(
            method,
            url,
            headers=headers,
            timeout=self.timeout,
            allow_redirects=False,
            stream=True,
            verify=not self.insecure,
        )

    def _pace(self):
        if self.min_interval <= 0:
            return
        now = time.monotonic()
        if self._next_send_at > now:
            time.sleep(self._next_send_at - now)
        self._next_send_at = time.monotonic() + self.min_interval

    def request_counts(self) -> dict:
        counts = {}
        for entry in self.requests_sent:
            counts[entry["method"]] = counts.get(entry["method"], 0) + 1
        return counts

    def send(self, method: str, url: str, read_limit: int = 0, follow_redirects: bool = False,
             extra_headers: dict = None) -> Fetched:
        """Send one request (plus same-origin redirect hops when asked) and return what came back.

        read_limit is the hard cap on body bytes read; 0 reads nothing. The
        connection is closed as soon as that many bytes are in hand.
        Raises TransportError when the request fails, OffOriginError when a
        module asks for a URL outside the named origin.
        """
        method = method.upper()
        hops = 0
        while True:
            if not self.target.same_origin(url):
                raise OffOriginError(f"{url} is not on the named origin {self.origin}")
            headers = {"User-Agent": USER_AGENT}
            if extra_headers:
                headers.update(extra_headers)
            self._pace()
            self.requests_sent.append({"method": method, "url": url})
            try:
                resp = self._transport(method, url, headers)
            except requests.RequestException as exc:
                raise TransportError(describe_error(exc)) from exc

            body = b""
            truncated = False
            try:
                if read_limit > 0 and method != "HEAD":
                    body = resp.raw.read(read_limit, decode_content=True) or b""
                    if len(body) >= read_limit:
                        # There may be more; we do not look.
                        truncated = True
            except (requests.RequestException, OSError, ValueError) as exc:
                raise TransportError(f"read failed: {type(exc).__name__}") from exc
            finally:
                resp.close()

            resp_headers = CaseInsensitiveDict(resp.headers)
            declared = _declared_length(resp_headers)
            if declared is not None and truncated and declared <= len(body):
                truncated = False
            try:
                cookie_names = set(resp.cookies.keys())
            except Exception:
                cookie_names = set()

            fetched = Fetched(
                method=method, url=url, status=int(resp.status_code), headers=resp_headers,
                cookie_names=cookie_names, body=body, read_limit=read_limit,
                truncated=truncated, declared_length=declared,
            )

            location = resp_headers.get("Location", "")
            if 300 <= fetched.status < 400 and location:
                dest = urljoin(url, location.strip())
                fetched.redirect_to = dest
                if not self.target.same_origin(dest):
                    fetched.redirect_refused = True
                    self.refused_redirects.append({"from": url, "to": dest, "status": fetched.status})
                    return fetched
                if follow_redirects and hops < MAX_REDIRECTS:
                    hops += 1
                    url = dest
                    continue
            return fetched

    def get(self, url: str, read_limit: int = PAGE_READ_LIMIT, follow_redirects: bool = True) -> Fetched:
        return self.send("GET", url, read_limit=read_limit, follow_redirects=follow_redirects)

    def head(self, url: str) -> Fetched:
        return self.send("HEAD", url)

    def options(self, url: str) -> Fetched:
        return self.send("OPTIONS", url)

    def get_capped(self, url: str, limit: int = PROBE_READ_LIMIT) -> Fetched:
        """A GET that asks for the first `limit` bytes (Range) and reads no more than that."""
        return self.send("GET", url, read_limit=limit, follow_redirects=False,
                         extra_headers={"Range": f"bytes=0-{limit - 1}"})

    def fetch_named(self) -> Fetched:
        """The single GET of the named URL, shared by every module that needs it.

        Same-origin redirects are followed; an off-origin redirect is refused
        and the redirect response itself is returned (redirect_refused=True).
        """
        if self._named is None:
            self._named = self.get(self.base_url)
        return self._named

    def named_cached(self):
        """The cached named-URL response, or None if it has not been fetched."""
        return self._named
