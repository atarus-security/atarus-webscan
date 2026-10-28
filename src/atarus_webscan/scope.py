"""The named target, the active scope and the confirmation terminal.

The scanner touches exactly one origin: the scheme, host and port the user
named. It does not switch ports, it does not follow a redirect anywhere else,
and the active modules run only when that host is inside --scope and the
user has typed the confirmation on the terminal.
"""
import ipaddress
import os
import re
import socket
from urllib.parse import urlsplit


LABEL_PATTERN = re.compile(r"^(xn--)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")

DEFAULT_PORTS = {"http": 80, "https": 443}

# The controlling terminal. The confirmation for active checks is read from
# here and nowhere else: not stdin, not an environment variable, not a file.
TTY_PATH = "/dev/tty"


def is_valid_name(name: str) -> bool:
    """True when name is a properly formed FQDN with at least two labels.
    Supports standard ASCII domains and Punycode (xn-- prefixed) IDN domains.
    """
    if not name or len(name) > 253:
        return False
    if "." not in name:
        return False
    labels = name.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not LABEL_PATTERN.match(label):
            return False
    tld = labels[-1]
    if len(tld) < 2:
        return False
    if not re.match(r"^[a-zA-Z]{2,}$", tld) and not tld.startswith("xn--"):
        return False
    return True


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _host_for_url(host: str) -> str:
    """An IPv6 literal needs brackets inside a URL."""
    return f"[{host}]" if ":" in host else host


class ScopeValidator:
    """The URL the user named, kept exactly: scheme, host, port and path.

    `base_url` is what the modules request; `origin` is the only place a
    request may go. `same_origin(url)` is the check behind the redirect
    policy: same scheme, same host and same port, nothing else.
    """

    def __init__(self, target: str):
        raw = (target or "").strip()
        if not raw:
            raise ValueError("empty target")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
            raw = f"https://{raw}"
        parts = urlsplit(raw)

        scheme = (parts.scheme or "").lower()
        if scheme not in DEFAULT_PORTS:
            raise ValueError(f"unsupported scheme: {parts.scheme}")

        host = (parts.hostname or "").lower().rstrip(".")
        if not host:
            raise ValueError(f"no host in target: {target}")
        if not _is_ip(host):
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError:
                raise ValueError(f"host is not a valid name: {host}")
            if not is_valid_name(host):
                raise ValueError(f"Invalid target: {host}")

        try:
            port = parts.port
        except ValueError:
            raise ValueError(f"invalid port in target: {target}")

        path = re.sub(r"/+$", "", parts.path or "")
        if path and not path.startswith("/"):
            path = "/" + path

        self.scheme = scheme
        self.host = host
        self.port = port
        self.path = path
        self.dropped_query = bool(parts.query or parts.fragment)

        # The name used for report files. Includes the port when one was named
        # so that scans of two services on one host do not overwrite each other.
        self.target = host if port is None else f"{host}:{port}"

    @property
    def effective_port(self) -> int:
        return self.port if self.port is not None else DEFAULT_PORTS[self.scheme]

    @property
    def origin(self) -> str:
        netloc = _host_for_url(self.host)
        if self.port is not None:
            netloc = f"{netloc}:{self.port}"
        return f"{self.scheme}://{netloc}"

    @property
    def base_url(self) -> str:
        return f"{self.origin}{self.path}"

    def normalize_target(self) -> str:
        return self.base_url

    def url_for(self, path: str) -> str:
        """A URL on the named origin for an absolute path such as /upload."""
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.origin}{path}"

    def same_origin(self, url: str) -> bool:
        """True when url has the same scheme, host and port as the named target."""
        try:
            parts = urlsplit(url)
            scheme = (parts.scheme or "").lower()
            host = (parts.hostname or "").lower().rstrip(".")
            if scheme not in DEFAULT_PORTS or not host:
                return False
            if not _is_ip(host):
                host = host.encode("idna").decode("ascii")
            port = parts.port if parts.port is not None else DEFAULT_PORTS[scheme]
        except (ValueError, UnicodeError):
            return False
        return scheme == self.scheme and host == self.host and port == self.effective_port

    def is_in_scope(self, url: str) -> bool:
        """Kept for callers of the old name: the scope is the named origin."""
        return self.same_origin(url)

    @staticmethod
    def sanitize_filename(name: str) -> str:
        return re.sub(r"[^a-zA-Z0-9._-]", "_", name)


class ActiveScope:
    """The hosts, networks and domains the user has placed in scope for active checks.

    Entries come from --scope, either a file (one entry per line, blank lines
    and # comments ignored) or a comma-separated list. Four forms:

        app.example.com     exactly that host
        *.example.com       every name under example.com, at any depth, not the apex
        203.0.113.7         that address
        203.0.113.0/24      every address in that network

    The named host is covered when its name matches a host or domain entry,
    or when every address it resolves to falls inside a network entry.
    Anything else is out of scope and no active module runs.
    """

    def __init__(self, entries: list):
        self.entries = []
        self.hosts = set()
        self.domains = set()
        self.networks = []
        for raw in entries:
            kind, value = self._parse_entry(raw)
            if kind == "host":
                self.hosts.add(value)
                self.entries.append(value)
            elif kind == "domain":
                self.domains.add(value)
                self.entries.append(f"*.{value}")
            else:
                self.networks.append(value)
                shown = str(value.network_address) if value.num_addresses == 1 else str(value)
                self.entries.append(shown)
        if not self.entries:
            raise ValueError("scope is empty: list at least one host, network or domain")

    @classmethod
    def from_option(cls, spec: str) -> "ActiveScope":
        """Build a scope from the --scope value: a file path or a comma-separated list."""
        spec = (spec or "").strip()
        if not spec:
            raise ValueError("scope is empty")
        if os.path.isfile(spec):
            with open(spec, "r") as f:
                lines = f.read().splitlines()
            raw = []
            for line in lines:
                line = line.split("#", 1)[0].strip()
                if line:
                    raw.append(line)
            if not raw:
                raise ValueError(f"scope file has no entries: {spec}")
            return cls(raw)
        return cls([part for part in spec.split(",") if part.strip()])

    @staticmethod
    def _parse_entry(raw: str) -> tuple:
        text = raw.strip().lower()
        if not text:
            raise ValueError("empty scope entry")
        try:
            return "network", ipaddress.ip_network(text, strict=False)
        except ValueError:
            pass
        if text.startswith(("http://", "https://")):
            text = urlsplit(text).hostname or ""
        if "/" in text:
            text = text.split("/")[0]
        kind = "host"
        if text.startswith("*."):
            kind = "domain"
            text = text[2:]
        if ":" in text:
            text = text.split(":")[0]
        text = text.rstrip(".")
        if not is_valid_name(text):
            raise ValueError(f"not a host, network or domain: {raw.strip()}")
        return kind, text

    def covers(self, hostname: str, ips=()) -> bool:
        """True when the name is listed, or every resolved address is inside a listed network."""
        name = (hostname or "").strip().lower().rstrip(".")
        if name and name in self.hosts:
            return True
        for domain in self.domains:
            if name.endswith(f".{domain}"):
                return True
        addrs = []
        for ip in ips:
            try:
                addrs.append(ipaddress.ip_address(ip))
            except ValueError:
                return False
        if not addrs:
            return False
        for addr in addrs:
            if not any(addr.version == net.version and addr in net for net in self.networks):
                return False
        return True

    def describe(self) -> str:
        return ", ".join(self.entries)


def resolve_host(hostname: str) -> list:
    """Every address the host resolves to, in resolver order, without duplicates.
    An address literal resolves to itself. Returns [] when resolution fails."""
    if _is_ip(hostname):
        return [hostname]
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError):
        return []
    seen = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)
    return seen


def _open_tty() -> int:
    """A raw read-write descriptor on the controlling terminal.

    Opened with os.open rather than open(path, "r+"): the latter builds a
    BufferedRandom, which demands a seekable stream, and a terminal is not
    one, so it raises io.UnsupportedOperation (an OSError) on every real
    terminal and the gate would never open.
    """
    return os.open(TTY_PATH, os.O_RDWR | getattr(os, "O_NOCTTY", 0))


def tty_available() -> bool:
    """True when a controlling terminal can be opened for the confirmation prompt."""
    try:
        fd = _open_tty()
    except OSError:
        return False
    os.close(fd)
    return True


def read_tty_line(prompt: str):
    """Write prompt to the controlling terminal and read one line back from it.

    Returns the stripped line, or None when there is no terminal or it hit
    end of file. Nothing else can answer: stdin is not read, and no
    environment variable or configuration file is consulted.
    """
    try:
        fd = _open_tty()
    except OSError:
        return None
    try:
        if prompt:
            os.write(fd, prompt.encode("utf-8", "replace"))
        with open(fd, "r", encoding="utf-8", errors="replace", closefd=False) as reader:
            line = reader.readline()
    except OSError:
        return None
    finally:
        os.close(fd)
    if not line:
        return None
    return line.strip()
