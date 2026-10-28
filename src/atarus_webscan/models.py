"""Data models for scan results and findings"""
from dataclasses import dataclass, field


@dataclass
class Finding:
    """A single security finding"""
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    url: str = ""
    evidence: str = ""
    remediation: str = ""
    category: str = ""  # headers, methods, dangerous_files, technology, etc
    owasp_mapping: str = ""
    cve: str = ""


@dataclass
class Technology:
    """A detected technology"""
    name: str
    version: str = ""
    category: str = ""  # framework, server, cdn, library
    confidence: str = "medium"  # high, medium, low


@dataclass
class HeaderAnalysis:
    """Security header analysis result"""
    header: str
    present: bool
    value: str = ""
    issue: str = ""
    severity: str = ""


@dataclass
class ScanResult:
    """Complete scan result for a target"""
    target: str
    # The URL exactly as named: scheme, host, port and path. Every request of
    # the run went to this origin and nowhere else.
    named_url: str = ""
    started_at: str = ""
    finished_at: str = ""
    site_type: str = ""  # spa, server-rendered, static, api, unknown
    framework: str = ""
    server: str = ""
    technologies: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    headers: list = field(default_factory=list)
    # Methods a probe confirmed, and methods the OPTIONS Allow header announced.
    methods_allowed: list = field(default_factory=list)
    methods_announced: list = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = ""  # critical, high, medium, low, clean
    baseline_404_hash: str = ""
    baseline_404_status: int = 0
    # Run mode record. "passive" means only safe requests (one GET, one HEAD,
    # one OPTIONS) went to the named URL; "active" means the user placed the
    # host in scope and confirmed.
    mode: str = "passive"
    active_scope: list = field(default_factory=list)
    confirmation: str = ""
    # TLS certificate verification was switched off with --insecure.
    insecure: bool = False
    # Paths the user named for the state-changing method probes.
    probe_paths: list = field(default_factory=list)
    # Modules that were selected but did not run or did not complete, with the
    # reason, so a report never reads as clean for a check that was never made.
    modules_not_run: list = field(default_factory=list)
    # The named host when it fell outside --scope and was therefore not probed.
    out_of_scope: list = field(default_factory=list)
    # Redirects that pointed off the named origin and were not followed.
    refused_redirects: list = field(default_factory=list)
    # How many requests of each method left the scanner.
    requests_sent: dict = field(default_factory=dict)
