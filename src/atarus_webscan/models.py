"""Data models for scan results and findings"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


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
    started_at: str = ""
    finished_at: str = ""
    site_type: str = ""  # spa, server-rendered, static, api, unknown
    framework: str = ""
    server: str = ""
    technologies: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    headers: list = field(default_factory=list)
    methods_allowed: list = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = ""  # critical, high, medium, low, clean
    baseline_404_hash: str = ""
    baseline_404_status: int = 0
