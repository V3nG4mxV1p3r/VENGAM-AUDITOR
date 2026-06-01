"""
VENGAM Auditor — Core Data Models
"""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from typing import Optional
from vengam.config import TOOL_VERSION


@dataclass
class FindingLocation:
    file:           str
    line:           int
    snippet:        str = ""
    redacted_match: str = ""   # first4****last4 of matched value


@dataclass
class Finding:
    title:          str
    severity:       str   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    confidence:     str   # HIGH / MEDIUM / LOW
    exploitability: str   # CONFIRMED / LIKELY / THEORETICAL
    secret_type:    str
    description:    str
    simulation:     str
    score_value:    int
    cvss_vector:    str = ""
    cwe_id:         str = ""
    owasp_ref:      str = ""
    category:       str = "General"  # General / GameEngine / AntiCheat / Economy / Config
    triage_note:    str = ""
    locations: list[FindingLocation] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["locations"] = [asdict(loc) for loc in self.locations]
        return d


@dataclass
class DynamicFinding:
    """Result from Frida runtime hook."""
    hook_name:   str
    severity:    str
    description: str
    evidence:    list[str] = field(default_factory=list)
    score_value: int = 10


@dataclass
class AttackSurface:
    auth:         set = field(default_factory=set)
    payment:      set = field(default_factory=set)
    user_data:    set = field(default_factory=set)
    internal_api: set = field(default_factory=set)
    other:        set = field(default_factory=set)

    @property
    def total(self) -> int:
        return sum(len(s) for s in [
            self.auth, self.payment, self.user_data,
            self.internal_api, self.other,
        ])


@dataclass
class EngineStats:
    files_scanned: int = 0
    lines_scanned: int = 0
    fp_suppressed: int = 0
    patterns_run:  int = 0
    scan_duration_sec: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    apk_name:         str
    apk_sha256:       str
    scan_timestamp:   str
    findings:         list[Finding]
    dynamic_findings: list[DynamicFinding]
    attack_surface:   AttackSurface
    total_score:      int
    verdict:          str
    engine_stats:     EngineStats = field(default_factory=EngineStats)
    tool_version:     str = TOOL_VERSION
    platform:         str = "android"   # android | ios

    def findings_by_severity(self, sev: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == sev]

    def findings_by_category(self, cat: str) -> list[Finding]:
        return [f for f in self.findings if f.category == cat]
