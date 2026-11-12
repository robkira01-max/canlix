"""Probe result types for active / runtime security testing."""

from __future__ import annotations

from dataclasses import dataclass, field

from canlix.models import Confidence, Severity


@dataclass
class ProbeResult:
    rule_id: str
    severity: Severity
    confidence: Confidence
    target: str
    message: str
    detail: str
    remediation: str


@dataclass
class ProbeSession:
    server_name: str
    server_url: str
    protocol_version: str = ""
    capabilities: dict = field(default_factory=dict)
    tools: list[dict] = field(default_factory=list)
    resources: list[dict] = field(default_factory=list)
    findings: list[ProbeResult] = field(default_factory=list)
    duration_ms: float = 0.0
    error: str = ""

    @property
    def score(self) -> int:
        raw = sum(f.severity.score for f in self.findings)
        return max(0, 100 - raw)

    @property
    def has_critical(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    def findings_by_severity(self) -> dict[Severity, list[ProbeResult]]:
        result: dict[Severity, list[ProbeResult]] = {s: [] for s in Severity}
        for f in self.findings:
            result[f.severity].append(f)
        return result
