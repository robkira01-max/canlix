"""Validate and sanitise an uploaded Canlix JSON report.

Privacy by construction: models use extra="ignore", so code snippets, evidence and probe details sent by a
client are dropped, never stored. Every kept string is redacted again server-side.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from canlix.models import Severity
from canlix.runtime.redact import redact

MAX_FINDINGS = 5000

Sev = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
Conf = Literal["HIGH", "MEDIUM", "LOW"]


class _In(BaseModel):
    model_config = ConfigDict(extra="ignore")


class ConfigFindingIn(_In):
    rule_id: str = Field(max_length=32)
    severity: Sev
    confidence: Conf
    server: str | None = Field(default=None, max_length=200)
    target: str | None = Field(default=None, max_length=200)
    message: str = Field(max_length=1000)
    remediation: str = Field(default="", max_length=2000)


class SourceFindingIn(_In):
    rule_id: str = Field(max_length=32)
    severity: Sev
    confidence: Conf
    file: str = Field(max_length=500)
    line: int = Field(default=0, ge=0)
    message: str = Field(max_length=1000)
    remediation: str = Field(default="", max_length=2000)


class ReportIn(_In):
    canlix_version: str | None = Field(default=None, max_length=32)
    findings: list[ConfigFindingIn] = Field(default_factory=list, max_length=MAX_FINDINGS)
    source_findings: list[SourceFindingIn] = Field(default_factory=list, max_length=MAX_FINDINGS)


@dataclass(frozen=True)
class NormalizedFinding:
    fingerprint: str
    kind: Literal["config", "source"]
    rule_id: str
    severity: str
    confidence: str
    location: str
    message: str
    remediation: str
    occurrences: int = 1


def _fingerprint(kind: str, rule_id: str, location: str, message: str) -> str:
    return hashlib.sha256(f"{kind}|{rule_id}|{location}|{message}".encode()).hexdigest()[:32]


def _norm_path(path: str) -> str:
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def normalize_report(payload: Any) -> list[NormalizedFinding]:
    """Raise pydantic.ValidationError on a malformed report; otherwise return de-duplicated findings."""
    report = ReportIn.model_validate(payload)
    merged: dict[str, NormalizedFinding] = {}

    def add(kind: str, rule_id: str, sev: str, conf: str, location: str, message: str, fix: str) -> None:
        location, message, fix = redact(location), redact(message), redact(fix)
        fp = _fingerprint(kind, rule_id, location, message)
        prev = merged.get(fp)
        if prev:
            merged[fp] = NormalizedFinding(**{**prev.__dict__, "occurrences": prev.occurrences + 1})
        else:
            merged[fp] = NormalizedFinding(fp, kind, rule_id, sev, conf, location, message, fix)  # type: ignore[arg-type]

    for f in report.findings:
        add("config", f.rule_id, f.severity, f.confidence, f.server or f.target or "", f.message, f.remediation)
    for s in report.source_findings:
        add("source", s.rule_id, s.severity, s.confidence, _norm_path(s.file), s.message, s.remediation)
    return list(merged.values())


def compute_score(findings: list[NormalizedFinding]) -> int:
    """Recomputed server-side: a client-supplied score is never trusted."""
    return max(0, 100 - sum(Severity(f.severity).score for f in findings))
