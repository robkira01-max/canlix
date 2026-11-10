from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self) -> str:
        return {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim",
        }[self.value]

    @property
    def score(self) -> int:
        return {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 2, "INFO": 0}[self.value]


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Transport(str, Enum):
    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"


class MCPServer(object):
    def __init__(
        self,
        name: str,
        transport: Transport = Transport.STDIO,
        command: str = "",
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        url: str = "",
        source_file: Path | None = None,
    ):
        self.name = name
        self.transport = transport
        self.command = command
        self.args = args or []
        self.env = env or {}
        self.url = url
        self.source_file = source_file


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    confidence: Confidence
    server_name: str
    message: str
    evidence: str
    remediation: str
    source_file: Path | None = None


@dataclass
class ScanResult:
    servers: list[MCPServer] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    scan_duration_ms: float = 0.0

    @property
    def score(self) -> int:
        raw = sum(f.severity.score for f in self.findings)
        return max(0, 100 - raw)

    @property
    def has_critical(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            result[f.severity].append(f)
        return result
