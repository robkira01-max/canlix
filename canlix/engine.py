"""Runs all rules against a list of MCPServers and returns a ScanResult."""

from __future__ import annotations

import time
from collections import Counter
from pathlib import Path

from canlix.analyzers import analyze_path
from canlix.models import Confidence, Finding, MCPServer, ScanResult, Severity, SourceFinding
from canlix.rules import ALL_RULES
from canlix.rules.cross_server import check_cross_server

_SOURCE_EXTS = {".py", ".ts", ".js"}


def _check_duplicate_names(servers: list[MCPServer]) -> list[Finding]:
    """CFG-005 : duplicate server names across config files."""
    counts = Counter(s.name for s in servers)
    findings = []
    for name, count in counts.items():
        if count > 1:
            findings.append(
                Finding(
                    rule_id="CFG-005",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    server_name=name,
                    message=f"Server name '{name}' is defined {count} times across config files",
                    evidence=f"count: {count}",
                    remediation="Use unique names for each MCP server to avoid ambiguity.",
                )
            )
    return findings


def _extract_source_path(server: MCPServer) -> Path | None:
    """Return a local source file or directory to analyze, if discoverable."""
    candidates = list(server.args) + [server.command]
    for token in candidates:
        if not token:
            continue
        p = Path(token)
        if p.suffix in _SOURCE_EXTS and p.exists():
            return p
        if p.is_dir():
            return p
    return None


def _collect_source_findings(servers: list[MCPServer]) -> list[SourceFinding]:
    seen: set[Path] = set()
    findings: list[SourceFinding] = []
    for server in servers:
        path = _extract_source_path(server)
        if path and path not in seen:
            seen.add(path)
            findings.extend(analyze_path(path))
    return findings


def scan(servers: list[MCPServer], *, analyze_source: bool = True) -> ScanResult:
    t0 = time.monotonic()
    findings: list[Finding] = []

    for server in servers:
        for rule_fn in ALL_RULES:
            finding = rule_fn(server)
            if finding is not None:
                findings.append(finding)

    findings.extend(_check_duplicate_names(servers))
    findings.extend(check_cross_server(servers))

    source_findings: list[SourceFinding] = []
    if analyze_source:
        source_findings = _collect_source_findings(servers)

    elapsed_ms = (time.monotonic() - t0) * 1000
    return ScanResult(servers=servers, findings=findings, source_findings=source_findings, scan_duration_ms=elapsed_ms)
