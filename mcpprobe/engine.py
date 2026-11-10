"""Runs all rules against a list of MCPServers and returns a ScanResult."""

from __future__ import annotations

import time
from collections import Counter

from mcpprobe.models import Confidence, Finding, MCPServer, ScanResult, Severity
from mcpprobe.rules import ALL_RULES


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


def scan(servers: list[MCPServer]) -> ScanResult:
    t0 = time.monotonic()
    findings: list[Finding] = []

    for server in servers:
        for rule_fn in ALL_RULES:
            finding = rule_fn(server)
            if finding is not None:
                findings.append(finding)

    findings.extend(_check_duplicate_names(servers))

    elapsed_ms = (time.monotonic() - t0) * 1000
    return ScanResult(servers=servers, findings=findings, scan_duration_ms=elapsed_ms)
