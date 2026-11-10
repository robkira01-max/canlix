"""Runs all rules against a list of MCPServers and returns a ScanResult."""
from __future__ import annotations
import time
from mcpprobe.models import MCPServer, ScanResult
from mcpprobe.rules import ALL_RULES


def scan(servers: list[MCPServer]) -> ScanResult:
    t0 = time.monotonic()
    findings = []
    for server in servers:
        for rule_fn in ALL_RULES:
            finding = rule_fn(server)
            if finding is not None:
                findings.append(finding)
    elapsed_ms = (time.monotonic() - t0) * 1000
    return ScanResult(servers=servers, findings=findings, scan_duration_ms=elapsed_ms)
