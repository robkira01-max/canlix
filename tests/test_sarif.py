"""Tests for the SARIF 2.1.0 reporter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpprobe.models import Confidence, Finding, Severity, SourceFinding
from mcpprobe.probes.base import ProbeResult, ProbeSession
from mcpprobe.reporters.sarif import (
    _sev_level,
    render_analyze_sarif,
    render_probe_sarif,
    render_scan_sarif,
)

# ── Fixtures ───────────────────────────────────────────────────────────────


def _src_finding(rule_id: str = "SRC-001", severity: Severity = Severity.CRITICAL) -> SourceFinding:
    return SourceFinding(
        rule_id=rule_id,
        severity=severity,
        confidence=Confidence.HIGH,
        file_path=Path("app/server.py"),
        line_number=42,
        message="Hardcoded API key",
        code_snippet='TOKEN = "sk-abc..."',
        remediation="Use env variables.",
    )


def _cfg_finding(rule_id: str = "SEC-001", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        confidence=Confidence.HIGH,
        server_name="my-server",
        message="API key in env block",
        evidence="env.TOKEN",
        remediation="Move to a secrets manager.",
    )


def _probe_finding(rule_id: str = "PROBE-001", severity: Severity = Severity.CRITICAL) -> ProbeResult:
    return ProbeResult(
        rule_id=rule_id,
        severity=severity,
        confidence=Confidence.HIGH,
        target="run_code",
        message="Prompt injection in description",
        detail="Pattern: 'ignore previous'",
        remediation="Remove injection patterns.",
    )


def _probe_session_with(findings: list[ProbeResult]) -> ProbeSession:
    s = ProbeSession(server_name="test-server", server_url="https://example.com/mcp")
    s.findings = findings
    return s


# ── Severity level mapping ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "sev, expected",
    [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "none"),
    ],
)
def test_severity_level_mapping(sev, expected):
    assert _sev_level(sev) == expected


# ── SARIF document structure ───────────────────────────────────────────────


def _parse(sarif_str: str) -> dict:
    return json.loads(sarif_str)


def test_sarif_version_field():
    doc = _parse(render_analyze_sarif([]))
    assert doc["version"] == "2.1.0"


def test_sarif_schema_field():
    doc = _parse(render_analyze_sarif([]))
    assert "$schema" in doc
    assert "sarif-schema-2.1.0" in doc["$schema"]


def test_sarif_has_runs():
    doc = _parse(render_analyze_sarif([]))
    assert "runs" in doc
    assert len(doc["runs"]) == 1


def test_sarif_tool_name():
    doc = _parse(render_analyze_sarif([]))
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "MCPProbe"
    assert driver["version"] == "0.1.0"


def test_sarif_empty_findings_valid():
    doc = _parse(render_analyze_sarif([]))
    run = doc["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


# ── Source findings — physical location ────────────────────────────────────


def test_source_finding_has_physical_location():
    doc = _parse(render_analyze_sarif([_src_finding()]))
    loc = doc["runs"][0]["results"][0]["locations"][0]
    assert "physicalLocation" in loc
    assert "artifactLocation" in loc["physicalLocation"]
    assert "region" in loc["physicalLocation"]


def test_source_finding_line_number():
    doc = _parse(render_analyze_sarif([_src_finding()]))
    region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 42


def test_source_finding_snippet():
    doc = _parse(render_analyze_sarif([_src_finding()]))
    region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert 'TOKEN = "sk-abc..."' in region["snippet"]["text"]


def test_source_finding_level_critical():
    doc = _parse(render_analyze_sarif([_src_finding(severity=Severity.CRITICAL)]))
    assert doc["runs"][0]["results"][0]["level"] == "error"


def test_source_finding_level_medium():
    doc = _parse(render_analyze_sarif([_src_finding(severity=Severity.MEDIUM)]))
    assert doc["runs"][0]["results"][0]["level"] == "warning"


# ── Config findings — logical location ─────────────────────────────────────


def test_config_finding_has_logical_location():
    from mcpprobe.models import ScanResult

    result = ScanResult(findings=[_cfg_finding()], source_findings=[])
    doc = _parse(render_scan_sarif(result))
    loc = doc["runs"][0]["results"][0]["locations"][0]
    assert "logicalLocations" in loc
    assert "mcp-server/" in loc["logicalLocations"][0]["name"]


# ── Probe findings — logical location ──────────────────────────────────────


def test_probe_finding_has_logical_location():
    session = _probe_session_with([_probe_finding()])
    doc = _parse(render_probe_sarif(session))
    loc = doc["runs"][0]["results"][0]["locations"][0]
    assert "logicalLocations" in loc
    assert "mcp-tool/run_code" in loc["logicalLocations"][0]["name"]


# ── Rules table ─────────────────────────────────────────────────────────────


def test_rule_deduplication():
    # Two findings with same rule_id — only one rule entry in the table
    findings = [_src_finding("SRC-001"), _src_finding("SRC-001", Severity.HIGH)]
    doc = _parse(render_analyze_sarif(findings))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "SRC-001"


def test_rule_index_matches_rule_position():
    findings = [_src_finding("SRC-001"), _src_finding("SRC-002")]
    doc = _parse(render_analyze_sarif(findings))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    results = doc["runs"][0]["results"]
    for result in results:
        idx = result["ruleIndex"]
        assert rules[idx]["id"] == result["ruleId"]


def test_multiple_rules_all_present():
    findings = [_src_finding("SRC-001"), _src_finding("SRC-002"), _src_finding("TS-001")]
    doc = _parse(render_analyze_sarif(findings))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {"SRC-001", "SRC-002", "TS-001"}


# ── Scan: mixed config + source findings ───────────────────────────────────


def test_scan_sarif_combines_config_and_source():
    from mcpprobe.models import ScanResult

    result = ScanResult(
        findings=[_cfg_finding("SEC-001")],
        source_findings=[_src_finding("SRC-002")],
    )
    doc = _parse(render_scan_sarif(result))
    results = doc["runs"][0]["results"]
    assert len(results) == 2
    rule_ids = {r["ruleId"] for r in results}
    assert rule_ids == {"SEC-001", "SRC-002"}
