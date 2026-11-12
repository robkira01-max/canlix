"""SARIF 2.1.0 reporter — output for GitHub Code Scanning and other SAST tools.

Usage:
    canlix scan   --output sarif > results.sarif
    canlix analyze ./src --output sarif > results.sarif
    canlix probe  https://server/ --output sarif > results.sarif

Then upload with:
    gh upload-sarif --sarif results.sarif
"""

from __future__ import annotations

import json
from pathlib import Path

from canlix.models import Finding, Severity, SourceFinding

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_TOOL_NAME = "Canlix"
_TOOL_VERSION = "0.1.0"
_TOOL_URI = "https://github.com/robkira01-max/canlix"

_SEV_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def render_scan_sarif(result) -> str:  # result: ScanResult
    """Render a full scan result (config + source findings) as SARIF."""
    pairs = [_config_finding_to_pair(f) for f in result.findings]
    pairs += [_source_finding_to_pair(f) for f in result.source_findings]
    return _build_sarif(pairs)


def render_analyze_sarif(findings: list[SourceFinding]) -> str:
    """Render source-code findings as SARIF."""
    return _build_sarif([_source_finding_to_pair(f) for f in findings])


def render_probe_sarif(session) -> str:  # session: ProbeSession
    """Render live-probe session findings as SARIF."""
    return _build_sarif([_probe_finding_to_pair(f) for f in session.findings])


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# A "pair" is (sarif_result_dict, rule_def_dict) used to build the final doc.
_Pair = tuple[dict, dict]


def _sev_level(sev: Severity) -> str:
    return _SEV_LEVEL.get(sev, "warning")


def _make_rule(rule_id: str, short_desc: str, remediation: str, sev: Severity) -> dict:
    return {
        "id": rule_id,
        "shortDescription": {"text": short_desc},
        "fullDescription": {"text": f"{short_desc} — {remediation}"},
        "defaultConfiguration": {"level": _sev_level(sev)},
        "helpUri": _TOOL_URI,
        "properties": {"tags": ["security", "mcp"]},
    }


def _file_uri(path: Path) -> str:
    """Return a URI suitable for SARIF artifactLocation.

    Tries to produce a path relative to CWD (what GitHub Code Scanning expects
    when uriBaseId is %SRCROOT%).  Falls back to the absolute path string.
    """
    try:
        return str(path.resolve().relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def _config_finding_to_pair(f: Finding) -> _Pair:
    rule_def = _make_rule(f.rule_id, f.message, f.remediation, f.severity)
    result: dict = {
        "ruleId": f.rule_id,
        "level": _sev_level(f.severity),
        "message": {"text": f"{f.message}" + (f" ({f.evidence})" if f.evidence else "")},
        "locations": [{"logicalLocations": [{"name": f"mcp-server/{f.server_name}", "kind": "module"}]}],
        "properties": {"confidence": f.confidence.value, "server": f.server_name},
    }
    if f.source_file:
        result["locations"].append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _file_uri(f.source_file), "uriBaseId": "%SRCROOT%"},
                }
            }
        )
    return result, rule_def


def _source_finding_to_pair(f: SourceFinding) -> _Pair:
    rule_def = _make_rule(f.rule_id, f.message, f.remediation, f.severity)
    result: dict = {
        "ruleId": f.rule_id,
        "level": _sev_level(f.severity),
        "message": {"text": f.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _file_uri(f.file_path), "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.line_number, "snippet": {"text": f.code_snippet}},
                }
            }
        ],
        "properties": {"confidence": f.confidence.value},
    }
    return result, rule_def


def _probe_finding_to_pair(f) -> _Pair:  # f: ProbeResult
    rule_def = _make_rule(f.rule_id, f.message, f.remediation, f.severity)
    result: dict = {
        "ruleId": f.rule_id,
        "level": _sev_level(f.severity),
        "message": {"text": f"{f.message} — {f.detail}"},
        "locations": [{"logicalLocations": [{"name": f"mcp-tool/{f.target}", "kind": "function"}]}],
        "properties": {"confidence": f.confidence.value, "target": f.target},
    }
    return result, rule_def


def _build_sarif(pairs: list[_Pair]) -> str:
    # Deduplicate rules (first occurrence wins)
    rules_map: dict[str, dict] = {}
    for _, rule_def in pairs:
        rid = rule_def["id"]
        if rid not in rules_map:
            rules_map[rid] = rule_def

    rule_index = {rid: i for i, rid in enumerate(rules_map)}

    results: list[dict] = []
    for result_dict, _ in pairs:
        rid = result_dict["ruleId"]
        idx = rule_index.get(rid)
        entry = dict(result_dict)
        if idx is not None:
            entry["ruleIndex"] = idx
        results.append(entry)

    doc = {
        "version": _SARIF_VERSION,
        "$schema": _SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": _TOOL_VERSION,
                        "informationUri": _TOOL_URI,
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
