"""JSON reporter for CI/CD pipelines."""

from __future__ import annotations

import json
from pathlib import Path

from mcpprobe.models import ScanResult, SourceFinding


def render_json(result: ScanResult) -> str:
    return json.dumps(
        {
            "mcpprobe_version": "0.1.0",
            "score": result.score,
            "servers_scanned": len(result.servers),
            "findings_count": len(result.findings),
            "source_findings_count": len(result.source_findings),
            "scan_duration_ms": round(result.scan_duration_ms, 2),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "server": f.server_name,
                    "message": f.message,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "source_file": str(f.source_file) if f.source_file else None,
                }
                for f in result.findings
            ],
            "source_findings": [_sf_to_dict(sf) for sf in result.source_findings],
        },
        indent=2,
    )


def render_source_json(findings: list[SourceFinding], path: Path, duration_ms: float) -> str:
    score = max(0, 100 - sum(f.severity.score for f in findings))
    return json.dumps(
        {
            "mcpprobe_version": "0.1.0",
            "analyzed_path": str(path),
            "score": score,
            "findings_count": len(findings),
            "scan_duration_ms": round(duration_ms, 2),
            "source_findings": [_sf_to_dict(sf) for sf in findings],
        },
        indent=2,
    )


def _sf_to_dict(sf: SourceFinding) -> dict:
    return {
        "rule_id": sf.rule_id,
        "severity": sf.severity.value,
        "confidence": sf.confidence.value,
        "file": str(sf.file_path),
        "line": sf.line_number,
        "message": sf.message,
        "code_snippet": sf.code_snippet,
        "remediation": sf.remediation,
    }
