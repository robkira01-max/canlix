"""JSON reporter for CI/CD pipelines."""

from __future__ import annotations

import json

from mcpprobe.models import ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps(
        {
            "mcpprobe_version": "0.1.0",
            "score": result.score,
            "servers_scanned": len(result.servers),
            "findings_count": len(result.findings),
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
        },
        indent=2,
    )
