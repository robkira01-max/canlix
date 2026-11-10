"""Source code security analyzer for MCP server implementations."""

from __future__ import annotations

from pathlib import Path

from mcpprobe.analyzers.python_ast import analyze_python
from mcpprobe.models import SourceFinding

_SKIP = {"node_modules", ".venv", "venv", "__pycache__", ".git", "dist", "build", ".tox"}


def analyze_path(path: Path) -> list[SourceFinding]:
    """Analyze a file or directory for security issues. Returns all findings."""
    path = Path(path)
    if path.is_file():
        return _analyze_file(path)
    findings: list[SourceFinding] = []
    for f in sorted(path.rglob("*")):
        if any(part in _SKIP for part in f.parts):
            continue
        findings.extend(_analyze_file(f))
    return findings


def _analyze_file(path: Path) -> list[SourceFinding]:
    if path.suffix == ".py":
        return analyze_python(path)
    return []


__all__ = ["analyze_path", "SourceFinding"]
