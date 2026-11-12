"""Source code security analyzer for MCP server implementations."""

from __future__ import annotations

from pathlib import Path

from canlix.analyzers.deps import analyze_package_json, analyze_requirements
from canlix.analyzers.python_ast import analyze_python
from canlix.analyzers.ts_regex import analyze_typescript
from canlix.models import SourceFinding

_SKIP = {"node_modules", ".venv", "venv", "__pycache__", ".git", "dist", "build", ".tox"}
_TS_SUFFIXES = {".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx"}


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
    if path.suffix in _TS_SUFFIXES:
        return analyze_typescript(path)
    if path.name == "package.json":
        return analyze_package_json(path)
    if path.name.endswith("requirements.txt") or path.name.startswith("requirements"):
        if path.suffix == ".txt":
            return analyze_requirements(path)
    return []


__all__ = ["analyze_path", "analyze_package_json", "analyze_requirements", "SourceFinding"]
