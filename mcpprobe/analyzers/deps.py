"""Dependency manifest analyzer — detects unpinned or risky package versions."""

from __future__ import annotations

import json
import re
from pathlib import Path

from mcpprobe.models import Confidence, Severity, SourceFinding

# ---------------------------------------------------------------------------
# requirements.txt helpers
# ---------------------------------------------------------------------------

# Lines to skip in requirements.txt
_REQ_SKIP = re.compile(r"^\s*(?:#|-r\s|-c\s|-e\s|--|-i\s|http[s]?://)")
# Strip VCS/URL-based specifiers (git+https://...)
_VCS_LINE = re.compile(r"^(?:git\+|svn\+|hg\+|bzr\+)")
# Strip extras: requests[security] → requests
_STRIP_EXTRAS = re.compile(r"\[.*?\]")
# Match only the package name at the start of a requirement line
_PKG_NAME = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9._-]*))")


def analyze_requirements(path: Path) -> list[SourceFinding]:
    """Scan a requirements*.txt file for unpinned packages."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    findings: list[SourceFinding] = []
    for lineno, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or _REQ_SKIP.match(line) or _VCS_LINE.match(line):
            continue
        clean = _STRIP_EXTRAS.sub("", line)
        # Exact pin present → safe
        if "==" in clean:
            continue
        m = _PKG_NAME.match(clean)
        if not m:
            continue
        pkg = m.group(1)
        findings.append(
            SourceFinding(
                rule_id="DEP-001",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                file_path=path,
                line_number=lineno,
                message=f"Package '{pkg}' has no exact version pin — supply chain risk",
                code_snippet=line,
                remediation=f"Pin to an exact version: {pkg}==<version>. Use pip-compile or uv to generate a lockfile.",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# package.json helpers
# ---------------------------------------------------------------------------

# Versions that mean "pull whatever is newest"
_FULLY_UNPINNED = {"*", "latest", ""}

# Exact pin: no leading ^ ~ >= <= > < (plain semver or git hash)
_EXACT_SEMVER = re.compile(r"^\d")


def _version_severity(version: str) -> Severity | None:
    """Return severity for a package.json version specifier, or None if safe."""
    v = version.strip()
    if v in _FULLY_UNPINNED:
        return Severity.HIGH
    if v.startswith(("^", "~", ">=", "<=", ">", "<", "||", "x", "X")):
        return Severity.MEDIUM
    # Exact pin (1.2.3, 1.2.3-alpha) or git URL → safe
    return None


def _find_line(lines: list[str], pkg: str, version: str) -> int:
    """Return the 1-based line number of a package entry in package.json."""
    needle = json.dumps(pkg)  # e.g. '"requests"'
    for i, line in enumerate(lines, start=1):
        if needle in line and version in line:
            return i
    return 1


def analyze_package_json(path: Path) -> list[SourceFinding]:
    """Scan a package.json for risky version specifiers."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(text)
    except (OSError, json.JSONDecodeError):
        return []

    lines = text.splitlines()
    findings: list[SourceFinding] = []

    dep_sections = [
        data.get("dependencies", {}),
        data.get("devDependencies", {}),
        data.get("optionalDependencies", {}),
    ]
    for section in dep_sections:
        if not isinstance(section, dict):
            continue
        for pkg, version in section.items():
            if not isinstance(version, str):
                continue
            sev = _version_severity(version)
            if sev is None:
                continue
            lineno = _find_line(lines, pkg, version)
            rule = "DEP-002" if sev == Severity.HIGH else "DEP-003"
            msg = (
                f"Package '{pkg}' version '{version}' is fully unpinned — highest supply chain risk"
                if sev == Severity.HIGH
                else f"Package '{pkg}' version '{version}' uses a range specifier — supply chain risk"
            )
            findings.append(
                SourceFinding(
                    rule_id=rule,
                    severity=sev,
                    confidence=Confidence.HIGH,
                    file_path=path,
                    line_number=lineno,
                    message=msg,
                    code_snippet=f'"{pkg}": "{version}"',
                    remediation=f'Pin to exact: "{pkg}": "{version.lstrip("^~>=<")}" and commit a lockfile.',
                )
            )
    return findings
