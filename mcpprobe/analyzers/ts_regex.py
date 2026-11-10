"""Regex-based security analyzer for TypeScript/JavaScript MCP server source files.

Does not require Node.js or any external parser — pure Python regex line scanning.
"""

from __future__ import annotations

import re
from pathlib import Path

from mcpprobe.models import Confidence, Severity, SourceFinding

# ---------------------------------------------------------------------------
# TS-001a: key-prefix secrets in string literals (CRITICAL)
# ---------------------------------------------------------------------------

_KEY_PREFIX = re.compile(
    r"""(?x)
    ["'`]
    (
        sk-[A-Za-z0-9]{32,}
        | ghp_[A-Za-z0-9]{36,}
        | ghs_[A-Za-z0-9]{36,}
        | AKIA[0-9A-Z]{16}
        | xox[bpoa]-[A-Za-z0-9\-]+
        | ya29\.[A-Za-z0-9_\-]+
        | AIza[A-Za-z0-9_\-]{35}
        | eyJ[A-Za-z0-9_\-]{40,}   # JWT (long base64url header)
    )
    ["'`]
    """,
)

# ---------------------------------------------------------------------------
# TS-001b: variable-name heuristic (HIGH)
# ---------------------------------------------------------------------------

_SECRET_ASSIGN = re.compile(
    r"""(?x)
    (?:const|let|var|export\s+const)\s+
    ([A-Za-z_$][A-Za-z0-9_$]*)        # variable name
    (?:\s*:\s*\w+)?                     # optional TypeScript type annotation
    \s*=\s*
    ["']([^"']{16,})["']               # string value >= 16 chars (not env lookup)
    """,
)
_SECRET_VARNAMES = re.compile(
    r"(?i)(api[_-]?key|apikey|secret|password|passwd|token|auth_token|credential|private[_-]?key|access[_-]?key)"
)

# ---------------------------------------------------------------------------
# TS-002: eval() — arbitrary code execution
# ---------------------------------------------------------------------------

_EVAL = re.compile(r"\beval\s*\(")

# ---------------------------------------------------------------------------
# TS-003: execSync() — always shell, can't pass shell=False
# ---------------------------------------------------------------------------

_EXEC_SYNC = re.compile(r"\bexecSync\s*\(")

# ---------------------------------------------------------------------------
# TS-004: shell: true in spawn/exec options
# ---------------------------------------------------------------------------

_SHELL_TRUE = re.compile(r"\bshell\s*:\s*true\b")

# ---------------------------------------------------------------------------
# TS-005: exec() with template literal — interpolation enables injection
# ---------------------------------------------------------------------------

_EXEC_TEMPLATE = re.compile(r"\bexec\s*\(\s*`")

# ---------------------------------------------------------------------------
# TS-006: prototype pollution — __proto__ assignment
# ---------------------------------------------------------------------------

_PROTO_POLLUTION = re.compile(
    r"""(?x)
    __proto__\s*[=\[]
    | \.constructor\s*\[\s*["']prototype["']
    """,
)

# ---------------------------------------------------------------------------
# TS-007: SSRF — fetch/axios/got with non-literal URL argument
# ---------------------------------------------------------------------------

_SSRF_FETCH = re.compile(
    r"""(?x)
    \bfetch\s*\(\s*[A-Za-z_$]          # fetch(variable
    | \baxios\.[a-z]+\s*\(\s*[A-Za-z_$]  # axios.get(variable
    | \bgot\s*\(\s*[A-Za-z_$]           # got(variable
    | \bneedle\.[a-z]+\s*\(\s*[A-Za-z_$]  # needle.get(variable
    """,
)
# Negation: skip lines where the argument is a plain https?:// string (definitely safe)
_SSRF_LITERAL_SAFE = re.compile(r"""\bfetch\s*\(\s*["'`]https?://""")
_SSRF_AXIOS_LITERAL_SAFE = re.compile(r"""\baxios\.[a-z]+\s*\(\s*["'`]https?://""")


def analyze_typescript(path: Path) -> list[SourceFinding]:
    """Scan a TypeScript/JavaScript file for security issues. Returns all findings."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings: list[SourceFinding] = []
    lines = source.splitlines()

    for lineno, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        findings.extend(_scan_line(path, lineno, raw_line, line))

    return findings


def _scan_line(path: Path, lineno: int, raw: str, line: str) -> list[SourceFinding]:
    result: list[SourceFinding] = []
    reported: set[str] = set()

    def _add(rule_id: str, sev: Severity, conf: Confidence, msg: str, rem: str) -> None:
        if rule_id not in reported:
            reported.add(rule_id)
            result.append(
                SourceFinding(
                    rule_id=rule_id,
                    severity=sev,
                    confidence=conf,
                    file_path=path,
                    line_number=lineno,
                    message=msg,
                    code_snippet=line,
                    remediation=rem,
                )
            )

    # TS-001a: key prefix (CRITICAL — takes precedence over TS-001b)
    if _KEY_PREFIX.search(raw):
        _add(
            "TS-001",
            Severity.CRITICAL,
            Confidence.HIGH,
            "Hardcoded API key or token detected in source code",
            "Move secret to process.env.VAR_NAME or a secrets manager. Never commit credentials.",
        )
    else:
        # TS-001b: name-based heuristic (HIGH)
        m = _SECRET_ASSIGN.search(raw)
        if m and _SECRET_VARNAMES.search(m.group(1)):
            _add(
                "TS-001",
                Severity.HIGH,
                Confidence.MEDIUM,
                f"Potential secret in variable '{m.group(1)}' — value looks like a credential",
                "Use process.env.VAR_NAME instead of hardcoding secrets.",
            )

    # TS-002: eval
    if _EVAL.search(raw):
        _add(
            "TS-002",
            Severity.HIGH,
            Confidence.HIGH,
            "eval() allows arbitrary code execution",
            "Remove eval(). Use explicit logic or JSON.parse() for data parsing.",
        )

    # TS-003: execSync
    if _EXEC_SYNC.search(raw):
        _add(
            "TS-003",
            Severity.HIGH,
            Confidence.HIGH,
            "execSync() runs commands through the shell — command injection risk",
            "Use execFileSync(cmd, args) with a separate argument array to avoid shell interpretation.",
        )

    # TS-004: shell: true
    if _SHELL_TRUE.search(raw):
        _add(
            "TS-004",
            Severity.HIGH,
            Confidence.HIGH,
            "shell: true enables command injection via unsanitised input",
            "Remove shell: true. Pass command and arguments as separate array elements.",
        )

    # TS-005: exec with template literal
    if _EXEC_TEMPLATE.search(raw):
        _add(
            "TS-005",
            Severity.HIGH,
            Confidence.MEDIUM,
            "exec() with template literal — string interpolation enables command injection",
            "Use execFile(cmd, args) with an argument array. Never interpolate user input into shell commands.",
        )

    # TS-006: prototype pollution
    if _PROTO_POLLUTION.search(raw):
        _add(
            "TS-006",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "Potential prototype pollution — assignment to __proto__ or constructor.prototype",
            "Validate object keys before merging. Use Object.create(null) for untrusted data maps.",
        )

    # TS-007: SSRF — HTTP client with non-literal URL
    if _SSRF_FETCH.search(raw) and not _SSRF_LITERAL_SAFE.search(raw) and not _SSRF_AXIOS_LITERAL_SAFE.search(raw):
        _add(
            "TS-007",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "HTTP request with variable URL — SSRF risk",
            "Validate the URL against an allowlist. Never pass raw user-supplied URLs to HTTP clients.",
        )

    return result
