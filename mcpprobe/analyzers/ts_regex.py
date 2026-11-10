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
# TS-012: weak hash algorithm — MD5 or SHA-1 passed to crypto.createHash
# ---------------------------------------------------------------------------

_WEAK_HASH = re.compile(
    r"""(?x)
    crypto\.createHash\s*\(\s*["'](md5|sha-?1)["']   # crypto.createHash('md5') / ('sha1') / ('sha-1')
    """,
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# TS-011: TLS verification disabled
# ---------------------------------------------------------------------------

# rejectUnauthorized: false — in any options object (https.request, tls.connect, etc.)
_TLS_REJECT_FALSE = re.compile(r"\brejectUnauthorized\s*:\s*false\b")
# NODE_TLS_REJECT_UNAUTHORIZED set to "0" or 0 at runtime
_TLS_ENV_ZERO = re.compile(r"""NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0["']?""")

# ---------------------------------------------------------------------------
# TS-015: open redirect — location / res.redirect with a non-literal URL
# ---------------------------------------------------------------------------

_OPEN_REDIRECT = re.compile(
    r"""(?x)
    window\.location(?:\.href)?\s*=\s*[A-Za-z_$]      # window.location[.href] = variable
    | res\.redirect\s*\(\s*[A-Za-z_$]                   # res.redirect(variable
    | response\.redirect\s*\(\s*[A-Za-z_$]              # response.redirect(variable
    | router\.navigate\s*\(\s*[A-Za-z_$]                # Angular router.navigate(variable
    | next\s*\(\s*['"]?redirect['"]\s*,\s*[A-Za-z_$]   # next('redirect', variable)
    """,
)
# Skip lines where the URL is clearly a literal string
_REDIRECT_LITERAL = re.compile(r"""(?:\.redirect|\.href|\.location)\s*\(?[= ]*["'`/]""")

# ---------------------------------------------------------------------------
# TS-014: debug mode hardcoded — NODE_ENV="development" or DEBUG=true in source
# ---------------------------------------------------------------------------

_DEBUG_NODE_ENV = re.compile(
    r"""(?x)
    NODE_ENV\s*[=:]\s*["']development["']   # NODE_ENV = "development" (assignment or object prop)
    | NODE_ENV\s*[=:]\s*["']dev["']          # NODE_ENV = "dev"
    """,
)
_DEBUG_TRUE = re.compile(
    r"""(?x)
    (?:const|let|var|export\s+const)\s+
    (?:DEBUG|debug|DEBUG_MODE|FLASK_DEBUG)   # variable name
    \s*(?::\s*\w+\s*)?=\s*true\b             # = true (TypeScript/JS boolean)
    """,
)

# ---------------------------------------------------------------------------
# TS-013: timing-safe comparison — === / !== with security-sensitive names
# ---------------------------------------------------------------------------

# Security variable names relevant for timing-attack detection.
# No leading \b so camelCase suffixes (storedToken, userPassword) are matched;
# trailing \b prevents matching tokenizer, protocol, etc.
_TS_SEC_VAR_TIMING = re.compile(
    r"""(?i)(?:token|secret|password|passwd|nonce|salt|api_?key|auth_?key|private_?key|otp|pin|session_?token)\b"""
)
# Any equality/inequality operator: == === != !==
# Pattern: one char from [!=] followed by 1-2 '=' chars  =>  matches ==, ===, !=, !==
_TS_EQ_OP = re.compile(r"[!=]={1,2}")
# Lines where one side of the comparison is a literal/null/undefined/true/false — these are benign
_TS_LITERAL_SIDE = re.compile(
    r"""(?x)
    # equality op immediately before a literal/null/undefined/true/false (rhs)
    [!=]={1,2}\s*(?:["'`\d]|null\b|undefined\b|true\b|false\b)
    # equality op immediately after a literal/null/undefined/true/false (lhs)
    | (?:["'`\d]|null\b|undefined\b|true\b|false\b)\s*[!=]={1,2}
    """,
)

# ---------------------------------------------------------------------------
# TS-010: insecure PRNG — Math.random() in a security-sensitive context
# ---------------------------------------------------------------------------

_MATH_RANDOM = re.compile(r"\bMath\.random\s*\(\s*\)")
# Checks whether the line contains a security-sensitive name (token, secret, etc.)
_TS_SECURITY_CONTEXT = re.compile(
    r"(?i)\b(?:token|secret|password|passwd|nonce|salt|otp|session_id|private_key|api_key|auth_key|pin)\b",
)

# ---------------------------------------------------------------------------
# TS-009: SQL injection — template literal in DB query/execute call
# ---------------------------------------------------------------------------

_SQL_TEMPLATE = re.compile(
    r"""(?x)
    \.(?:query|execute|raw|run|exec)\s*\(\s*`[^`]*\$\{  # .query(`...${
    | \bknex\s*\.\s*raw\s*\(\s*`[^`]*\$\{               # knex.raw(`...${
    | \bsequelize\s*\.\s*query\s*\(\s*`[^`]*\$\{         # sequelize.query(`...${
    """,
)

# ---------------------------------------------------------------------------
# TS-008: path traversal — fs I/O with non-literal path argument
# ---------------------------------------------------------------------------

_PATH_FS = re.compile(
    r"""(?x)
    \bfs\.readFile(?:Sync)?\s*\(\s*[A-Za-z_$]
    | \bfs\.writeFile(?:Sync)?\s*\(\s*[A-Za-z_$]
    | \bfs\.appendFile(?:Sync)?\s*\(\s*[A-Za-z_$]
    | \bfs\.unlink(?:Sync)?\s*\(\s*[A-Za-z_$]
    | \bfs\.open(?:Sync)?\s*\(\s*[A-Za-z_$]
    | \bfs\.stat(?:Sync)?\s*\(\s*[A-Za-z_$]
    | \bfs\.rmdir(?:Sync)?\s*\(\s*[A-Za-z_$]
    | \bfs\.rm(?:Sync)?\s*\(\s*[A-Za-z_$]
    | \bfsp\.readFile\s*\(\s*[A-Za-z_$]
    | \bfsp\.writeFile\s*\(\s*[A-Za-z_$]
    """,
)
_PATH_FS_LITERAL_SAFE = re.compile(r"""\bfs\.\w+\s*\(\s*["'`][^"'`]""")

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

    # TS-009: SQL injection — template literal in DB query
    if _SQL_TEMPLATE.search(raw):
        _add(
            "TS-009",
            Severity.HIGH,
            Confidence.MEDIUM,
            "SQL query built with template literal interpolation — SQL injection risk",
            "Use parameterised queries: db.query(sql, [params]). Never interpolate values into SQL.",
        )

    # TS-008: path traversal — fs I/O with non-literal path
    if _PATH_FS.search(raw) and not _PATH_FS_LITERAL_SAFE.search(raw):
        _add(
            "TS-008",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "File I/O with variable path — path traversal risk",
            "Validate the path with path.resolve() + a trusted prefix check before I/O operations.",
        )

    # TS-012: weak hash algorithm
    m012 = _WEAK_HASH.search(raw)
    if m012:
        algo = m012.group(1).lower()
        _add(
            "TS-012",
            Severity.MEDIUM,
            Confidence.HIGH,
            f"crypto.createHash('{algo}') uses a broken algorithm — do not use for security-sensitive hashing",
            "Use crypto.createHash('sha256') or 'sha3-256' for security. For passwords use bcrypt/argon2.",
        )

    # TS-011: TLS verification disabled
    if _TLS_REJECT_FALSE.search(raw) or _TLS_ENV_ZERO.search(raw):
        _add(
            "TS-011",
            Severity.HIGH,
            Confidence.HIGH,
            "TLS certificate verification disabled — allows MITM attacks",
            "Remove rejectUnauthorized: false. Never set NODE_TLS_REJECT_UNAUTHORIZED=0 in production.",
        )

    # TS-015: open redirect — location / res.redirect with a non-literal URL
    if _OPEN_REDIRECT.search(raw) and not _REDIRECT_LITERAL.search(raw):
        _add(
            "TS-015",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "Open redirect: URL set to a variable — attacker can redirect to a malicious site",
            "Validate the redirect URL against an allowlist. Never redirect to a raw user-supplied value.",
        )

    # TS-014: debug mode hardcoded in source
    if _DEBUG_NODE_ENV.search(raw) or _DEBUG_TRUE.search(raw):
        _add(
            "TS-014",
            Severity.MEDIUM,
            Confidence.HIGH,
            "Debug mode hardcoded in source — must not be enabled in production",
            "Read NODE_ENV / DEBUG from process.env at runtime; never hardcode 'development' or true.",
        )

    # TS-013: timing-safe comparison — ==, ===, !=, !== used on a security-sensitive name vs non-literal
    if _TS_EQ_OP.search(raw) and _TS_SEC_VAR_TIMING.search(raw) and not _TS_LITERAL_SIDE.search(raw):
        _add(
            "TS-013",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "Non-constant-time comparison on a security-sensitive name — vulnerable to timing attacks",
            "Use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) to prevent timing-based secret leakage.",
        )

    # TS-010: insecure PRNG — Math.random() used in a security-sensitive context
    if _MATH_RANDOM.search(raw) and _TS_SECURITY_CONTEXT.search(raw):
        _add(
            "TS-010",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "Math.random() used in a security-sensitive context — not cryptographically secure",
            "Use crypto.getRandomValues() (browser) or crypto.randomBytes() (Node.js) for security tokens.",
        )

    return result
