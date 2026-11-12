"""Passive probes — analyse tool/resource metadata without sending tool calls."""

from __future__ import annotations

import re

from mcpprobe.models import Confidence, Severity
from mcpprobe.probes.base import ProbeResult, ProbeSession

# --- PROBE-001: prompt-injection in tool description ---

_INJECTION_PATTERNS = [
    r"ignore previous",
    r"ignore all previous",
    r"disregard (?:previous|all|your) instructions",
    r"forget (?:previous|your) instructions",
    r"you are now",
    r"pretend you are",
    r"act as if you",
    r"new instructions?:",
    r"\[\[system\]\]",
    r"<\|im_start\|>",
    r"<\|system\|>",
    r"###\s*instruction",
    r"jailbreak",
    r"bypass (?:your )?(?:filter|restriction|safety)",
    r"override (?:your )?(?:instruction|guideline|system prompt)",
    r"do not (?:follow|obey)",
    r"prompt injection",
]
_INJECTION_RE = re.compile("|".join(_INJECTION_PATTERNS), re.IGNORECASE)

# --- PROBE-002: dangerous execution capability ---

_EXEC_NAME_PATTERNS = re.compile(
    r"(?i)(run_shell|execute_command|run_command|shell_exec|run_bash|"
    r"run_script|system_command|exec_code|eval_code|run_code_unsafe|"
    r"arbitrary_command)",
)
_EXEC_DESC_PHRASES = [
    "run arbitrary",
    "executes arbitrary",
    "runs shell commands",
    "executes shell commands",
    "arbitrary code",
    "run any command",
    "execute any",
    "arbitrary shell",
]

# --- PROBE-003: unrestricted filesystem tool ---

_FS_NAME_PATTERNS = re.compile(
    r"(?i)(read_file|write_file|delete_file|list_(?:directory|files)|"
    r"file_manager|filesystem|file_system|read_files|write_files)",
)

# --- PROBE-004: dangerous input schema parameter ---

_UNSAFE_PARAM_NAMES = {
    "code",
    "command",
    "script",
    "eval",
    "exec",
    "cmd",
    "shell_command",
    "shell",
    "expression",
}

# --- PROBE-005: excessive tool surface area ---

_TOOL_COUNT_THRESHOLD = 15


def _schema_props(tool: dict) -> set[str]:
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    return set((schema.get("properties") or {}).keys())


def run_metadata_probes(session: ProbeSession) -> list[ProbeResult]:
    findings: list[ProbeResult] = []
    for tool in session.tools:
        f = _probe_injection(tool)
        if f:
            findings.append(f)
        f = _probe_dangerous_exec(tool)
        if f:
            findings.append(f)
        f = _probe_filesystem(tool)
        if f:
            findings.append(f)
        f = _probe_dangerous_param(tool)
        if f:
            findings.append(f)
    f = _probe_surface_area(session)
    if f:
        findings.append(f)
    return findings


def _probe_injection(tool: dict) -> ProbeResult | None:
    desc = (tool.get("description") or "").strip()
    if not desc:
        return None
    m = _INJECTION_RE.search(desc)
    if not m:
        return None
    name = tool.get("name", "unknown")
    return ProbeResult(
        rule_id="PROBE-001",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        target=name,
        message=f"Tool '{name}' description contains prompt-injection pattern: '{m.group()}'",
        detail=f"Description: {desc[:300]}",
        remediation=(
            "Remove injection-like phrases from tool descriptions. "
            "MCP tool descriptions are read by the AI agent — a malicious server can hijack it here."
        ),
    )


def _probe_dangerous_exec(tool: dict) -> ProbeResult | None:
    name = tool.get("name", "")
    desc = (tool.get("description") or "").lower()
    name_match = _EXEC_NAME_PATTERNS.search(name)
    desc_match = any(phrase in desc for phrase in _EXEC_DESC_PHRASES)
    if not name_match and not desc_match:
        return None
    trigger = name_match.group() if name_match else next(p for p in _EXEC_DESC_PHRASES if p in desc)
    return ProbeResult(
        rule_id="PROBE-002",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH if name_match else Confidence.MEDIUM,
        target=name,
        message=f"Tool '{name}' exposes dangerous command-execution capability",
        detail=f"Trigger: '{trigger}'. Tools that run arbitrary commands give a compromised agent OS-level access.",
        remediation=(
            "Restrict shell/exec tools to a predefined allow-list of commands. "
            "Never expose a general-purpose shell to an AI agent."
        ),
    )


def _probe_filesystem(tool: dict) -> ProbeResult | None:
    name = tool.get("name", "")
    if not _FS_NAME_PATTERNS.search(name):
        return None
    props = _schema_props(tool)
    if "path" not in props:
        return None
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    path_prop = (schema.get("properties") or {}).get("path", {})
    has_pattern = bool(path_prop.get("pattern"))
    has_desc = bool(path_prop.get("description"))
    _restrict_words = ["only", "within", "relative", "must"]
    if has_pattern or (has_desc and any(w in path_prop["description"].lower() for w in _restrict_words)):
        return None
    return ProbeResult(
        rule_id="PROBE-003",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        target=name,
        message=f"Tool '{name}' accepts a 'path' parameter with no documented constraints",
        detail="No 'pattern' constraint or restrictive description on the path parameter. Path traversal (../../) may be possible.",  # noqa: E501
        remediation=(
            "Add a 'pattern' JSON-schema constraint limiting paths to an allowed base directory. "
            "Validate and canonicalize paths server-side before reading or writing."
        ),
    )


def _probe_dangerous_param(tool: dict) -> ProbeResult | None:
    name = tool.get("name", "")
    props = _schema_props(tool)
    dangerous = props & _UNSAFE_PARAM_NAMES
    if not dangerous:
        return None
    param = sorted(dangerous)[0]
    return ProbeResult(
        rule_id="PROBE-004",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        target=name,
        message=f"Tool '{name}' accepts a '{param}' parameter — potential arbitrary code/command injection",
        detail=f"Parameters matching dangerous names: {', '.join(sorted(dangerous))}.",
        remediation=(
            "Replace open-ended parameters like 'command' or 'code' with typed enumerations "
            "or structured inputs that prevent injection."
        ),
    )


def _probe_surface_area(session: ProbeSession) -> ProbeResult | None:
    count = len(session.tools)
    if count < _TOOL_COUNT_THRESHOLD:
        return None
    return ProbeResult(
        rule_id="PROBE-005",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        target=session.server_name,
        message=f"Server exposes {count} tools — large attack surface",
        detail=(
            f"Each tool is a potential injection or misuse vector. "
            f"{count} tools exceed the recommended threshold of {_TOOL_COUNT_THRESHOLD}."
        ),
        remediation=(
            "Expose only the tools required for the agent's task. Consider scoping tool sets per session or role."
        ),
    )
