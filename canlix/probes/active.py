"""Active probes — opt-in, send actual tool calls to the server.

WARNING: these probes execute real tool calls on the target server.
Only use with --active on servers you own or have explicit permission to test.
"""

from __future__ import annotations

import re

from canlix.models import Confidence, Severity
from canlix.probes.base import ProbeResult, ProbeSession
from canlix.probes.transport import MCPClient, MCPConnectionError

_TRAVERSAL_PAYLOAD = "../../../../etc/passwd"
_PATH_LEAK_RE = re.compile(r"/(?:home|etc|usr|var|opt|root|proc|sys)/[a-zA-Z0-9_/\-\.]+")
_ROOT_CONTENT_RE = re.compile(r"root:[x*0-9!$]:|daemon:[x*]:|bin:/(?:bin|sbin)")


def _schema_props(tool: dict) -> set[str]:
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    return set((schema.get("properties") or {}).keys())


def _tool_response_text(resp: dict) -> str:
    """Extract text content from a tools/call response."""
    content = resp.get("content") or []
    parts = [c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text"]
    text = " ".join(parts)
    return text if text else str(resp)


def run_active_probes(client: MCPClient, session: ProbeSession) -> list[ProbeResult]:
    findings: list[ProbeResult] = []
    for tool in session.tools:
        findings.extend(_probe_path_traversal(client, tool))
        findings.extend(_probe_error_disclosure(client, tool))
    return findings


def _probe_path_traversal(client: MCPClient, tool: dict) -> list[ProbeResult]:
    if "path" not in _schema_props(tool):
        return []
    tool_name = tool.get("name", "unknown")
    try:
        resp = client.call_tool(tool_name, {"path": _TRAVERSAL_PAYLOAD})
        resp_text = _tool_response_text(resp)
        if _ROOT_CONTENT_RE.search(resp_text):
            return [
                ProbeResult(
                    rule_id="PROBE-010",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    target=tool_name,
                    message=f"Path traversal succeeded in tool '{tool_name}'",
                    detail=(
                        f"Tool returned /etc/passwd-like content when sent '{_TRAVERSAL_PAYLOAD}'. "
                        f"Snippet: {resp_text[:200]}"
                    ),
                    remediation=(
                        "Validate and canonicalize file paths. Reject paths containing '..' or "
                        "escaping the configured base directory. Use Path.resolve() and check the prefix."
                    ),
                )
            ]
        if _PATH_LEAK_RE.search(resp_text):
            return [
                ProbeResult(
                    rule_id="PROBE-010",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    target=tool_name,
                    message=f"Tool '{tool_name}' may be vulnerable to path traversal",
                    detail=(
                        f"Response contained an internal filesystem path when sent traversal payload. "
                        f"Snippet: {resp_text[:200]}"
                    ),
                    remediation="Validate and canonicalize file paths. Reject paths containing '..'.",
                )
            ]
    except MCPConnectionError:
        pass
    return []


def _probe_error_disclosure(client: MCPClient, tool: dict) -> list[ProbeResult]:
    tool_name = tool.get("name", "unknown")
    try:
        # Send empty arguments — most tools require parameters, so this triggers an error response
        resp = client.call_tool(tool_name, {})
        resp_text = _tool_response_text(resp)
        # Some tools return isError=true in the response body instead of a JSON-RPC error
        is_error = resp.get("isError", False)
        if is_error and _PATH_LEAK_RE.search(resp_text):
            return [
                ProbeResult(
                    rule_id="PROBE-011",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    target=tool_name,
                    message=f"Tool '{tool_name}' error response leaks an internal filesystem path",
                    detail=f"Error response: {resp_text[:300]}",
                    remediation=(
                        "Sanitize error messages returned to clients. "
                        "Log internal details server-side only; return generic error codes to callers."
                    ),
                )
            ]
    except MCPConnectionError as exc:
        err_str = str(exc)
        if _PATH_LEAK_RE.search(err_str):
            return [
                ProbeResult(
                    rule_id="PROBE-011",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    target=tool_name,
                    message=f"Tool '{tool_name}' JSON-RPC error leaks an internal filesystem path",
                    detail=f"Error message: {err_str[:300]}",
                    remediation=("Sanitize error messages returned to clients. Log internal details server-side only."),
                )
            ]
    return []
