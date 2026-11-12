"""Rules 5-8 : excessive permissions and dangerous tool exposure."""

from __future__ import annotations

import re

from canlix.models import Confidence, Finding, MCPServer, Severity
from canlix.rules.base import rule

_DANGEROUS_TOOLS = re.compile(r"(?i)(filesystem|shell|exec|run|eval|delete|drop|admin|root|sudo|system)")
# Matches top-level broad paths only — not scoped subdirectories like /home/user/project
_BROAD_FS_PATHS = re.compile(r"^(/(?:home|root|etc|var|tmp)?$|~$)")


@rule
def PERM_001_broad_filesystem_access(server: MCPServer) -> Finding | None:
    """MCP server configured with access to broad filesystem paths."""
    for arg in server.args:
        if _BROAD_FS_PATHS.match(arg):
            return Finding(
                rule_id="PERM-001",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                server_name=server.name,
                message=f"MCP server has access to broad filesystem path '{arg}'",
                evidence=f"args: {server.args}",
                remediation="Restrict filesystem access to the minimum required directory.",
                source_file=server.source_file,
            )
    return None


@rule
def PERM_002_dangerous_tool_name(server: MCPServer) -> Finding | None:
    """Server name or command suggests dangerous capabilities."""
    target = f"{server.name} {server.command}".lower()
    if _DANGEROUS_TOOLS.search(target):
        cmd_name = server.command.split("/")[-1]
        return Finding(
            rule_id="PERM-002",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            server_name=server.name,
            message=f"Server name/command '{server.name}' suggests elevated capabilities",
            evidence=f"name: {server.name}, command: {cmd_name}",
            remediation="Review what tools this MCP server exposes. Apply least-privilege principle.",
            source_file=server.source_file,
        )
    return None


@rule
def PERM_003_home_dir_db(server: MCPServer) -> Finding | None:
    """SQLite DB located in home directory — may contain sensitive user data."""
    for arg in server.args:
        if arg.endswith(".db") and ("/home/" in arg or arg.startswith("~")):
            return Finding(
                rule_id="PERM-003",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                server_name=server.name,
                message=f"MCP server accesses a user-level database at '{arg}'",
                evidence=f"db path: {arg}",
                remediation="Verify this DB has no credentials or PII accessible via MCP tools.",
                source_file=server.source_file,
            )
    return None


@rule
def PERM_004_multiple_high_risk_servers(server: MCPServer) -> Finding | None:
    """Single-server rule — multi-server risk is handled at engine level."""
    return None


PERMISSIONS_RULES = [
    PERM_001_broad_filesystem_access,
    PERM_002_dangerous_tool_name,
    PERM_003_home_dir_db,
    PERM_004_multiple_high_risk_servers,
]
