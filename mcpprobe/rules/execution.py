"""Rules 13-16 : dangerous execution patterns."""
from __future__ import annotations
import re
from mcpprobe.models import MCPServer, Finding, Severity, Confidence
from mcpprobe.rules.base import rule

_SHELLS = {"sh", "bash", "zsh", "fish", "dash", "cmd", "powershell", "pwsh"}
_SHELL_FLAGS = {"-c", "/c", "/C"}


@rule
def EXEC_001_relative_command(server: MCPServer) -> Finding | None:
    """CMD path is relative — vulnerable to PATH hijacking."""
    cmd = server.command
    if not cmd:
        return None
    if not cmd.startswith("/") and "/" not in cmd and "\\" not in cmd:
        return Finding(
            rule_id="EXEC-001",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            server_name=server.name,
            message=f"Command '{cmd}' uses a relative path — vulnerable to PATH hijacking",
            evidence=f"command: {cmd}",
            remediation=f"Use an absolute path, e.g. $(which {cmd}) or /usr/local/bin/{cmd}",
            source_file=server.source_file,
        )
    return None


@rule
def EXEC_002_direct_shell(server: MCPServer) -> Finding | None:
    """MCP server command is a shell interpreter."""
    cmd_name = server.command.split("/")[-1].lower()
    if cmd_name in _SHELLS:
        return Finding(
            rule_id="EXEC-002",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            server_name=server.name,
            message=f"MCP server runs a shell interpreter ('{server.command}')",
            evidence=f"command: {server.command}, args: {server.args}",
            remediation="Avoid shell interpreters as MCP entry points. Use a specific, purpose-built executable.",
            source_file=server.source_file,
        )
    return None


@rule
def EXEC_003_shell_flag_in_args(server: MCPServer) -> Finding | None:
    """Shell -c flag in args allows arbitrary command injection."""
    for flag in server.args:
        if flag in _SHELL_FLAGS:
            return Finding(
                rule_id="EXEC-003",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                server_name=server.name,
                message=f"Shell flag '{flag}' in args enables arbitrary command execution",
                evidence=f"args: {server.args}",
                remediation="Remove shell -c patterns. Use explicit executables with fixed argument lists.",
                source_file=server.source_file,
            )
    return None


@rule
def EXEC_004_unpinned_npx(server: MCPServer) -> Finding | None:
    """npx -y downloads and runs arbitrary packages without version pinning."""
    cmd_name = server.command.split("/")[-1].lower()
    if cmd_name in ("npx", "bunx", "uvx"):
        has_y = "-y" in server.args or "--yes" in server.args
        has_version = any("@" in a for a in server.args if not a.startswith("-"))
        if has_y and not has_version:
            return Finding(
                rule_id="EXEC-004",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                server_name=server.name,
                message=f"'{cmd_name} -y' downloads latest package version without pinning",
                evidence=f"command: {server.command}, args: {server.args}",
                remediation="Pin the package version: e.g. 'npx -y package@1.2.3' to prevent supply chain attacks.",
                source_file=server.source_file,
            )
    return None


EXECUTION_RULES = [EXEC_001_relative_command, EXEC_002_direct_shell, EXEC_003_shell_flag_in_args, EXEC_004_unpinned_npx]
