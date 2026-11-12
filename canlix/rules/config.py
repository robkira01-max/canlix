"""Rules 17-20 : configuration and transport hygiene."""

from __future__ import annotations

from canlix.models import Confidence, Finding, MCPServer, Severity, Transport
from canlix.rules.base import rule


@rule
def CFG_001_no_command_no_url(server: MCPServer) -> Finding | None:
    """Server has neither a command nor a URL — misconfiguration."""
    if not server.command and not server.url:
        return Finding(
            rule_id="CFG-001",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            server_name=server.name,
            message="MCP server has no command and no URL — likely misconfigured",
            evidence=f"command: '{server.command}', url: '{server.url}'",
            remediation="Set either 'command' (stdio) or 'url' (HTTP/SSE) for the MCP server.",
            source_file=server.source_file,
        )
    return None


@rule
def CFG_002_http_without_url(server: MCPServer) -> Finding | None:
    """Transport is HTTP/SSE but no URL provided."""
    if server.transport in (Transport.HTTP, Transport.SSE) and not server.url:
        return Finding(
            rule_id="CFG-002",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            server_name=server.name,
            message=f"Transport '{server.transport.value}' specified but no URL configured",
            evidence=f"transport: {server.transport.value}, url: '{server.url}'",
            remediation="Provide a 'url' field for HTTP or SSE transports.",
            source_file=server.source_file,
        )
    return None


@rule
def CFG_003_empty_server_name(server: MCPServer) -> Finding | None:
    """Empty or whitespace-only server name."""
    if not server.name or not server.name.strip():
        return Finding(
            rule_id="CFG-003",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            server_name="(unnamed)",
            message="MCP server has an empty name",
            evidence="name: ''",
            remediation="Give every MCP server a unique, descriptive name.",
            source_file=server.source_file,
        )
    return None


@rule
def CFG_004_command_with_url(server: MCPServer) -> Finding | None:
    """Both command and URL are set — ambiguous configuration."""
    if server.command and server.url:
        return Finding(
            rule_id="CFG-004",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            server_name=server.name,
            message="Both 'command' and 'url' are set — which transport will be used?",
            evidence=f"command: {server.command}, url: {server.url}",
            remediation="Set either 'command' (stdio) or 'url' (HTTP/SSE), not both.",
            source_file=server.source_file,
        )
    return None


CONFIG_RULES = [
    CFG_001_no_command_no_url,
    CFG_002_http_without_url,
    CFG_003_empty_server_name,
    CFG_004_command_with_url,
]
