"""Rules 9-12 : network and transport security."""

from __future__ import annotations

import re

from canlix.models import Confidence, Finding, MCPServer, Severity, Transport
from canlix.rules.base import rule


@rule
def NET_001_http_url(server: MCPServer) -> Finding | None:
    """HTTP (non-TLS) transport exposes traffic to interception."""
    if server.transport in (Transport.HTTP, Transport.SSE):
        url = server.url
        if url.startswith("http://"):
            return Finding(
                rule_id="NET-001",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                server_name=server.name,
                message="MCP server uses unencrypted HTTP transport",
                evidence=f"url: {url}",
                remediation="Use HTTPS (TLS). Replace http:// with https://.",
                source_file=server.source_file,
            )
    return None


@rule
def NET_002_public_url(server: MCPServer) -> Finding | None:
    """MCP server points to a public internet URL — data leaves the machine."""
    if not server.url:
        return None
    local = re.compile(r"^https?://(localhost|127\.|0\.0\.0\.0|\[::1\]|::1)")
    if not local.match(server.url):
        return Finding(
            rule_id="NET-002",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            server_name=server.name,
            message="MCP server connects to a remote URL — data may leave your machine",
            evidence=f"url: {server.url}",
            remediation="Verify this is intentional. Understand what data the MCP tool sends to this endpoint.",
            source_file=server.source_file,
        )
    return None


@rule
def NET_003_no_auth_remote(server: MCPServer) -> Finding | None:
    """Remote HTTP/SSE server with no auth headers configured."""
    if server.transport not in (Transport.HTTP, Transport.SSE):
        return None
    if not server.url or server.url.startswith("http://localhost") or server.url.startswith("http://127."):
        return None
    has_auth = any(k.lower() in ("authorization", "x-api-key", "bearer") for k in server.env)
    if not has_auth:
        return Finding(
            rule_id="NET-003",
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            server_name=server.name,
            message="Remote MCP server has no authentication headers configured",
            evidence=f"url: {server.url}, env keys: {list(server.env.keys())}",
            remediation="Add authentication (Authorization header or API key) for remote MCP connections.",
            source_file=server.source_file,
        )
    return None


@rule
def NET_004_sensitive_path_in_args(server: MCPServer) -> Finding | None:
    """DB or file path in args points to sensitive data locations."""
    sensitive = re.compile(r"(?i)(password|passwd|secret|credential|private|key|token|wallet|ssh|\.env|id_rsa)")
    broad_paths = re.compile(r"^(/home|/root|/etc|/var|~)")
    for arg in server.args:
        if sensitive.search(arg):
            return Finding(
                rule_id="NET-004",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                server_name=server.name,
                message=f"Argument '{arg}' references a potentially sensitive path",
                evidence=f"args: {server.args}",
                remediation="Verify this MCP server only accesses the minimum required data. Restrict DB permissions.",
                source_file=server.source_file,
            )
        if broad_paths.match(arg) and arg.endswith(".db"):
            return Finding(
                rule_id="NET-004",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                server_name=server.name,
                message=f"MCP server has unrestricted access to database at '{arg}'",
                evidence=f"args: {server.args}",
                remediation="Ensure the DB contains no sensitive data, or restrict MCP server to read-only access.",
                source_file=server.source_file,
            )
    return None


@rule
def NET_005_tls_verification_disabled(server: MCPServer) -> Finding | None:
    """Explicit TLS disable flags in env or args."""
    tls_disable = re.compile(r"(?i)(no[_-]?verify|insecure|skip[_-]?tls|ssl[_-]?verify\s*=\s*(false|0|no))")
    for key, value in server.env.items():
        if tls_disable.search(f"{key}={value}"):
            return Finding(
                rule_id="NET-005",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                server_name=server.name,
                message=f"TLS verification appears disabled via env '{key}'",
                evidence=f"env.{key} = {value}",
                remediation="Remove TLS bypass flags. Use a valid certificate or add your CA to the trust store.",
                source_file=server.source_file,
            )
    for arg in server.args:
        if tls_disable.search(arg):
            return Finding(
                rule_id="NET-005",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                server_name=server.name,
                message=f"TLS verification appears disabled via arg '{arg}'",
                evidence=f"args: {server.args}",
                remediation="Remove TLS bypass flags. Use a valid certificate or add your CA to the trust store.",
                source_file=server.source_file,
            )
    return None


NETWORK_RULES = [
    NET_001_http_url,
    NET_002_public_url,
    NET_003_no_auth_remote,
    NET_004_sensitive_path_in_args,
    NET_005_tls_verification_disabled,
]
