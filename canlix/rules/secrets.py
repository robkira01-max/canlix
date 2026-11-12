"""Rules 1-4 : secrets exposed in MCP configuration."""

from __future__ import annotations

import re

from canlix.models import Confidence, Finding, MCPServer, Severity
from canlix.rules.base import rule

# Patterns that look like secrets — conservative to avoid false positives
_SECRET_PATTERNS = [
    (re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?"), "API key"),
    (re.compile(r"(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{20,})['\"]?"), "access token"),
    (re.compile(r"(?i)(password|passwd|secret)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?"), "password/secret"),
    (re.compile(r"(?i)(sk-[A-Za-z0-9]{32,})"), "OpenAI-style key"),
    (re.compile(r"(?i)(ghp_[A-Za-z0-9]{36,})"), "GitHub personal access token"),
    (re.compile(r"(?i)(AKIA[0-9A-Z]{16})"), "AWS access key ID"),
]

_GIT_TRACKED_CONFIGS = {".claude/settings.json"}  # never .local.json (gitignored)


@rule
def SEC_001_api_key_in_env(server: MCPServer) -> Finding | None:
    """Detects API keys stored in plain text inside env block."""
    for key, value in server.env.items():
        for pattern, label in _SECRET_PATTERNS:
            if pattern.search(f"{key}={value}"):
                return Finding(
                    rule_id="SEC-001",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    server_name=server.name,
                    message=f"Potential {label} found in env variable '{key}'",
                    evidence=f"env.{key} = {value[:6]}...[REDACTED]",
                    remediation=(
                        "Store secrets in a secrets manager or environment variables set outside the config file."
                        " Never commit credentials."
                    ),
                    source_file=server.source_file,
                )
    return None


@rule
def SEC_002_secret_in_args(server: MCPServer) -> Finding | None:
    """Detects secrets passed directly as CLI arguments."""
    for i, arg in enumerate(server.args):
        for pattern, label in _SECRET_PATTERNS:
            if pattern.search(arg):
                return Finding(
                    rule_id="SEC-002",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    server_name=server.name,
                    message=f"Potential {label} passed as a command-line argument",
                    evidence=f"args[{i}] = {arg[:6]}...[REDACTED]",
                    remediation="Pass secrets via environment variables, not CLI args (visible in process listings).",
                    source_file=server.source_file,
                )
    return None


@rule
def SEC_003_secret_key_name_in_env(server: MCPServer) -> Finding | None:
    """Flags env keys whose names suggest they hold secrets (even if value looks like a placeholder)."""
    sensitive_names = re.compile(r"(?i)(api_key|apikey|secret|password|passwd|token|credential|private_key|access_key)")
    for key, value in server.env.items():
        if sensitive_names.search(key) and len(value) > 3 and value not in ("", "null", "none", "false"):
            return Finding(
                rule_id="SEC-003",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                server_name=server.name,
                message=f"Environment variable '{key}' likely contains a secret",
                evidence=f"env key: {key}",
                remediation="Verify this value is not in a tracked config file. Use .env files excluded from git.",
                source_file=server.source_file,
            )
    return None


@rule
def SEC_004_secret_in_tracked_config(server: MCPServer) -> Finding | None:
    """Warns when any env value is non-empty in a git-tracked config file."""
    if server.source_file is None:
        return None
    is_tracked = any(str(server.source_file).endswith(p) for p in _GIT_TRACKED_CONFIGS)
    if is_tracked and any(v for v in server.env.values()):
        return Finding(
            rule_id="SEC-004",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            server_name=server.name,
            message="Non-empty env values in a git-tracked config file",
            evidence=f"source: {server.source_file}",
            remediation="Move secrets to .claude/settings.local.json (gitignored) or a .env file.",
            source_file=server.source_file,
        )
    return None


SECRETS_RULES = [
    SEC_001_api_key_in_env,
    SEC_002_secret_in_args,
    SEC_003_secret_key_name_in_env,
    SEC_004_secret_in_tracked_config,
]
