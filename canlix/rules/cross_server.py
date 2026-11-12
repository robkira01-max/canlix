"""Cross-server rules XSV-001..004: risks that only exist when several servers share one agent."""

from __future__ import annotations

import re
from collections import defaultdict
from itertools import combinations
from urllib.parse import urlparse

from canlix.models import Confidence, Finding, MCPServer, Severity, Transport

_LAUNCHERS = {
    "npx", "uvx", "node", "python", "python3", "pipx", "bunx", "bun", "deno",
    "sh", "bash", "zsh", "docker", "uv", "pip", "run", "y", "c", "m", "server", "mcp",
}  # fmt: skip

_PRIVATE_DATA = {
    "filesystem", "files", "sqlite", "postgres", "postgresql", "mysql", "mongodb", "mongo", "redis",
    "gdrive", "drive", "notion", "obsidian", "1password", "onepassword", "vault", "secrets",
    "git", "github", "gitlab", "memory",
}  # fmt: skip
_EGRESS = {
    "fetch", "http", "browser", "puppeteer", "playwright", "slack", "email", "smtp", "gmail", "mail",
    "webhook", "discord", "telegram", "twitter", "sendgrid", "mailgun", "teams",
}  # fmt: skip
_UNTRUSTED_CONTENT = {
    "fetch", "browser", "puppeteer", "playwright", "web", "scrape", "scraper", "crawl", "firecrawl",
    "brave", "search", "rss", "email", "gmail", "mail", "slack", "discord", "telegram", "twitter",
    "github", "issues",
}  # fmt: skip
_EXEC = {
    "shell", "exec", "bash", "terminal", "sudo", "ssh", "docker", "kubectl", "powershell", "commander",
}  # fmt: skip

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
_MIN_SECRET_LEN = 8


def _tokens(server: MCPServer) -> set[str]:
    cmd = server.command.replace("\\", "/").split("/")[-1]
    raw = " ".join([server.name, cmd, *server.args]).lower()
    return {t for t in re.split(r"[^a-z0-9]+", raw) if t} - _LAUNCHERS


def _is_remote(server: MCPServer) -> bool:
    if server.transport == Transport.STDIO or not server.url:
        return False
    host = urlparse(server.url).hostname or ""
    return host not in _LOCAL_HOSTS


def _has_private_data(s: MCPServer) -> bool:
    return bool(_tokens(s) & _PRIVATE_DATA)


def _has_egress(s: MCPServer) -> bool:
    return bool(_tokens(s) & _EGRESS) or _is_remote(s)


def _has_untrusted_content(s: MCPServer) -> bool:
    return bool(_tokens(s) & _UNTRUSTED_CONTENT)


def _has_exec(s: MCPServer) -> bool:
    return bool(_tokens(s) & _EXEC)


def _label(servers: list[MCPServer]) -> str:
    return " + ".join(sorted({s.name for s in servers}))


def _normalize_name(name: str) -> str:
    return re.sub(r"[\s_\-.]+", "", name.lower())


def _within_one_edit(a: str, b: str) -> bool:
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return any(long_[:i] + long_[i + 1 :] == short for i in range(len(long_)))


def _xsv_001_exfiltration_path(group: list[MCPServer]) -> list[Finding]:
    """Private data, untrusted content and an outbound channel reachable by the same agent."""
    private = [s for s in group if _has_private_data(s)]
    egress = [s for s in group if _has_egress(s)]
    untrusted = [s for s in group if _has_untrusted_content(s)]
    findings: list[Finding] = []

    for p in private:
        out = [s for s in egress if s is not p]
        if not out:
            continue
        inbound = [s for s in untrusted if s is not p]
        trifecta = bool(inbound)
        involved = [p, *out, *[s for s in inbound if s not in out]]
        findings.append(
            Finding(
                rule_id="XSV-001",
                severity=Severity.HIGH if trifecta else Severity.MEDIUM,
                confidence=Confidence.LOW,
                server_name=_label(involved),
                message=(
                    f"Potential data exfiltration path: '{p.name}' can read private data and "
                    f"{_label(out)} can send data out"
                    + (
                        f"; {_label(inbound)} can ingest untrusted content (prompt-injection trigger)"
                        if trifecta
                        else ""
                    )
                ),
                evidence=(
                    f"private: {p.name}; egress: {_label(out)}; untrusted-content: "
                    f"{_label(inbound) if trifecta else 'none detected'}"
                ),
                remediation=(
                    "Split these servers into separate agent profiles, or require human approval for outbound "
                    "tool calls. Capabilities are inferred from server names and arguments, so confirm them "
                    "against the tools each server really exposes."
                ),
                source_file=p.source_file,
            )
        )
    return findings


def _xsv_002_injection_to_exec(group: list[MCPServer]) -> list[Finding]:
    """A server that reads untrusted content next to a server that can run commands."""
    findings: list[Finding] = []
    for ex in (s for s in group if _has_exec(s)):
        inbound = [s for s in group if s is not ex and _has_untrusted_content(s)]
        if not inbound:
            continue
        findings.append(
            Finding(
                rule_id="XSV-002",
                severity=Severity.HIGH,
                confidence=Confidence.LOW,
                server_name=_label([ex, *inbound]),
                message=(
                    f"Potential prompt-injection-to-command path: {_label(inbound)} can ingest untrusted content "
                    f"while '{ex.name}' can execute commands"
                ),
                evidence=f"untrusted-content: {_label(inbound)}; exec: {ex.name}",
                remediation=(
                    "Do not expose command execution in the same agent that reads web, mail or chat content. "
                    "Require explicit approval for every command."
                ),
                source_file=ex.source_file,
            )
        )
    return findings


def _xsv_003_shared_secret(group: list[MCPServer]) -> list[Finding]:
    """The same literal secret value is injected into several servers (values are never reported)."""
    by_value: dict[str, list[tuple[MCPServer, str]]] = defaultdict(list)
    for s in group:
        for key, value in s.env.items():
            v = str(value).strip()
            if len(v) >= _MIN_SECRET_LEN and not v.startswith("$"):
                by_value[v].append((s, key))

    findings: list[Finding] = []
    for entries in by_value.values():
        servers = {s.name for s, _ in entries}
        if len(servers) < 2:
            continue
        first = entries[0][0]
        names = ", ".join(sorted(f"{s.name}.{k}" for s, k in entries))
        findings.append(
            Finding(
                rule_id="XSV-003",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                server_name=_label([s for s, _ in entries]),
                message=f"The same credential value is shared by {len(servers)} servers; one compromise exposes all",
                evidence=f"shared by: {names} (value redacted)",
                remediation=(
                    "Issue a separate, least-privilege credential per server and reference it through the environment."
                ),
                source_file=first.source_file,
            )
        )
    return findings


def _xsv_004_name_shadowing(group: list[MCPServer]) -> list[Finding]:
    """Near-identical server names let a malicious server shadow a trusted one."""
    unique = {s.name: s for s in group}
    findings: list[Finding] = []
    for (n1, s1), (n2, s2) in combinations(sorted(unique.items()), 2):
        a, b = _normalize_name(n1), _normalize_name(n2)
        if len(a) < 5 or len(b) < 5 or not _within_one_edit(a, b):
            continue
        findings.append(
            Finding(
                rule_id="XSV-004",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                server_name=f"{n1} + {n2}",
                message=f"Server names '{n1}' and '{n2}' are nearly identical — possible tool shadowing or typosquat",
                evidence=f"normalized: '{a}' vs '{b}'",
                remediation="Rename one server and confirm that each one comes from a source you trust.",
                source_file=s1.source_file or s2.source_file,
            )
        )
    return findings


_CHECKS = (
    _xsv_001_exfiltration_path,
    _xsv_002_injection_to_exec,
    _xsv_003_shared_secret,
    _xsv_004_name_shadowing,
)


def check_cross_server(servers: list[MCPServer]) -> list[Finding]:
    """Group servers by config file (one file = one agent toolset) and run every cross-server check."""
    groups: dict[object, list[MCPServer]] = defaultdict(list)
    for s in servers:
        groups[s.source_file].append(s)

    findings: list[Finding] = []
    for group in groups.values():
        if len(group) < 2:
            continue
        for check in _CHECKS:
            findings.extend(check(group))
    return findings
