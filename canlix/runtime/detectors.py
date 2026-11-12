"""Stateful detectors RUN-001..007 that consume MCP JSON-RPC messages one at a time."""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import re
from collections import deque
from typing import Any
from urllib.parse import urlparse

from canlix.models import Confidence, Finding, Severity
from canlix.probes.metadata import _INJECTION_RE
from canlix.runtime.redact import iter_strings, secret_kinds

C2S = "c2s"
S2C = "s2c"

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_SENSITIVE_PATH_RE = re.compile(
    r"(?:^|[\\/])(?:\.ssh[\\/]|id_rsa|id_ed25519|\.aws[\\/]credentials|\.kube[\\/]config|\.netrc|\.npmrc"
    r"|\.git-credentials|\.env(?:\.[\w-]+)?(?:$|[\s\"']))|/etc/(?:shadow|passwd|sudoers)\b",
    re.IGNORECASE,
)
_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "fd00:ec2::254"}


def _hosts_in(text: str) -> list[str]:
    hosts = []
    for url in _URL_RE.findall(text):
        host = urlparse(url).hostname
        if host:
            hosts.append(host.lower())
    return hosts


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (ip.is_private or ip.is_link_local) and not ip.is_loopback


class RuntimeAnalyzer:
    """Feed every observed message to observe(); it returns the new findings it produced."""

    def __init__(
        self,
        server_name: str = "server",
        *,
        allow_hosts: tuple[str, ...] | list[str] = (),
        rate_limit: int = 30,
        rate_window: float = 10.0,
    ) -> None:
        self.server_name = server_name
        self.allow_hosts = tuple(h.lower() for h in allow_hosts)
        self.rate_limit = rate_limit
        self.rate_window = rate_window
        self.findings: list[Finding] = []
        self.hosts_seen: set[str] = set()
        self.tool_calls = 0
        self._pending: dict[Any, tuple[str, str]] = {}
        self._tools_hash: str | None = None
        self._call_times: deque[float] = deque()
        self._dedupe: set[tuple[str, str]] = set()

    def observe(self, direction: str, message: Any, ts: float) -> list[Finding]:
        if not isinstance(message, dict):
            return []
        new: list[Finding] = []
        if direction == C2S:
            new += self._on_request(message, ts)
        elif direction == S2C:
            new += self._on_response(message)
        return [f for f in new if self._remember(f)]

    def _remember(self, f: Finding) -> bool:
        key = (f.rule_id, f.evidence)
        if key in self._dedupe:
            return False
        self._dedupe.add(key)
        self.findings.append(f)
        return True

    def _finding(self, rule_id: str, sev: Severity, conf: Confidence, message: str, evidence: str, fix: str) -> Finding:
        return Finding(
            rule_id=rule_id,
            severity=sev,
            confidence=conf,
            server_name=self.server_name,
            message=message,
            evidence=evidence,
            remediation=fix,
        )

    def _on_request(self, msg: dict, ts: float) -> list[Finding]:
        method = msg.get("method")
        if not isinstance(method, str):
            return []
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        tool = str(params.get("name", "")) if method == "tools/call" else ""
        if "id" in msg:
            self._pending[msg["id"]] = (method, tool)
        if method != "tools/call":
            return []

        self.tool_calls += 1
        out = self._check_rate(ts, tool)
        args = params.get("arguments", {})
        for text in iter_strings(args):
            out += self._check_text_in_args(text, tool)
        return out

    def _check_rate(self, ts: float, tool: str) -> list[Finding]:
        self._call_times.append(ts)
        while self._call_times and ts - self._call_times[0] > self.rate_window:
            self._call_times.popleft()
        if len(self._call_times) <= self.rate_limit:
            return []
        bucket = int(ts // self.rate_window)
        return [
            self._finding(
                "RUN-006",
                Severity.MEDIUM,
                Confidence.MEDIUM,
                f"{len(self._call_times)} tool calls in {self.rate_window:g}s (limit {self.rate_limit}): "
                "possible loop or runaway agent",
                f"window={bucket}",
                "Add a per-session call budget and require confirmation for repeated calls.",
            )
        ]

    def _check_text_in_args(self, text: str, tool: str) -> list[Finding]:
        out: list[Finding] = []
        kinds = secret_kinds(text)
        if kinds:
            out.append(
                self._finding(
                    "RUN-001",
                    Severity.HIGH,
                    Confidence.HIGH,
                    f"Tool call '{tool}' sends a secret to the server ({', '.join(kinds)})",
                    f"tool={tool}; kinds={','.join(kinds)} (value redacted)",
                    "Never place credentials in tool arguments. Let the server read them from its own environment.",
                )
            )
        sensitive = _SENSITIVE_PATH_RE.search(text)
        if sensitive:
            matched = sensitive.group().strip(" \"'")
            out.append(
                self._finding(
                    "RUN-007",
                    Severity.HIGH,
                    Confidence.MEDIUM,
                    f"Tool call '{tool}' targets a sensitive path (credentials, keys or system files)",
                    f"tool={tool}; matched='{matched}'",
                    "Restrict the server to a project directory and deny access to credential files.",
                )
            )
        out += self._check_hosts(text, tool)
        return out

    def _check_hosts(self, text: str, tool: str) -> list[Finding]:
        out: list[Finding] = []
        for host in _hosts_in(text):
            self.hosts_seen.add(host)
            if _is_loopback(host):
                continue
            if host in _METADATA_HOSTS:
                out.append(
                    self._finding(
                        "RUN-003",
                        Severity.HIGH,
                        Confidence.HIGH,
                        f"Tool call '{tool}' targets the cloud metadata endpoint {host} (SSRF attempt)",
                        f"tool={tool}; host={host}",
                        "Block link-local and metadata addresses at the network layer and validate URLs in the server.",
                    )
                )
            elif _is_private(host):
                out.append(
                    self._finding(
                        "RUN-003",
                        Severity.MEDIUM,
                        Confidence.MEDIUM,
                        f"Tool call '{tool}' targets internal address {host} (possible SSRF)",
                        f"tool={tool}; host={host}",
                        "Validate destination URLs against an allowlist and reject private ranges.",
                    )
                )
            elif self.allow_hosts and not any(fnmatch.fnmatch(host, p) for p in self.allow_hosts):
                out.append(
                    self._finding(
                        "RUN-002",
                        Severity.HIGH,
                        Confidence.HIGH,
                        f"Tool call '{tool}' contacts {host}, which is not in the allowed host list",
                        f"tool={tool}; host={host}",
                        "Add the host to --allow-host if expected, otherwise investigate possible data exfiltration.",
                    )
                )
        return out

    def _on_response(self, msg: dict) -> list[Finding]:
        out: list[Finding] = []
        if msg.get("method") == "notifications/tools/list_changed":
            out.append(
                self._finding(
                    "RUN-005",
                    Severity.MEDIUM,
                    Confidence.MEDIUM,
                    "Server announced that its tool list changed during the session",
                    "notification=tools/list_changed",
                    "Re-review the new tools before use; a changing tool list is a rug-pull signal.",
                )
            )
        if "id" not in msg or "result" not in msg:
            return out
        method, tool = self._pending.pop(msg["id"], ("", ""))
        result = msg["result"]
        if method == "tools/list" and isinstance(result, dict):
            out += self._check_tool_list(result)
        elif method == "tools/call":
            out += self._check_tool_result(result, tool)
        return out

    def _check_tool_list(self, result: dict) -> list[Finding]:
        tools = result.get("tools", [])
        digest = hashlib.sha256(json.dumps(tools, sort_keys=True).encode()).hexdigest()
        out: list[Finding] = []
        if self._tools_hash is not None and digest != self._tools_hash:
            out.append(
                self._finding(
                    "RUN-005",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "Tool definitions changed since the first tools/list of this session (possible rug pull)",
                    f"before={self._tools_hash[:12]}; after={digest[:12]}",
                    "Pin and review tool definitions; treat a server that rewrites its tools as untrusted.",
                )
            )
        self._tools_hash = digest
        for tool in tools if isinstance(tools, list) else []:
            desc = str(tool.get("description", "")) if isinstance(tool, dict) else ""
            m = _INJECTION_RE.search(desc)
            if m:
                out.append(self._injection(f"description of '{tool.get('name', '?')}'", m.group()))
        return out

    def _check_tool_result(self, result: Any, tool: str) -> list[Finding]:
        out: list[Finding] = []
        for text in iter_strings(result):
            m = _INJECTION_RE.search(text)
            if m:
                out.append(self._injection(f"result of '{tool}'", m.group()))
            kinds = secret_kinds(text)
            if kinds:
                out.append(
                    self._finding(
                        "RUN-001",
                        Severity.MEDIUM,
                        Confidence.HIGH,
                        f"Result of '{tool}' contains a secret ({', '.join(kinds)})",
                        f"tool={tool}; result kinds={','.join(kinds)} (value redacted)",
                        "Filter credentials from tool output before it reaches the model.",
                    )
                )
        return out

    def _injection(self, where: str, matched: str) -> Finding:
        return self._finding(
            "RUN-004",
            Severity.HIGH,
            Confidence.MEDIUM,
            f"Prompt-injection pattern in {where}: '{matched}'",
            f"{where}; pattern='{matched}'",
            "Treat this content as untrusted; do not let it steer the agent. Review the server before further use.",
        )
