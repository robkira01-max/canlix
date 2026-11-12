"""
Parses MCP server configurations from Claude Code settings files.
Locations checked (in order):
  ~/.claude.json              — global user config
  .claude/settings.json       — project-level
  .claude/settings.local.json — local overrides (gitignored)
"""

from __future__ import annotations

import json
from pathlib import Path

from mcpprobe.models import MCPServer, Transport


def _transport(raw: str) -> Transport:
    t = raw.lower()
    if t in ("http", "streamable-http", "streamablehttp"):
        return Transport.HTTP
    if t == "sse":
        return Transport.SSE
    return Transport.STDIO


def _parse_servers(data: dict, source: Path) -> list[MCPServer]:
    servers = []
    raw_map = data.get("mcpServers") or data.get("mcp_servers") or {}
    for name, cfg in raw_map.items():
        if not isinstance(cfg, dict):
            continue
        servers.append(
            MCPServer(
                name=name,
                transport=_transport(cfg.get("type", "stdio")),
                command=cfg.get("command", ""),
                args=cfg.get("args", []),
                env=cfg.get("env", {}),
                url=cfg.get("url", ""),
                source_file=source,
            )
        )
    return servers


def parse_claude(extra_paths: list[Path] | None = None) -> list[MCPServer]:
    """Return all MCP servers from Claude Code config files."""
    candidates: list[Path] = [
        Path.home() / ".claude.json",
        Path.cwd() / ".claude" / "settings.json",
        Path.cwd() / ".claude" / "settings.local.json",
    ]
    if extra_paths:
        candidates.extend(extra_paths)

    servers: list[MCPServer] = []
    seen: set[str] = set()

    for path in candidates:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for s in _parse_servers(data, path):
            key = f"{s.name}:{s.command}:{s.url}"
            if key not in seen:
                seen.add(key)
                servers.append(s)

    return servers
