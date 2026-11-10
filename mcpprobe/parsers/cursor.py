"""
Parses MCP server configurations from Cursor editor settings.
Locations checked:
  ~/.cursor/mcp.json         — global
  .cursor/mcp.json           — project-level
"""

from __future__ import annotations

import json
from pathlib import Path

from mcpprobe.models import MCPServer
from mcpprobe.parsers.claude import _parse_servers


def parse_cursor(extra_paths: list[Path] | None = None) -> list[MCPServer]:
    candidates: list[Path] = [
        Path.home() / ".cursor" / "mcp.json",
        Path.cwd() / ".cursor" / "mcp.json",
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
