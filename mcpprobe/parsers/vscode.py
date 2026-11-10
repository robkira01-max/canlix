"""
Parses MCP server configurations from VS Code / GitHub Copilot settings.
Locations checked:
  ~/.config/Code/User/settings.json        — Linux global
  ~/Library/Application Support/Code/User/settings.json  — macOS global
  .vscode/mcp.json                         — project-level (official spec)
  .vscode/settings.json                    — project settings with mcp key
"""

from __future__ import annotations

import json
from pathlib import Path

from mcpprobe.models import MCPServer
from mcpprobe.parsers.claude import _parse_servers


def _vscode_global_paths() -> list[Path]:
    return [
        Path.home() / ".config" / "Code" / "User" / "settings.json",
        Path.home() / "Library" / "Application Support" / "Code" / "User" / "settings.json",
        Path.home() / "AppData" / "Roaming" / "Code" / "User" / "settings.json",
    ]


def parse_vscode(extra_paths: list[Path] | None = None) -> list[MCPServer]:
    candidates: list[Path] = _vscode_global_paths() + [
        Path.cwd() / ".vscode" / "mcp.json",
        Path.cwd() / ".vscode" / "settings.json",
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
        # VS Code wraps under "mcp" key in settings.json
        if "mcp" in data and isinstance(data["mcp"], dict):
            data = data["mcp"]
        for s in _parse_servers(data, path):
            key = f"{s.name}:{s.command}:{s.url}"
            if key not in seen:
                seen.add(key)
                servers.append(s)

    return servers
