"""Parse a standalone JSON/YAML MCP config file passed via --config."""

from __future__ import annotations

import json
from pathlib import Path

from canlix.models import MCPServer
from canlix.parsers.claude import _parse_servers


def parse_json_file(path: Path) -> list[MCPServer]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return _parse_servers(data, path)
