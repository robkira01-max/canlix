from mcpprobe.parsers.claude import parse_claude
from mcpprobe.parsers.cursor import parse_cursor
from mcpprobe.parsers.generic import parse_json_file
from mcpprobe.parsers.vscode import parse_vscode


def parse_all() -> list:
    """Auto-discover MCP servers from all supported editors."""
    seen: set[str] = set()
    servers = []
    for s in parse_claude() + parse_cursor() + parse_vscode():
        key = f"{s.name}:{s.command}:{s.url}"
        if key not in seen:
            seen.add(key)
            servers.append(s)
    return servers


__all__ = ["parse_all", "parse_claude", "parse_cursor", "parse_vscode", "parse_json_file"]
