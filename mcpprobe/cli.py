"""MCPProbe CLI — mcpprobe scan"""
from __future__ import annotations
from pathlib import Path
from typing import Optional
import typer
from rich import print as rprint

app = typer.Typer(
    name="mcpprobe",
    help="Open-source security scanner for MCP servers and AI agents.",
    add_completion=False,
)


@app.command()
def scan(
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to a JSON MCP config file (auto-detects Claude Code if omitted)."
    ),
    output: str = typer.Option(
        "terminal", "--output", "-o", help="Output format: terminal | json"
    ),
    fail_on: str = typer.Option(
        "CRITICAL", "--fail-on", help="Exit with code 1 if any finding meets or exceeds this severity (CRITICAL|HIGH|MEDIUM|LOW)."
    ),
) -> None:
    """Scan MCP server configurations for security issues."""
    from mcpprobe.parsers import parse_claude, parse_json_file
    from mcpprobe.engine import scan as run_scan
    from mcpprobe.reporters import render_terminal, render_json

    if config:
        if not config.exists():
            rprint(f"[red]Error:[/red] File not found: {config}")
            raise typer.Exit(2)
        servers = parse_json_file(config)
    else:
        servers = parse_claude()

    if not servers:
        rprint("[yellow]No MCP servers found. Nothing to scan.[/yellow]")
        rprint("[dim]Tip: Claude Code config is read from ~/.claude.json and .claude/settings.json[/dim]")
        raise typer.Exit(0)

    result = run_scan(servers)

    if output == "json":
        print(render_json(result))
    else:
        render_terminal(result)

    # Exit code for CI/CD
    severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    threshold = fail_on.upper()
    if threshold in severity_order:
        threshold_idx = severity_order.index(threshold)
        for f in result.findings:
            if severity_order.index(f.severity.value) >= threshold_idx:
                raise typer.Exit(1)


@app.command()
def version() -> None:
    """Print MCPProbe version."""
    from mcpprobe import __version__
    rprint(f"MCPProbe v{__version__}")


if __name__ == "__main__":
    app()
