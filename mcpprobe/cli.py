"""MCPProbe CLI — mcpprobe scan / analyze"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint

app = typer.Typer(
    name="mcpprobe",
    help="Open-source security scanner for MCP servers and AI agents.",
    add_completion=False,
)

_SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _exit_on_severity(findings, source_findings, fail_on: str) -> None:
    threshold = fail_on.upper()
    if threshold not in _SEVERITY_ORDER:
        return
    idx = _SEVERITY_ORDER.index(threshold)
    all_findings = list(findings) + list(source_findings)
    for f in all_findings:
        if _SEVERITY_ORDER.index(f.severity.value) >= idx:
            raise typer.Exit(1)


@app.command()
def scan(
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to a JSON MCP config file (auto-detects Claude Code if omitted)."
    ),
    output: str = typer.Option("terminal", "--output", "-o", help="Output format: terminal | json"),
    fail_on: str = typer.Option(
        "CRITICAL", "--fail-on", help="Exit with code 1 if any finding meets or exceeds this severity."
    ),
    no_source: bool = typer.Option(False, "--no-source", help="Disable automatic source code analysis."),
) -> None:
    """Scan MCP server configurations (and detected source files) for security issues."""
    from mcpprobe.engine import scan as run_scan
    from mcpprobe.parsers import parse_all, parse_json_file
    from mcpprobe.reporters import render_json, render_terminal

    if config:
        if not config.exists():
            rprint(f"[red]Error:[/red] File not found: {config}")
            raise typer.Exit(2)
        servers = parse_json_file(config)
    else:
        servers = parse_all()

    if not servers:
        rprint("[yellow]No MCP servers found. Nothing to scan.[/yellow]")
        rprint("[dim]Tip: Claude Code config is read from ~/.claude.json and .claude/settings.json[/dim]")
        raise typer.Exit(0)

    result = run_scan(servers, analyze_source=not no_source)

    if output == "json":
        print(render_json(result))
    else:
        render_terminal(result)

    _exit_on_severity(result.findings, result.source_findings, fail_on)


@app.command()
def analyze(
    path: Path = typer.Argument(..., help="File or directory to analyze for security issues."),
    output: str = typer.Option("terminal", "--output", "-o", help="Output format: terminal | json"),
    fail_on: str = typer.Option(
        "CRITICAL", "--fail-on", help="Exit with code 1 if any finding meets or exceeds this severity."
    ),
) -> None:
    """Analyze MCP server source code (Python/TypeScript) for security issues."""
    from mcpprobe.analyzers import analyze_path
    from mcpprobe.reporters import render_source_json, render_source_only

    if not path.exists():
        rprint(f"[red]Error:[/red] Path not found: {path}")
        raise typer.Exit(2)

    t0 = time.monotonic()
    findings = analyze_path(path)
    duration_ms = (time.monotonic() - t0) * 1000

    if output == "json":
        from mcpprobe.reporters.json_report import render_source_json

        print(render_source_json(findings, path, duration_ms))
    else:
        render_source_only(findings, str(path), duration_ms)

    _exit_on_severity(findings, [], fail_on)


@app.command()
def version() -> None:
    """Print MCPProbe version."""
    from mcpprobe import __version__

    rprint(f"MCPProbe v{__version__}")


if __name__ == "__main__":
    app()
