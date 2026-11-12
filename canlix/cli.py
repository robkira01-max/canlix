"""Canlix CLI — canlix scan / analyze / probe"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint

app = typer.Typer(
    name="canlix",
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
    output: str = typer.Option("terminal", "--output", "-o", help="Output format: terminal | json | sarif"),
    fail_on: str = typer.Option(
        "CRITICAL", "--fail-on", help="Exit with code 1 if any finding meets or exceeds this severity."
    ),
    no_source: bool = typer.Option(False, "--no-source", help="Disable automatic source code analysis."),
) -> None:
    """Scan MCP server configurations (and detected source files) for security issues."""
    from canlix.engine import scan as run_scan
    from canlix.parsers import parse_all, parse_json_file
    from canlix.reporters import render_json, render_scan_sarif, render_terminal

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
    elif output == "sarif":
        print(render_scan_sarif(result))
    else:
        render_terminal(result)

    _exit_on_severity(result.findings, result.source_findings, fail_on)


@app.command()
def analyze(
    path: Path = typer.Argument(..., help="File or directory to analyze for security issues."),
    output: str = typer.Option("terminal", "--output", "-o", help="Output format: terminal | json | sarif"),
    fail_on: str = typer.Option(
        "CRITICAL", "--fail-on", help="Exit with code 1 if any finding meets or exceeds this severity."
    ),
) -> None:
    """Analyze MCP server source code (Python/TypeScript) for security issues."""
    from canlix.analyzers import analyze_path
    from canlix.reporters import render_analyze_sarif, render_source_json, render_source_only

    if not path.exists():
        rprint(f"[red]Error:[/red] Path not found: {path}")
        raise typer.Exit(2)

    t0 = time.monotonic()
    findings = analyze_path(path)
    duration_ms = (time.monotonic() - t0) * 1000

    if output == "json":
        from canlix.reporters.json_report import render_source_json

        print(render_source_json(findings, path, duration_ms))
    elif output == "sarif":
        print(render_analyze_sarif(findings))
    else:
        render_source_only(findings, str(path), duration_ms)

    _exit_on_severity(findings, [], fail_on)


@app.command()
def probe(
    target: str = typer.Argument(
        ...,
        help="Server URL (https://…) or server name from an MCP config file.",
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to a JSON MCP config file (auto-detects Claude Code if omitted)."
    ),
    output: str = typer.Option("terminal", "--output", "-o", help="Output format: terminal | json | sarif"),
    active: bool = typer.Option(
        False,
        "--active",
        help="Enable active probes (sends real tool calls). Use ONLY on servers you own or have permission to test.",
    ),
    fail_on: str = typer.Option(
        "CRITICAL", "--fail-on", help="Exit with code 1 if any finding meets or exceeds this severity."
    ),
    timeout: float = typer.Option(5.0, "--timeout", help="Connection timeout in seconds."),
) -> None:
    """Probe a live MCP server for runtime security issues."""
    from canlix.models import Transport
    from canlix.probes.runner import probe_server
    from canlix.probes.transport import HttpMCPClient, StdioMCPClient
    from canlix.reporters import render_probe_json, render_probe_sarif, render_probe_session

    if target.startswith("http://") or target.startswith("https://"):
        client: HttpMCPClient | StdioMCPClient = HttpMCPClient(target, timeout=timeout)
        server_name = target.rsplit("/", 1)[-1] or target
        server_url = target
    else:
        from canlix.parsers import parse_all, parse_json_file

        servers = parse_json_file(config) if config else parse_all()
        server = next((s for s in servers if s.name == target), None)
        if not server:
            rprint(
                f"[red]Error:[/red] Server {target!r} not found in config. "
                "Pass a URL (https://…) or a server name that appears in the config."
            )
            raise typer.Exit(2)

        if server.transport in (Transport.HTTP, Transport.SSE) or server.url:
            client = HttpMCPClient(server.url, timeout=timeout)
            server_url = server.url
        else:
            client = StdioMCPClient(server.command, server.args, timeout=timeout)
            server_url = f"stdio://{server.command}"

        server_name = server.name

    if active:
        rprint("[yellow]⚠  --active mode: real tool calls will be sent to the server.[/yellow]")

    session = probe_server(client, server_name, server_url, active=active)

    if output == "json":
        print(render_probe_json(session))
    elif output == "sarif":
        print(render_probe_sarif(session))
    else:
        render_probe_session(session)

    _exit_on_severity(session.findings, [], fail_on)


@app.command()
def watch(
    command: list[str] = typer.Argument(..., help="MCP server command to run behind the proxy (after --)."),
    trace: Optional[Path] = typer.Option(None, "--trace", help="Append a redacted JSONL trace to this file."),
    allow_host: list[str] = typer.Option(
        [], "--allow-host", help="Allowed destination host (wildcards ok). Repeat. Others raise RUN-002."
    ),
    kill_on: Optional[str] = typer.Option(
        None, "--kill-on", help="Emergency stop: terminate the server at this severity or above (exit code 3)."
    ),
    fail_on: str = typer.Option("CRITICAL", "--fail-on", help="Exit 1 if a finding meets this severity."),
    name: Optional[str] = typer.Option(None, "--name", help="Server label used in findings."),
    rate_limit: int = typer.Option(30, "--rate-limit", help="Max tool calls per 10 s before RUN-006."),
) -> None:
    """Run an MCP server behind an observing proxy (stdio). Never modifies traffic; diagnostics go to stderr."""
    from canlix.runtime import RuntimeAnalyzer, run_proxy

    label = name or Path(command[0]).name
    analyzer = RuntimeAnalyzer(label, allow_hosts=allow_host, rate_limit=rate_limit)
    code = run_proxy(command, analyzer, trace_path=trace, kill_on=kill_on)
    if code != 0:
        raise typer.Exit(code)
    _exit_on_severity(analyzer.findings, [], fail_on)


@app.command()
def replay(
    trace: Path = typer.Argument(..., help="JSONL trace recorded by `canlix watch --trace`."),
    output: str = typer.Option("terminal", "--output", "-o", help="Output format: terminal | json"),
    allow_host: list[str] = typer.Option([], "--allow-host", help="Allowed destination host (wildcards ok)."),
    fail_on: str = typer.Option("CRITICAL", "--fail-on", help="Exit 1 if a finding meets this severity."),
) -> None:
    """Re-run the runtime detectors over a recorded trace (for CI or after tuning the allowlist)."""
    import json

    from canlix.runtime import RuntimeAnalyzer
    from canlix.runtime.proxy import finding_to_dict

    if not trace.is_file():
        rprint(f"[red]Trace not found:[/red] {trace}")
        raise typer.Exit(2)

    analyzer = RuntimeAnalyzer(trace.stem, allow_hosts=allow_host)
    for raw in trace.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if isinstance(rec, dict) and "dir" in rec and "msg" in rec:
            analyzer.observe(rec["dir"], rec["msg"], float(rec.get("ts", 0.0)))

    if output == "json":
        typer.echo(json.dumps([finding_to_dict(f) for f in analyzer.findings], indent=2))
    else:
        for f in analyzer.findings:
            typer.echo(f"{f.severity.value:8} {f.rule_id}  {f.message}")
        typer.echo(f"{len(analyzer.findings)} finding(s), {analyzer.tool_calls} tool call(s) replayed")

    _exit_on_severity(analyzer.findings, [], fail_on)


@app.command()
def push(
    file: Optional[Path] = typer.Argument(None, help="JSON report file; reads stdin if omitted."),
    url: Optional[str] = typer.Option(None, "--url", envvar="CANLIX_API_URL", help="SaaS base URL."),
    token: Optional[str] = typer.Option(None, "--token", envvar="CANLIX_API_TOKEN", help="API token (cnx_...)."),
    project: Optional[str] = typer.Option(None, "--project", envvar="CANLIX_PROJECT", help="Project ID (32-char hex)."),
    no_strip: bool = typer.Option(False, "--no-strip", help="Send raw report without client-side stripping."),
) -> None:
    """Push a scan report (JSON) to the Canlix SaaS and show the diff."""
    import json as _json
    import sys

    from canlix.saas_client import push_scan, strip_report

    if not token:
        rprint("[red]Error:[/red] Set CANLIX_API_TOKEN or pass --token")
        raise typer.Exit(1)
    if not project:
        rprint("[red]Error:[/red] Set CANLIX_PROJECT or pass --project")
        raise typer.Exit(1)

    base_url = url or "https://api.canlix.dev"

    if file is not None:
        try:
            raw = file.read_text(encoding="utf-8")
        except OSError as exc:
            rprint(f"[red]Error:[/red] Cannot read {file}: {exc}")
            raise typer.Exit(1)
    else:
        raw = sys.stdin.read()

    try:
        payload = _json.loads(raw)
    except _json.JSONDecodeError as exc:
        rprint(f"[red]Error:[/red] Invalid JSON — {exc}")
        raise typer.Exit(1)

    if not no_strip:
        payload = strip_report(payload)

    try:
        result = push_scan(base_url, token, project, payload)
    except ValueError as exc:
        rprint(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)
    except Exception as exc:
        rprint(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    scan_id = result["scan_id"]
    score = result["score"]
    diff = result["diff"]

    rprint(f"[green]✓[/green] Scan submitted  [dim]{scan_id}  {result['created_at']}[/dim]")
    rprint(f"  Score      : [bold]{score}/100[/bold]")
    if diff["baseline"]:
        rprint("  Baseline   : [bold]yes[/bold] [dim](first scan — no prior diff)[/dim]")
    else:
        new_str = f"[red]{diff['new']}[/red]" if diff["new"] > 0 else str(diff["new"])
        fix_str = f"[green]{diff['fixed']}[/green]" if diff["fixed"] > 0 else str(diff["fixed"])
        rprint(f"  New        : {new_str}")
        rprint(f"  Fixed      : {fix_str}")
        rprint(f"  Persisting : {diff['persisting']}")


@app.command()
def version() -> None:
    """Print Canlix version."""
    from canlix import __version__

    rprint(f"Canlix v{__version__}")


if __name__ == "__main__":
    app()
