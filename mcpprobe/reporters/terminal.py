"""Rich terminal reporter."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcpprobe.models import ScanResult, Severity, SourceFinding

console = Console()


def _score_color(score: int) -> str:
    if score >= 80:
        return "bold green"
    if score >= 50:
        return "yellow"
    return "bold red"


def render_terminal(result: ScanResult) -> None:
    total = len(result.findings) + len(result.source_findings)
    console.print()
    console.print(
        Panel(
            f"[bold]MCPProbe[/bold]  ·  {len(result.servers)} server(s) scanned  ·  "
            f"{total} finding(s)  ·  "
            f"[{_score_color(result.score)}]Score {result.score}/100[/{_score_color(result.score)}]  ·  "
            f"{result.scan_duration_ms:.0f} ms",
            border_style="blue",
        )
    )

    if not result.findings and not result.source_findings:
        console.print("[bold green]✓  No issues found.[/bold green]\n")
        return

    if result.findings:
        _render_config_findings(result)

    if result.source_findings:
        _render_source_findings(result.source_findings)


def _render_config_findings(result: ScanResult) -> None:
    by_sev = result.findings_by_severity()
    for sev in Severity:
        group = by_sev[sev]
        if not group:
            continue
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style=sev.color,
            title=f"[{sev.color}]{sev.value}[/{sev.color}] ({len(group)})",
            title_justify="left",
        )
        table.add_column("Rule", style="bold", width=10)
        table.add_column("Server", width=18)
        table.add_column("Message")
        table.add_column("Conf.", width=8)
        for f in group:
            table.add_row(f.rule_id, f.server_name, f.message, f"[dim]{f.confidence.value}[/dim]")
        console.print(table)

    console.print("\n[bold]Config Findings — Details & Remediations[/bold]\n")
    for f in result.findings:
        console.print(
            f"  [{f.severity.color}][{f.rule_id}][/{f.severity.color}] [bold]{f.server_name}[/bold] — {f.message}"
        )
        console.print(f"    [dim]Evidence:[/dim] {f.evidence}")
        console.print(f"    [dim]Fix:[/dim]      {f.remediation}")
        if f.source_file:
            console.print(f"    [dim]Source:[/dim]   {f.source_file}")
        console.print()


def _render_source_findings(findings: list[SourceFinding]) -> None:
    console.print("[bold]Source Analysis Findings[/bold]\n")

    # Group by file
    by_file: dict[str, list[SourceFinding]] = {}
    for sf in findings:
        key = str(sf.file_path)
        by_file.setdefault(key, []).append(sf)

    for file_path, file_findings in sorted(by_file.items()):
        console.print(f"  [bold cyan]{file_path}[/bold cyan]")
        for sf in sorted(file_findings, key=lambda x: x.line_number):
            console.print(
                f"    [{sf.severity.color}][{sf.rule_id}][/{sf.severity.color}] line {sf.line_number}: {sf.message}"
            )
            if sf.code_snippet:
                console.print(f"      [dim]{sf.code_snippet}[/dim]")
            console.print(f"      [dim]Fix:[/dim] {sf.remediation}")
        console.print()


def render_source_only(findings: list[SourceFinding], path: str, duration_ms: float) -> None:
    """Standalone renderer for the `analyze` command."""
    console.print()
    score = max(0, 100 - sum(f.severity.score for f in findings))
    console.print(
        Panel(
            f"[bold]MCPProbe analyze[/bold]  ·  {path}  ·  "
            f"{len(findings)} finding(s)  ·  "
            f"[{_score_color(score)}]Score {score}/100[/{_score_color(score)}]  ·  "
            f"{duration_ms:.0f} ms",
            border_style="blue",
        )
    )
    if not findings:
        console.print("[bold green]✓  No issues found.[/bold green]\n")
        return
    _render_source_findings(findings)
