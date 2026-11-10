"""Rich terminal reporter."""
from __future__ import annotations
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from mcpprobe.models import ScanResult, Severity

console = Console()


def _score_color(score: int) -> str:
    if score >= 80:
        return "bold green"
    if score >= 50:
        return "yellow"
    return "bold red"


def render_terminal(result: ScanResult) -> None:
    # Header
    console.print()
    console.print(Panel(
        f"[bold]MCPProbe[/bold]  ·  {len(result.servers)} server(s) scanned  ·  "
        f"{len(result.findings)} finding(s)  ·  "
        f"[{_score_color(result.score)}]Score {result.score}/100[/{_score_color(result.score)}]  ·  "
        f"{result.scan_duration_ms:.0f} ms",
        border_style="blue",
    ))

    if not result.findings:
        console.print("[bold green]✓  No issues found.[/bold green]\n")
        return

    # Group by severity
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
        table.add_column("Confidence", width=10)

        for f in group:
            table.add_row(
                f.rule_id,
                f.server_name,
                f.message,
                f"[dim]{f.confidence.value}[/dim]",
            )
        console.print(table)

    # Detailed findings
    console.print("\n[bold]Details & Remediations[/bold]\n")
    for f in result.findings:
        console.print(
            f"  [{f.severity.color}][{f.rule_id}][/{f.severity.color}] "
            f"[bold]{f.server_name}[/bold] — {f.message}"
        )
        console.print(f"    [dim]Evidence:[/dim] {f.evidence}")
        console.print(f"    [dim]Fix:[/dim]      {f.remediation}")
        if f.source_file:
            console.print(f"    [dim]Source:[/dim]   {f.source_file}")
        console.print()
