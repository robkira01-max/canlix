"""HTML scan report with print stylesheet.

Usage: open in a browser and use Ctrl+P / "Save as PDF" to export.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

_SEVERITY_COLOR = {
    "CRITICAL": "#c0392b",
    "HIGH": "#e67e22",
    "MEDIUM": "#f1c40f",
    "LOW": "#27ae60",
    "INFO": "#2980b9",
}

_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;color:#1a1a2e;
     background:#fff;padding:24px 32px;max-width:960px;margin:0 auto}
h1{font-size:1.6rem;margin-bottom:4px}
.subtitle{color:#555;font-size:.9rem;margin-bottom:24px}
.meta-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px 24px;margin-bottom:24px}
.meta-row{display:flex;gap:8px;font-size:.88rem}
.meta-label{color:#666;min-width:100px}
.score-bar{background:#e9ecef;border-radius:6px;height:18px;width:200px;overflow:hidden;display:inline-block;vertical-align:middle;margin-left:8px}
.score-fill{height:100%;background:var(--bar-color,#27ae60)}
.stat-row{display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap}
.stat{text-align:center;min-width:80px}
.stat-num{font-size:1.5rem;font-weight:700}
.stat-label{font-size:.75rem;color:#666;text-transform:uppercase;letter-spacing:.05em}
table{width:100%;border-collapse:collapse;font-size:.85rem;margin-bottom:24px}
th{background:#f4f6f8;padding:8px 10px;text-align:left;font-weight:600;border-bottom:2px solid #dee2e6}
td{padding:7px 10px;border-bottom:1px solid #eee;vertical-align:top}
tr:hover td{background:#fafafa}
.sev{display:inline-block;padding:2px 8px;border-radius:3px;color:#fff;
     font-size:.78rem;font-weight:700;white-space:nowrap}
.badge-new{background:#2980b9;color:#fff;padding:1px 6px;border-radius:3px;font-size:.75rem;margin-left:4px}
.section-title{font-size:1rem;font-weight:600;margin:20px 0 10px;
               border-left:4px solid #2980b9;padding-left:10px}
.diff-summary{background:#f8f9fa;border:1px solid #dee2e6;border-radius:6px;
              padding:12px 16px;margin-bottom:20px;font-size:.9rem}
footer{margin-top:32px;padding-top:12px;border-top:1px solid #dee2e6;font-size:.78rem;color:#888}
@media print{
  body{padding:0;max-width:100%}
  tr{page-break-inside:avoid}
  .no-print{display:none}
}
"""


def _sev_badge(sev: str) -> str:
    color = _SEVERITY_COLOR.get(sev, "#888")
    return f'<span class="sev" style="background:{color}">{html.escape(sev)}</span>'


def generate_scan_report(
    org_name: str,
    project_name: str,
    scan,
) -> str:
    """Return a self-contained HTML scan report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    created = getattr(scan, "created_at", None)
    scan_date = created.strftime("%Y-%m-%d %H:%M UTC") if created else now

    score = scan.score
    bar_color = "#27ae60" if score >= 80 else "#e67e22" if score >= 50 else "#c0392b"

    diff = scan.diff
    new_count = len(diff.new)
    fixed_count = len(diff.fixed)
    persisting_count = len(diff.persisting)

    # Severity counters
    sev_counts: dict[str, int] = {}
    for f in scan.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    new_fps = set(f.fingerprint for f in diff.new)

    # Build findings rows ordered by severity
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    def sev_key(f):
        return sev_order.index(f.severity) if f.severity in sev_order else 99

    sorted_findings = sorted(scan.findings, key=sev_key)

    rows = []
    for f in sorted_findings:
        badge = ' <span class="badge-new">NEW</span>' if f.fingerprint in new_fps else ""
        rows.append(
            f"<tr>"
            f"<td>{_sev_badge(f.severity)}{badge}</td>"
            f"<td>{html.escape(f.rule_id)}</td>"
            f"<td>{html.escape(f.location)}</td>"
            f"<td>{html.escape(f.message)}</td>"
            f"<td>{html.escape(f.remediation or '—')}</td>"
            f"</tr>"
        )

    _no_findings = "<tr><td colspan='5' style='text-align:center;color:#888'>No findings</td></tr>"
    findings_html = "\n".join(rows) if rows else _no_findings

    stat_rows = []
    for sev in sev_order:
        n = sev_counts.get(sev, 0)
        if n:
            color = _SEVERITY_COLOR.get(sev, "#888")
            stat_rows.append(
                f'<div class="stat"><div class="stat-num" style="color:{color}">{n}</div>'
                f'<div class="stat-label">{sev}</div></div>'
            )

    diff_line = (
        f"<b>Baseline scan</b> — all {len(scan.findings)} finding(s) are new."
        if diff.baseline
        else (
            f"<b>{new_count}</b> new &nbsp;·&nbsp; <b>{fixed_count}</b> fixed"
            f" &nbsp;·&nbsp; <b>{persisting_count}</b> persisting"
        )
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Canlix Security Report — {html.escape(project_name)}</title>
<style>{_CSS}</style>
</head>
<body>
<h1>Canlix Security Report</h1>
<div class="subtitle">{html.escape(org_name)} &rsaquo; {html.escape(project_name)}</div>

<div class="meta-grid">
  <div class="meta-row"><span class="meta-label">Scan ID</span><span>{html.escape(scan.id)}</span></div>
  <div class="meta-row"><span class="meta-label">Scan date</span><span>{scan_date}</span></div>
  <div class="meta-row"><span class="meta-label">Score</span>
    <span>{score}/100
      <span class="score-bar"><span class="score-fill" style="width:{score}%;--bar-color:{bar_color}"></span></span>
    </span>
  </div>
  <div class="meta-row"><span class="meta-label">Total findings</span><span>{len(scan.findings)}</span></div>
</div>

<div class="diff-summary">{diff_line}</div>

<div class="stat-row">{"".join(stat_rows) or '<span style="color:#888">No findings detected</span>'}</div>

<div class="section-title">Findings</div>
<table>
<thead><tr>
  <th>Severity</th><th>Rule</th><th>Location</th><th>Message</th><th>Remediation</th>
</tr></thead>
<tbody>{findings_html}</tbody>
</table>

<footer>
  Generated {now} by <strong>Canlix</strong> — open-source MCP/agent security scanner.
  <span class="no-print"> &nbsp;·&nbsp; <a href="javascript:window.print()">Print / Save as PDF</a></span>
</footer>
</body>
</html>"""
