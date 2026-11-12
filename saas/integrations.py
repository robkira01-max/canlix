"""Outbound alert integrations: Slack, PagerDuty, Jira.

Dispatch runs in a daemon thread so it never blocks the HTTP response.
Webhook URLs and credentials stored in Integration.config are treated
as secrets: never logged, never echoed in API responses.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

INTEGRATION_TYPES = frozenset({"slack", "pagerduty", "jira"})

# Severity levels that trigger alerts (new findings only)
_ALERT_SEVERITIES = frozenset({"CRITICAL", "HIGH"})

# Hard timeout for outbound webhook calls
_TIMEOUT = 8.0


@dataclass
class Integration:
    id: str
    org_id: str
    type: str  # "slack" | "pagerduty" | "jira"
    name: str
    config: dict[str, Any]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Dispatch helpers
# ---------------------------------------------------------------------------


def _post_json(url: str, payload: dict, headers: dict[str, str] | None = None) -> int:
    """POST JSON payload; return HTTP status code. Never raises."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return 0


def _dispatch_slack(config: dict, text: str) -> int:
    url = config.get("webhook_url", "")
    if not url:
        return 0
    return _post_json(url, {"text": text})


def _dispatch_pagerduty(config: dict, summary: str, severity: str, dedup_key: str) -> int:
    routing_key = config.get("routing_key", "")
    if not routing_key:
        return 0
    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": summary,
            "severity": severity.lower(),  # PD: critical/error/warning/info
            "source": "Canlix",
        },
    }
    return _post_json("https://events.pagerduty.com/v2/enqueue", payload)


def _dispatch_jira(config: dict, summary: str, description: str) -> int:
    import base64

    base_url = config.get("base_url", "").rstrip("/")
    email = config.get("email", "")
    api_token = config.get("api_token", "")
    project_key = config.get("project_key", "")
    issue_type = config.get("issue_type", "Task")
    if not (base_url and email and api_token and project_key):
        return 0
    creds = base64.b64encode(f"{email}:{api_token}".encode()).decode()
    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "description": {
                "type": "doc",
                "version": 1,
                "content": [{"type": "paragraph", "content": [{"type": "text", "text": description}]}],
            },
            "issuetype": {"name": issue_type},
        }
    }
    return _post_json(
        f"{base_url}/rest/api/3/issue",
        payload,
        headers={"Authorization": f"Basic {creds}"},
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_alert_text(scan_id: str, project_name: str, new_findings: list) -> str:
    """Build a human-readable alert message for new critical/high findings."""
    severities = [f.severity for f in new_findings if f.severity in _ALERT_SEVERITIES]
    critical = severities.count("CRITICAL")
    high = severities.count("HIGH")
    parts = []
    if critical:
        parts.append(f"{critical} CRITICAL")
    if high:
        parts.append(f"{high} HIGH")
    summary = ", ".join(parts) or f"{len(new_findings)} finding(s)"
    return f"[Canlix] New findings in {project_name}: {summary} — scan {scan_id[:8]}"


def dispatch_all(integrations: list[Integration], scan, project_name: str) -> None:
    """Fire-and-forget: dispatch alerts to all integrations in background threads.

    Only triggers when the scan has new CRITICAL or HIGH findings.
    """
    if not integrations:
        return

    new_critical_or_high = [f for f in scan.diff.new if f.severity in _ALERT_SEVERITIES]
    if not new_critical_or_high:
        return

    text = build_alert_text(scan.id, project_name, new_critical_or_high)
    dedup_key = f"canlix-{scan.id}"
    worst = "CRITICAL" if any(f.severity == "CRITICAL" for f in new_critical_or_high) else "HIGH"
    pd_severity = "critical" if worst == "CRITICAL" else "error"
    description = text + "\n\nAffected rules: " + ", ".join(sorted({f.rule_id for f in new_critical_or_high}))

    for intg in integrations:
        t = threading.Thread(
            target=_dispatch_one,
            args=(intg, text, pd_severity, dedup_key, description),
            daemon=True,
        )
        t.start()


def _dispatch_one(
    intg: Integration,
    text: str,
    pd_severity: str,
    dedup_key: str,
    description: str,
) -> None:
    if intg.type == "slack":
        _dispatch_slack(intg.config, text)
    elif intg.type == "pagerduty":
        _dispatch_pagerduty(intg.config, text, pd_severity, dedup_key)
    elif intg.type == "jira":
        _dispatch_jira(intg.config, text, description)
