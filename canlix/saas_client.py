"""Client-side helpers for the Canlix SaaS API.

Uses only stdlib — no extra dependencies beyond the base wheel.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

_SENSITIVE_KEYS: frozenset[str] = frozenset(["code_snippet", "evidence"])


def strip_report(payload: dict) -> dict:
    """Remove sensitive per-finding fields before sending to the SaaS.

    Defense-in-depth: the server also uses Pydantic extra="ignore".
    Strips code_snippet and evidence from every finding / source_finding entry.
    Non-dict items in the lists are preserved as-is so the server can reject them.
    """
    out = dict(payload)
    for key in ("findings", "source_findings"):
        if key in out and isinstance(out[key], list):
            out[key] = [
                {k: v for k, v in f.items() if k not in _SENSITIVE_KEYS} if isinstance(f, dict) else f for f in out[key]
            ]
    return out


def push_scan(
    base_url: str,
    token: str,
    project_id: str,
    payload: dict,
    *,
    timeout: int = 30,
) -> dict:
    """POST a report to /projects/{project_id}/scans and return the scan summary dict.

    Raises:
        urllib.error.URLError — network-level failure (DNS, connection refused, …)
        ValueError            — HTTP error response from server (4xx / 5xx)
    """
    url = f"{base_url.rstrip('/')}/projects/{project_id}/scans"
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode(errors="replace")
        raise ValueError(f"HTTP {exc.code}: {body_text}") from exc
