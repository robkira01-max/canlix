"""Secret detection and redaction. Redaction is idempotent: a marker is itself recognised as a secret."""

from __future__ import annotations

import re
from typing import Any

_PATTERNS: dict[str, re.Pattern[str]] = {
    "private-key": re.compile(
        r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z]+ )?PRIVATE KEY-----|$)"
    ),
    "aws-key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github-token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "api-key": re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    "slack-token": re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "bearer": re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}"),
}
_MARKER = re.compile(r"<redacted:([a-z\-]+)>")


def secret_kinds(text: str) -> list[str]:
    """Return the distinct kinds of secret found in text, in a stable order."""
    kinds = [k for k, rx in _PATTERNS.items() if rx.search(text)]
    kinds += [k for k in dict.fromkeys(_MARKER.findall(text)) if k not in kinds]
    return kinds


def redact(text: str) -> str:
    for kind, rx in _PATTERNS.items():
        text = rx.sub(f"<redacted:{kind}>", text)
    return text


def redact_obj(obj: Any) -> Any:
    """Return a deep copy of a JSON-like object with every string value redacted."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, list):
        return [redact_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    return obj


def iter_strings(obj: Any):
    """Yield every string value in a JSON-like object."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, list):
        for x in obj:
            yield from iter_strings(x)
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from iter_strings(v)
