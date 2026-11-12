"""Scan-to-scan comparison by finding fingerprint (line numbers are deliberately not part of it)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from saas.ingest import NormalizedFinding


@dataclass(frozen=True)
class ScanDiff:
    baseline: bool
    new: tuple[str, ...]
    fixed: tuple[str, ...]
    persisting: tuple[str, ...]


def diff_scans(previous: Iterable[NormalizedFinding] | None, current: Iterable[NormalizedFinding]) -> ScanDiff:
    """The first scan of a project is a baseline: nothing is reported as new."""
    cur = {f.fingerprint for f in current}
    if previous is None:
        return ScanDiff(True, (), (), tuple(sorted(cur)))
    prev = {f.fingerprint for f in previous}
    return ScanDiff(False, tuple(sorted(cur - prev)), tuple(sorted(prev - cur)), tuple(sorted(cur & prev)))
