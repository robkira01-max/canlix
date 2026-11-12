"""Tests for saas/report.py HTML scan report generator."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

from saas.report import generate_scan_report


def _make_scan(findings=(), new_fps=(), fixed_fps=(), baseline=False, score=80):
    scan = MagicMock()
    scan.id = "a1b2c3d4" * 4
    scan.created_at = datetime(2026, 11, 12, 10, 0, 0, tzinfo=timezone.utc)
    scan.score = score
    scan.findings = list(findings)
    diff = MagicMock()
    diff.baseline = baseline
    diff.new = [f for f in findings if f.fingerprint in new_fps]
    diff.fixed = [f for f in findings if f.fingerprint in fixed_fps]
    diff.persisting = [f for f in findings if f.fingerprint not in new_fps and f.fingerprint not in fixed_fps]
    scan.diff = diff
    return scan


def _finding(rule_id: str, severity: str, location: str = "app/server.py", fingerprint: str = None):
    f = MagicMock()
    f.rule_id = rule_id
    f.severity = severity
    f.confidence = "HIGH"
    f.location = location
    f.message = f"Issue {rule_id}"
    f.remediation = "Fix it"
    f.fingerprint = fingerprint or rule_id
    f.occurrences = 1
    return f


def test_report_contains_project_and_org_name():
    scan = _make_scan()
    html = generate_scan_report("AcmeCorp", "my-scanner", scan)
    assert "AcmeCorp" in html
    assert "my-scanner" in html


def test_report_contains_scan_id():
    scan = _make_scan()
    html = generate_scan_report("Org", "Project", scan)
    assert scan.id in html


def test_report_shows_findings_severity():
    f1 = _finding("RUN-001", "CRITICAL", fingerprint="fp1")
    f2 = _finding("CFG-001", "HIGH", fingerprint="fp2")
    scan = _make_scan(findings=[f1, f2])
    html = generate_scan_report("Org", "Proj", scan)
    assert "CRITICAL" in html
    assert "HIGH" in html
    assert "RUN-001" in html
    assert "CFG-001" in html


def test_report_marks_new_findings():
    f1 = _finding("RUN-001", "CRITICAL", fingerprint="fp1")
    scan = _make_scan(findings=[f1], new_fps={"fp1"})
    html = generate_scan_report("Org", "Proj", scan)
    assert "NEW" in html


def test_report_baseline_message_when_first_scan():
    scan = _make_scan(baseline=True)
    html = generate_scan_report("Org", "Proj", scan)
    assert "Baseline" in html or "baseline" in html.lower()


def test_report_no_findings_shows_placeholder():
    scan = _make_scan()
    html = generate_scan_report("Org", "Proj", scan)
    assert "No findings" in html


def test_report_score_shown():
    scan = _make_scan(score=65)
    html = generate_scan_report("Org", "Proj", scan)
    assert "65" in html


def test_report_is_valid_html():
    scan = _make_scan()
    html = generate_scan_report("Org", "Proj", scan)
    assert html.startswith("<!DOCTYPE html>")
    assert "</html>" in html


def test_report_escapes_html_in_names():
    scan = _make_scan()
    html = generate_scan_report("<script>alert(1)</script>", "<b>proj</b>", scan)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
