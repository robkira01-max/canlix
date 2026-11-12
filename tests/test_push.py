"""Tests for canlix push command and saas_client helpers."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from canlix.cli import app
from canlix.saas_client import strip_report

runner = CliRunner()

# ---------------------------------------------------------------------------
# strip_report — pure function
# ---------------------------------------------------------------------------


def test_strip_removes_code_snippet_from_source_findings():
    payload = {"source_findings": [{"rule_id": "X", "code_snippet": "os.system(cmd)", "message": "m"}]}
    out = strip_report(payload)
    assert "code_snippet" not in out["source_findings"][0]
    assert out["source_findings"][0]["message"] == "m"


def test_strip_removes_evidence_from_findings():
    payload = {"findings": [{"rule_id": "NET-001", "evidence": "args=['--token','abc']", "message": "m"}]}
    out = strip_report(payload)
    assert "evidence" not in out["findings"][0]
    assert out["findings"][0]["message"] == "m"


def test_strip_keeps_rule_id_severity_message():
    payload = {
        "findings": [{"rule_id": "X", "severity": "HIGH", "confidence": "HIGH",
                       "message": "msg", "evidence": "leaked"}]
    }
    kept = strip_report(payload)["findings"][0]
    assert kept["rule_id"] == "X" and kept["severity"] == "HIGH" and kept["message"] == "msg"


def test_strip_passthrough_no_findings():
    payload = {"canlix_version": "0.1.0", "score": 90}
    assert strip_report(payload) == payload


def test_strip_non_dict_items_preserved():
    payload = {"findings": [None, "bad"]}
    out = strip_report(payload)
    assert out["findings"] == [None, "bad"]


# ---------------------------------------------------------------------------
# push CLI — missing config
# ---------------------------------------------------------------------------

_FAKE_SUMMARY = {
    "scan_id": "a" * 32,
    "project_id": "b" * 32,
    "created_at": "2026-11-12T08:00:00+00:00",
    "score": 87,
    "total_findings": 1,
    "diff": {"baseline": False, "new": 1, "fixed": 0, "persisting": 0},
}

_GOOD_REPORT = json.dumps({"findings": [{"rule_id": "X", "severity": "HIGH",
                                          "confidence": "HIGH", "server": "s", "message": "m"}]})


def test_push_no_token_exits_nonzero(tmp_path):
    f = tmp_path / "r.json"
    f.write_text(_GOOD_REPORT)
    r = runner.invoke(app, ["push", str(f), "--project", "a" * 32], env={"CANLIX_API_TOKEN": ""})
    assert r.exit_code != 0


def test_push_no_project_exits_nonzero(tmp_path):
    f = tmp_path / "r.json"
    f.write_text(_GOOD_REPORT)
    r = runner.invoke(app, ["push", str(f), "--token", "cnx_x"], env={"CANLIX_PROJECT": ""})
    assert r.exit_code != 0


def test_push_bad_json_exits_nonzero(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("not-json")
    r = runner.invoke(app, ["push", str(f), "--token", "cnx_x", "--project", "a" * 32])
    assert r.exit_code != 0


# ---------------------------------------------------------------------------
# push CLI — with mocked HTTP
# ---------------------------------------------------------------------------


def test_push_success_non_baseline(tmp_path):
    f = tmp_path / "r.json"
    f.write_text(_GOOD_REPORT)
    with patch("canlix.saas_client.push_scan", return_value=_FAKE_SUMMARY) as mock_push:
        r = runner.invoke(app, ["push", str(f), "--token", "cnx_test", "--project", "a" * 32])
    assert r.exit_code == 0
    assert "87/100" in r.output
    assert "New" in r.output and "1" in r.output
    mock_push.assert_called_once()


def test_push_success_baseline(tmp_path):
    baseline_summary = {**_FAKE_SUMMARY, "diff": {"baseline": True, "new": 0, "fixed": 0, "persisting": 1}}
    f = tmp_path / "r.json"
    f.write_text(_GOOD_REPORT)
    with patch("canlix.saas_client.push_scan", return_value=baseline_summary):
        r = runner.invoke(app, ["push", str(f), "--token", "cnx_test", "--project", "a" * 32])
    assert r.exit_code == 0 and "Baseline" in r.output and "yes" in r.output


def test_push_server_error_exits_nonzero(tmp_path):
    f = tmp_path / "r.json"
    f.write_text(_GOOD_REPORT)
    with patch("canlix.saas_client.push_scan", side_effect=ValueError("HTTP 401: missing_or_invalid_token")):
        r = runner.invoke(app, ["push", str(f), "--token", "cnx_bad", "--project", "a" * 32])
    assert r.exit_code != 0 and "401" in r.output


def test_push_strips_sensitive_fields_before_send(tmp_path):
    report_with_secrets = json.dumps(
        {"source_findings": [{"rule_id": "X", "severity": "CRITICAL", "confidence": "HIGH",
                               "file": "s.py", "line": 1, "message": "m",
                               "code_snippet": "subprocess.run(cmd, shell=True)"}]}
    )
    f = tmp_path / "r.json"
    f.write_text(report_with_secrets)
    captured = {}

    def _mock_push(base_url, token, project_id, payload, **kw):
        captured["payload"] = payload
        return _FAKE_SUMMARY

    with patch("canlix.saas_client.push_scan", side_effect=_mock_push):
        runner.invoke(app, ["push", str(f), "--token", "cnx_test", "--project", "a" * 32])

    sf = captured["payload"]["source_findings"][0]
    assert "code_snippet" not in sf and sf["message"] == "m"


def test_push_no_strip_flag_skips_stripping(tmp_path):
    report_with_secrets = json.dumps(
        {"findings": [{"rule_id": "X", "severity": "HIGH", "confidence": "HIGH",
                        "server": "s", "message": "m", "evidence": "sensitive"}]}
    )
    f = tmp_path / "r.json"
    f.write_text(report_with_secrets)
    captured = {}

    def _mock_push(base_url, token, project_id, payload, **kw):
        captured["payload"] = payload
        return _FAKE_SUMMARY

    with patch("canlix.saas_client.push_scan", side_effect=_mock_push):
        runner.invoke(app, ["push", str(f), "--token", "cnx_test", "--project", "a" * 32, "--no-strip"])

    assert captured["payload"]["findings"][0].get("evidence") == "sensitive"
