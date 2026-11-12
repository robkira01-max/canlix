"""Tests for saas/integrations.py and integration CRUD/dispatch."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from saas.integrations import (
    INTEGRATION_TYPES,
    _dispatch_jira,
    _dispatch_pagerduty,
    _dispatch_slack,
    build_alert_text,
    dispatch_all,
)
from saas.store import Store, UnknownIntegrationTypeError

# ---------------------------------------------------------------------------
# Integration type constants
# ---------------------------------------------------------------------------


def test_integration_types_contains_expected_values():
    assert INTEGRATION_TYPES == {"slack", "pagerduty", "jira"}


# ---------------------------------------------------------------------------
# Store integration CRUD
# ---------------------------------------------------------------------------


def _make_store_with_org():
    s = Store()
    org, token = s.create_org("ACME")
    return s, org, token


def test_add_and_list_integration():
    s, org, _ = _make_store_with_org()
    intg = s.add_integration(org.id, "My Slack", "slack", {"webhook_url": "https://hooks.slack.com/x"})
    assert intg.id
    assert intg.type == "slack"
    assert intg.org_id == org.id
    lst = s.list_integrations(org.id)
    assert len(lst) == 1 and lst[0].id == intg.id


def test_list_integrations_empty_by_default():
    s, org, _ = _make_store_with_org()
    assert s.list_integrations(org.id) == []


def test_get_integration_by_id():
    s, org, _ = _make_store_with_org()
    intg = s.add_integration(org.id, "PD", "pagerduty", {"routing_key": "abc"})
    found = s.get_integration(org.id, intg.id)
    assert found and found.id == intg.id


def test_get_integration_wrong_org_returns_none():
    s = Store()
    org_a, _ = s.create_org("A")
    org_b, _ = s.create_org("B")
    intg = s.add_integration(org_a.id, "X", "slack", {})
    assert s.get_integration(org_b.id, intg.id) is None


def test_delete_integration_removes_it():
    s, org, _ = _make_store_with_org()
    intg = s.add_integration(org.id, "Del", "jira", {})
    assert s.delete_integration(org.id, intg.id) is True
    assert s.list_integrations(org.id) == []


def test_delete_integration_wrong_org_returns_false():
    s = Store()
    org_a, _ = s.create_org("A")
    org_b, _ = s.create_org("B")
    intg = s.add_integration(org_a.id, "X", "slack", {})
    assert s.delete_integration(org_b.id, intg.id) is False
    assert len(s.list_integrations(org_a.id)) == 1


def test_delete_integration_idempotent():
    s, org, _ = _make_store_with_org()
    intg = s.add_integration(org.id, "X", "slack", {})
    assert s.delete_integration(org.id, intg.id) is True
    assert s.delete_integration(org.id, intg.id) is False


def test_unknown_integration_type_raises():
    s, org, _ = _make_store_with_org()
    with pytest.raises(UnknownIntegrationTypeError):
        s.add_integration(org.id, "X", "discord", {})


# ---------------------------------------------------------------------------
# Dispatch helpers — mocked HTTP
# ---------------------------------------------------------------------------


def test_dispatch_slack_calls_webhook():
    with patch("saas.integrations._post_json", return_value=200) as mock_post:
        result = _dispatch_slack({"webhook_url": "https://hooks.example.com/abc"}, "Alert text")
    assert result == 200
    mock_post.assert_called_once()
    call_args = mock_post.call_args
    assert call_args[0][0] == "https://hooks.example.com/abc"
    assert call_args[0][1]["text"] == "Alert text"


def test_dispatch_slack_missing_url_returns_zero():
    result = _dispatch_slack({}, "Alert")
    assert result == 0


def test_dispatch_pagerduty_calls_events_api():
    with patch("saas.integrations._post_json", return_value=202) as mock_post:
        result = _dispatch_pagerduty({"routing_key": "rk123"}, "summary", "critical", "dedup-1")
    assert result == 202
    call_url, call_payload = mock_post.call_args[0]
    assert "pagerduty.com" in call_url
    assert call_payload["routing_key"] == "rk123"
    assert call_payload["payload"]["severity"] == "critical"


def test_dispatch_pagerduty_missing_key_returns_zero():
    result = _dispatch_pagerduty({}, "summary", "critical", "dedup")
    assert result == 0


def test_dispatch_jira_calls_rest_api():
    config = {
        "base_url": "https://acme.atlassian.net",
        "email": "user@acme.com",
        "api_token": "token123",
        "project_key": "SEC",
    }
    with patch("saas.integrations._post_json", return_value=201) as mock_post:
        result = _dispatch_jira(config, "New finding", "Details here")
    assert result == 201
    call_url, call_payload = mock_post.call_args[0]
    assert "atlassian.net" in call_url
    assert call_payload["fields"]["project"]["key"] == "SEC"
    assert call_payload["fields"]["summary"] == "New finding"


def test_dispatch_jira_missing_config_returns_zero():
    result = _dispatch_jira({"base_url": "https://x.com"}, "s", "d")
    assert result == 0


# ---------------------------------------------------------------------------
# build_alert_text
# ---------------------------------------------------------------------------


def _mock_finding(severity: str, rule_id: str = "RUN-001") -> MagicMock:
    f = MagicMock()
    f.severity = severity
    f.rule_id = rule_id
    return f


def test_build_alert_text_critical_and_high():
    findings = [_mock_finding("CRITICAL"), _mock_finding("HIGH"), _mock_finding("MEDIUM")]
    text = build_alert_text("abc123", "my-project", findings)
    assert "CRITICAL" in text
    assert "HIGH" in text
    assert "my-project" in text
    assert "abc123"[:8] in text


def test_build_alert_text_no_critical_high():
    findings = [_mock_finding("MEDIUM"), _mock_finding("LOW")]
    text = build_alert_text("xyz", "proj", findings)
    assert "proj" in text


# ---------------------------------------------------------------------------
# dispatch_all — no trigger when no critical/high
# ---------------------------------------------------------------------------


def test_dispatch_all_no_alert_for_medium_findings(monkeypatch):
    s, org, _ = _make_store_with_org()
    s.add_integration(org.id, "Slack", "slack", {"webhook_url": "https://hooks.example.com"})

    dispatched = []

    def fake_post(url, payload, headers=None):
        dispatched.append(url)
        return 200

    monkeypatch.setattr("saas.integrations._post_json", fake_post)

    # Build a fake scan with only MEDIUM diff.new
    scan = MagicMock()
    scan.id = "a" * 32
    scan.diff = MagicMock()
    scan.diff.new = [_mock_finding("MEDIUM")]

    intg = s.list_integrations(org.id)
    dispatch_all(intg, scan, "my-project")
    # Give background thread a moment, but expect no call for MEDIUM
    import time

    time.sleep(0.05)
    assert dispatched == []


def test_dispatch_all_triggers_for_critical(monkeypatch):
    s, org, _ = _make_store_with_org()
    s.add_integration(org.id, "Slack", "slack", {"webhook_url": "https://hooks.example.com"})

    called = []

    def fake_post(url, payload, headers=None):
        called.append((url, payload))
        return 200

    monkeypatch.setattr("saas.integrations._post_json", fake_post)

    scan = MagicMock()
    scan.id = "b" * 32
    scan.diff = MagicMock()
    scan.diff.new = [_mock_finding("CRITICAL")]

    intg = s.list_integrations(org.id)
    dispatch_all(intg, scan, "my-project")

    import time

    time.sleep(0.1)
    assert any("example.com" in url for url, _ in called)
