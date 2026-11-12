from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from saas.diff import diff_scans
from saas.ingest import MAX_FINDINGS, compute_score, normalize_report
from saas.security import hash_token, lookup_key, new_api_token, verify_token
from saas.store import PlanLimitError, Store, UnknownPlanError

FAKE_KEY = "sk-" + "a1b2c3d4" * 4


def _cfg(rule="NET-001", sev="HIGH", server="analytics", msg="HTTP transport sends data unencrypted", **extra):
    return {"rule_id": rule, "severity": sev, "confidence": "HIGH", "server": server, "message": msg, **extra}


def _src(rule="SRC-001", sev="CRITICAL", file="./src/server.py", line=3, msg="shell=True with user input", **extra):
    return {
        "rule_id": rule,
        "severity": sev,
        "confidence": "HIGH",
        "file": file,
        "line": line,
        "message": msg,
        **extra,
    }


# --- tokens ---


def test_token_roundtrip_and_hash_only_storage():
    token, key, digest = new_api_token()
    assert token.startswith("cnx_") and key == lookup_key(token) and digest == hash_token(token)
    assert token not in digest and verify_token(token, digest)
    assert not verify_token(token + "x", digest)


def test_tokens_are_unique():
    assert len({new_api_token()[0] for _ in range(50)}) == 50


# --- ingestion ---


def test_snippets_evidence_and_extra_fields_are_dropped_by_construction():
    payload = {
        "findings": [_cfg(evidence="args: ['--token', 'abc']", extra_field=1)],
        "source_findings": [_src(code_snippet="subprocess.run(cmd, shell=True)")],
    }
    out = normalize_report(payload)
    blob = json.dumps([f.__dict__ for f in out])
    assert "subprocess.run" not in blob and "--token" not in blob and len(out) == 2


def test_secrets_in_messages_are_redacted_server_side():
    out = normalize_report({"findings": [_cfg(msg=f"hardcoded key {FAKE_KEY}", server=f"srv-{FAKE_KEY}")]})
    blob = json.dumps(out[0].__dict__)
    assert FAKE_KEY not in blob and "<redacted:api-key>" in blob


def test_malformed_reports_are_rejected():
    for bad in (
        {"findings": [_cfg(sev="SUPER")]},
        {"findings": [{"rule_id": "X"}]},
        {"findings": "nope"},
        {"source_findings": [_src(line=-1)]},
        {"findings": [_cfg(msg="x" * 1001)]},
        [],
    ):
        with pytest.raises(ValidationError):
            normalize_report(bad)


def test_finding_count_is_capped():
    with pytest.raises(ValidationError):
        normalize_report({"findings": [_cfg(rule=f"R-{i}") for i in range(MAX_FINDINGS + 1)]})


def test_fingerprint_ignores_line_numbers_and_dot_slash_and_merges_duplicates():
    out = normalize_report({"source_findings": [_src(line=3), _src(line=40, file="src/server.py")]})
    assert len(out) == 1 and out[0].occurrences == 2 and out[0].location == "src/server.py"


def test_score_is_recomputed_not_trusted():
    out = normalize_report({"findings": [_cfg(sev="HIGH")], "source_findings": [_src(sev="CRITICAL")], "score": 100})
    assert compute_score(out) == 100 - 20 - 40
    many = normalize_report({"source_findings": [_src(rule=f"R-{i}", sev="CRITICAL") for i in range(5)]})
    assert compute_score(many) == 0


# --- diff ---


def test_first_scan_is_baseline_then_new_fixed_persisting():
    a = normalize_report({"findings": [_cfg(rule="A"), _cfg(rule="B")]})
    b = normalize_report({"findings": [_cfg(rule="B"), _cfg(rule="C")]})
    base = diff_scans(None, a)
    assert base.baseline and base.new == () and len(base.persisting) == 2
    d = diff_scans(a, b)
    assert not d.baseline and len(d.new) == len(d.fixed) == len(d.persisting) == 1
    assert set(d.new).isdisjoint(d.persisting)


# --- store / tenancy ---


def test_authentication_and_unknown_tokens():
    s = Store()
    org, token = s.create_org("Acme")
    assert s.authenticate(token) == org
    assert s.authenticate(token + "x") is None
    assert s.authenticate("cnx_unknown_token_value") is None
    assert s.authenticate("") is None


def test_unknown_plan_rejected():
    with pytest.raises(UnknownPlanError):
        Store().create_org("Acme", plan="platinum")


def test_plan_limit_on_projects():
    s = Store()
    org, _ = s.create_org("Acme", "free")
    s.create_project(org.id, "one")
    with pytest.raises(PlanLimitError):
        s.create_project(org.id, "two")
    team, _ = s.create_org("Big", "team")
    for i in range(10):
        s.create_project(team.id, f"p{i}")
    with pytest.raises(PlanLimitError):
        s.create_project(team.id, "p11")


def test_cross_tenant_access_returns_none_everywhere():
    s = Store()
    a, _ = s.create_org("A")
    b, _ = s.create_org("B")
    pa = s.create_project(a.id, "pa")
    scan = s.add_scan(a.id, pa.id, normalize_report({"findings": [_cfg()]}))
    assert scan is not None
    assert s.get_project(b.id, pa.id) is None
    assert s.add_scan(b.id, pa.id, []) is None
    assert s.list_scans(b.id, pa.id) is None
    assert s.get_scan(b.id, pa.id, scan.id) is None
    assert s.list_projects(b.id) == []
    assert s.get_scan(a.id, pa.id, scan.id) == scan


def test_history_and_diff_flow_through_store():
    s = Store()
    org, _ = s.create_org("A")
    p = s.create_project(org.id, "p")
    s1 = s.add_scan(org.id, p.id, normalize_report({"findings": [_cfg(rule="A")]}))
    s2 = s.add_scan(org.id, p.id, normalize_report({"findings": [_cfg(rule="A"), _cfg(rule="B")]}))
    assert s1.diff.baseline and len(s2.diff.new) == 1 and len(s2.diff.persisting) == 1
    assert [x.id for x in s.list_scans(org.id, p.id)] == [s2.id, s1.id]
    assert len(s.list_scans(org.id, p.id, limit=1)) == 1


# --- token revocation and rotation ---


def test_revoke_token_blocks_further_auth():
    s = Store()
    org, token = s.create_org("A")
    assert s.authenticate(token) == org
    assert s.revoke_token(org.id, token) is True
    assert s.authenticate(token) is None


def test_revoke_token_wrong_org_returns_false():
    s = Store()
    org_a, token_a = s.create_org("A")
    org_b, _ = s.create_org("B")
    assert s.revoke_token(org_b.id, token_a) is False
    assert s.authenticate(token_a) == org_a  # still valid


def test_revoke_idempotent():
    s = Store()
    org, token = s.create_org("A")
    assert s.revoke_token(org.id, token) is True
    assert s.revoke_token(org.id, token) is False  # already revoked


def test_rotate_token_old_invalid_new_valid():
    s = Store()
    org, old_token = s.create_org("A")
    new_token = s.rotate_token(org.id, old_token)
    assert new_token is not None and new_token != old_token
    assert s.authenticate(old_token) is None
    assert s.authenticate(new_token) == org


def test_rotate_token_wrong_org_returns_none():
    s = Store()
    org_a, token_a = s.create_org("A")
    org_b, _ = s.create_org("B")
    result = s.rotate_token(org_b.id, token_a)
    assert result is None
    assert s.authenticate(token_a) == org_a  # original unchanged


def test_token_ttl_expiry():
    from datetime import datetime, timedelta, timezone

    # expired token should not authenticate
    s = Store()
    org, token = s.create_org("A", token_ttl_days=1)
    assert s.authenticate(token) == org
    # simulate expiry by patching the token's expires_at to the past
    from saas.security import lookup_key

    key = lookup_key(token)
    with s._lock:
        entries = s._tokens[key]
        s._tokens[key] = [(d, o, datetime.now(timezone.utc) - timedelta(seconds=1)) for d, o, _ in entries]
    assert s.authenticate(token) is None


def test_ttl_none_means_no_expiry():
    s = Store()
    _, token = s.create_org("A", token_ttl_days=None)
    from saas.security import lookup_key

    key = lookup_key(token)
    with s._lock:
        entries = s._tokens[key]
        assert all(expires_at is None for _, _, expires_at in entries)


# --- email auth ---


def test_register_creates_org_and_authenticates():
    s = Store()
    org, token = s.register("Acme", "alice@example.com", "hunter2!")
    assert org.name == "Acme"
    assert s.authenticate(token) == org


def test_register_duplicate_email_raises():
    from saas.store import EmailAlreadyExistsError

    s = Store()
    s.register("A", "dup@example.com", "password1")
    with pytest.raises(EmailAlreadyExistsError):
        s.register("B", "dup@example.com", "password2")


def test_register_email_case_insensitive():
    from saas.store import EmailAlreadyExistsError

    s = Store()
    s.register("A", "Upper@Example.COM", "password1")
    with pytest.raises(EmailAlreadyExistsError):
        s.register("B", "upper@example.com", "password2")


def test_login_with_email_returns_valid_token():
    s = Store()
    org, _ = s.register("Acme", "bob@example.com", "s3cr3t!")
    login_token = s.login_with_email("bob@example.com", "s3cr3t!")
    assert login_token is not None
    assert s.authenticate(login_token) == org


def test_login_wrong_password_returns_none():
    s = Store()
    s.register("Acme", "carol@example.com", "rightpassword")
    assert s.login_with_email("carol@example.com", "wrongpassword") is None


def test_login_unknown_email_returns_none():
    s = Store()
    assert s.login_with_email("nobody@example.com", "whatever") is None


def test_login_produces_independent_tokens():
    s = Store()
    s.register("Acme", "dave@example.com", "pass1234")
    t1 = s.login_with_email("dave@example.com", "pass1234")
    t2 = s.login_with_email("dave@example.com", "pass1234")
    assert t1 != t2
    org = s.authenticate(t1)
    assert s.authenticate(t2) == org  # both tokens belong to same org


def test_auth_module_hash_verify_roundtrip():
    from saas.auth import hash_password, verify_password

    h = hash_password("hello world")
    assert verify_password("hello world", h)
    assert not verify_password("wrong", h)
    assert not verify_password("hello world", "badformat")
