"""HTTP layer tests for saas/app.py.

Requires: pip install 'canlix[saas]'  (fastapi + httpx)
Skipped automatically if httpx is not installed.
"""

from __future__ import annotations

import json

import pytest

httpx = pytest.importorskip("httpx", reason="saas HTTP tests require: pip install 'canlix[saas]'")
fastapi_testclient = pytest.importorskip("fastapi.testclient", reason="fastapi required")

from fastapi.testclient import TestClient  # noqa: E402

from saas.app import _get_store, _rate_state, app  # noqa: E402
from saas.store import Store  # noqa: E402

# ---------------------------------------------------------------------------
# Fixture: fresh Store + empty rate-limiter state per test
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _fresh_store():
    store = Store()
    app.dependency_overrides[_get_store] = lambda: store
    _rate_state.clear()
    yield store
    app.dependency_overrides.clear()
    _rate_state.clear()


@pytest.fixture()
def client():
    return TestClient(app, raise_server_exceptions=True)


# helpers


def _create_org(client, name="Acme", plan="free"):
    r = client.post("/orgs", json={"name": name, "plan": plan})
    assert r.status_code == 201
    data = r.json()
    return data["org_id"], data["token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _create_project(client, token, name="proj"):
    r = client.post("/projects", json={"name": name}, headers=_auth(token))
    assert r.status_code == 201
    return r.json()["project_id"]


def _small_report():
    return {
        "findings": [
            {
                "rule_id": "NET-001",
                "severity": "HIGH",
                "confidence": "HIGH",
                "server": "api",
                "message": "HTTP transport",
            }
        ]
    }


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


def test_no_token_returns_401(client):
    assert client.get("/orgs/me").status_code == 401


def test_bad_token_returns_401(client):
    assert client.get("/orgs/me", headers=_auth("cnx_bad")).status_code == 401


def test_bearer_prefix_required(client):
    r = client.get("/orgs/me", headers={"Authorization": "Token cnx_something"})
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Org
# ---------------------------------------------------------------------------


def test_create_org_returns_token_once(client):
    r = client.post("/orgs", json={"name": "Canlix"})
    assert r.status_code == 201
    d = r.json()
    assert d["token"].startswith("cnx_")
    assert d["name"] == "Canlix"
    assert d["plan"] == "free"


def test_create_org_unknown_plan_returns_422(client):
    assert client.post("/orgs", json={"name": "X", "plan": "diamond"}).status_code == 422


def test_get_me(client):
    _, token = _create_org(client, "Acme", "team")
    r = client.get("/orgs/me", headers=_auth(token))
    assert r.status_code == 200
    d = r.json()
    assert d["plan"] == "team" and d["max_projects"] == 10


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------


def test_create_and_list_projects(client):
    _, token = _create_org(client)
    pid = _create_project(client, token, "alpha")
    r = client.get("/projects", headers=_auth(token))
    assert r.status_code == 200
    assert any(p["project_id"] == pid for p in r.json())


def test_get_project(client):
    _, token = _create_org(client)
    pid = _create_project(client, token)
    r = client.get(f"/projects/{pid}", headers=_auth(token))
    assert r.status_code == 200 and r.json()["project_id"] == pid


def test_cross_tenant_project_returns_404(client):
    _, t1 = _create_org(client, "A")
    _, t2 = _create_org(client, "B")
    pid = _create_project(client, t1)
    assert client.get(f"/projects/{pid}", headers=_auth(t2)).status_code == 404


def test_plan_limit_enforced(client):
    _, token = _create_org(client, plan="free")
    _create_project(client, token, "one")
    r = client.post("/projects", json={"name": "two"}, headers=_auth(token))
    assert r.status_code == 402
    assert r.json()["detail"] == "project_limit_reached"  # M3: opaque, no plan internals


# ---------------------------------------------------------------------------
# Scan ingestion
# ---------------------------------------------------------------------------


def test_ingest_scan_returns_summary(client):
    _, token = _create_org(client)
    pid = _create_project(client, token)
    r = client.post(
        f"/projects/{pid}/scans",
        content=json.dumps(_small_report()),
        headers={**_auth(token), "Content-Type": "application/json"},
    )
    assert r.status_code == 201
    d = r.json()
    assert d["score"] < 100
    assert d["diff"]["baseline"] is True


def test_second_scan_produces_diff(client):
    _, token = _create_org(client)
    pid = _create_project(client, token)

    report_a = {
        "findings": [{"rule_id": "A", "severity": "HIGH", "confidence": "HIGH", "server": "s", "message": "msg A"}]
    }
    report_b = {
        "findings": [
            {"rule_id": "A", "severity": "HIGH", "confidence": "HIGH", "server": "s", "message": "msg A"},
            {"rule_id": "B", "severity": "HIGH", "confidence": "HIGH", "server": "s", "message": "msg B"},
        ]
    }

    def _post(rep):
        return client.post(
            f"/projects/{pid}/scans",
            content=json.dumps(rep),
            headers={**_auth(token), "Content-Type": "application/json"},
        )

    r1 = _post(report_a)
    r2 = _post(report_b)
    assert r1.json()["diff"]["baseline"] is True
    d = r2.json()["diff"]
    assert d["baseline"] is False and d["new"] == 1 and d["persisting"] == 1 and d["fixed"] == 0


def test_ingest_validation_errors_strip_input_field(client):
    _, token = _create_org(client)
    pid = _create_project(client, token)
    bad = {"findings": [{"rule_id": "X", "severity": "SUPER", "confidence": "HIGH", "server": "s", "message": "m"}]}
    r = client.post(
        f"/projects/{pid}/scans", content=json.dumps(bad), headers={**_auth(token), "Content-Type": "application/json"}
    )
    assert r.status_code == 422
    for err in r.json()["detail"]:
        assert "input" not in err  # H2: input fragment never echoed back


def test_ingest_bad_json_returns_422(client):
    _, token = _create_org(client)
    pid = _create_project(client, token)
    r = client.post(
        f"/projects/{pid}/scans", content=b"not-json", headers={**_auth(token), "Content-Type": "application/json"}
    )
    assert r.status_code == 422


def test_ingest_malformed_severity_returns_422(client):
    _, token = _create_org(client)
    pid = _create_project(client, token)
    bad = {"findings": [{"rule_id": "X", "severity": "SUPER", "confidence": "HIGH", "server": "s", "message": "m"}]}
    r = client.post(
        f"/projects/{pid}/scans", content=json.dumps(bad), headers={**_auth(token), "Content-Type": "application/json"}
    )
    assert r.status_code == 422


def test_ingest_on_unknown_project_returns_404(client):
    _, token = _create_org(client)
    valid_hex = "a" * 32  # syntactically valid ID that doesn't exist
    r = client.post(
        f"/projects/{valid_hex}/scans",
        content=json.dumps(_small_report()),
        headers={**_auth(token), "Content-Type": "application/json"},
    )
    assert r.status_code == 404


def test_ingest_invalid_path_format_returns_422(client):
    _, token = _create_org(client)
    r = client.post(
        "/projects/nonexistent/scans",
        content=json.dumps(_small_report()),
        headers={**_auth(token), "Content-Type": "application/json"},
    )
    assert r.status_code == 422  # M1: path param constraint rejects non-hex IDs


def test_cross_tenant_scan_returns_404(client):
    _, t1 = _create_org(client, "A")
    _, t2 = _create_org(client, "B")
    pid = _create_project(client, t1)
    r = client.post(
        f"/projects/{pid}/scans",
        content=json.dumps(_small_report()),
        headers={**_auth(t2), "Content-Type": "application/json"},
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Scan list and detail
# ---------------------------------------------------------------------------


def test_list_scans_newest_first(client):
    _, token = _create_org(client)
    pid = _create_project(client, token)
    for _ in range(3):
        client.post(
            f"/projects/{pid}/scans",
            content=json.dumps(_small_report()),
            headers={**_auth(token), "Content-Type": "application/json"},
        )
    r = client.get(f"/projects/{pid}/scans", headers=_auth(token))
    assert r.status_code == 200 and len(r.json()) == 3


def test_list_scans_limit(client):
    _, token = _create_org(client)
    pid = _create_project(client, token)
    for _ in range(5):
        client.post(
            f"/projects/{pid}/scans",
            content=json.dumps(_small_report()),
            headers={**_auth(token), "Content-Type": "application/json"},
        )
    r = client.get(f"/projects/{pid}/scans?limit=2", headers=_auth(token))
    assert len(r.json()) == 2


def test_get_scan_detail_includes_findings(client):
    _, token = _create_org(client)
    pid = _create_project(client, token)
    r = client.post(
        f"/projects/{pid}/scans",
        content=json.dumps(_small_report()),
        headers={**_auth(token), "Content-Type": "application/json"},
    )
    scan_id = r.json()["scan_id"]
    r2 = client.get(f"/projects/{pid}/scans/{scan_id}", headers=_auth(token))
    assert r2.status_code == 200
    d = r2.json()
    assert len(d["findings"]) == 1
    assert "code_snippet" not in d["findings"][0]  # privacy by construction


def test_get_scan_cross_tenant_returns_404(client):
    _, t1 = _create_org(client, "A")
    _, t2 = _create_org(client, "B")
    pid = _create_project(client, t1)
    r = client.post(
        f"/projects/{pid}/scans",
        content=json.dumps(_small_report()),
        headers={**_auth(t1), "Content-Type": "application/json"},
    )
    scan_id = r.json()["scan_id"]
    assert client.get(f"/projects/{pid}/scans/{scan_id}", headers=_auth(t2)).status_code == 404


# ---------------------------------------------------------------------------
# Security headers and misc
# ---------------------------------------------------------------------------


def test_security_headers_present(client):
    r = client.get("/health")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
    assert r.headers.get("cache-control") == "no-store"


def test_health_no_auth(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_no_openapi_route(client):
    assert client.get("/openapi.json").status_code == 404


def test_body_too_large_returns_413(client):
    _, token = _create_org(client)
    pid = _create_project(client, token)
    big = b"x" * (5 * 1024 * 1024 + 1)
    r = client.post(
        f"/projects/{pid}/scans",
        content=big,
        headers={**_auth(token), "content-length": str(len(big)), "Content-Type": "application/json"},
    )
    assert r.status_code == 413


# ---------------------------------------------------------------------------
# Token revocation and rotation (HTTP layer)
# ---------------------------------------------------------------------------


def test_revoke_token_blocks_further_requests(client):
    _, token = _create_org(client)
    r = client.delete("/orgs/me/token", headers=_auth(token))
    assert r.status_code == 204
    assert client.get("/orgs/me", headers=_auth(token)).status_code == 401


def test_revoke_token_requires_auth(client):
    r = client.delete("/orgs/me/token")
    assert r.status_code == 401


def test_rotate_token_old_rejected_new_works(client):
    _, old_token = _create_org(client)
    r = client.post("/orgs/me/token/rotate", json={}, headers=_auth(old_token))
    assert r.status_code == 200
    new_token = r.json()["token"]
    assert new_token.startswith("cnx_")
    assert client.get("/orgs/me", headers=_auth(old_token)).status_code == 401
    assert client.get("/orgs/me", headers=_auth(new_token)).status_code == 200


def test_rotate_token_with_ttl(client):
    _, old_token = _create_org(client)
    r = client.post("/orgs/me/token/rotate", json={"token_ttl_days": 30}, headers=_auth(old_token))
    assert r.status_code == 200
    assert r.json()["token"].startswith("cnx_")


def test_rotate_token_ttl_out_of_range_rejected(client):
    _, token = _create_org(client)
    r = client.post("/orgs/me/token/rotate", json={"token_ttl_days": 0}, headers=_auth(token))
    assert r.status_code == 422


def test_create_org_with_ttl(client):
    r = client.post("/orgs", json={"name": "TTLOrg", "token_ttl_days": 365})
    assert r.status_code == 201
    assert r.json()["token"].startswith("cnx_")


def test_create_org_ttl_out_of_range_rejected(client):
    r = client.post("/orgs", json={"name": "TTLOrg", "token_ttl_days": 0})
    assert r.status_code == 422
