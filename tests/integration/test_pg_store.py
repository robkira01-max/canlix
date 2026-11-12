"""Integration tests for PgStore.

Requires a real PostgreSQL instance.  Skipped automatically when
CANLIX_DATABASE_URL is not set.

Run:
    docker compose up -d db
    python -m saas.migrate
    CANLIX_DATABASE_URL=postgresql://canlix:canlix@localhost:5433/canlix \
        pytest tests/integration/ -v
"""

from __future__ import annotations

import os

import pytest

DB_URL = os.getenv("CANLIX_DATABASE_URL", "")

pytestmark = pytest.mark.skipif(not DB_URL, reason="CANLIX_DATABASE_URL not set")


@pytest.fixture(scope="session")
def pool():
    """One connection pool for the whole test session."""
    from psycopg_pool import ConnectionPool

    p = ConnectionPool(DB_URL, min_size=1, max_size=5, open=True)
    yield p
    p.close()


@pytest.fixture(autouse=True)
def _truncate(pool):
    """Wipe every table before each test so they are fully isolated."""
    with pool.connection() as conn:
        conn.execute("TRUNCATE findings, scans, projects, tokens, orgs RESTART IDENTITY CASCADE")


@pytest.fixture
def store(pool):
    from saas.pg_store import PgStore

    return PgStore(pool)


# ---------------------------------------------------------------------------
# NormalizedFinding helper
# ---------------------------------------------------------------------------


def _finding(rule_id="R001", severity="HIGH", confidence="HIGH", fp=None):
    from saas.ingest import NormalizedFinding

    fingerprint = fp or f"fp-{rule_id}"
    return NormalizedFinding(
        fingerprint=fingerprint,
        kind="config",
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        location="mcp://test-server",
        message=f"Test finding {rule_id}",
        remediation="Fix it",
    )


# ---------------------------------------------------------------------------
# create_org / authenticate
# ---------------------------------------------------------------------------


def test_create_org_returns_org_and_token(store):
    org, token = store.create_org("Acme")
    assert org.name == "Acme"
    assert org.plan == "free"
    assert len(token) > 20


def test_authenticate_valid_token(store):
    org, token = store.create_org("Beta")
    result = store.authenticate(token)
    assert result is not None
    assert result.id == org.id
    assert result.name == "Beta"


def test_authenticate_invalid_token_returns_none(store):
    store.create_org("Gamma")
    assert store.authenticate("bad-token") is None


def test_authenticate_unknown_prefix_timing_guard(store):
    # Must not raise, must return None — timing guard path
    assert store.authenticate("xx" + "a" * 40) is None


# ---------------------------------------------------------------------------
# create_project
# ---------------------------------------------------------------------------


def test_create_project(store):
    org, _ = store.create_org("Delta")
    project = store.create_project(org.id, "scanner-v1")
    assert project.name == "scanner-v1"
    assert project.org_id == org.id


def test_plan_limit_free(store):
    from saas.store import PlanLimitError

    org, _ = store.create_org("Echo", plan="free")
    store.create_project(org.id, "p1")
    with pytest.raises(PlanLimitError):
        store.create_project(org.id, "p2")


def test_list_projects_empty(store):
    org, _ = store.create_org("Foxtrot")
    assert store.list_projects(org.id) == []


def test_list_projects(store):
    org, _ = store.create_org("Golf", plan="team")
    store.create_project(org.id, "alpha")
    store.create_project(org.id, "beta")
    names = {p.name for p in store.list_projects(org.id)}
    assert names == {"alpha", "beta"}


def test_get_project_cross_tenant_returns_none(store):
    org_a, _ = store.create_org("Hotel", plan="team")
    org_b, _ = store.create_org("India", plan="team")
    proj = store.create_project(org_a.id, "secret")
    assert store.get_project(org_b.id, proj.id) is None


# ---------------------------------------------------------------------------
# add_scan / list_scans / get_scan
# ---------------------------------------------------------------------------


def test_add_scan_baseline(store):
    org, _ = store.create_org("Juliet", plan="team")
    proj = store.create_project(org.id, "p")
    scan = store.add_scan(org.id, proj.id, [_finding()])
    assert scan is not None
    assert scan.diff.baseline is True
    assert len(scan.findings) == 1
    assert scan.score > 0


def test_add_scan_diff_new_vs_fixed(store):
    org, _ = store.create_org("Kilo", plan="team")
    proj = store.create_project(org.id, "p")

    store.add_scan(org.id, proj.id, [_finding("R001", fp="fp-R001"), _finding("R002", fp="fp-R002")])
    scan2 = store.add_scan(org.id, proj.id, [_finding("R002", fp="fp-R002"), _finding("R003", fp="fp-R003")])

    assert scan2 is not None
    assert scan2.diff.baseline is False
    assert "fp-R001" in scan2.diff.fixed
    assert "fp-R003" in scan2.diff.new
    assert "fp-R002" in scan2.diff.persisting


def test_add_scan_cross_tenant_returns_none(store):
    org_a, _ = store.create_org("Lima", plan="team")
    org_b, _ = store.create_org("Mike", plan="team")
    proj = store.create_project(org_a.id, "p")
    result = store.add_scan(org_b.id, proj.id, [_finding()])
    assert result is None


def test_list_scans_ordered_newest_first(store):
    org, _ = store.create_org("November", plan="team")
    proj = store.create_project(org.id, "p")
    store.add_scan(org.id, proj.id, [_finding("R001", fp="f1")])
    store.add_scan(org.id, proj.id, [_finding("R002", fp="f2")])
    scans = store.list_scans(org.id, proj.id)
    assert scans is not None
    assert len(scans) == 2
    # newest first
    assert scans[0].created_at >= scans[1].created_at


def test_list_scans_cross_tenant_returns_none(store):
    org_a, _ = store.create_org("Oscar", plan="team")
    org_b, _ = store.create_org("Papa", plan="team")
    proj = store.create_project(org_a.id, "p")
    store.add_scan(org_a.id, proj.id, [])
    assert store.list_scans(org_b.id, proj.id) is None


def test_get_scan_round_trip(store):
    org, _ = store.create_org("Quebec", plan="team")
    proj = store.create_project(org.id, "p")
    added = store.add_scan(org.id, proj.id, [_finding("R999", fp="fp-999")])
    assert added is not None
    fetched = store.get_scan(org.id, proj.id, added.id)
    assert fetched is not None
    assert fetched.id == added.id
    assert len(fetched.findings) == 1
    assert fetched.findings[0].fingerprint == "fp-999"


def test_get_scan_cross_tenant_returns_none(store):
    org_a, _ = store.create_org("Romeo", plan="team")
    org_b, _ = store.create_org("Sierra", plan="team")
    proj = store.create_project(org_a.id, "p")
    scan = store.add_scan(org_a.id, proj.id, [_finding()])
    assert scan is not None
    assert store.get_scan(org_b.id, proj.id, scan.id) is None


def test_empty_findings_scan(store):
    org, _ = store.create_org("Tango", plan="team")
    proj = store.create_project(org.id, "p")
    scan = store.add_scan(org.id, proj.id, [])
    assert scan is not None
    assert len(scan.findings) == 0
    assert scan.score == 100


def test_persistence_across_pool_connections(store, pool):
    """Data written in one connection is visible through another (basic sanity check)."""
    org, _ = store.create_org("Uniform", plan="team")
    proj = store.create_project(org.id, "p")
    store.add_scan(org.id, proj.id, [_finding()])

    # Fresh PgStore instance shares the same pool
    from saas.pg_store import PgStore

    store2 = PgStore(pool)
    scans = store2.list_scans(org.id, proj.id)
    assert scans is not None
    assert len(scans) == 1
