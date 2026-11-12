"""Apply Canlix database migrations.

Usage:
    python -m saas.migrate                # uses CANLIX_DATABASE_URL env var
    python -m saas.migrate postgresql://user:pass@host/db

Migrations are idempotent: running them twice is safe.
"""

from __future__ import annotations

import os
import sys

_DDL_0001 = """
CREATE TABLE IF NOT EXISTS orgs (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    plan        TEXT NOT NULL CHECK (plan IN ('free', 'team', 'business')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tokens (
    lookup_key  TEXT NOT NULL,
    digest      TEXT NOT NULL,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (lookup_key, digest)
);

CREATE TABLE IF NOT EXISTS projects (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS projects_org_idx ON projects(org_id);

ALTER TABLE projects ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename='projects' AND policyname='projects_tenant'
    ) THEN
        CREATE POLICY projects_tenant ON projects
            USING (org_id = current_setting('app.org_id', true));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    org_id          TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    score           INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    total_findings  INTEGER NOT NULL DEFAULT 0,
    diff            JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS scans_project_created_idx ON scans(project_id, created_at DESC);

ALTER TABLE scans ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename='scans' AND policyname='scans_tenant'
    ) THEN
        CREATE POLICY scans_tenant ON scans
            USING (org_id = current_setting('app.org_id', true));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('config', 'source')),
    rule_id     TEXT NOT NULL,
    severity    TEXT NOT NULL,
    confidence  TEXT NOT NULL,
    location    TEXT NOT NULL,
    message     TEXT NOT NULL,
    remediation TEXT NOT NULL DEFAULT '',
    occurrences INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS findings_scan_idx ON findings(scan_id);
CREATE INDEX IF NOT EXISTS findings_fp_idx   ON findings(fingerprint);

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename='findings' AND policyname='findings_tenant'
    ) THEN
        CREATE POLICY findings_tenant ON findings
            USING (org_id = current_setting('app.org_id', true));
    END IF;
END $$;
"""

_DDL_0002 = """
ALTER TABLE tokens
    ADD COLUMN IF NOT EXISTS revoked_at  TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS expires_at  TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS label       TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS tokens_lookup_active_idx
    ON tokens(lookup_key)
    WHERE revoked_at IS NULL;
"""

_DDL_0003 = """
ALTER TABLE orgs
    ADD COLUMN IF NOT EXISTS email         TEXT UNIQUE NULL,
    ADD COLUMN IF NOT EXISTS password_hash TEXT NULL;
"""

_MIGRATIONS: list[tuple[str, str]] = [
    ("0001_initial", _DDL_0001),
    ("0002_token_revocation", _DDL_0002),
    ("0003_email_auth", _DDL_0003),
]


def upgrade(url: str = "") -> None:
    import psycopg

    url = url or os.environ["CANLIX_DATABASE_URL"]
    with psycopg.connect(url) as conn:
        with conn.transaction():
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS _migrations (
                    version    TEXT PRIMARY KEY,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
        for version, ddl in _MIGRATIONS:
            applied = conn.execute("SELECT 1 FROM _migrations WHERE version = %s", [version]).fetchone()
            if not applied:
                with conn.transaction():
                    conn.execute(ddl)
                    conn.execute("INSERT INTO _migrations(version) VALUES(%s)", [version])
                print(f"Applied  {version}")
            else:
                print(f"Skipped  {version} (already applied)")


if __name__ == "__main__":
    upgrade(sys.argv[1] if len(sys.argv) > 1 else "")
