"""PostgreSQL-backed store — same contract as saas/store.py (in-memory).

Every method takes org_id and returns None for rows of another tenant.
RLS (projects/scans/findings) is defence-in-depth; app-level filtering is primary.
"""

from __future__ import annotations

import hmac as _hmac
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

from psycopg_pool import ConnectionPool

from saas.diff import ScanDiff, diff_scans
from saas.ingest import NormalizedFinding, compute_score
from saas.security import hash_token, lookup_key, new_api_token, verify_token
from saas.store import PLANS, Org, PlanLimitError, Project, Scan, UnknownPlanError, _ttl_to_dt


def _jsonb(value: object) -> object:
    """Wrap a Python value for psycopg3 JSONB insertion."""
    from psycopg.types.json import Jsonb  # local import — only needed with PgStore

    return Jsonb(value)


class PgStore:
    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    # ------------------------------------------------------------------
    # Org
    # ------------------------------------------------------------------

    def create_org(self, name: str, plan: str = "free", token_ttl_days: int | None = None) -> tuple[Org, str]:
        if plan not in PLANS:
            raise UnknownPlanError(plan)
        token, key, digest = new_api_token()
        org_id = uuid.uuid4().hex
        expires_at = _ttl_to_dt(token_ttl_days)
        with self._pool.connection() as conn:
            with conn.transaction():
                conn.execute(
                    "INSERT INTO orgs(id, name, plan) VALUES(%s, %s, %s)",
                    [org_id, name, plan],
                )
                conn.execute(
                    "INSERT INTO tokens(lookup_key, digest, org_id, expires_at) VALUES(%s, %s, %s, %s)",
                    [key, digest, org_id, expires_at],
                )
        return Org(org_id, name, plan), token

    def authenticate(self, token: str) -> Org | None:
        key = lookup_key(token)
        now = datetime.now(timezone.utc)
        with self._pool.connection() as conn:
            rows = conn.execute(
                """SELECT t.digest, o.id, o.name, o.plan
                   FROM tokens t JOIN orgs o ON t.org_id = o.id
                   WHERE t.lookup_key = %s
                     AND t.revoked_at IS NULL
                     AND (t.expires_at IS NULL OR t.expires_at > %s)""",
                [key, now],
            ).fetchall()
        for row in rows:
            if verify_token(token, row[0]):
                return Org(row[1], row[2], row[3])
        # M2: equalize timing for unknown-prefix branch
        _hmac.compare_digest(hash_token(token), hash_token(token))
        return None

    def revoke_token(self, org_id: str, token: str) -> bool:
        """Mark a token as revoked. Returns False if the token is not found/valid for this org."""
        key = lookup_key(token)
        with self._pool.connection() as conn:
            rows = conn.execute(
                """SELECT t.digest FROM tokens t
                   WHERE t.lookup_key = %s AND t.org_id = %s AND t.revoked_at IS NULL""",
                [key, org_id],
            ).fetchall()
            for row in rows:
                if verify_token(token, row[0]):
                    conn.execute(
                        "UPDATE tokens SET revoked_at = now() WHERE lookup_key = %s AND digest = %s",
                        [key, row[0]],
                    )
                    return True
        return False

    def rotate_token(self, org_id: str, old_token: str, token_ttl_days: int | None = None) -> str | None:
        """Atomically revoke old token and issue a new one. Returns new token or None if invalid."""
        key = lookup_key(old_token)
        new_token, new_key, new_digest = new_api_token()
        expires_at = _ttl_to_dt(token_ttl_days)
        with self._pool.connection() as conn:
            with conn.transaction():
                rows = conn.execute(
                    """SELECT t.digest FROM tokens t
                       WHERE t.lookup_key = %s AND t.org_id = %s AND t.revoked_at IS NULL""",
                    [key, org_id],
                ).fetchall()
                found = False
                for row in rows:
                    if verify_token(old_token, row[0]):
                        conn.execute(
                            "UPDATE tokens SET revoked_at = now() WHERE lookup_key = %s AND digest = %s",
                            [key, row[0]],
                        )
                        found = True
                        break
                if not found:
                    return None
                conn.execute(
                    "INSERT INTO tokens(lookup_key, digest, org_id, expires_at) VALUES(%s, %s, %s, %s)",
                    [new_key, new_digest, org_id, expires_at],
                )
        return new_token

    # ------------------------------------------------------------------
    # Project
    # ------------------------------------------------------------------

    def create_project(self, org_id: str, name: str) -> Project:
        with self._pool.connection() as conn:
            with conn.transaction():
                org_row = conn.execute("SELECT plan FROM orgs WHERE id = %s", [org_id]).fetchone()
                if not org_row:
                    raise KeyError(org_id)
                plan = org_row[0]
                count = conn.execute("SELECT COUNT(*) FROM projects WHERE org_id = %s", [org_id]).fetchone()[0]
                if count >= PLANS[plan]["projects"]:
                    raise PlanLimitError(f"plan '{plan}' allows {PLANS[plan]['projects']} project(s)")
                project_id = uuid.uuid4().hex
                conn.execute(
                    "INSERT INTO projects(id, org_id, name) VALUES(%s, %s, %s)",
                    [project_id, org_id, name],
                )
        return Project(project_id, org_id, name)

    def list_projects(self, org_id: str) -> list[Project]:
        with self._pool.connection() as conn:
            rows = conn.execute(
                "SELECT id, org_id, name FROM projects WHERE org_id = %s ORDER BY created_at",
                [org_id],
            ).fetchall()
        return [Project(r[0], r[1], r[2]) for r in rows]

    def get_project(self, org_id: str, project_id: str) -> Project | None:
        with self._pool.connection() as conn:
            row = conn.execute(
                "SELECT id, org_id, name FROM projects WHERE id = %s AND org_id = %s",
                [project_id, org_id],
            ).fetchone()
        return Project(row[0], row[1], row[2]) if row else None

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    def add_scan(self, org_id: str, project_id: str, findings: list[NormalizedFinding]) -> Scan | None:
        with self._pool.connection() as conn:
            with conn.transaction():
                # Set RLS context (defence-in-depth; app-level check below is primary)
                conn.execute("SELECT set_config('app.org_id', %s, true)", [org_id])

                proj = conn.execute(
                    "SELECT id FROM projects WHERE id = %s AND org_id = %s",
                    [project_id, org_id],
                ).fetchone()
                if not proj:
                    return None

                # Fetch previous scan fingerprints for diff
                prev = conn.execute(
                    "SELECT id FROM scans WHERE project_id = %s ORDER BY created_at DESC LIMIT 1",
                    [project_id],
                ).fetchone()
                prev_findings = None
                if prev:
                    fp_rows = conn.execute("SELECT fingerprint FROM findings WHERE scan_id = %s", [prev[0]]).fetchall()
                    prev_findings = [SimpleNamespace(fingerprint=r[0]) for r in fp_rows]

                diff = diff_scans(prev_findings, findings)
                score = compute_score(findings)
                scan_id = uuid.uuid4().hex
                now = datetime.now(timezone.utc)

                diff_dict = {
                    "baseline": diff.baseline,
                    "new": list(diff.new),
                    "fixed": list(diff.fixed),
                    "persisting": list(diff.persisting),
                }
                conn.execute(
                    """INSERT INTO scans(id, project_id, org_id, created_at, score, total_findings, diff)
                       VALUES(%s, %s, %s, %s, %s, %s, %s)""",
                    [scan_id, project_id, org_id, now, score, len(findings), _jsonb(diff_dict)],
                )
                for f in findings:
                    conn.execute(
                        """INSERT INTO findings(id, scan_id, org_id, fingerprint, kind, rule_id,
                           severity, confidence, location, message, remediation, occurrences)
                           VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                        [
                            uuid.uuid4().hex,
                            scan_id,
                            org_id,
                            f.fingerprint,
                            f.kind,
                            f.rule_id,
                            f.severity,
                            f.confidence,
                            f.location,
                            f.message,
                            f.remediation,
                            f.occurrences,
                        ],
                    )

        return Scan(scan_id, project_id, now, score, tuple(findings), diff)

    def list_scans(self, org_id: str, project_id: str, limit: int = 50) -> list[Scan] | None:
        if not self.get_project(org_id, project_id):
            return None
        with self._pool.connection() as conn:
            scan_rows = conn.execute(
                """SELECT id, project_id, created_at, score, total_findings, diff
                   FROM scans WHERE project_id = %s AND org_id = %s
                   ORDER BY created_at DESC LIMIT %s""",
                [project_id, org_id, limit],
            ).fetchall()
            if not scan_rows:
                return []
            scan_ids = [r[0] for r in scan_rows]
            finding_rows = conn.execute(
                """SELECT scan_id, fingerprint, kind, rule_id, severity, confidence,
                   location, message, remediation, occurrences
                   FROM findings WHERE scan_id = ANY(%s)""",
                [scan_ids],
            ).fetchall()

        findings_by_scan: dict[str, list[NormalizedFinding]] = {sid: [] for sid in scan_ids}
        for fr in finding_rows:
            findings_by_scan[fr[0]].append(
                NormalizedFinding(
                    fingerprint=fr[1],
                    kind=fr[2],
                    rule_id=fr[3],
                    severity=fr[4],
                    confidence=fr[5],
                    location=fr[6],
                    message=fr[7],
                    remediation=fr[8],
                    occurrences=fr[9],
                )
            )

        result = []
        for r in scan_rows:
            diff_data = r[5]
            diff = ScanDiff(
                baseline=diff_data["baseline"],
                new=tuple(diff_data["new"]),
                fixed=tuple(diff_data["fixed"]),
                persisting=tuple(diff_data["persisting"]),
            )
            result.append(
                Scan(
                    id=r[0],
                    project_id=r[1],
                    created_at=r[2],
                    score=r[3],
                    findings=tuple(findings_by_scan[r[0]]),
                    diff=diff,
                )
            )
        return result

    def get_scan(self, org_id: str, project_id: str, scan_id: str) -> Scan | None:
        if not self.get_project(org_id, project_id):
            return None
        with self._pool.connection() as conn:
            scan_row = conn.execute(
                """SELECT id, project_id, created_at, score, diff
                   FROM scans WHERE id = %s AND project_id = %s AND org_id = %s""",
                [scan_id, project_id, org_id],
            ).fetchone()
            if not scan_row:
                return None
            finding_rows = conn.execute(
                """SELECT fingerprint, kind, rule_id, severity, confidence,
                   location, message, remediation, occurrences
                   FROM findings WHERE scan_id = %s""",
                [scan_id],
            ).fetchall()

        diff_data = scan_row[4]
        diff = ScanDiff(
            baseline=diff_data["baseline"],
            new=tuple(diff_data["new"]),
            fixed=tuple(diff_data["fixed"]),
            persisting=tuple(diff_data["persisting"]),
        )
        findings = tuple(
            NormalizedFinding(
                fingerprint=fr[0],
                kind=fr[1],
                rule_id=fr[2],
                severity=fr[3],
                confidence=fr[4],
                location=fr[5],
                message=fr[6],
                remediation=fr[7],
                occurrences=fr[8],
            )
            for fr in finding_rows
        )
        return Scan(
            id=scan_row[0],
            project_id=scan_row[1],
            created_at=scan_row[2],
            score=scan_row[3],
            findings=findings,
            diff=diff,
        )
