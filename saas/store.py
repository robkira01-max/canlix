"""Tenant-scoped storage. Every method takes org_id and returns None for rows of another tenant.

This in-memory implementation defines the contract; the PostgreSQL one must keep the same semantics
(see docs/adr/0001-saas-architecture.md).
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from saas.diff import ScanDiff, diff_scans
from saas.ingest import NormalizedFinding, compute_score
from saas.security import hash_token, lookup_key, new_api_token, verify_token

# Proposed limits, to be confirmed with the owner after pricing interviews.
PLANS: dict[str, dict[str, int]] = {
    "free": {"projects": 1},
    "team": {"projects": 10},
    "business": {"projects": 100},
}


class PlanLimitError(Exception):
    pass


class UnknownPlanError(ValueError):
    pass


@dataclass(frozen=True)
class Org:
    id: str
    name: str
    plan: str


@dataclass(frozen=True)
class Project:
    id: str
    org_id: str
    name: str


@dataclass(frozen=True)
class Scan:
    id: str
    project_id: str
    created_at: datetime
    score: int
    findings: tuple[NormalizedFinding, ...]
    diff: ScanDiff


@dataclass
class Store:
    _orgs: dict[str, Org] = field(default_factory=dict)
    _tokens: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    _projects: dict[str, Project] = field(default_factory=dict)
    _scans: dict[str, list[Scan]] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)

    def create_org(self, name: str, plan: str = "free") -> tuple[Org, str]:
        if plan not in PLANS:
            raise UnknownPlanError(plan)
        token, key, digest = new_api_token()
        org = Org(uuid.uuid4().hex, name, plan)
        with self._lock:
            self._orgs[org.id] = org
            self._tokens.setdefault(key, []).append((digest, org.id))
        return org, token

    def authenticate(self, token: str) -> Org | None:
        import hmac as _hmac

        with self._lock:
            candidates = list(self._tokens.get(lookup_key(token), []))
        for digest, org_id in candidates:
            if verify_token(token, digest):
                return self._orgs.get(org_id)
        # M2: equalize timing for unknown-prefix branch — same work as verify_token()
        _hmac.compare_digest(hash_token(token), hash_token(token))
        return None

    def create_project(self, org_id: str, name: str) -> Project:
        with self._lock:
            org = self._orgs[org_id]
            owned = sum(1 for p in self._projects.values() if p.org_id == org_id)
            if owned >= PLANS[org.plan]["projects"]:
                raise PlanLimitError(f"plan '{org.plan}' allows {PLANS[org.plan]['projects']} project(s)")
            project = Project(uuid.uuid4().hex, org_id, name)
            self._projects[project.id] = project
            self._scans[project.id] = []
            return project

    def list_projects(self, org_id: str) -> list[Project]:
        with self._lock:
            return [p for p in self._projects.values() if p.org_id == org_id]

    def get_project(self, org_id: str, project_id: str) -> Project | None:
        with self._lock:
            p = self._projects.get(project_id)
            return p if p and p.org_id == org_id else None

    def add_scan(self, org_id: str, project_id: str, findings: list[NormalizedFinding]) -> Scan | None:
        with self._lock:
            if not self.get_project(org_id, project_id):
                return None
            history = self._scans[project_id]
            diff = diff_scans(history[-1].findings if history else None, findings)
            scan = Scan(
                uuid.uuid4().hex, project_id, datetime.now(timezone.utc), compute_score(findings), tuple(findings), diff
            )
            history.append(scan)
            return scan

    def list_scans(self, org_id: str, project_id: str, limit: int = 50) -> list[Scan] | None:
        with self._lock:
            if not self.get_project(org_id, project_id):
                return None
            return list(reversed(self._scans[project_id]))[:limit]

    def get_scan(self, org_id: str, project_id: str, scan_id: str) -> Scan | None:
        with self._lock:
            if not self.get_project(org_id, project_id):
                return None
            return next((s for s in self._scans.get(project_id, []) if s.id == scan_id), None)
