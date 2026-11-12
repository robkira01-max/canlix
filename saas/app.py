"""Canlix SaaS HTTP layer.

Endpoints
---------
POST /orgs                                create org, returns token shown ONCE
GET  /orgs/me                             current org
POST /projects                            create project
GET  /projects                            list projects
GET  /projects/{id}                       get project
POST /projects/{id}/scans                 ingest a scan report
GET  /projects/{id}/scans                 list scans (newest first, max 100)
GET  /projects/{id}/scans/{scan_id}       scan detail with findings
GET  /health                              liveness probe, no auth required

Security
--------
- Auth: Bearer token only. org_id never in URL.
- Cross-tenant resource: 404, not 403 (don't reveal existence).
- API docs disabled (openapi_url=None) — don't leak route schema in production.
- Security headers on every response (see _security_headers middleware).
- Body size capped at 5 MB at the middleware level; also checked explicitly in
  ingest_scan before JSON parsing.
- Rate limiting: sliding-window in-memory counter per client IP.
  By default request.client.host is used (safe behind Caddy). Set
  CANLIX_TRUST_PROXY=1 only when the reverse proxy unconditionally overwrites
  X-Forwarded-For before forwarding (Caddy's trusted_proxies directive).
- HSTS is intentionally absent here: it must only appear over HTTPS and is
  set by Caddy. Adding it here would cause it to appear over plain HTTP too.
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Path, Request
from pydantic import BaseModel, Field, ValidationError

from saas.ingest import normalize_report
from saas.store import PLANS, Org, PlanLimitError, Scan, Store, UnknownPlanError

_MAX_BODY_BYTES = 5 * 1024 * 1024  # 5 MB; reverse proxy should also enforce this

app = FastAPI(
    title="Canlix SaaS",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# ---------------------------------------------------------------------------
# Store dependency — override in tests via app.dependency_overrides
# ---------------------------------------------------------------------------

_default_store = Store()


def _get_store() -> Store:
    return _default_store


# ---------------------------------------------------------------------------
# Middleware: security headers + content-length guard
# ---------------------------------------------------------------------------


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        cl = request.headers.get("content-length", "")
        if cl.isdigit() and int(cl) > _MAX_BODY_BYTES:
            from fastapi.responses import JSONResponse  # local import avoids circular

            return JSONResponse({"detail": "payload_too_large"}, status_code=413)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------------------
# Rate limiting: in-memory sliding window per key
# ---------------------------------------------------------------------------

_rate_lock = threading.Lock()
_rate_state: dict[str, list[float]] = {}
_WINDOW = 60.0
_ANON_LIMIT = 10  # POST /orgs per IP per minute
_AUTH_LIMIT = 300  # authenticated calls per IP per minute

# H1 fix: trust XFF only when explicitly enabled (requires proxy to overwrite it)
_TRUST_PROXY = os.getenv("CANLIX_TRUST_PROXY", "").lower() in ("1", "true", "yes")


def _client_ip(request: Request) -> str:
    if _TRUST_PROXY:
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _rate_check(key: str, limit: int) -> None:
    now = time.monotonic()
    with _rate_lock:
        ts = [t for t in _rate_state.get(key, []) if now - t < _WINDOW]
        if len(ts) >= limit:
            raise HTTPException(status_code=429, detail="rate_limit_exceeded")
        ts.append(now)
        _rate_state[key] = ts


# ---------------------------------------------------------------------------
# Authentication dependency
# ---------------------------------------------------------------------------


def _require_org(request: Request, store: Store = Depends(_get_store)) -> Org:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing_or_invalid_token")
    token = auth[7:]
    _rate_check(f"auth:{_client_ip(request)}", _AUTH_LIMIT)
    org = store.authenticate(token)
    if org is None:
        raise HTTPException(status_code=401, detail="missing_or_invalid_token")
    return org


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class CreateOrgBody(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    plan: str = Field(default="free", max_length=20)


class CreateOrgOut(BaseModel):
    org_id: str
    name: str
    plan: str
    token: str = Field(description="API token shown once — do not log or store in version control")


class OrgOut(BaseModel):
    org_id: str
    name: str
    plan: str
    max_projects: int


class CreateProjectBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class ProjectOut(BaseModel):
    project_id: str
    name: str


class DiffOut(BaseModel):
    baseline: bool
    new: int
    fixed: int
    persisting: int


class ScanSummaryOut(BaseModel):
    scan_id: str
    project_id: str
    created_at: str
    score: int
    total_findings: int
    diff: DiffOut


class FindingOut(BaseModel):
    fingerprint: str
    kind: str
    rule_id: str
    severity: str
    confidence: str
    location: str
    message: str
    remediation: str
    occurrences: int


class ScanDetailOut(ScanSummaryOut):
    findings: list[FindingOut]


# H2 fix: strip "input" key from pydantic errors before returning to client
def _safe_errors(exc: ValidationError) -> list[dict]:
    return [{k: v for k, v in e.items() if k != "input"} for e in exc.errors()]


# M1: path-param type alias — only 32-char lowercase hex IDs reach the store
_HexId = Annotated[str, Path(min_length=32, max_length=32, pattern=r"^[0-9a-f]{32}$")]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _diff_out(scan: Scan) -> DiffOut:
    return DiffOut(
        baseline=scan.diff.baseline,
        new=len(scan.diff.new),
        fixed=len(scan.diff.fixed),
        persisting=len(scan.diff.persisting),
    )


def _summary(scan: Scan) -> ScanSummaryOut:
    return ScanSummaryOut(
        scan_id=scan.id,
        project_id=scan.project_id,
        created_at=scan.created_at.isoformat(),
        score=scan.score,
        total_findings=len(scan.findings),
        diff=_diff_out(scan),
    )


def _detail(scan: Scan) -> ScanDetailOut:
    return ScanDetailOut(
        **_summary(scan).model_dump(),
        findings=[FindingOut(**f.__dict__) for f in scan.findings],
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.post("/orgs", status_code=201)
def create_org(body: CreateOrgBody, request: Request, store: Store = Depends(_get_store)) -> CreateOrgOut:
    _rate_check(f"anon:{_client_ip(request)}", _ANON_LIMIT)
    try:
        org, token = store.create_org(body.name, body.plan)
    except UnknownPlanError:
        raise HTTPException(status_code=422, detail="unknown_plan")
    return CreateOrgOut(org_id=org.id, name=org.name, plan=org.plan, token=token)


@app.get("/orgs/me")
def get_me(org: Org = Depends(_require_org)) -> OrgOut:
    return OrgOut(org_id=org.id, name=org.name, plan=org.plan, max_projects=PLANS[org.plan]["projects"])


@app.post("/projects", status_code=201)
def create_project(
    body: CreateProjectBody,
    org: Org = Depends(_require_org),
    store: Store = Depends(_get_store),
) -> ProjectOut:
    try:
        project = store.create_project(org.id, body.name)
    except PlanLimitError:
        raise HTTPException(status_code=402, detail="project_limit_reached")
    return ProjectOut(project_id=project.id, name=project.name)


@app.get("/projects")
def list_projects(org: Org = Depends(_require_org), store: Store = Depends(_get_store)) -> list[ProjectOut]:
    return [ProjectOut(project_id=p.id, name=p.name) for p in store.list_projects(org.id)]


@app.get("/projects/{project_id}")
def get_project(
    project_id: _HexId,
    org: Org = Depends(_require_org),
    store: Store = Depends(_get_store),
) -> ProjectOut:
    p = store.get_project(org.id, project_id)
    if p is None:
        raise HTTPException(status_code=404)
    return ProjectOut(project_id=p.id, name=p.name)


@app.post("/projects/{project_id}/scans", status_code=201)
async def ingest_scan(
    project_id: _HexId,
    request: Request,
    org: Org = Depends(_require_org),
    store: Store = Depends(_get_store),
) -> ScanSummaryOut:
    if store.get_project(org.id, project_id) is None:
        raise HTTPException(status_code=404)
    body = await request.body()
    if len(body) > _MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="payload_too_large")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=422, detail="invalid_json")
    try:
        findings = normalize_report(payload)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=_safe_errors(exc))
    scan = store.add_scan(org.id, project_id, findings)
    if scan is None:
        raise HTTPException(status_code=404)
    return _summary(scan)


@app.get("/projects/{project_id}/scans")
def list_scans(
    project_id: _HexId,
    limit: int = 20,
    org: Org = Depends(_require_org),
    store: Store = Depends(_get_store),
) -> list[ScanSummaryOut]:
    limit = max(1, min(limit, 100))
    scans = store.list_scans(org.id, project_id, limit=limit)
    if scans is None:
        raise HTTPException(status_code=404)
    return [_summary(s) for s in scans]


@app.get("/projects/{project_id}/scans/{scan_id}")
def get_scan(
    project_id: _HexId,
    scan_id: _HexId,
    org: Org = Depends(_require_org),
    store: Store = Depends(_get_store),
) -> ScanDetailOut:
    scan = store.get_scan(org.id, project_id, scan_id)
    if scan is None:
        raise HTTPException(status_code=404)
    return _detail(scan)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
