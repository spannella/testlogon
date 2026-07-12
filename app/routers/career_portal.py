"""ATS Career Portal router (PRT-001..PRT-005).

Admin-facing: /ui/admin/career-portal/* (require_ui_session + ADMIN/ROOT gate)
Public-facing: /public/careers/* (no auth; unauthenticated)

Route declaration order on public_router (CRITICAL — FastAPI matches in order):
  GET  /config          ← static  (PRT-002)
  GET  /jobs            ← static  (PRT-002)
  GET  /jobs.rss        ← static  (PRT-003) must precede /jobs/{slug}
  GET  /jobs/{slug}     ← dynamic (PRT-002)
  POST /jobs/{slug}/resume-presign  ← dynamic (PRT-005)
  POST /jobs/{slug}/apply           ← dynamic (PRT-004)
"""

from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response as _FastAPIResponse

from app.auth.roles import Role, role_allows_admin_features
from app.models import (
    CareerApplyIn,
    CareerApplyOut,
    CareerJobDetailOut,
    CareerJobListOut,
    CareerPortalConfigIn,
    CareerPortalConfigOut,
    CareerResumePresignIn,
    CareerResumePresignOut,
)
from app.services.career_portal import (
    build_jobs_rss,
    create_application,
    get_job_detail,
    get_portal_config,
    get_portal_config_public,
    list_public_jobs,
    presign_resume_upload,
    set_portal_config,
)
from app.services.sessions import require_ui_session

# ── Admin router (session-auth required) ────────────────────────────────────

router = APIRouter(prefix="/ui/admin/career-portal", tags=["career_portal_admin"])

# ── Public router skeleton (no auth; populated by PRT-002+) ─────────────────

public_router = APIRouter(prefix="/public/careers", tags=["career_portal_public"])


# ── PRT-001: Admin config endpoints ─────────────────────────────────────────


@router.get("/config", response_model=CareerPortalConfigOut)
def admin_get_config(ctx: dict = Depends(require_ui_session)) -> CareerPortalConfigOut:
    if not role_allows_admin_features(ctx.get("role")):
        raise HTTPException(status_code=403, detail="Admin or Root role required")
    return get_portal_config()


@router.put("/config", response_model=CareerPortalConfigOut)
def admin_put_config(
    body: CareerPortalConfigIn,
    ctx: dict = Depends(require_ui_session),
) -> CareerPortalConfigOut:
    if not role_allows_admin_features(ctx.get("role")):
        raise HTTPException(status_code=403, detail="Admin or Root role required")
    return set_portal_config(body.model_dump(), actor_sub=ctx["user_sub"])


# ── PRT-002: Static public paths (must precede dynamic /jobs/{slug}) ─────────


@public_router.get("/config", response_model=CareerPortalConfigOut)
def public_get_config() -> CareerPortalConfigOut:
    return get_portal_config_public()


@public_router.get("/jobs", response_model=CareerJobListOut)
def public_list_jobs(
    limit: int = Query(default=25, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
) -> CareerJobListOut:
    return list_public_jobs(limit=limit, cursor=cursor)


# ── PRT-003: RSS feed (must precede /jobs/{slug}) ───────────────────────────


@public_router.get("/jobs.rss")
def public_jobs_rss() -> _FastAPIResponse:
    """Public RSS 2.0 feed of all open job postings.
    No auth. Mirrors the calendar iCal handler pattern at
    app/routers/calendar.py:2097-2109.
    Flag off → build_jobs_rss() raises HTTPException(404) via _require_enabled().
    """
    xml = build_jobs_rss()
    return _FastAPIResponse(
        content=xml,
        media_type="application/rss+xml; charset=utf-8",
        headers={
            "Content-Disposition": 'inline; filename="jobs.rss"',
            "X-Content-Type-Options": "nosniff",
        },
    )


# ── PRT-002: Dynamic public path (after all statics) ─────────────────────────


@public_router.get("/jobs/{slug}", response_model=CareerJobDetailOut)
def public_get_job(slug: str) -> CareerJobDetailOut:
    return get_job_detail(slug)


# ── PRT-005: Résumé presign (PRT-005, after GET /jobs/{slug}) ────────────────


@public_router.post("/jobs/{slug}/resume-presign", response_model=CareerResumePresignOut)
async def resume_presign(
    slug: str,
    body: CareerResumePresignIn,
    request: Request,
) -> CareerResumePresignOut:
    from app.core.normalize import client_ip_from_request
    ip = client_ip_from_request(request)
    return await asyncio.to_thread(
        presign_resume_upload,
        slug=slug,
        data=body,
        source_ip=ip,
    )


# ── PRT-004: Self-apply (PRT-004) ────────────────────────────────────────────


@public_router.post(
    "/jobs/{slug}/apply",
    response_model=CareerApplyOut,
    status_code=200,
)
async def apply_to_job(
    slug: str,
    body: CareerApplyIn,
    request: Request,
) -> CareerApplyOut:
    from app.core.normalize import client_ip_from_request
    ip = client_ip_from_request(request)
    return await asyncio.to_thread(
        create_application,
        slug=slug,
        data=body,
        source_ip=ip,
    )
