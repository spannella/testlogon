"""RSK-003/RSK-004 — ATS résumé search + skill-based candidate/job-order search.

Static routes (/search/resume, /search/skills) are declared BEFORE any
dynamic /{candidate_id} or /{job_order_id} routes from the CND/JOB clusters
(FastAPI declaration-order constraint, CLAUDE.md "KYC template-signature endpoints").

All endpoints gate on S.candidates_enabled.
"""
from __future__ import annotations

from typing import Dict, List, Union

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.roles import Role, normalize_role
from app.core.settings import S
from app.models import (
    CandidateMatchOut,
    JobOrderMatchOut,
    ResumeSearchOut,
    ResumeSearchResultItem,
    SkillSearchResultsOut,
)
from app.services.rate_limit import _bucket_limit
from app.services.sessions import require_ui_session

router = APIRouter(tags=["ats-recruiting"])


def _check_candidates_flag() -> None:
    if not S.candidates_enabled:
        raise HTTPException(status_code=404)


# ─────────────────────────────────────────────────────────────────────────────
# RSK-003: Résumé full-text search
# Declared BEFORE /{candidate_id} routes (CND-002 owns those)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/ui/ats/candidates/search/resume", response_model=ResumeSearchOut)
async def search_resumes_endpoint(
    q: str = Query(..., min_length=2, max_length=200),
    limit: int = Query(25, ge=1, le=50),
    all: bool = Query(False),
    ctx: Dict = Depends(require_ui_session),
):
    """Full-text search over extracted résumé content."""
    _check_candidates_flag()

    user_sub = ctx["user_sub"]
    if not _bucket_limit(user_sub, "rl#resume_search", 30, 60):
        raise HTTPException(status_code=429, detail="Too many requests")

    # Owner scope
    owner_scope = None
    if not all:
        owner_scope = user_sub
    elif normalize_role(ctx["role"]) not in {Role.ADMIN, Role.ROOT}:
        raise HTTPException(status_code=403, detail="admin required for all=true")

    from app.services.resume_search import search_resumes

    items_raw = search_resumes(q, owner_sub=owner_scope, limit=limit)
    items = [
        ResumeSearchResultItem(
            candidate_id=r["candidate_id"],
            name_snippet=r.get("name_snippet", ""),
            owner_sub=r.get("owner_sub", ""),
            updated_at=int(r.get("updated_at", 0)),
        )
        for r in items_raw
    ]
    return ResumeSearchOut(
        items=items,
        query=q,
        total_estimate=len(items),
        has_more=len(items) >= limit,
    )


# ─────────────────────────────────────────────────────────────────────────────
# RSK-004: Skill-based candidate search
# Declared BEFORE /{candidate_id} routes
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/ui/ats/candidates/search/skills", response_model=SkillSearchResultsOut)
async def search_candidates_by_skills_endpoint(
    skill_ids: str = Query(..., description="Comma-separated skill IDs or names"),
    match: str = Query("all", pattern="^(all|any)$"),
    limit: int = Query(50, ge=1, le=200),
    all: bool = Query(False),
    ctx: Dict = Depends(require_ui_session),
):
    """Search candidates by skill IDs (AND/OR semantics)."""
    _check_candidates_flag()

    if not _bucket_limit(ctx["user_sub"], "rl#ats_skill_search", 30, 60):
        raise HTTPException(status_code=429, detail="Too many requests")

    skill_id_list = [s.strip() for s in skill_ids.split(",") if s.strip()]
    if not skill_id_list:
        raise HTTPException(status_code=422, detail={"code": "skill_ids_required"})

    # Owner scope
    is_admin = normalize_role(ctx["role"]) in {Role.ADMIN, Role.ROOT}
    owner_scope = None if (all and is_admin) else ctx["user_sub"]
    if all and not is_admin:
        owner_scope = ctx["user_sub"]  # silently scope to own

    from app.services.ats_skills import find_candidates_by_skills

    try:
        raw = find_candidates_by_skills(
            skill_id_list, match=match, owner_sub=owner_scope, limit=limit
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # Strip email for non-admin callers
    items: List[CandidateMatchOut] = []
    for r in raw:
        email = r.get("email") if is_admin else None
        items.append(
            CandidateMatchOut(
                candidate_id=r["candidate_id"],
                name=r.get("name", ""),
                email=email,
                matched_skill_ids=r.get("matched_skill_ids", []),
                match_score=r.get("match_score", 0.0),
                owner_sub=r.get("owner_sub") if is_admin else None,
            )
        )

    from app.services.ats_skills import normalize_skill
    normalized_ids: List[str] = []
    for sid in skill_id_list:
        try:
            normalized_ids.append(normalize_skill(sid)[0])
        except Exception:
            pass

    return SkillSearchResultsOut(
        items=items,  # type: ignore[arg-type]
        total=len(items),
        query_skill_ids=normalized_ids,
        match=match,
    )


# ─────────────────────────────────────────────────────────────────────────────
# RSK-004: Skill-based job-order search
# Declared BEFORE /{job_order_id} routes
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/ui/ats/job-orders/search/skills", response_model=SkillSearchResultsOut)
async def search_job_orders_by_skills_endpoint(
    skill_ids: str = Query(...),
    match: str = Query("all", pattern="^(all|any)$"),
    required_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
    ctx: Dict = Depends(require_ui_session),
):
    """Search job orders by skill IDs."""
    _check_candidates_flag()

    if not _bucket_limit(ctx["user_sub"], "rl#ats_skill_search", 30, 60):
        raise HTTPException(status_code=429, detail="Too many requests")

    skill_id_list = [s.strip() for s in skill_ids.split(",") if s.strip()]
    if not skill_id_list:
        raise HTTPException(status_code=422, detail={"code": "skill_ids_required"})

    from app.services.ats_skills import find_job_orders_by_skills

    try:
        raw = find_job_orders_by_skills(
            skill_id_list, match=match, required_only=required_only, limit=limit
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    items: List[JobOrderMatchOut] = [
        JobOrderMatchOut(
            job_order_id=r["job_order_id"],
            title=r.get("title", ""),
            status=r.get("status", "unknown"),
            matched_skill_ids=r.get("matched_skill_ids", []),
            match_score=r.get("match_score", 0.0),
        )
        for r in raw
    ]

    from app.services.ats_skills import normalize_skill
    normalized_ids: List[str] = []
    for sid in skill_id_list:
        try:
            normalized_ids.append(normalize_skill(sid)[0])
        except Exception:
            pass

    return SkillSearchResultsOut(
        items=items,  # type: ignore[arg-type]
        total=len(items),
        query_skill_ids=normalized_ids,
        match=match,
    )


# ─────────────────────────────────────────────────────────────────────────────
# RSK-004: Matching candidates for job order
# Dynamic suffix route (after static /search/skills routes)
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/ui/ats/job-orders/{job_order_id}/matching-candidates",
    response_model=SkillSearchResultsOut,
)
async def matching_candidates_for_job_order_endpoint(
    job_order_id: str,
    limit: int = Query(50, ge=1, le=200),
    ctx: Dict = Depends(require_ui_session),
):
    """Return ranked candidates by how well they match a job order's required skills."""
    _check_candidates_flag()

    if not _bucket_limit(ctx["user_sub"], "rl#ats_match_candidates", 10, 60):
        raise HTTPException(status_code=429, detail="Too many requests")

    # Authorization: verify ownership or admin
    is_admin = normalize_role(ctx["role"]) in {Role.ADMIN, Role.ROOT}
    if not is_admin:
        # Try to look up job order ownership (lazy — job_orders table may not exist)
        try:
            from app.core.tables import T as _T
            resp = _T.job_orders.query(  # type: ignore[attr-defined]
                IndexName="GSI_DIRECT",
                KeyConditionExpression="job_id = :jid",
                ExpressionAttributeValues={":jid": job_order_id},
                Limit=1,
            )
            rows = resp.get("Items", [])
            if not rows:
                raise HTTPException(status_code=404, detail="Job order not found")
            recruiter_subs = rows[0].get("recruiter_subs", [])
            if ctx["user_sub"] not in recruiter_subs:
                raise HTTPException(status_code=403, detail="Access denied")
        except HTTPException:
            raise
        except Exception:
            # job_orders table not available; allow (will be gated by CND/JOB routers)
            pass

    from app.services.ats_skills import match_candidates_to_job_order, list_entity_skills

    raw = match_candidates_to_job_order(
        job_order_id, actor_sub=ctx["user_sub"], limit=limit
    )

    # Fetch required skill IDs for the response envelope
    all_skills = list_entity_skills("job_order", job_order_id)
    required_skill_ids = [s["skill_id"] for s in all_skills if s.get("required")]

    items: List[CandidateMatchOut] = []
    for r in raw:
        email = r.get("email") if is_admin else None
        items.append(
            CandidateMatchOut(
                candidate_id=r["candidate_id"],
                name=r.get("name", ""),
                email=email,
                matched_skill_ids=r.get("matched_skill_ids", []),
                match_score=r.get("match_score", 0.0),
                owner_sub=r.get("owner_sub") if is_admin else None,
            )
        )

    return SkillSearchResultsOut(
        items=items,  # type: ignore[arg-type]
        total=len(items),
        query_skill_ids=required_skill_ids,
        match="all",
    )
