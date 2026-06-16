"""RSK-001/RSK-004 — ATS Skill Registry + Skill-Based Search router.

All endpoints require require_ui_session (cookie auth + CSRF on non-GET).
Gated by S.candidates_enabled AND S.ats_skills_enabled.

Static routes are declared before any dynamic /{...} routes per FastAPI
declaration-order constraint (CLAUDE.md "KYC template-signature endpoints").
"""
from __future__ import annotations

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.roles import Role, normalize_role
from app.core.settings import S
from app.models import (
    EntitySkillsOut,
    SkillAssignmentIn,
    SkillOut,
    SkillSearchResultsOut,
    CandidateMatchOut,
    JobOrderMatchOut,
)
from app.services.rate_limit import _bucket_limit
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/ats/skills", tags=["ats-skills"])


def _check_flag() -> None:
    if not (S.candidates_enabled and S.ats_skills_enabled):
        raise HTTPException(status_code=404)


# ─────────────────────────────────────────────────────────────────────────────
# RSK-001 endpoints: skill registry + assignment
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/search")
def search_skills_endpoint(
    prefix: str = Query(..., min_length=1, max_length=100),
    limit: int = Query(20, ge=1, le=50),
    ctx: Dict = Depends(require_ui_session),
):
    """Autocomplete skill names by prefix."""
    _check_flag()
    from app.services.ats_skills import search_skills

    if not _bucket_limit(ctx["user_sub"], "ats:skills:search", 60, 60):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    items = search_skills(prefix, limit=min(limit, 50))
    skills = [
        SkillOut(
            skill_id=item.get("skill_id", ""),
            name=item.get("name", ""),
            usage_count=int(item.get("usage_count", 0)),
            created_at=int(item.get("created_at", 0)),
        )
        for item in items
    ]
    return {"skills": skills}


@router.get("/entity/{entity_type}/{entity_id}")
def list_entity_skills_endpoint(
    entity_type: str,
    entity_id: str,
    ctx: Dict = Depends(require_ui_session),
):
    """List all skills assigned to an entity."""
    _check_flag()
    if entity_type not in ("candidate", "job_order"):
        raise HTTPException(status_code=422, detail="Invalid entity_type")

    from app.services.ats_skills import list_entity_skills

    skills_raw = list_entity_skills(entity_type, entity_id)
    skills = [
        SkillOut(
            skill_id=s["skill_id"],
            name=s["name"],
            weight=s.get("weight"),
            required=s.get("required"),
            created_at=s.get("created_at", 0),
        )
        for s in skills_raw
    ]
    return EntitySkillsOut(
        entity_type=entity_type,
        entity_id=entity_id,
        skills=skills,
    )


@router.post("/entity/{entity_type}/{entity_id}", status_code=201)
def assign_skill_endpoint(
    entity_type: str,
    entity_id: str,
    body: SkillAssignmentIn,
    ctx: Dict = Depends(require_ui_session),
):
    """Assign a skill to an entity."""
    _check_flag()
    if entity_type not in ("candidate", "job_order"):
        raise HTTPException(status_code=422, detail="Invalid entity_type")

    from app.services.ats_skills import assign_skill

    result = assign_skill(
        entity_type,
        entity_id,
        body.name,
        weight=body.weight,
        required=body.required,
        actor_sub=ctx["user_sub"],
    )
    return SkillOut(
        skill_id=result["skill_id"],
        name=result["name"],
        weight=result.get("weight"),
        required=result.get("required"),
        created_at=result.get("created_at", 0),
    )


@router.delete("/entity/{entity_type}/{entity_id}/{skill_id}")
def unassign_skill_endpoint(
    entity_type: str,
    entity_id: str,
    skill_id: str,
    ctx: Dict = Depends(require_ui_session),
):
    """Unassign a skill from an entity."""
    _check_flag()
    if entity_type not in ("candidate", "job_order"):
        raise HTTPException(status_code=422, detail="Invalid entity_type")

    from app.services.ats_skills import unassign_skill

    unassign_skill(entity_type, entity_id, skill_id, ctx["user_sub"])
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────────────────
# RSK-003 endpoint: résumé full-text search
# ─────────────────────────────────────────────────────────────────────────────

# Declared here (before any /{candidate_id} dynamic route) per declaration-order
# constraint. Prefix is /ui/ats/candidates so we need a separate router or
# use the resume router (see ats_resume.py). This function is defined in
# ats_resume.py to keep résumé concerns together. Nothing here.


# ─────────────────────────────────────────────────────────────────────────────
# RSK-004 endpoints: skill-based search + matching
# ─────────────────────────────────────────────────────────────────────────────

# NOTE: These endpoints use /ui/ats/candidates and /ui/ats/job-orders prefixes.
# They are registered in ats_recruiting.py to allow declaration before
# any dynamic candidate/job-order routes from CND/JOB clusters.
