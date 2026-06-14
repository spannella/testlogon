"""ATS Pipeline router — PIP-008.

Mounts every service function from PIP-001..PIP-006 as HTTP endpoints.
Route ordering: literal-segment routes before any /{...} dynamic segments
so FastAPI's first-match-wins dispatch does not shadow literal paths.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response

from app.auth.roles import Role, normalize_role
from app.core.settings import S
from app.models import (
    PipelineEntryCreateIn,
    PipelineEntryOut,
    PipelineRatingIn,
    PipelineStatusChangeIn,
    PipelineStatusConfigIn,
    PipelineStatusConfigOut,
    PlacementIn,
    PlacementOut,
)
from app.services.ats_pipeline import (
    _require_flag,
    add_to_pipeline,
    change_status,
    get_pipeline_entry,
    get_placement,
    get_status_config,
    list_pipeline_for_candidate,
    list_pipeline_for_job,
    record_placement,
    remove_from_pipeline,
    set_rating,
    set_status_config,
)
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/ats/pipeline", tags=["ats-pipeline"])
router_admin = APIRouter(prefix="/ui/admin/ats", tags=["ats-pipeline-admin"])


# ---------------------------------------------------------------------------
# Probe — declared first so it is never shadowed by /{...} routes
# ---------------------------------------------------------------------------

@router.get("/feature-status")
async def pipeline_feature_status() -> dict:
    """Return the ATS pipeline enabled flag. Does NOT call _require_flag()."""
    return {"enabled": S.ats_pipeline_enabled}


# ---------------------------------------------------------------------------
# Status config (PIP-002)
# ---------------------------------------------------------------------------

@router.get("/statuses", response_model=PipelineStatusConfigOut)
async def list_pipeline_statuses(
    ctx: dict = Depends(require_ui_session),
) -> PipelineStatusConfigOut:
    return get_status_config()


# ---------------------------------------------------------------------------
# Bulk-list by job / candidate (PIP-001) — literal second segments before /{id}
# ---------------------------------------------------------------------------

@router.get("/by-job/{job_order_id}")
async def list_by_job(
    job_order_id: str,
    cursor: Optional[str] = None,
    limit: int = 50,
    ctx: dict = Depends(require_ui_session),
) -> dict:
    return list_pipeline_for_job(ctx["user_sub"], job_order_id, cursor=cursor, limit=limit)


@router.get("/by-candidate/{candidate_id}")
async def list_by_candidate(
    candidate_id: str,
    cursor: Optional[str] = None,
    limit: int = 50,
    ctx: dict = Depends(require_ui_session),
) -> dict:
    return list_pipeline_for_candidate(ctx["user_sub"], candidate_id, cursor=cursor, limit=limit)


# ---------------------------------------------------------------------------
# Pipeline entry CRUD (PIP-001)
# ---------------------------------------------------------------------------

@router.post("/entries", response_model=PipelineEntryOut, status_code=201)
async def create_pipeline_entry(
    body: PipelineEntryCreateIn,
    ctx: dict = Depends(require_ui_session),
) -> PipelineEntryOut:
    return add_to_pipeline(ctx["user_sub"], body)


@router.delete("/by-job/{job_order_id}/candidate/{candidate_id}", status_code=204, response_class=Response)
async def delete_pipeline_entry(
    job_order_id: str,
    candidate_id: str,
    ctx: dict = Depends(require_ui_session),
) -> Response:
    remove_from_pipeline(ctx["user_sub"], job_order_id, candidate_id)
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Status change (PIP-003)
# ---------------------------------------------------------------------------

@router.patch(
    "/by-job/{job_order_id}/candidate/{candidate_id}/status",
    response_model=PipelineEntryOut,
)
async def patch_pipeline_status(
    job_order_id: str,
    candidate_id: str,
    body: PipelineStatusChangeIn,
    ctx: dict = Depends(require_ui_session),
) -> PipelineEntryOut:
    return change_status(
        ctx["user_sub"], job_order_id, candidate_id,
        body.new_status, note=body.note,
    )


# ---------------------------------------------------------------------------
# Rating (PIP-004)
# ---------------------------------------------------------------------------

@router.patch(
    "/by-job/{job_order_id}/candidate/{candidate_id}/rating",
    response_model=PipelineEntryOut,
)
async def patch_pipeline_rating(
    job_order_id: str,
    candidate_id: str,
    body: PipelineRatingIn,
    ctx: dict = Depends(require_ui_session),
) -> PipelineEntryOut:
    return set_rating(ctx["user_sub"], job_order_id, candidate_id, body)


# ---------------------------------------------------------------------------
# Placement (PIP-006)
# ---------------------------------------------------------------------------

@router.post(
    "/by-job/{job_order_id}/candidate/{candidate_id}/placement",
    response_model=PlacementOut,
    status_code=201,
)
async def create_placement(
    job_order_id: str,
    candidate_id: str,
    body: PlacementIn,
    ctx: dict = Depends(require_ui_session),
) -> PlacementOut:
    return record_placement(ctx["user_sub"], job_order_id, candidate_id, body)


@router.get(
    "/by-job/{job_order_id}/candidate/{candidate_id}/placement",
    response_model=PlacementOut,
)
async def fetch_placement(
    job_order_id: str,
    candidate_id: str,
    ctx: dict = Depends(require_ui_session),
) -> PlacementOut:
    return get_placement(ctx["user_sub"], job_order_id, candidate_id)


# ---------------------------------------------------------------------------
# Admin: status config write (PIP-002)
# ---------------------------------------------------------------------------

@router_admin.put("/pipeline/statuses", response_model=PipelineStatusConfigOut)
async def update_pipeline_statuses(
    body: PipelineStatusConfigIn,
    ctx: dict = Depends(require_ui_session),
) -> PipelineStatusConfigOut:
    if normalize_role(ctx.get("role")) not in {Role.ADMIN, Role.ROOT}:
        raise HTTPException(403, detail={"code": "admin_role_required"})
    return set_status_config(ctx["user_sub"], body)
