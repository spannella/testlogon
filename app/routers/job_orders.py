"""
ATS — Job Order REST router (JOB-003, JOB-004, JOB-005).

Prefix: /ui/ats/job-orders
Auth:   require_ui_session on all endpoints except feature-status
Flags:  S.ats_enabled AND S.job_orders_enabled (checked via _require_flag())

Route declaration order (IMPORTANT — FastAPI matches in declaration order):
  1. GET  /feature-status   — literal; no auth; must be before /{job_id}
  2. GET  /open             — literal; before /{job_id}
  3. GET  /hot              — literal; before /{job_id}
  4. GET  /mine             — literal; before /{job_id}
  5. POST /                 — create
  6. GET  /{job_id}         — get single
  7. PATCH /{job_id}        — update
  8. POST /{job_id}/status  — set_status
  9. GET  /{job_id}/openings — openings summary (JOB-005)
 10. DELETE /{job_id}       — soft-delete
"""
from __future__ import annotations

from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel

import app.services.job_orders as _svc
from app.core.settings import S
from app.models import JobOrderCreateIn, JobOrderOut, JobOrderUpdateIn
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/ats/job-orders", tags=["ats-job-orders"])


def _require_flag() -> None:
    """Raise HTTP 503 if either the master ATS gate or the job-orders sub-gate is off."""
    from fastapi import HTTPException
    if not (S.ats_enabled and S.job_orders_enabled):
        raise HTTPException(
            status_code=503,
            detail={"code": "job_orders_disabled"},
        )


# ---------------------------------------------------------------------------
# Feature-status — MUST be before /{job_id}
# ---------------------------------------------------------------------------

@router.get("/feature-status")
async def feature_status() -> dict:
    """
    Return the current ATS feature-flag state.
    No auth required — the frontend calls this at mount time to determine
    whether to show the Job Orders nav entry. Never 503s.
    """
    return {
        "ats_enabled": S.ats_enabled,
        "job_orders_enabled": S.job_orders_enabled,
    }


# ---------------------------------------------------------------------------
# List endpoints — MUST be before /{job_id}
# ---------------------------------------------------------------------------

@router.get("/open")
async def get_open_job_orders(
    company_id: Optional[str] = Query(None, max_length=128),
    status: Optional[str] = Query(None),
    cursor: Optional[str] = Query(None),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: Dict = Depends(require_ui_session),
) -> Dict:
    """Return non-terminal, non-deleted job orders (newest-first, cursor-paginated)."""
    _require_flag()
    items, next_cursor = _svc.list_open(
        cursor=cursor, limit=limit, company_id=company_id, status=status
    )
    return {"items": [i.model_dump() for i in items], "next_cursor": next_cursor}


@router.get("/hot")
async def get_hot_job_orders(
    cursor: Optional[str] = Query(None),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: Dict = Depends(require_ui_session),
) -> Dict:
    """Return hot-flagged, non-deleted job orders (newest-first, cursor-paginated)."""
    _require_flag()
    items, next_cursor = _svc.list_hot(cursor=cursor, limit=limit)
    return {"items": [i.model_dump() for i in items], "next_cursor": next_cursor}


@router.get("/mine")
async def get_my_job_orders(
    cursor: Optional[str] = Query(None),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: Dict = Depends(require_ui_session),
) -> Dict:
    """Return job orders assigned to the calling recruiter (newest-first, cursor-paginated)."""
    _require_flag()
    recruiter_sub = ctx["user_sub"]
    items, next_cursor = _svc.list_mine(
        recruiter_sub=recruiter_sub, cursor=cursor, limit=limit
    )
    return {"items": [i.model_dump() for i in items], "next_cursor": next_cursor}


# ---------------------------------------------------------------------------
# CRUD endpoints
# ---------------------------------------------------------------------------

@router.post("/", status_code=201, response_model=JobOrderOut)
async def create_job_order(
    body: JobOrderCreateIn,
    session: dict = Depends(require_ui_session),
) -> JobOrderOut:
    """Create a new Job Order. Returns 201 + JobOrderOut."""
    _require_flag()
    return _svc.create_job_order(actor_sub=session["user_sub"], data=body)


@router.get("/{job_id}", response_model=JobOrderOut)
async def get_job_order(
    job_id: str,
    session: dict = Depends(require_ui_session),
) -> JobOrderOut:
    """Fetch a single Job Order by ID. Returns 404 if not found or deleted."""
    _require_flag()
    return _svc.get_job_order(job_id=job_id)


@router.patch("/{job_id}", response_model=JobOrderOut)
async def update_job_order(
    job_id: str,
    body: JobOrderUpdateIn,
    session: dict = Depends(require_ui_session),
) -> JobOrderOut:
    """Partial-update a Job Order. Status changes are routed through the state-machine guard."""
    _require_flag()
    return _svc.update_job_order(
        actor_sub=session["user_sub"], job_id=job_id, data=body
    )


class SetStatusIn(BaseModel):
    status: str


@router.post("/{job_id}/status", response_model=JobOrderOut)
async def set_job_order_status(
    job_id: str,
    body: SetStatusIn,
    session: dict = Depends(require_ui_session),
) -> JobOrderOut:
    """Transition a Job Order's status via the 7-state machine. Returns 409 on illegal transitions."""
    _require_flag()
    return _svc.set_status(
        actor_sub=session["user_sub"], job_id=job_id, new_status=body.status
    )


@router.get("/{job_id}/openings")
async def get_openings_summary_endpoint(
    job_id: str,
    ctx: Dict = Depends(require_ui_session),
) -> Dict:
    """
    Return the lightweight openings summary for a job order.
    Returns: {"openings": int, "placed_count": int, "openings_remaining": int}
    """
    _require_flag()
    return _svc.get_openings_summary(job_id)


@router.delete("/{job_id}", status_code=204)
async def delete_job_order(
    job_id: str,
    session: dict = Depends(require_ui_session),
) -> Response:
    """Soft-delete a Job Order (sets deleted_at, removes recruiter index rows)."""
    _require_flag()
    _svc.delete_job_order(actor_sub=session["user_sub"], job_id=job_id)
    return Response(status_code=204)
