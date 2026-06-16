"""Returns / RMA router (ADR-001 OFB-008/009/010, Milestone 3).

Additive + flag-gated (``RETURNS_RMA_ENABLED``, default OFF). Every handler
short-circuits to 404 when the flag is off, so mounting the router is a no-op
until the milestone explicitly enables it.

Role model (SECOPS-007 / ADR §Security):
  * Customer request + read own returns → ``require_ui_session``.
  * Admin approve / reject / receive / refund / close → ``require_admin_or_root_csrf``.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root_csrf
from app.models import (
    ReturnDecisionIn,
    ReturnOut,
    ReturnRequestIn,
)
from app.services import returns_rma as rma
from app.services.sessions import require_ui_session

returns_rma_router = APIRouter(prefix="/ui/returns", tags=["returns"])


# ── customer flow (OFB-008) ──────────────────────────────────────────────


@returns_rma_router.post("", response_model=ReturnOut)
async def create_return(body: ReturnRequestIn, session=Depends(require_ui_session)):
    rma._require_enabled()
    rec = rma.request_return(
        user_sub=session["user_sub"],
        order_id=body.order_id,
        reason=body.reason,
        lines=[ln.model_dump() for ln in body.lines],
    )
    return ReturnOut(**rec)


@returns_rma_router.get("/{return_id}", response_model=ReturnOut)
async def get_return(return_id: str, session=Depends(require_ui_session)):
    rma._require_enabled()
    rec = rma.get_return(return_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Return not found")
    if rec.get("user_sub") != session["user_sub"]:
        # Ownership: a customer can only read their own return (foreign -> 404).
        raise HTTPException(status_code=404, detail="Return not found")
    return ReturnOut(**rec)


# ── admin queue + decisions (OFB-009/010) ────────────────────────────────


@returns_rma_router.get("/admin/queue")
async def admin_queue(
    status: str = "requested",
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    rma._require_enabled()
    if status not in ("requested", "approved", "received", "refunded", "rejected", "closed"):
        raise HTTPException(status_code=422, detail="invalid status filter")
    return {"returns": rma.list_returns_by_status(status)}


@returns_rma_router.post("/admin/{return_id}/approve", response_model=ReturnOut)
async def admin_approve(
    return_id: str,
    body: ReturnDecisionIn | None = None,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    rma._require_enabled()
    rec = rma.approve_return(return_id, actor_sub=user.sub, note=(body.note if body else None))
    return ReturnOut(**rec)


@returns_rma_router.post("/admin/{return_id}/reject", response_model=ReturnOut)
async def admin_reject(
    return_id: str,
    body: ReturnDecisionIn | None = None,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    rma._require_enabled()
    rec = rma.reject_return(return_id, actor_sub=user.sub, note=(body.note if body else None))
    return ReturnOut(**rec)


@returns_rma_router.post("/admin/{return_id}/receive", response_model=ReturnOut)
async def admin_receive(
    return_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    rma._require_enabled()
    rec = rma.receive_return(return_id, actor_sub=user.sub)
    return ReturnOut(**rec)


@returns_rma_router.post("/admin/{return_id}/refund", response_model=ReturnOut)
async def admin_refund(
    return_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    rma._require_enabled()
    rec = rma.refund_return(return_id, actor_sub=user.sub)
    return ReturnOut(**rec)


@returns_rma_router.post("/admin/{return_id}/close", response_model=ReturnOut)
async def admin_close(
    return_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    rma._require_enabled()
    rec = rma.close_return(return_id, actor_sub=user.sub)
    return ReturnOut(**rec)
