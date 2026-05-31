"""
Billing Disputes router — BILLING-001.

Customer endpoints:
  POST /ui/billing/disputes        — file a new dispute
  GET  /ui/billing/disputes        — list the user's own disputes
  GET  /ui/billing/disputes/{id}   — get a single dispute detail (owner or admin)

Admin endpoints:
  GET  /ui/admin/disputes                  — list disputes by status
  POST /ui/admin/disputes/{id}/respond     — submit dispute evidence
  POST /ui/admin/disputes/{id}/resolve     — resolve a dispute (won|lost|accepted)
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.auth.roles import Role, normalize_role
from app.models import (
    DisputeFileIn,
    DisputeRespondIn,
    DisputeResolveIn,
)
from app.services.sessions import require_ui_session
from app.services.billing_disputes import (
    file_dispute,
    get_dispute,
    list_disputes_by_status,
    list_user_disputes,
    resolve_dispute,
    submit_evidence,
    _to_out,
)

billing_disputes_router = APIRouter(tags=["billing-disputes"])
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Customer endpoints
# ---------------------------------------------------------------------------

@billing_disputes_router.post("/ui/billing/disputes", status_code=201)
def file_billing_dispute(
    body: DisputeFileIn,
    req: Request = None,
    ctx=Depends(require_ui_session),
) -> Dict[str, Any]:
    item = file_dispute(
        user_id=ctx["user_sub"],
        amount_cents=body.amount_cents,
        reason=body.reason,
        currency=body.currency,
        transaction_entry_id=body.transaction_entry_id,
        provider=body.provider,
        request_obj=req,
    )
    return _to_out(item)


@billing_disputes_router.get("/ui/billing/disputes")
def list_my_disputes(
    ctx=Depends(require_ui_session),
    limit: int = 50,
) -> Dict[str, Any]:
    items = list_user_disputes(ctx["user_sub"], limit=limit)
    return {"items": [_to_out(it) for it in items]}


@billing_disputes_router.get("/ui/billing/disputes/{dispute_id}")
def get_my_dispute(
    dispute_id: str,
    ctx=Depends(require_ui_session),
) -> Dict[str, Any]:
    item = get_dispute(dispute_id)
    if not item:
        raise HTTPException(404, "Dispute not found")
    if item.get("user_id") != ctx["user_sub"]:
        role = normalize_role(ctx.get("role"))
        if role not in (Role.ADMIN, Role.ROOT):
            raise HTTPException(404, "Dispute not found")
    return _to_out(item)


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------

@billing_disputes_router.get("/ui/admin/disputes")
def admin_list_disputes(
    status: str = "open",
    limit: int = 50,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    items = list_disputes_by_status(status=status, limit=limit)
    return {"items": [_to_out(it) for it in items]}


@billing_disputes_router.post("/ui/admin/disputes/{dispute_id}/respond")
def admin_respond_dispute(
    dispute_id: str,
    body: DisputeRespondIn,
    req: Request = None,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    item = submit_evidence(
        dispute_id=dispute_id,
        admin_id=actor.sub,
        evidence_text=body.evidence_text,
        evidence_files=body.evidence_files,
        request_obj=req,
    )
    return {
        "ok": True,
        "dispute_id": item["dispute_id"],
        "evidence_submitted": True,
        "status": item["status"],
    }


@billing_disputes_router.post("/ui/admin/disputes/{dispute_id}/resolve")
def admin_resolve_dispute(
    dispute_id: str,
    body: DisputeResolveIn,
    req: Request = None,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    item = resolve_dispute(
        dispute_id=dispute_id,
        admin_id=actor.sub,
        resolution=body.resolution,
        notes=body.notes,
        request_obj=req,
    )
    return {
        "ok": True,
        "dispute_id": item["dispute_id"],
        "status": item["status"],
        "resolution": item["resolution"],
    }
