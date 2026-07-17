"""
Billing Disputes router — BILLING-001 + DISP E1/E2.

Customer endpoints (DISP-020):
  POST /ui/billing/disputes                — file a new dispute (open-from-receipt)
  GET  /ui/billing/disputes                — list the user's own disputes
  GET  /ui/billing/disputes/{id}           — get a single dispute detail (owner or admin)
  POST /ui/billing/disputes/{id}/withdraw  — payer withdraws an open dispute

Creator/seller endpoints (DISP-021):
  GET  /ui/creator/disputes                — inbound queue (disputes against me)
  POST /ui/creator/disputes/{id}/respond   — rebut within the response window

Admin endpoints (DISP-022 — AdminScope.PAYMENT_DISPUTES):
  GET  /ui/admin/disputes                  — status queue w/ rail preview + linked incident
  GET  /ui/admin/disputes/{id}             — full admin view (rail preview, rebuttal, incident)
  POST /ui/admin/disputes/{id}/respond     — submit dispute evidence (legacy path)
  POST /ui/admin/disputes/{id}/resolve     — resolve (refunded|partial|denied); dual-approval > threshold
  POST /ui/admin/disputes/sweep            — response-window SLA sweep
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_scope
from app.auth.roles import (
    AdminScope,
    Role,
    admin_profile_has_scope,
    normalize_admin_profile,
    normalize_role,
)
from app.core.settings import S
from app.core.tables import T
from app.models import (
    CreatorDisputeRespondIn,
    DisputeFileIn,
    DisputeRespondIn,
    DisputeResolveIn,
)
from app.services.sessions import require_ui_session
from app.services.billing_disputes import (
    admin_dispute_view,
    creator_respond,
    file_dispute,
    get_dispute,
    list_creator_disputes,
    list_disputes_by_status,
    list_user_disputes,
    resolve_dispute,
    submit_evidence,
    withdraw_dispute,
    _to_out,
)
from app.services import dispute_lifecycle as DL

billing_disputes_router = APIRouter(tags=["billing-disputes"])
logger = logging.getLogger(__name__)

# DISP-022: the admin scope that gates the payment-dispute queue. A GENERAL admin
# profile still passes (admin_profile_has_scope returns True for GENERAL), so this
# does not regress the existing broad-admin behavior; a SCOPED admin must hold
# payment_disputes.
require_payment_disputes_admin = require_admin_scope(AdminScope.PAYMENT_DISPUTES)


# ---------------------------------------------------------------------------
# DISP-022 — dual-approval (real, non-self-attested) for high-value money moves
# ---------------------------------------------------------------------------

def _admin_has_payment_disputes_scope(user_sub: str) -> bool:
    """Is ``user_sub`` a real admin that actually holds PAYMENT_DISPUTES (or a
    GENERAL admin profile, or ROOT)? A caller-supplied string that is not a real
    qualifying admin is rejected. Mirrors admin_moderation._admin_user_has_senior_scope."""
    if not user_sub:
        return False
    try:
        item = T.users.get_item(Key={"user_sub": user_sub}).get("Item")
    except ClientError:
        item = None
    if not item:
        return False
    try:
        role = normalize_role(item.get("role"))
    except Exception:
        role = None
    if role == Role.ROOT:
        return True
    if role != Role.ADMIN:
        return False
    profile = normalize_admin_profile(item.get("admin_profile"))
    return admin_profile_has_scope(profile, AdminScope.PAYMENT_DISPUTES)


def _enforce_dual_approval_if_needed(
    *, actor: AuthenticatedUser, body: DisputeResolveIn, item: Dict[str, Any]
) -> None:
    """DISP-022: a resolve that MOVES money (refunded/partial) at/above the
    dual-approval threshold requires a second, DISTINCT, real PAYMENT_DISPUTES
    admin id. A denial (no money move) never needs a second approver. ROOT acting
    alone is exempt (mirrors the moderation permanent-ban gate)."""
    if not bool(getattr(S, "dispute_dual_approval_enabled", True)):
        return
    res = (body.resolution or "").strip().lower()
    # legacy tokens that map to a money move
    moves_money = res in ("refunded", "partial", "lost", "accepted")
    if not moves_money:
        return
    # the amount that would move
    amount = int(item.get("amount_cents", 0) or 0)
    if res == "partial" and body.override_amount_cents:
        amount = int(body.override_amount_cents)
    threshold = int(getattr(S, "dispute_dual_approval_threshold_cents", 0) or 0)
    if threshold <= 0 or amount < threshold:
        return
    if actor.role.name == "ROOT":
        return
    approver = str(body.second_approver_admin_user_id or "").strip()
    if not approver:
        raise HTTPException(403, {"code": "dual_approval_required",
                                  "message": "A second payment-disputes admin must approve a refund of this size.",
                                  "threshold_cents": threshold, "amount_cents": amount})
    if approver == actor.sub:
        raise HTTPException(403, {"code": "dual_approval_self",
                                  "message": "The second approver must be different from the acting admin."})
    if not _admin_has_payment_disputes_scope(approver):
        raise HTTPException(403, {"code": "dual_approval_invalid_approver",
                                  "message": "The second approver must be an existing admin holding the payment_disputes scope.",
                                  "required_scope": AdminScope.PAYMENT_DISPUTES.value})


# ---------------------------------------------------------------------------
# Customer endpoints (DISP-020)
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
        charge_type=body.charge_type or "",
        charge_ref=body.charge_ref or "",
        recipient_id=body.recipient_id or "",
        reason_detail=body.reason_detail or "",
        provider=body.provider,
        request_obj=req,
    )
    return _to_out(item)


@billing_disputes_router.post("/ui/billing/disputes/{dispute_id}/withdraw")
def withdraw_my_dispute(
    dispute_id: str,
    req: Request = None,
    ctx=Depends(require_ui_session),
) -> Dict[str, Any]:
    item = withdraw_dispute(dispute_id=dispute_id, user_id=ctx["user_sub"], request_obj=req)
    return {"ok": True, "dispute_id": dispute_id, "status": item.get("status")}


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
# Creator/seller endpoints (DISP-021)
# ---------------------------------------------------------------------------

@billing_disputes_router.get("/ui/creator/disputes")
def list_my_creator_disputes(
    ctx=Depends(require_ui_session),
    limit: int = 50,
) -> Dict[str, Any]:
    """Inbound queue: every non-terminal dispute filed against me (as
    creator/seller) that I can still respond to or that is awaiting an admin."""
    items = list_creator_disputes(ctx["user_sub"], limit=limit)
    return {"items": [_to_out(it) for it in items]}


@billing_disputes_router.get("/ui/creator/disputes/{dispute_id}")
def get_my_creator_dispute(
    dispute_id: str,
    ctx=Depends(require_ui_session),
) -> Dict[str, Any]:
    item = get_dispute(dispute_id)
    rid = str((item or {}).get("creator_id") or (item or {}).get("recipient_id") or "")
    if not item or rid != ctx["user_sub"]:
        raise HTTPException(404, "Dispute not found")
    return _to_out(item)


@billing_disputes_router.post("/ui/creator/disputes/{dispute_id}/respond")
def respond_to_dispute_as_creator(
    dispute_id: str,
    body: CreatorDisputeRespondIn,
    req: Request = None,
    ctx=Depends(require_ui_session),
) -> Dict[str, Any]:
    item = creator_respond(
        dispute_id=dispute_id,
        creator_id=ctx["user_sub"],
        response_text=body.response_text,
        evidence_files=body.evidence_files,
        request_obj=req,
    )
    return {
        "ok": True,
        "dispute_id": dispute_id,
        "status": item.get("status"),
        "creator_response": item.get("creator_response") or None,
    }


# ---------------------------------------------------------------------------
# Admin endpoints (DISP-022 — AdminScope.PAYMENT_DISPUTES)
# ---------------------------------------------------------------------------

@billing_disputes_router.get("/ui/admin/disputes")
def admin_list_disputes(
    status: str = "open",
    limit: int = 50,
    actor: AuthenticatedUser = Depends(require_payment_disputes_admin),
) -> Dict[str, Any]:
    items = list_disputes_by_status(status=status, limit=limit)
    return {"items": [admin_dispute_view(it) for it in items]}


@billing_disputes_router.get("/ui/admin/disputes/{dispute_id}")
def admin_get_dispute(
    dispute_id: str,
    actor: AuthenticatedUser = Depends(require_payment_disputes_admin),
) -> Dict[str, Any]:
    item = get_dispute(dispute_id)
    if not item:
        raise HTTPException(404, "Dispute not found")
    return admin_dispute_view(item)


@billing_disputes_router.post("/ui/admin/disputes/{dispute_id}/respond")
def admin_respond_dispute(
    dispute_id: str,
    body: DisputeRespondIn,
    req: Request = None,
    actor: AuthenticatedUser = Depends(require_payment_disputes_admin),
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
    actor: AuthenticatedUser = Depends(require_payment_disputes_admin),
) -> Dict[str, Any]:
    item = get_dispute(dispute_id)
    if not item:
        raise HTTPException(404, "Dispute not found")
    # DISP-022: dual-approval gate BEFORE any money moves.
    _enforce_dual_approval_if_needed(actor=actor, body=body, item=item)
    item = resolve_dispute(
        dispute_id=dispute_id,
        admin_id=actor.sub,
        resolution=body.resolution,
        notes=body.notes,
        override_amount_cents=body.override_amount_cents,
        request_obj=req,
    )
    return {
        "ok": True,
        "dispute_id": item.get("dispute_id", dispute_id),
        "status": item.get("status"),
        "resolution": item.get("resolution"),
        "moved_cents": item.get("moved_cents", 0),
    }


@billing_disputes_router.post("/ui/admin/disputes/sweep")
def admin_sweep_dispute_responses(
    limit: int = 200,
    actor: AuthenticatedUser = Depends(require_payment_disputes_admin),
) -> Dict[str, Any]:
    """DISP-012: run the response-window SLA sweep — every ``needs_response``
    dispute past its ``respond_by`` auto-advances to ``under_review`` (admin
    decides; NOT auto-refunded)."""
    return DL.sweep_expired_dispute_responses(limit=limit)
