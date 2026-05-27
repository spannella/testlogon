"""
Refund Requests router — BILLING-001.

Customer endpoints:
  POST /ui/billing/refund-requests       — submit a new refund request
  GET  /ui/billing/refund-requests       — list user's own refund requests
  GET  /ui/billing/refund-requests/{id}  — get single request detail

Admin endpoints:
  GET  /ui/admin/refund-requests             — list pending (or filtered) requests
  POST /ui/admin/refund-requests/{id}/approve — approve a request
  POST /ui/admin/refund-requests/{id}/reject  — deny a request
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import require_admin_or_root
from app.auth.roles import Role, normalize_role
from app.models import (
    AdminRefundApproveIn,
    AdminRefundDenyIn,
    RefundRequestIn,
    RefundRequestOut,
)
from app.services.sessions import require_ui_session
from app.services.refund_requests import (
    approve_request,
    create_refund_request,
    get_request,
    list_pending_requests,
    list_user_requests,
    reject_request,
)

router = APIRouter(tags=["refund-requests"])
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "refund_request_id": item.get("refund_request_id", ""),
        "status": item.get("status", ""),
        "amount_cents": int(item.get("amount_cents", 0)),
        "currency": item.get("currency", "USD"),
        "reason": item.get("reason", ""),
        "transaction_type": item.get("transaction_type"),
        "transaction_entry_id": item.get("transaction_entry_id"),
        "created_at": int(item.get("created_at", 0)),
        "admin_notes": item.get("admin_notes") or None,
        "completed_at": int(item.get("completed_at", 0)) or None,
        "requester_user_id": item.get("requester_user_id"),
    }


# ---------------------------------------------------------------------------
# Customer endpoints
# ---------------------------------------------------------------------------

@router.post("/ui/billing/refund-requests", status_code=201)
def submit_refund_request(
    body: RefundRequestIn,
    req: Request = None,
    ctx=Depends(require_ui_session),
) -> Dict[str, Any]:
    user_id = ctx["user_sub"]
    item = create_refund_request(
        user_id=user_id,
        transaction_entry_id=body.transaction_entry_id,
        reason=body.reason,
        amount_cents=body.amount_cents,
    )
    return _to_out(item)


@router.get("/ui/billing/refund-requests")
def list_my_refund_requests(
    ctx=Depends(require_ui_session),
    limit: int = 50,
) -> Dict[str, Any]:
    user_id = ctx["user_sub"]
    items = list_user_requests(user_id, limit=limit)
    return {"items": [_to_out(it) for it in items]}


@router.get("/ui/billing/refund-requests/{request_id}")
def get_refund_request_detail(
    request_id: str,
    ctx=Depends(require_ui_session),
) -> Dict[str, Any]:
    item = get_request(request_id)
    if not item:
        raise HTTPException(404, "Refund request not found")
    # Users can only see their own
    if item.get("requester_user_id") != ctx["user_sub"]:
        role = normalize_role(ctx.get("role"))
        if role not in (Role.ADMIN, Role.ROOT):
            raise HTTPException(404, "Refund request not found")
    return _to_out(item)


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------

@router.get("/ui/admin/refund-requests")
def admin_list_refund_requests(
    status: str = "pending",
    limit: int = 50,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    items = list_pending_requests(status=status, limit=limit)
    return {"items": [_to_out(it) for it in items]}


@router.post("/ui/admin/refund-requests/{request_id}/approve")
def admin_approve_refund(
    request_id: str,
    body: AdminRefundApproveIn,
    req: Request = None,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    result = approve_request(
        request_id=request_id,
        admin_id=actor.sub,
        notes=body.notes,
        override_amount_cents=body.amount_cents,
        request_obj=req,
    )
    return {
        "ok": True,
        "refund_request_id": result["refund_request_id"],
        "status": result["status"],
        "approved_amount_cents": int(result.get("amount_cents", 0)),
    }


@router.post("/ui/admin/refund-requests/{request_id}/reject")
def admin_reject_refund(
    request_id: str,
    body: AdminRefundDenyIn,
    req: Request = None,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    result = reject_request(
        request_id=request_id,
        admin_id=actor.sub,
        notes=body.notes,
        request_obj=req,
    )
    return {
        "ok": True,
        "refund_request_id": result["refund_request_id"],
        "status": result["status"],
    }
