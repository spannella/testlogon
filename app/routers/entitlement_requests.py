"""VEW-004 — Entitlement-request router.

Exposes two APIRouter objects:
  router  — user + admin routes merged (prefix wiring happens per-route)

Both are gated at the main.py level when entitlement_requests_enabled is ON.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import require_admin_or_root, require_admin_or_root_csrf, require_root
from app.services import entitlement_requests as svc

logger = logging.getLogger(__name__)

router = APIRouter(tags=["entitlement-requests"])


def _require_enabled() -> None:
    svc._require_enabled()


# ---------------------------------------------------------------------------
# User routes (prefix /ui/entitlement-requests)
# ---------------------------------------------------------------------------

# NOTE: /mine must be declared before /{request_id} to avoid capture
@router.get("/ui/entitlement-requests/mine")
async def list_my_requests(
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> List[Dict[str, Any]]:
    _require_enabled()
    return svc.list_my_requests(user.sub)


@router.post("/ui/entitlement-requests", status_code=status.HTTP_201_CREATED)
async def create_request(
    body: "EntitlementRequestCreateIn",
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> Dict[str, Any]:
    _require_enabled()
    return svc.create_request(
        requester_sub=user.sub,
        entitlement_kind=body.entitlement_kind,
        target_ref=body.target_ref,
        justification=body.justification,
    )


@router.post("/ui/entitlement-requests/{request_id}/cancel")
async def cancel_request(
    request_id: str,
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> Dict[str, Any]:
    _require_enabled()
    return svc.cancel_request(request_id, user.sub)


# ---------------------------------------------------------------------------
# Admin routes (prefix /ui/admin/entitlement-requests)
# ---------------------------------------------------------------------------


@router.get("/ui/admin/entitlement-requests")
async def list_queue(
    status_filter: str = Query(default="pending", alias="status"),
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    _require_enabled()
    return svc.list_queue(status_filter, cursor=cursor, limit=limit)


@router.get("/ui/admin/entitlement-requests/{request_id}/history")
async def get_request_history(
    request_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> List[Dict[str, Any]]:
    _require_enabled()
    return svc.get_request_history(request_id)


@router.get("/ui/admin/entitlement-requests/{request_id}")
async def get_request(
    request_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    _require_enabled()
    return svc.get_request(request_id)


@router.post("/ui/admin/entitlement-requests/{request_id}/claim")
async def claim_request(
    request_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    _require_enabled()
    return svc.claim_request(request_id, user.sub)


@router.post("/ui/admin/entitlement-requests/{request_id}/approve")
async def approve_request(
    request_id: str,
    body: "EntitlementDecisionIn",
    user: AuthenticatedUser = Depends(require_root),
) -> Dict[str, Any]:
    _require_enabled()
    return svc.approve_request(request_id, user.sub, reason=body.reason)


@router.post("/ui/admin/entitlement-requests/{request_id}/reject")
async def reject_request(
    request_id: str,
    body: "EntitlementDecisionIn",
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    _require_enabled()
    return svc.reject_request(request_id, user.sub, body.reason)


# ---------------------------------------------------------------------------
# Model imports (at bottom to avoid circular imports at load time)
# ---------------------------------------------------------------------------

from app.models import (  # noqa: E402
    EntitlementRequestCreateIn,
    EntitlementDecisionIn,
)
