"""License request & approval workflow router (LICENSE-004)."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.services.sessions import require_ui_session
from app.models import (
    LicenseRequestCreateIn,
    LicenseRequestDenyIn,
    LicenseRequestCounterIn,
    LicenseRequestOut,
    LicenseRequestApprovalOut,
    LicenseRequestListOut,
)
from app.services import license_requests as svc
from app.services.license_requests import ConflictError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/licenses/requests", tags=["license-requests"])


def _request_out(item: Dict[str, Any]) -> LicenseRequestOut:
    """Convert a DDB item / service dict to LicenseRequestOut."""
    # Coerce Decimal values to int in proposed_terms / counter_terms
    pt = item.get("proposed_terms") or {}
    clean_pt: Dict[str, Any] = {}
    for k, v in pt.items():
        try:
            clean_pt[k] = int(v)
        except (TypeError, ValueError):
            clean_pt[k] = v

    ct = item.get("counter_terms")
    clean_ct: Optional[Dict[str, Any]] = None
    if ct:
        clean_ct = {}
        for k, v in ct.items():
            try:
                clean_ct[k] = int(v)
            except (TypeError, ValueError):
                clean_ct[k] = v

    return LicenseRequestOut(
        request_id=item.get("request_id") or "",
        content_id=item.get("content_id") or "",
        content_type=item.get("content_type") or "",
        requester_id=item.get("requester_id") or "",
        requester_display_name=item.get("requester_display_name") or "",
        owner_id=item.get("owner_id") or "",
        owner_display_name=item.get("owner_display_name") or "",
        status=item.get("status") or "",
        proposed_terms=clean_pt,
        counter_terms=clean_ct,
        denial_reason=item.get("denial_reason") or "",
        message=item.get("message") or "",
        created_at=int(item.get("created_at", 0)),
        updated_at=int(item.get("updated_at", 0)),
        expires_at=int(item.get("expires_at", 0)),
    )


# ─── Create a new license request ───────────────────────────────────────────

@router.post("", response_model=LicenseRequestOut)
async def create_license_request(
    body: LicenseRequestCreateIn,
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        item = svc.create_request(
            requester_sub=user_sub,
            content_id=body.content_id,
            content_type=body.content_type,
            owner_id=body.owner_id,
            proposed_terms=body.proposed_terms.model_dump(),
            message=body.message,
        )
        return _request_out(item)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except ConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


# ─── List sent requests ─────────────────────────────────────────────────────

@router.get("/sent", response_model=LicenseRequestListOut)
async def list_sent_requests(
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    result = svc.list_sent_requests(
        requester_sub=user_sub,
        status_filter=status,
        limit=limit,
        cursor=cursor,
    )
    return LicenseRequestListOut(
        items=[_request_out(i) for i in result["items"]],
        next_cursor=result.get("next_cursor"),
    )


# ─── List received requests (license inbox) ─────────────────────────────────

@router.get("/received", response_model=LicenseRequestListOut)
async def list_received_requests(
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    result = svc.list_received_requests(
        owner_sub=user_sub,
        status_filter=status,
        limit=limit,
        cursor=cursor,
    )
    return LicenseRequestListOut(
        items=[_request_out(i) for i in result["items"]],
        next_cursor=result.get("next_cursor"),
    )


# ─── Get request detail ─────────────────────────────────────────────────────

@router.get("/{request_id}", response_model=LicenseRequestOut)
async def get_request_detail(
    request_id: str,
    content_id: str = Query(...),
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        item = svc.get_request_detail(
            content_id=content_id,
            request_id=request_id,
            user_id=user_sub,
        )
        if not item:
            raise HTTPException(status_code=404, detail="Request not found")
        return _request_out(item)
    except LookupError:
        raise HTTPException(status_code=404, detail="Request not found")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Not authorized")


# ─── Approve request ────────────────────────────────────────────────────────

@router.post("/{request_id}/approve")
async def approve_request(
    request_id: str,
    content_id: str = Query(...),
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        result = svc.approve_request(
            owner_sub=user_sub,
            request_id=request_id,
            content_id=content_id,
        )
        return {
            "request": _request_out(result["request"]).model_dump(),
            "issued_license": result["issued_license"],
        }
    except LookupError:
        raise HTTPException(status_code=404, detail="Request not found")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Not authorized")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ─── Deny request ───────────────────────────────────────────────────────────

@router.post("/{request_id}/deny", response_model=LicenseRequestOut)
async def deny_request(
    request_id: str,
    body: LicenseRequestDenyIn,
    content_id: str = Query(...),
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        item = svc.deny_request(
            owner_sub=user_sub,
            request_id=request_id,
            content_id=content_id,
            reason=body.reason,
        )
        return _request_out(item)
    except LookupError:
        raise HTTPException(status_code=404, detail="Request not found")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Not authorized")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ─── Counter-offer ──────────────────────────────────────────────────────────

@router.post("/{request_id}/counter", response_model=LicenseRequestOut)
async def counter_offer(
    request_id: str,
    body: LicenseRequestCounterIn,
    content_id: str = Query(...),
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        item = svc.counter_offer(
            owner_sub=user_sub,
            request_id=request_id,
            content_id=content_id,
            counter_terms=body.counter_terms.model_dump(),
        )
        return _request_out(item)
    except LookupError:
        raise HTTPException(status_code=404, detail="Request not found")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Not authorized")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ─── Accept counter-offer ───────────────────────────────────────────────────

@router.post("/{request_id}/accept-counter")
async def accept_counter(
    request_id: str,
    content_id: str = Query(...),
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        result = svc.accept_counter(
            requester_sub=user_sub,
            request_id=request_id,
            content_id=content_id,
        )
        return {
            "request": _request_out(result["request"]).model_dump(),
            "issued_license": result["issued_license"],
        }
    except LookupError:
        raise HTTPException(status_code=404, detail="Request not found")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Not authorized")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ─── Reject counter-offer ───────────────────────────────────────────────────

@router.post("/{request_id}/reject-counter", response_model=LicenseRequestOut)
async def reject_counter(
    request_id: str,
    content_id: str = Query(...),
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        item = svc.reject_counter(
            requester_sub=user_sub,
            request_id=request_id,
            content_id=content_id,
        )
        return _request_out(item)
    except LookupError:
        raise HTTPException(status_code=404, detail="Request not found")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Not authorized")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ─── Withdraw request ───────────────────────────────────────────────────────

@router.post("/{request_id}/withdraw", response_model=LicenseRequestOut)
async def withdraw_request(
    request_id: str,
    content_id: str = Query(...),
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        item = svc.withdraw_request(
            requester_sub=user_sub,
            request_id=request_id,
            content_id=content_id,
        )
        return _request_out(item)
    except LookupError:
        raise HTTPException(status_code=404, detail="Request not found")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Not authorized")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
