"""Issued license management router (LICENSE-002)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.services.sessions import require_ui_session
from app.models import (
    IssueLicenseIn,
    UpdateLicenseTermsIn,
    RevokeLicenseIn,
    IssuedLicenseOut,
    HeldLicenseOut,
    LibraryItemOut,
    LicenseCheckOut,
)
from app.services import issued_licenses as svc

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/licenses", tags=["issued-licenses"])


def _license_out(item: Dict[str, Any]) -> IssuedLicenseOut:
    """Convert a DDB item to IssuedLicenseOut."""
    return IssuedLicenseOut(
        issued_license_id=item.get("issued_license_id", ""),
        content_id=item.get("content_id", ""),
        content_type=item.get("content_type", ""),
        licensor_id=item.get("licensor_id", ""),
        licensor_display_name=item.get("licensor_display_name") or "",
        licensee_id=item.get("licensee_id"),
        license_mode=item.get("license_mode", ""),
        status=item.get("status", ""),
        profit_share_pct=int(item.get("profit_share_pct", 0)),
        fixed_cost_cents=int(item.get("fixed_cost_cents", 0)),
        revenue_share_pct=int(item.get("revenue_share_pct", 0)),
        currency=item.get("currency", "usd"),
        title=item.get("title", ""),
        thumbnail_url=item.get("thumbnail_url", ""),
        created_at=int(item.get("created_at", 0)),
        updated_at=int(item.get("updated_at", 0)),
        expires_at=int(item["expires_at"]) if item.get("expires_at") is not None else None,
    )


def _held_out(item: Dict[str, Any]) -> HeldLicenseOut:
    """Convert a DDB item to HeldLicenseOut."""
    ts = item.get("terms_snapshot", {})
    # Coerce Decimal to int in terms_snapshot
    clean_ts = {}
    for k, v in ts.items():
        try:
            clean_ts[k] = int(v)
        except (TypeError, ValueError):
            clean_ts[k] = v
    return HeldLicenseOut(
        issued_license_id=item.get("issued_license_id", ""),
        content_id=item.get("content_id", ""),
        content_type=item.get("content_type", ""),
        licensor_id=item.get("licensor_id", ""),
        licensor_display_name=item.get("licensor_display_name") or "",
        status=item.get("status", ""),
        license_mode=item.get("license_mode", "per_user"),
        syndicate_id=item.get("syndicate_id"),
        terms_snapshot=clean_ts,
    )


def _library_out(item: Dict[str, Any]) -> LibraryItemOut:
    """Convert a DDB item to LibraryItemOut."""
    return LibraryItemOut(
        content_id=item.get("content_id", ""),
        content_type=item.get("content_type", ""),
        licensor_id=item.get("licensor_id", ""),
        licensor_display_name=item.get("licensor_display_name") or "",
        title=item.get("title", ""),
        thumbnail_url=item.get("thumbnail_url", ""),
        profit_share_pct=int(item.get("profit_share_pct", 0)),
        fixed_cost_cents=int(item.get("fixed_cost_cents", 0)),
        created_at=int(item.get("created_at", 0)),
    )


# ─── Issue a new license ──────────────────────────────────────────────────────

@router.post("/issued", response_model=IssuedLicenseOut)
def create_issued_license(
    body: IssueLicenseIn,
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    # GAP-0294: ADMIN/ROOT may bypass content-ownership enforcement.
    role = str(session.get("role") or "").strip().lower()
    is_admin = role in ("admin", "root")
    try:
        item = svc.issue_license(
            licensor_sub=user_sub,
            content_id=body.content_id,
            content_type=body.content_type,
            license_mode=body.license_mode,
            licensee_id=body.licensee_id,
            profit_share_pct=body.profit_share_pct,
            fixed_cost_cents=body.fixed_cost_cents,
            revenue_share_pct=body.revenue_share_pct,
            currency=body.currency,
            title=body.title,
            thumbnail_url=body.thumbnail_url,
            expires_at=body.expires_at,
            skip_ownership_check=is_admin,
        )
        return _license_out(item)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))


# ─── List licenses I've issued ────────────────────────────────────────────────

@router.get("/issued")
def list_issued_licenses(
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    result = svc.list_licenses_issued_by(
        licensor_sub=user_sub,
        status_filter=status,
        limit=limit,
        cursor=cursor,
    )
    return {
        "items": [_license_out_from_index(i) for i in result["items"]],
        "next_cursor": result.get("next_cursor"),
    }


def _license_out_from_index(item: Dict[str, Any]) -> Dict[str, Any]:
    """Minimal conversion from licensor index item."""
    return {
        "issued_license_id": item.get("issued_license_id", ""),
        "content_id": item.get("content_id", ""),
        "licensee_id": item.get("licensee_id"),
        "license_mode": item.get("license_mode", ""),
        "status": item.get("status", ""),
        "created_at": int(item.get("created_at", 0)),
    }


# ─── Get issued license detail ────────────────────────────────────────────────

@router.get("/issued/{issued_license_id}", response_model=IssuedLicenseOut)
def get_issued_license_detail(
    issued_license_id: str,
    content_id: str = Query(...),
    session: dict = Depends(require_ui_session),
):
    item = svc.get_issued_license(
        content_id=content_id,
        issued_license_id=issued_license_id,
    )
    if not item:
        raise HTTPException(status_code=404, detail="License not found")
    return _license_out(item)


# ─── Update license terms ─────────────────────────────────────────────────────

@router.patch("/issued/{issued_license_id}", response_model=IssuedLicenseOut)
def update_license(
    issued_license_id: str,
    body: UpdateLicenseTermsIn,
    content_id: str = Query(...),
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")
    try:
        item = svc.update_license_terms(
            licensor_sub=user_sub,
            issued_license_id=issued_license_id,
            content_id=content_id,
            updates=updates,
        )
        return _license_out(item)
    except LookupError:
        raise HTTPException(status_code=404, detail="License not found")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Not the licensor")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ─── Revoke license ───────────────────────────────────────────────────────────

@router.post("/issued/{issued_license_id}/revoke", response_model=IssuedLicenseOut)
def revoke_issued_license(
    issued_license_id: str,
    body: RevokeLicenseIn,
    content_id: str = Query(...),
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        item = svc.revoke_license(
            licensor_sub=user_sub,
            issued_license_id=issued_license_id,
            content_id=content_id,
            reason=body.reason,
        )
        return _license_out(item)
    except LookupError:
        raise HTTPException(status_code=404, detail="License not found")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Not the licensor")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ─── List licenses I hold ─────────────────────────────────────────────────────

@router.get("/held")
def list_held_licenses(
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    result = svc.list_licenses_held_by(
        licensee_sub=user_sub,
        status_filter=status,
        limit=limit,
        cursor=cursor,
    )
    return {
        "items": [_held_out(i) for i in result["items"]],
        "next_cursor": result.get("next_cursor"),
    }


# ─── Content license queries ──────────────────────────────────────────────────

@router.get("/content/{content_id}")
def list_content_licenses(
    content_id: str,
    status: Optional[str] = Query(default=None),
    session: dict = Depends(require_ui_session),
):
    items = svc.list_licenses_for_content(
        content_id=content_id,
        status_filter=status,
    )
    return {"items": [_license_out(i) for i in items]}


@router.get("/content/{content_id}/check", response_model=LicenseCheckOut)
def check_user_license(
    content_id: str,
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    lic = svc.check_license_for_use(content_id=content_id, user_id=user_sub)
    if lic:
        return LicenseCheckOut(
            has_license=True,
            issued_license_id=lic.get("issued_license_id"),
            license_mode=lic.get("license_mode"),
            terms={
                "profit_share_pct": int(lic.get("profit_share_pct", 0)),
                "fixed_cost_cents": int(lic.get("fixed_cost_cents", 0)),
                "revenue_share_pct": int(lic.get("revenue_share_pct", 0)),
            },
        )
    return LicenseCheckOut(has_license=False)


# ─── Licensed Content Library ─────────────────────────────────────────────────

@router.get("/library")
def browse_licensed_library(
    content_type: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    session: dict = Depends(require_ui_session),
):
    result = svc.browse_library(
        content_type=content_type,
        limit=limit,
        cursor=cursor,
    )
    return {
        "items": [_library_out(i) for i in result["items"]],
        "next_cursor": result.get("next_cursor"),
    }


@router.get("/library/creator/{licensor_id}")
def browse_creator_library(
    licensor_id: str,
    limit: int = Query(default=20, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    session: dict = Depends(require_ui_session),
):
    result = svc.browse_library(
        licensor_id=licensor_id,
        limit=limit,
        cursor=cursor,
    )
    return {
        "items": [_library_out(i) for i in result["items"]],
        "next_cursor": result.get("next_cursor"),
    }
