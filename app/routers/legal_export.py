"""Legal hold + law-enforcement / subpoena export endpoints (LEX-008/011/012).

All endpoints are gated behind the master flag ``S.legal_export_enabled``
(DEFAULT OFF — 404 when off) AND ``_require_legal`` (ROOT, or a user_sub in the
``LEGAL_EXPORT_AUTHORIZED_SUBS`` allowlist). Ordinary ADMIN/USER get 403.

Every place/release/intake/generate/download writes an ``audit_event`` so each
legal action is itself fully audited.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from app.auth.roles import Role
from app.core.settings import S
from app.services import legal_export as legal_export_svc
from app.services import legal_hold as legal_hold_svc
from app.services.alerts import audit_event
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/legal", tags=["legal-export"])


# ---------------------------------------------------------------------------
# Access control (LEX-011)
# ---------------------------------------------------------------------------

def _authorized_subs() -> set[str]:
    raw = S.legal_export_authorized_subs or ""
    return {s.strip() for s in raw.split(",") if s.strip()}


def _require_enabled() -> None:
    if not S.legal_export_enabled:
        raise HTTPException(status_code=404, detail="Legal export is not enabled")


def _require_legal(ctx: Dict[str, Any]) -> str:
    """ROOT or an allowlisted legal user. Returns the acting user_sub.

    Mirrors ``audit_export._require_root`` but adds the LEGAL allowlist. ADMIN
    and USER are rejected with 403 unless they are explicitly allowlisted.
    """
    _require_enabled()
    role = ctx.get("role")
    user_sub = ctx.get("user_sub", "")
    if role == Role.ROOT:
        return user_sub
    if user_sub and user_sub in _authorized_subs():
        return user_sub
    raise HTTPException(status_code=403, detail="Legal role or root access required")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class PlaceHoldIn(BaseModel):
    user_sub: str
    reason: str
    case_id: Optional[str] = None
    matter_ref: Optional[str] = None
    expires_at: Optional[int] = None


class HoldOut(BaseModel):
    hold_id: str
    user_sub: str
    case_id: str = ""
    matter_ref: str = ""
    reason: str = ""
    status: str
    created_by: str
    created_at: int
    released_by: Optional[str] = None
    released_at: Optional[int] = None
    expires_at: Optional[int] = None


class LegalExportIntakeIn(BaseModel):
    matter_ref: str
    requesting_authority: str
    legal_basis: str
    target_user_subs: List[str] = Field(default_factory=list)
    data_types: Optional[List[str]] = None
    from_ts: Optional[int] = None
    to_ts: Optional[int] = None
    reason: Optional[str] = None


def _hold_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "hold_id": item.get("hold_id", ""),
        "user_sub": item.get("user_sub", ""),
        "case_id": item.get("case_id", ""),
        "matter_ref": item.get("matter_ref", ""),
        "reason": item.get("reason", ""),
        "status": item.get("status", ""),
        "created_by": item.get("created_by", ""),
        "created_at": int(item.get("created_at", 0)),
        "released_by": item.get("released_by"),
        "released_at": (int(item["released_at"]) if item.get("released_at") is not None else None),
        "expires_at": (int(item["expires_at"]) if item.get("expires_at") is not None else None),
    }


# ---------------------------------------------------------------------------
# Legal hold endpoints (LEX-008)
# ---------------------------------------------------------------------------

@router.post("/holds", status_code=201, response_model=HoldOut)
def place_hold(body: PlaceHoldIn, ctx: Dict[str, Any] = Depends(require_ui_session)) -> HoldOut:
    actor = _require_legal(ctx)
    try:
        item = legal_hold_svc.place_hold(
            user_sub=body.user_sub,
            reason=body.reason,
            created_by=actor,
            case_id=body.case_id,
            matter_ref=body.matter_ref,
            expires_at=body.expires_at,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _safe_audit("legal_hold.placed", actor, hold_id=item["hold_id"],
                target_user_sub=body.user_sub, matter_ref=body.matter_ref or "")
    return HoldOut(**_hold_to_out(item))


@router.get("/holds", response_model=List[HoldOut])
def list_holds(ctx: Dict[str, Any] = Depends(require_ui_session)) -> List[HoldOut]:
    _require_legal(ctx)
    return [HoldOut(**_hold_to_out(h)) for h in legal_hold_svc.list_active_holds()]


@router.get("/holds/{hold_id}", response_model=HoldOut)
def get_hold(hold_id: str, ctx: Dict[str, Any] = Depends(require_ui_session)) -> HoldOut:
    _require_legal(ctx)
    item = legal_hold_svc.get_hold(hold_id)
    if not item:
        raise HTTPException(status_code=404, detail="Hold not found")
    return HoldOut(**_hold_to_out(item))


@router.post("/holds/{hold_id}/release", response_model=HoldOut)
def release_hold(hold_id: str, ctx: Dict[str, Any] = Depends(require_ui_session)) -> HoldOut:
    actor = _require_legal(ctx)
    item = legal_hold_svc.release_hold(hold_id, released_by=actor)
    if not item:
        raise HTTPException(status_code=404, detail="Hold not found")
    _safe_audit("legal_hold.released", actor, hold_id=hold_id,
                target_user_sub=item.get("user_sub", ""))
    return HoldOut(**_hold_to_out(item))


# ---------------------------------------------------------------------------
# Legal export endpoints (LEX-012)
# ---------------------------------------------------------------------------

@router.post("/exports", status_code=201)
def create_export(body: LegalExportIntakeIn, ctx: Dict[str, Any] = Depends(require_ui_session)) -> Dict[str, Any]:
    actor = _require_legal(ctx)
    try:
        item = legal_export_svc.create_intake(
            matter_ref=body.matter_ref,
            requesting_authority=body.requesting_authority,
            requested_by=actor,
            legal_basis=body.legal_basis,
            target_user_subs=body.target_user_subs,
            data_types=body.data_types,
            from_ts=body.from_ts,
            to_ts=body.to_ts,
            reason=body.reason,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _safe_audit("legal_export.intake_created", actor,
                legal_export_id=item["legal_export_id"], matter_ref=body.matter_ref,
                target_user_subs=",".join(body.target_user_subs))
    return item


@router.post("/exports/{legal_export_id}/generate")
def generate_export(legal_export_id: str, ctx: Dict[str, Any] = Depends(require_ui_session)) -> Dict[str, Any]:
    actor = _require_legal(ctx)
    try:
        item = legal_export_svc.generate_package(legal_export_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Legal export not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Generation failed: {e}")
    _safe_audit("legal_export.generated", actor, legal_export_id=legal_export_id,
                matter_ref=item.get("matter_ref", ""), package_sha256=item.get("package_sha256", ""))
    return item


@router.get("/exports")
def list_exports(ctx: Dict[str, Any] = Depends(require_ui_session)) -> List[Dict[str, Any]]:
    _require_legal(ctx)
    return legal_export_svc.list_exports()


@router.get("/exports/{legal_export_id}")
def get_export(legal_export_id: str, ctx: Dict[str, Any] = Depends(require_ui_session)) -> Dict[str, Any]:
    actor = _require_legal(ctx)
    item = legal_export_svc.get_export(legal_export_id)
    if not item:
        raise HTTPException(status_code=404, detail="Legal export not found")
    _safe_audit("legal_export.status_viewed", actor, legal_export_id=legal_export_id,
                matter_ref=item.get("matter_ref", ""))
    return item


@router.get("/exports/{legal_export_id}/download")
def download_export(legal_export_id: str, ctx: Dict[str, Any] = Depends(require_ui_session)):
    actor = _require_legal(ctx)
    item = legal_export_svc.get_export(legal_export_id)
    if not item:
        raise HTTPException(status_code=404, detail="Legal export not found")
    url = legal_export_svc.get_download_url(legal_export_id)
    if not url:
        raise HTTPException(status_code=404, detail="Package not available or expired")
    _safe_audit("legal_export.downloaded", actor, legal_export_id=legal_export_id,
                matter_ref=item.get("matter_ref", ""))
    return RedirectResponse(url=url, status_code=302)


def _safe_audit(event: str, actor: str, **fields: Any) -> None:
    try:
        audit_event(event, actor, outcome="success", **fields)
    except Exception:
        logger.exception("legal audit_event %s failed", event)
