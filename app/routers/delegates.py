"""Delegate management router (DELEGATE-001).

Endpoints for creator-side delegate management and delegate-side invite handling.
Static paths (settings, invites, managed, presets, audit) MUST be registered
before path-parameter routes (/{delegate_id}) to avoid ambiguous matching.
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends

from app.services import delegates as svc
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/delegates", tags=["delegates"])


# ---------------------------------------------------------------------------
# Static paths first (must precede /{delegate_id} catch-all)
# ---------------------------------------------------------------------------


@router.get("/settings")
async def get_settings(user=Depends(require_ui_session)):
    """Get creator delegation settings."""
    return svc.get_creator_settings(user["user_sub"])


@router.put("/settings")
async def update_settings(
    body: dict,
    user=Depends(require_ui_session),
):
    """Update creator delegation settings."""
    return svc.update_creator_settings(
        creator_id=user["user_sub"],
        require_acceptance=body.get("require_acceptance", True),
        max_delegates=body.get("max_delegates", 10),
        default_preset=body.get("default_preset"),
        delegate_tag_enabled=body.get("delegate_tag_enabled", True),
        delegate_tag_format=body.get("delegate_tag_format", "[via @{delegate_name}]"),
    )


@router.get("/invites")
async def list_invites(user=Depends(require_ui_session)):
    """List pending delegation invites for the current user."""
    return svc.list_pending_invites(user["user_sub"])


@router.post("/invites/{creator_id}/respond")
async def respond_to_invite(
    creator_id: str,
    body: dict,
    user=Depends(require_ui_session),
):
    """Accept or decline a delegation invite."""
    result = svc.respond_to_invite(
        creator_id=creator_id,
        delegate_id=user["user_sub"],
        accept=body.get("accept", False),
    )
    if result:
        return {"ok": True, "status": result.get("status", "active")}
    return {"ok": True, "status": "declined"}


@router.get("/managed")
async def list_managed_creators(user=Depends(require_ui_session)):
    """List all creators the current user manages."""
    return svc.list_managed_creators(user["user_sub"])


@router.get("/presets")
async def list_presets(user=Depends(require_ui_session)):
    """List available permission presets."""
    return svc.get_presets()


@router.get("/audit")
async def get_audit_log(user=Depends(require_ui_session)):
    """Get delegation audit log."""
    return svc.get_audit_log(user["user_sub"])


# ---------------------------------------------------------------------------
# Creator-side delegate CRUD (path-parameter routes)
# ---------------------------------------------------------------------------


@router.get("")
async def list_delegates(user=Depends(require_ui_session)):
    """List all delegates for the current user (as creator)."""
    return svc.list_delegates(user["user_sub"])


@router.post("")
async def add_delegate(
    body: dict,
    user=Depends(require_ui_session),
):
    """Add a new delegate."""
    return svc.add_delegate(
        creator_id=user["user_sub"],
        delegate_id=body["delegate_id"],
        permissions=body.get("permissions", []),
        preset=body.get("preset"),
        label=body.get("label", ""),
    )


@router.get("/{delegate_id}")
async def get_delegate(
    delegate_id: str,
    user=Depends(require_ui_session),
):
    """Get a specific delegate."""
    item = svc.get_delegate(user["user_sub"], delegate_id)
    if not item:
        from fastapi import HTTPException
        raise HTTPException(404, "Delegate not found")
    return item


@router.put("/{delegate_id}/permissions")
async def update_permissions(
    delegate_id: str,
    body: dict,
    user=Depends(require_ui_session),
):
    """Update a delegate's permissions."""
    return svc.update_delegate_permissions(
        creator_id=user["user_sub"],
        delegate_id=delegate_id,
        permissions=body["permissions"],
        preset=body.get("preset"),
    )


@router.delete("/{delegate_id}")
async def revoke_delegate(
    delegate_id: str,
    user=Depends(require_ui_session),
):
    """Revoke a delegate."""
    svc.revoke_delegate(creator_id=user["user_sub"], delegate_id=delegate_id)
    return {"ok": True}
