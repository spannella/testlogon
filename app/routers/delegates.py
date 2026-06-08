"""Delegate management router (DELEGATE-001)."""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends

from app.models import (
    DelegateAddIn,
    DelegateAuditOut,
    DelegateInviteRespondIn,
    DelegateOut,
    DelegateSettingsIn,
    DelegateSettingsOut,
    DelegateUpdatePermissionsIn,
    ManagedCreatorOut,
    PermissionPresetOut,
)
from app.services import delegates as svc
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/delegates", tags=["delegates"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_delegate_out(item: dict) -> DelegateOut:
    return DelegateOut(
        delegate_id=item.get("delegate_id", ""),
        creator_id=item.get("creator_id", ""),
        permissions=item.get("permissions", []),
        preset=item.get("preset"),
        status=item.get("status", ""),
        label=item.get("label", ""),
        show_delegate_tag=bool(item.get("show_delegate_tag", True)),
        delegate_tag_format=item.get("delegate_tag_format", "[via @{delegate_name}]"),
        invited_at=int(item.get("invited_at", 0)),
        accepted_at=int(item.get("accepted_at", 0)),
        updated_at=int(item.get("updated_at", 0)),
    )


def _to_managed_creator(item: dict) -> ManagedCreatorOut:
    return ManagedCreatorOut(
        creator_id=item.get("creator_id", ""),
        permissions=item.get("permissions", []),
        preset=item.get("preset"),
        status=item.get("status", ""),
        label=item.get("label", ""),
        accepted_at=int(item.get("accepted_at", 0)),
    )


def _to_audit_out(item: dict) -> DelegateAuditOut:
    return DelegateAuditOut(
        event_id=item.get("event_id", ""),
        actor_id=item.get("actor_id", ""),
        actor_type=item.get("actor_type", ""),
        action=item.get("action", ""),
        target_id=item.get("target_id", ""),
        details=item.get("details"),
        ts=int(item.get("ts", 0)),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/presets", response_model=List[PermissionPresetOut])
async def list_presets(user=Depends(require_ui_session)):
    """List available permission presets."""
    return svc.get_presets()


@router.get("/settings", response_model=DelegateSettingsOut)
async def get_settings(user=Depends(require_ui_session)):
    """Get creator delegation settings."""
    item = svc.get_creator_settings(user["user_sub"])
    return DelegateSettingsOut(
        require_acceptance=bool(item.get("require_acceptance", True)),
        max_delegates=int(item.get("max_delegates", 10)),
        default_preset=item.get("default_preset"),
        delegate_tag_enabled=bool(item.get("delegate_tag_enabled", True)),
        delegate_tag_format=item.get("delegate_tag_format", "[via @{delegate_name}]"),
        hide_delegate_from_recipients=bool(item.get("hide_delegate_from_recipients", False)),
    )


@router.put("/settings", response_model=DelegateSettingsOut)
async def update_settings(body: DelegateSettingsIn, user=Depends(require_ui_session)):
    """Update creator delegation settings."""
    item = svc.update_creator_settings(
        creator_id=user["user_sub"],
        require_acceptance=body.require_acceptance,
        max_delegates=body.max_delegates,
        default_preset=body.default_preset,
        delegate_tag_enabled=body.delegate_tag_enabled,
        delegate_tag_format=body.delegate_tag_format,
        hide_delegate_from_recipients=body.hide_delegate_from_recipients,
    )
    return DelegateSettingsOut(
        require_acceptance=bool(item.get("require_acceptance", True)),
        max_delegates=int(item.get("max_delegates", 10)),
        default_preset=item.get("default_preset"),
        delegate_tag_enabled=bool(item.get("delegate_tag_enabled", True)),
        delegate_tag_format=item.get("delegate_tag_format", "[via @{delegate_name}]"),
        hide_delegate_from_recipients=bool(item.get("hide_delegate_from_recipients", False)),
    )


@router.get("/invites", response_model=List[DelegateOut])
async def list_invites(user=Depends(require_ui_session)):
    """List pending delegation invites for the current user."""
    items = svc.list_pending_invites(user["user_sub"])
    return [_to_delegate_out(i) for i in items]


@router.get("/managed", response_model=List[ManagedCreatorOut])
async def list_managed(user=Depends(require_ui_session)):
    """List creators the current user delegates for."""
    items = svc.list_managed_creators(user["user_sub"])
    return [_to_managed_creator(i) for i in items]


@router.get("/audit", response_model=List[DelegateAuditOut])
async def get_audit(user=Depends(require_ui_session)):
    """Get delegation audit log for the current user (as creator)."""
    items = svc.get_audit_log(user["user_sub"])
    return [_to_audit_out(i) for i in items]


@router.post("", response_model=DelegateOut)
async def add_delegate(body: DelegateAddIn, user=Depends(require_ui_session)):
    """Add a new delegate."""
    item = svc.add_delegate(
        creator_id=user["user_sub"],
        delegate_id=body.delegate_id,
        permissions=body.permissions,
        preset=body.preset,
        label=body.label,
    )
    return _to_delegate_out(item)


@router.get("", response_model=List[DelegateOut])
async def list_delegates(user=Depends(require_ui_session)):
    """List current user's delegates (as creator)."""
    items = svc.list_delegates(user["user_sub"])
    return [_to_delegate_out(i) for i in items]


@router.get("/{delegate_id}", response_model=DelegateOut)
async def get_delegate(delegate_id: str, user=Depends(require_ui_session)):
    """Get specific delegate details."""
    from fastapi import HTTPException

    item = svc.get_delegate(user["user_sub"], delegate_id)
    if not item:
        raise HTTPException(404, "Delegate not found")
    return _to_delegate_out(item)


@router.put("/{delegate_id}/permissions", response_model=DelegateOut)
async def update_permissions(
    delegate_id: str,
    body: DelegateUpdatePermissionsIn,
    user=Depends(require_ui_session),
):
    """Update delegate permissions."""
    item = svc.update_delegate_permissions(
        creator_id=user["user_sub"],
        delegate_id=delegate_id,
        permissions=body.permissions,
        preset=body.preset,
    )
    return _to_delegate_out(item)


@router.delete("/{delegate_id}")
async def revoke_delegate(delegate_id: str, user=Depends(require_ui_session)):
    """Revoke delegate access."""
    svc.revoke_delegate(creator_id=user["user_sub"], delegate_id=delegate_id)
    return {"ok": True}


@router.post("/invites/{creator_id}/respond", response_model=dict)
async def respond_to_invite(
    creator_id: str,
    body: DelegateInviteRespondIn,
    user=Depends(require_ui_session),
):
    """Accept or decline a delegation invite."""
    result = svc.respond_to_invite(
        creator_id=creator_id,
        delegate_id=user["user_sub"],
        accept=body.accept,
    )
    if result:
        return {"ok": True, "status": "active"}
    return {"ok": True, "status": "declined"}
