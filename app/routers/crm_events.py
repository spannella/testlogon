"""CRM Events router — EVT-002/003/004.

All routes are gated by S.crm_events_enabled (default False).
"""
from __future__ import annotations

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.core.settings import S
from app.services.sessions import require_ui_session
from app.auth.roles import normalize_role, role_allows_admin_features
from app import models
import app.services.crm_events as svc

router = APIRouter(prefix="/ui/crm/events", tags=["crm_events"])


def _require_crm_events_enabled() -> None:
    """Raise HTTP 404 when the CRM Events feature flag is off."""
    if not S.crm_events_enabled:
        raise HTTPException(status_code=404, detail="CRM Events feature is not enabled")


def _load_event_or_404(event_id: str) -> dict:
    meta = svc.get_crm_event(event_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Event not found")
    return meta


def _require_owner_or_admin(meta: dict, ctx: Dict[str, str]) -> None:
    role = normalize_role(ctx.get("role", "user"))
    if ctx["user_sub"] != meta["owner_sub"] and not role_allows_admin_features(role):
        raise HTTPException(status_code=403, detail="Forbidden")


# ---------------------------------------------------------------------------
# EVT-002: Event creation + invitee management
# ---------------------------------------------------------------------------

@router.post("/", response_model=models.CrmEventOut, status_code=201)
async def create_crm_event(
    body: models.CrmEventCreateIn,
    request: Request,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_crm_events_enabled()
    item = svc.create_crm_event(
        owner_sub=ctx["user_sub"],
        name=body.name,
        description=body.description,
        calendar_event_id=body.calendar_event_id,
        max_attendance=body.max_attendance,
    )
    return item


@router.get("", response_model=models.CrmEventListOut)
async def list_crm_events(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_crm_events_enabled()
    return svc.list_events(ctx["user_sub"], limit=limit, cursor=cursor)


@router.get("/{event_id}", response_model=models.CrmEventOut)
async def get_crm_event_endpoint(
    event_id: str,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_crm_events_enabled()
    meta = _load_event_or_404(event_id)
    _require_owner_or_admin(meta, ctx)
    return svc._event_out(meta)


@router.patch("/{event_id}", response_model=models.CrmEventOut)
async def update_crm_event_endpoint(
    event_id: str,
    body: models.CrmEventUpdateIn,
    request: Request,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_crm_events_enabled()
    meta = _load_event_or_404(event_id)
    _require_owner_or_admin(meta, ctx)
    updated = svc.update_event(
        event_id,
        body.model_dump(exclude_unset=True),
        actor_sub=ctx["user_sub"],
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return svc._event_out(updated)


@router.post("/{event_id}/invitees", response_model=models.CrmInviteeOut, status_code=201)
async def add_invitee(
    event_id: str,
    body: models.CrmInviteeAddIn,
    request: Request,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_crm_events_enabled()
    meta = _load_event_or_404(event_id)
    _require_owner_or_admin(meta, ctx)
    item, _was_new = svc.add_invitee(event_id, body.invitee_sub, actor_sub=ctx["user_sub"])
    return svc._invitee_out(item)


@router.delete("/{event_id}/invitees/{invitee_sub}", status_code=204)
async def remove_invitee(
    event_id: str,
    invitee_sub: str,
    request: Request,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_crm_events_enabled()
    meta = _load_event_or_404(event_id)
    _require_owner_or_admin(meta, ctx)
    found = svc.remove_invitee(event_id, invitee_sub, actor_sub=ctx["user_sub"])
    if not found:
        raise HTTPException(status_code=404, detail="Invitee not found")


@router.post("/{event_id}/invitees/bulk-import")
async def bulk_import_invitees(
    event_id: str,
    body: models.CrmInviteeBulkImportIn,
    request: Request,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_crm_events_enabled()
    meta = _load_event_or_404(event_id)
    _require_owner_or_admin(meta, ctx)
    result = svc.bulk_import_invitees(event_id, body.user_subs, actor_sub=ctx["user_sub"])
    return result


@router.post("/{event_id}/invitees/send-invitations", response_model=models.CrmSendInvitationsOut)
async def send_invitations(
    event_id: str,
    request: Request,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_crm_events_enabled()
    meta = _load_event_or_404(event_id)
    _require_owner_or_admin(meta, ctx)
    result = svc.send_invitations(event_id, meta, actor_sub=ctx["user_sub"])
    return result


@router.get("/{event_id}/invitees", response_model=models.CrmInviteeListOut)
async def list_invitees(
    event_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_crm_events_enabled()
    meta = _load_event_or_404(event_id)
    _require_owner_or_admin(meta, ctx)
    return svc.list_invitees(event_id, limit=limit, cursor=cursor)


# ---------------------------------------------------------------------------
# EVT-003: Registration workflow
# ---------------------------------------------------------------------------

@router.post("/{event_id}/registrations", response_model=models.CrmRegistrationOut, status_code=201)
async def register_for_event(
    event_id: str,
    request: Request,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_crm_events_enabled()
    _load_event_or_404(event_id)  # 404 if missing
    item = svc.register_for_event(event_id, ctx["user_sub"])
    return svc._reg_out(item)


@router.post("/{event_id}/registrations/{registrant_sub}/respond", response_model=models.CrmRegistrationOut)
async def respond_to_invitation(
    event_id: str,
    registrant_sub: str,
    body: models.CrmRespondIn,
    request: Request,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_crm_events_enabled()
    _load_event_or_404(event_id)
    # Only the registrant themselves can accept/decline their own registration
    if ctx["user_sub"] != registrant_sub:
        raise HTTPException(status_code=403, detail="Forbidden")
    item = svc.respond_to_invitation(event_id, registrant_sub, body.new_status, actor_sub=ctx["user_sub"])
    return svc._reg_out(item)


@router.post("/{event_id}/registrations/{registrant_sub}/check-in", response_model=models.CrmRegistrationOut)
async def check_in_attendee(
    event_id: str,
    registrant_sub: str,
    request: Request,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_crm_events_enabled()
    meta = _load_event_or_404(event_id)
    _require_owner_or_admin(meta, ctx)
    item = svc.check_in_attendee(event_id, registrant_sub, actor_sub=ctx["user_sub"])
    return svc._reg_out(item)


@router.delete("/{event_id}/registrations/{registrant_sub}", status_code=204)
async def cancel_registration(
    event_id: str,
    registrant_sub: str,
    request: Request,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_crm_events_enabled()
    meta = _load_event_or_404(event_id)
    role = normalize_role(ctx.get("role", "user"))
    # Only the registrant, the event owner, or an admin can cancel
    if (
        ctx["user_sub"] != registrant_sub
        and ctx["user_sub"] != meta["owner_sub"]
        and not role_allows_admin_features(role)
    ):
        raise HTTPException(status_code=403, detail="Forbidden")
    found = svc.cancel_registration(event_id, registrant_sub, actor_sub=ctx["user_sub"])
    if not found:
        raise HTTPException(status_code=404, detail="Registration not found")


@router.get("/{event_id}/registrations", response_model=models.CrmRegistrationListOut)
async def list_registrations(
    event_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_crm_events_enabled()
    meta = _load_event_or_404(event_id)
    _require_owner_or_admin(meta, ctx)
    return svc.list_registrations(event_id, limit=limit, cursor=cursor)


# ---------------------------------------------------------------------------
# EVT-004: Capacity
# ---------------------------------------------------------------------------

@router.get("/{event_id}/capacity", response_model=models.CrmCapacityOut)
async def get_event_capacity(
    event_id: str,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_crm_events_enabled()
    return svc.get_event_capacity(event_id)
