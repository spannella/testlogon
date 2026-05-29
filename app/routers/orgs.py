"""Organization / Team Workspaces router (ENTERPRISE-003)."""
from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Response, UploadFile, File, Form
from fastapi.responses import StreamingResponse
import io

from app.services.sessions import require_ui_session
from app.models import (
    OrgCreateReq,
    OrgUpdateReq,
    OrgMemberInviteReq,
    OrgMemberRoleUpdateReq,
    OrgTransferOwnershipReq,
    OrgInviteAcceptReq,
    OrgEventCreateReq,
    OrgEventUpdateReq,
)

router = APIRouter(tags=["organizations"])


# ── Org CRUD ──────────────────────────────────────────────────────

@router.post("/ui/orgs", status_code=201)
def create_org(body: OrgCreateReq, session=Depends(require_ui_session)):
    from app.services.org_service import create_org as _create
    org = _create(
        name=body.name,
        owner_user_sub=session["user_sub"],
        description=body.description or "",
        billing_mode=body.billing_mode,
    )
    return org


@router.get("/ui/orgs")
def list_orgs(session=Depends(require_ui_session)):
    from app.services.org_service import list_user_orgs
    return list_user_orgs(session["user_sub"])


@router.get("/ui/orgs/invites/pending")
def list_pending_invites(session=Depends(require_ui_session)):
    from app.services.org_service import list_pending_invites as _list
    return _list(session["user_sub"])


@router.post("/ui/orgs/invites/{invite_id}/accept")
def accept_invite(invite_id: str, body: OrgInviteAcceptReq, session=Depends(require_ui_session)):
    from app.services.org_service import accept_invite as _accept
    return _accept(invite_id, session["user_sub"], body.token)


@router.post("/ui/orgs/invites/{invite_id}/decline", status_code=204)
def decline_invite(invite_id: str, session=Depends(require_ui_session)):
    from app.services.org_service import decline_invite as _decline
    _decline(invite_id, session["user_sub"])
    return Response(status_code=204)


@router.get("/ui/orgs/{org_id}")
def get_org(org_id: str, session=Depends(require_ui_session)):
    from app.services.org_service import get_org as _get, assert_org_membership
    assert_org_membership(org_id, session["user_sub"], min_role="viewer")
    org = _get(org_id)
    if not org:
        raise HTTPException(404, "Organization not found")
    return org


@router.patch("/ui/orgs/{org_id}")
def update_org(org_id: str, body: OrgUpdateReq, session=Depends(require_ui_session)):
    from app.services.org_service import update_org as _update
    updates = body.model_dump(exclude_none=True)
    return _update(org_id, session["user_sub"], updates)


@router.delete("/ui/orgs/{org_id}", status_code=204)
def archive_org(org_id: str, session=Depends(require_ui_session)):
    from app.services.org_service import archive_org as _archive
    _archive(org_id, session["user_sub"])
    return Response(status_code=204)


# ── Members ───────────────────────────────────────────────────────

@router.get("/ui/orgs/{org_id}/members")
def list_members(org_id: str, session=Depends(require_ui_session)):
    from app.services.org_service import list_members as _list
    return _list(org_id, session["user_sub"])


@router.post("/ui/orgs/{org_id}/members/invite", status_code=201)
def invite_member(org_id: str, body: OrgMemberInviteReq, session=Depends(require_ui_session)):
    from app.services.org_service import invite_member as _invite
    return _invite(org_id, session["user_sub"], body.email, body.org_role)


@router.patch("/ui/orgs/{org_id}/members/{member_sub}/role")
def change_member_role(org_id: str, member_sub: str, body: OrgMemberRoleUpdateReq, session=Depends(require_ui_session)):
    from app.services.org_service import change_member_role as _change
    return _change(org_id, session["user_sub"], member_sub, body.org_role)


@router.delete("/ui/orgs/{org_id}/members/{member_sub}", status_code=204)
def remove_member(org_id: str, member_sub: str, session=Depends(require_ui_session)):
    from app.services.org_service import remove_member as _remove
    _remove(org_id, session["user_sub"], member_sub)
    return Response(status_code=204)


@router.post("/ui/orgs/{org_id}/leave", status_code=204)
def leave_org(org_id: str, session=Depends(require_ui_session)):
    from app.services.org_service import leave_org as _leave
    _leave(org_id, session["user_sub"])
    return Response(status_code=204)


@router.post("/ui/orgs/{org_id}/transfer-ownership", status_code=204)
def transfer_ownership(org_id: str, body: OrgTransferOwnershipReq, session=Depends(require_ui_session)):
    from app.services.org_service import transfer_ownership as _transfer
    _transfer(org_id, session["user_sub"], body.new_owner_user_sub)
    return Response(status_code=204)


# ── Files ─────────────────────────────────────────────────────────

@router.get("/ui/orgs/{org_id}/files")
def list_org_files(org_id: str, session=Depends(require_ui_session)):
    from app.services.org_files import org_list_children
    return org_list_children(org_id, session["user_sub"])


@router.post("/ui/orgs/{org_id}/files/upload", status_code=201)
def upload_org_file(
    org_id: str,
    file: UploadFile = File(...),
    session=Depends(require_ui_session),
):
    from app.services.org_files import org_upload_file
    return org_upload_file(org_id, session["user_sub"], file.filename or "unnamed", file)


@router.get("/ui/orgs/{org_id}/files/{node_id}/download")
def download_org_file(org_id: str, node_id: str, session=Depends(require_ui_session)):
    from app.services.org_files import org_download_file
    result = org_download_file(org_id, session["user_sub"], node_id)
    return StreamingResponse(
        io.BytesIO(result["content"]),
        media_type=result["content_type"],
        headers={"Content-Disposition": f'attachment; filename="{result["filename"]}"'},
    )


@router.delete("/ui/orgs/{org_id}/files/{node_id}", status_code=204)
def delete_org_file(org_id: str, node_id: str, session=Depends(require_ui_session)):
    from app.services.org_files import org_remove_file
    org_remove_file(org_id, session["user_sub"], node_id)
    return Response(status_code=204)


# ── Calendar ──────────────────────────────────────────────────────

@router.get("/ui/orgs/{org_id}/calendar/events")
def list_org_events(org_id: str, session=Depends(require_ui_session)):
    from app.services.org_calendar import list_org_events as _list
    return _list(org_id, session["user_sub"])


@router.post("/ui/orgs/{org_id}/calendar/events", status_code=201)
def create_org_event(org_id: str, body: OrgEventCreateReq, session=Depends(require_ui_session)):
    from app.services.org_calendar import create_org_event as _create
    return _create(
        org_id=org_id,
        user_sub=session["user_sub"],
        title=body.title,
        start_time=body.start_time,
        end_time=body.end_time,
        description=body.description or "",
        all_day=body.all_day,
        attendees=body.attendees,
    )


@router.patch("/ui/orgs/{org_id}/calendar/events/{event_id}")
def update_org_event(org_id: str, event_id: str, body: OrgEventUpdateReq, session=Depends(require_ui_session)):
    from app.services.org_calendar import update_org_event as _update
    return _update(
        org_id=org_id,
        user_sub=session["user_sub"],
        event_id=event_id,
        title=body.title,
        description=body.description,
        start_time=body.start_time,
        end_time=body.end_time,
    )


@router.delete("/ui/orgs/{org_id}/calendar/events/{event_id}", status_code=204)
def delete_org_event(org_id: str, event_id: str, session=Depends(require_ui_session)):
    from app.services.org_calendar import delete_org_event as _delete
    _delete(org_id, session["user_sub"], event_id)
    return Response(status_code=204)


# ── Billing ───────────────────────────────────────────────────────

@router.get("/ui/orgs/{org_id}/billing/payment-methods")
def list_org_payment_methods(org_id: str, session=Depends(require_ui_session)):
    from app.services.org_service import assert_org_membership
    from app.services.org_billing import list_org_payment_methods as _list
    assert_org_membership(org_id, session["user_sub"], min_role="owner")
    return _list(org_id)


@router.post("/ui/orgs/{org_id}/billing/payment-methods", status_code=201)
def add_org_payment_method(org_id: str, body: dict, session=Depends(require_ui_session)):
    from app.services.org_billing import add_org_payment_method as _add
    return _add(
        org_id=org_id,
        user_sub=session["user_sub"],
        provider=body.get("provider", "stripe"),
        pm_type=body.get("type", "card"),
        last4=body.get("last4", "4242"),
        brand=body.get("brand", "visa"),
        exp_month=body.get("exp_month", 12),
        exp_year=body.get("exp_year", 2027),
        billing_email=body.get("billing_email", ""),
    )


@router.delete("/ui/orgs/{org_id}/billing/payment-methods/{pm_id}", status_code=204)
def remove_org_payment_method(org_id: str, pm_id: str, session=Depends(require_ui_session)):
    from app.services.org_billing import remove_org_payment_method as _remove
    _remove(org_id, session["user_sub"], pm_id)
    return Response(status_code=204)


@router.post("/ui/orgs/{org_id}/billing/set-default")
def set_org_default_pm(org_id: str, body: dict, session=Depends(require_ui_session)):
    from app.services.org_billing import set_org_default_payment_method as _set
    _set(org_id, session["user_sub"], body.get("payment_method_id", ""))
    return {"ok": True}


@router.get("/ui/orgs/{org_id}/billing/history")
def get_org_billing_history(org_id: str, session=Depends(require_ui_session)):
    from app.services.org_service import assert_org_membership
    from app.services.org_billing import get_org_billing_history as _get
    assert_org_membership(org_id, session["user_sub"], min_role="owner")
    return _get(org_id)
