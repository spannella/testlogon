"""Syndicate management router (SYND-001)."""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, Query

from app.services.sessions import require_ui_session
from app.models import (
    SyndicateAuditOut,
    SyndicateCreateIn,
    SyndicateInviteIn,
    SyndicateInviteOut,
    SyndicateInviteRespondIn,
    SyndicateJoinRequestIn,
    SyndicateMemberOut,
    SyndicateOut,
    SyndicateRequestOut,
    SyndicateTransferAdminIn,
    SyndicateUpdateIn,
)
from app.services import syndicates as svc

router = APIRouter(prefix="/ui/syndicates", tags=["syndicates"])


# ---------------------------------------------------------------------------
# Syndicate CRUD
# ---------------------------------------------------------------------------

@router.post("", status_code=201)
def create_syndicate(body: SyndicateCreateIn, session=Depends(require_ui_session)):
    meta = svc.create_syndicate(
        creator_sub=session["user_sub"],
        name=body.name,
        description=body.description,
    )
    return _meta_to_out(meta)


@router.get("")
def list_my_syndicates(session=Depends(require_ui_session)):
    items = svc.list_user_syndicates(session["user_sub"])
    return [
        {
            "syndicate_id": i["syndicate_id"],
            "syndicate_name": i.get("syndicate_name", ""),
            "role": i.get("role", "member"),
            "joined_at": int(i.get("joined_at", 0)),
        }
        for i in items
    ]


@router.get("/invites")
def list_my_invites(session=Depends(require_ui_session)):
    items = svc.list_pending_invites(session["user_sub"])
    return [
        SyndicateInviteOut(
            syndicate_id=i.get("syndicate_id", ""),
            syndicate_name=i.get("syndicate_name", ""),
            user_id=i.get("user_id", ""),
            invited_by=i.get("invited_by", ""),
            invited_at=int(i.get("invited_at", 0)),
            status=i.get("status", "pending"),
        )
        for i in items
    ]


@router.get("/discover")
def discover_syndicates(
    limit: int = Query(default=50, ge=1, le=100),
    session=Depends(require_ui_session),
):
    items = svc.list_active_syndicates(limit=limit)
    return [_meta_to_out(i) for i in items]


@router.get("/{syndicate_id}")
def get_syndicate(syndicate_id: str, session=Depends(require_ui_session)):
    detail = svc.get_syndicate_detail(syndicate_id)
    return _detail_to_out(detail)


# ---------------------------------------------------------------------------
# Membership management
# ---------------------------------------------------------------------------

@router.post("/{syndicate_id}/invite", status_code=201)
def invite_member(
    syndicate_id: str,
    body: SyndicateInviteIn,
    session=Depends(require_ui_session),
):
    invite = svc.invite_member(
        syndicate_id=syndicate_id,
        admin_sub=session["user_sub"],
        invitee_user_id=body.user_id,
    )
    return SyndicateInviteOut(
        syndicate_id=invite.get("syndicate_id", syndicate_id),
        syndicate_name=invite.get("syndicate_name", ""),
        user_id=invite.get("user_id", ""),
        invited_by=invite.get("invited_by", ""),
        invited_at=int(invite.get("invited_at", 0)),
        status=invite.get("status", "pending"),
    )


@router.post("/{syndicate_id}/invite/respond")
def respond_to_invite(
    syndicate_id: str,
    body: SyndicateInviteRespondIn,
    session=Depends(require_ui_session),
):
    result = svc.respond_to_invite(
        syndicate_id=syndicate_id,
        user_id=session["user_sub"],
        accept=body.accept,
    )
    return {"ok": True, "status": result.get("status", "")}


@router.post("/{syndicate_id}/request", status_code=201)
def request_to_join(
    syndicate_id: str,
    body: SyndicateJoinRequestIn,
    session=Depends(require_ui_session),
):
    req = svc.request_to_join(
        syndicate_id=syndicate_id,
        user_id=session["user_sub"],
        message=body.message,
    )
    return SyndicateRequestOut(
        syndicate_id=req.get("syndicate_id", syndicate_id),
        user_id=req.get("user_id", ""),
        requested_at=int(req.get("requested_at", 0)),
        message=req.get("message", ""),
        status=req.get("status", "pending"),
    )


@router.post("/{syndicate_id}/request/{user_id}/approve")
def approve_request(
    syndicate_id: str,
    user_id: str,
    session=Depends(require_ui_session),
):
    svc.approve_request(
        syndicate_id=syndicate_id,
        admin_sub=session["user_sub"],
        requester_user_id=user_id,
    )
    return {"ok": True}


@router.post("/{syndicate_id}/request/{user_id}/reject")
def reject_request(
    syndicate_id: str,
    user_id: str,
    session=Depends(require_ui_session),
):
    svc.reject_request(
        syndicate_id=syndicate_id,
        admin_sub=session["user_sub"],
        requester_user_id=user_id,
    )
    return {"ok": True}


@router.post("/{syndicate_id}/transfer-admin")
def transfer_admin(
    syndicate_id: str,
    body: SyndicateTransferAdminIn,
    session=Depends(require_ui_session),
):
    meta = svc.transfer_admin(
        syndicate_id=syndicate_id,
        current_admin_sub=session["user_sub"],
        new_admin_user_id=body.new_admin_user_id,
    )
    return _meta_to_out(meta)


@router.post("/{syndicate_id}/leave")
def leave_syndicate(syndicate_id: str, session=Depends(require_ui_session)):
    result = svc.leave_syndicate(
        syndicate_id=syndicate_id,
        user_id=session["user_sub"],
    )
    return result


@router.post("/{syndicate_id}/remove/{user_id}")
def remove_member(
    syndicate_id: str,
    user_id: str,
    session=Depends(require_ui_session),
):
    svc.remove_member(
        syndicate_id=syndicate_id,
        admin_sub=session["user_sub"],
        target_user_id=user_id,
    )
    return {"ok": True}


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

@router.get("/{syndicate_id}/members")
def list_members(syndicate_id: str, session=Depends(require_ui_session)):
    items = svc.list_members(syndicate_id)
    return [
        SyndicateMemberOut(
            user_id=m.get("user_id", ""),
            display_name=m.get("display_name", ""),
            role=m.get("role", "member"),
            joined_at=int(m.get("joined_at", 0)),
        )
        for m in items
    ]


@router.get("/{syndicate_id}/requests")
def list_requests(syndicate_id: str, session=Depends(require_ui_session)):
    # Admin-only check done in service
    items = svc.list_pending_requests(syndicate_id)
    return [
        SyndicateRequestOut(
            syndicate_id=r.get("syndicate_id", syndicate_id),
            user_id=r.get("user_id", ""),
            requested_at=int(r.get("requested_at", 0)),
            message=r.get("message", ""),
            status=r.get("status", "pending"),
        )
        for r in items
    ]


@router.get("/{syndicate_id}/audit")
def get_audit(
    syndicate_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    session=Depends(require_ui_session),
):
    items = svc.get_audit_log(syndicate_id, limit=limit)
    return [
        SyndicateAuditOut(
            event_id=a.get("event_id", ""),
            actor_id=a.get("actor_id", ""),
            action=a.get("action", ""),
            target_id=a.get("target_id", ""),
            details=a.get("details"),
            ts=int(a.get("ts", 0)),
        )
        for a in items
    ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _meta_to_out(meta: dict) -> SyndicateOut:
    return SyndicateOut(
        syndicate_id=meta.get("syndicate_id", ""),
        name=meta.get("name", ""),
        description=meta.get("description", ""),
        admin_user_id=meta.get("admin_user_id", ""),
        status=meta.get("status", "active"),
        member_count=int(meta.get("member_count", 0)),
        created_at=int(meta.get("created_at", 0)),
        updated_at=int(meta.get("updated_at", 0)),
    )


def _detail_to_out(detail: dict) -> SyndicateOut:
    members = [
        SyndicateMemberOut(
            user_id=m.get("user_id", ""),
            display_name=m.get("display_name", ""),
            role=m.get("role", "member"),
            joined_at=int(m.get("joined_at", 0)),
        )
        for m in detail.get("members", [])
    ]
    return SyndicateOut(
        syndicate_id=detail.get("syndicate_id", ""),
        name=detail.get("name", ""),
        description=detail.get("description", ""),
        admin_user_id=detail.get("admin_user_id", ""),
        status=detail.get("status", "active"),
        member_count=int(detail.get("member_count", 0)),
        created_at=int(detail.get("created_at", 0)),
        updated_at=int(detail.get("updated_at", 0)),
        members=members,
    )
