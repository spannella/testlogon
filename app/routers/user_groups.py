"""User group management router (GROUP-001)."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.services.sessions import require_ui_session
from app.models import (
    CreateGroupIn,
    GroupInviteIn,
    GroupInviteResponseIn,
    GroupListOut,
    GroupMemberListOut,
    GroupMemberOut,
    GroupOut,
    GroupReviewRequestIn,
    GroupUpdateRoleIn,
    UpdateGroupIn,
)
from app.services import user_groups as svc

router = APIRouter(prefix="/ui/groups", tags=["user-groups"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _meta_to_out(meta: dict, my_role: Optional[str] = None) -> GroupOut:
    return GroupOut(
        group_id=meta.get("group_id", ""),
        name=meta.get("name", ""),
        description=meta.get("description", ""),
        topic=meta.get("topic"),
        visibility=meta.get("visibility", "public"),
        status=meta.get("status", "active"),
        admin_user_id=meta.get("admin_user_id", ""),
        cover_image_url=meta.get("cover_image_url"),
        member_count=int(meta.get("member_count", 0)),
        created_at=int(meta.get("created_at", 0)),
        updated_at=int(meta.get("updated_at", 0)),
        my_role=my_role or meta.get("my_role"),
    )


def _member_to_out(m: dict) -> GroupMemberOut:
    return GroupMemberOut(
        user_id=m.get("user_id", ""),
        role=m.get("role", "member"),
        status=m.get("status", "active"),
        display_name=m.get("display_name", ""),
        joined_at=int(m["joined_at"]) if m.get("joined_at") is not None else None,
        promoted_at=int(m["promoted_at"]) if m.get("promoted_at") is not None else None,
    )


# ---------------------------------------------------------------------------
# Group CRUD
# ---------------------------------------------------------------------------


@router.post("", status_code=201)
def create_group(body: CreateGroupIn, session=Depends(require_ui_session)):
    meta = svc.create_group(
        creator_sub=session["user_sub"],
        name=body.name,
        description=body.description,
        visibility=body.visibility,
        topic=body.topic,
    )
    return _meta_to_out(meta, my_role="admin")


@router.get("")
def list_my_groups(session=Depends(require_ui_session)):
    items = svc.list_user_groups(session["user_sub"])
    groups = []
    for item in items:
        gid = item.get("group_id", "")
        meta = svc.get_group(gid)
        if meta and meta.get("status") != "dissolved":
            # Determine role by querying membership
            membership = svc._get_membership(gid, session["user_sub"])
            role = membership.get("role") if membership else None
            groups.append(_meta_to_out(meta, my_role=role))
    # Return the wrapped {groups: [...]} shape (consistent with /discover and
    # the frontend listMyGroups contract). A bare list left the UI's
    # `myGroups.groups` undefined, so the "My Groups" tab rendered nothing.
    return GroupListOut(groups=groups, cursor=None, has_more=False)


@router.get("/discover")
def discover_groups(
    query: Optional[str] = Query(default=None),
    topic: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    session=Depends(require_ui_session),
):
    items = svc.search_public_groups(query=query, topic=topic, limit=limit)
    return GroupListOut(
        groups=[_meta_to_out(i) for i in items],
        cursor=None,
        has_more=False,
    )


@router.get("/{group_id}")
def get_group(group_id: str, session=Depends(require_ui_session)):
    meta = svc.get_group_detail(group_id, viewer_sub=session["user_sub"])
    return _meta_to_out(meta)


@router.patch("/{group_id}")
def update_group(group_id: str, body: UpdateGroupIn, session=Depends(require_ui_session)):
    meta = svc.update_group(
        group_id=group_id,
        admin_sub=session["user_sub"],
        name=body.name,
        description=body.description,
        visibility=body.visibility,
        topic=body.topic,
    )
    return _meta_to_out(meta)


@router.delete("/{group_id}")
def dissolve_group(group_id: str, session=Depends(require_ui_session)):
    return svc.dissolve_group(group_id=group_id, admin_id=session["user_sub"])


# ---------------------------------------------------------------------------
# Membership
# ---------------------------------------------------------------------------


@router.get("/{group_id}/members")
def list_members(group_id: str, session=Depends(require_ui_session)):
    # Check visibility for private groups
    meta = svc.get_group_or_404(group_id)
    if meta.get("visibility") == "private":
        membership = svc._get_membership(group_id, session["user_sub"])
        if not membership or membership.get("status") != "active":
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="Not a member of this group")

    members = svc.list_members(group_id)
    return GroupMemberListOut(
        members=[_member_to_out(m) for m in members],
        count=len(members),
    )


@router.post("/{group_id}/join")
def join_group(group_id: str, session=Depends(require_ui_session)):
    result = svc.join_group(
        group_id=group_id,
        user_id=session["user_sub"],
        display_name="",
    )
    return _member_to_out(result)


@router.post("/{group_id}/leave")
def leave_group(group_id: str, session=Depends(require_ui_session)):
    return svc.leave_group(group_id=group_id, user_id=session["user_sub"])


@router.post("/{group_id}/invite")
def invite_to_group(group_id: str, body: GroupInviteIn, session=Depends(require_ui_session)):
    result = svc.invite_to_group(
        group_id=group_id,
        inviter_id=session["user_sub"],
        invitee_id=body.user_id,
    )
    return _member_to_out(result)


@router.post("/{group_id}/invites/{user_id}/respond")
def respond_to_invite(
    group_id: str,
    user_id: str,
    body: GroupInviteResponseIn,
    session=Depends(require_ui_session),
):
    # Verify the responding user matches the invite target
    if session["user_sub"] != user_id:
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="You can only respond to your own invitations")
    return svc.respond_to_invite(
        group_id=group_id,
        user_id=user_id,
        accept=body.accept,
    )


@router.post("/{group_id}/requests/{user_id}/review")
def review_join_request(
    group_id: str,
    user_id: str,
    body: GroupReviewRequestIn,
    session=Depends(require_ui_session),
):
    return svc.approve_join_request(
        group_id=group_id,
        approver_id=session["user_sub"],
        applicant_id=user_id,
        approved=body.approved,
    )


@router.patch("/{group_id}/members/{user_id}/role")
def update_member_role(
    group_id: str,
    user_id: str,
    body: GroupUpdateRoleIn,
    session=Depends(require_ui_session),
):
    result = svc.promote_member(
        group_id=group_id,
        admin_id=session["user_sub"],
        target_id=user_id,
        new_role=body.role,
    )
    return _member_to_out(result)


@router.delete("/{group_id}/members/{user_id}")
def remove_member(group_id: str, user_id: str, session=Depends(require_ui_session)):
    return svc.remove_member(
        group_id=group_id,
        remover_id=session["user_sub"],
        target_id=user_id,
    )


@router.get("/{group_id}/pending")
def list_pending(group_id: str, session=Depends(require_ui_session)):
    svc._require_role(group_id, session["user_sub"], "moderator")
    pending = svc.list_pending(group_id)
    return [_member_to_out(m) for m in pending]
