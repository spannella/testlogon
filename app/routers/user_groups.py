"""User Groups router (GROUP-001)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.services.sessions import require_ui_session
from app.models import (
    CreateGroupIn,
    UpdateGroupIn,
    GroupInviteIn,
    GroupInviteResponseIn,
    GroupReviewRequestIn,
    GroupUpdateRoleIn,
)

router = APIRouter(tags=["user-groups"])


# ── Group CRUD ────────────────────────────────────────────────────────────────

@router.post("/ui/groups", status_code=201)
def create_group(body: CreateGroupIn, session=Depends(require_ui_session)):
    from app.services.user_groups import create_group as _create
    result = _create(
        creator_sub=session["user_sub"],
        name=body.name,
        description=body.description,
        visibility=body.visibility,
        topic=body.topic,
    )
    return _sanitize(result)


@router.get("/ui/groups")
def list_groups(session=Depends(require_ui_session)):
    from app.services.user_groups import list_user_groups
    groups = list_user_groups(session["user_sub"])
    return {"groups": [_sanitize(g) for g in groups]}


@router.get("/ui/groups/discover")
def discover_groups(query: str = "", limit: int = 20, session=Depends(require_ui_session)):
    from app.services.user_groups import search_public_groups
    groups = search_public_groups(query=query, limit=limit)
    return {"groups": [_sanitize(g) for g in groups]}


@router.get("/ui/groups/{group_id}")
def get_group(group_id: str, session=Depends(require_ui_session)):
    from app.services.user_groups import get_group as _get
    group = _get(group_id, viewer_id=session["user_sub"])
    if not group:
        raise HTTPException(404, "Group not found")
    if group.get("status") == "dissolved":
        raise HTTPException(410, "This group has been dissolved")
    return _sanitize(group)


@router.patch("/ui/groups/{group_id}")
def update_group(group_id: str, body: UpdateGroupIn, session=Depends(require_ui_session)):
    from app.services.user_groups import update_group as _update
    try:
        result = _update(
            group_id,
            session["user_sub"],
            name=body.name,
            description=body.description,
            visibility=body.visibility,
            topic=body.topic,
        )
        return _sanitize(result)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.delete("/ui/groups/{group_id}")
def dissolve_group(group_id: str, session=Depends(require_ui_session)):
    from app.services.user_groups import dissolve_group as _dissolve
    try:
        return _dissolve(group_id, session["user_sub"])
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(404, str(e))


# ── Members ───────────────────────────────────────────────────────────────────

@router.get("/ui/groups/{group_id}/members")
def list_members(group_id: str, session=Depends(require_ui_session)):
    from app.services.user_groups import list_members as _list, get_group as _get
    group = _get(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    members = _list(group_id)
    return {"members": members, "count": len(members)}


@router.post("/ui/groups/{group_id}/join")
def join_group(group_id: str, session=Depends(require_ui_session)):
    from app.services.user_groups import join_group as _join
    try:
        result = _join(group_id, session["user_sub"], display_name=session["user_sub"])
        return _sanitize_member(result)
    except ValueError as e:
        msg = str(e)
        if "dissolved" in msg:
            raise HTTPException(410, msg)
        if "Already" in msg or "pending" in msg:
            raise HTTPException(409, msg)
        raise HTTPException(404, msg)


@router.post("/ui/groups/{group_id}/leave")
def leave_group(group_id: str, session=Depends(require_ui_session)):
    from app.services.user_groups import leave_group as _leave
    try:
        return _leave(group_id, session["user_sub"])
    except ValueError as e:
        raise HTTPException(404, str(e))


# ── Invitations ───────────────────────────────────────────────────────────────

@router.post("/ui/groups/{group_id}/invite")
def invite_to_group(group_id: str, body: GroupInviteIn, session=Depends(require_ui_session)):
    from app.services.user_groups import invite_to_group as _invite
    try:
        result = _invite(group_id, session["user_sub"], body.user_id)
        return _sanitize_member(result)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(409, str(e))


@router.post("/ui/groups/{group_id}/invites/{user_id}/respond")
def respond_to_invite(group_id: str, user_id: str, body: GroupInviteResponseIn, session=Depends(require_ui_session)):
    from app.services.user_groups import respond_to_invite as _respond
    if session["user_sub"] != user_id:
        raise HTTPException(403, "Can only respond to your own invitations")
    try:
        return _respond(group_id, user_id, body.accept)
    except ValueError as e:
        raise HTTPException(404, str(e))


# ── Join request review ──────────────────────────────────────────────────────

@router.post("/ui/groups/{group_id}/requests/{user_id}/review")
def review_join_request(group_id: str, user_id: str, body: GroupReviewRequestIn, session=Depends(require_ui_session)):
    from app.services.user_groups import approve_join_request as _approve
    try:
        return _approve(group_id, session["user_sub"], user_id, body.approved)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(404, str(e))


# ── Role management ──────────────────────────────────────────────────────────

@router.patch("/ui/groups/{group_id}/members/{user_id}/role")
def update_member_role(group_id: str, user_id: str, body: GroupUpdateRoleIn, session=Depends(require_ui_session)):
    from app.services.user_groups import promote_member as _promote
    try:
        return _promote(group_id, session["user_sub"], user_id, body.role)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.delete("/ui/groups/{group_id}/members/{user_id}")
def remove_member(group_id: str, user_id: str, session=Depends(require_ui_session)):
    from app.services.user_groups import remove_member as _remove
    try:
        return _remove(group_id, session["user_sub"], user_id)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(404, str(e))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sanitize(item: dict) -> dict:
    """Remove DDB internal keys from response."""
    out = {k: v for k, v in item.items() if k not in ("pk", "sk", "GSI1PK", "GSI1SK", "GSI2PK", "GSI2SK")}
    # Coerce Decimal to int for numeric fields
    for field in ("member_count", "created_at", "updated_at"):
        if field in out and out[field] is not None:
            out[field] = int(out[field])
    return out


def _sanitize_member(item: dict) -> dict:
    out = {k: v for k, v in item.items() if k not in ("pk", "sk")}
    for field in ("joined_at", "promoted_at", "created_at"):
        if field in out and out[field] is not None:
            out[field] = int(out[field])
    return out
