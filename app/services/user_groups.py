"""User group creation, membership, and lifecycle management (GROUP-001)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_group(
    *,
    creator_sub: str,
    name: str,
    description: str = "",
    visibility: str = "public",
    topic: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a new user group. Creator becomes admin."""
    ts = now_ts()
    group_id = f"grp_{uuid4().hex[:12]}"

    # Check user isn't already in too many groups
    existing_count = _count_user_groups(creator_sub)
    if existing_count >= S.user_group_max_per_user:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum number of groups reached ({S.user_group_max_per_user})",
        )

    meta: Dict[str, Any] = {
        "pk": f"GROUP#{group_id}",
        "sk": "META",
        "group_id": group_id,
        "name": name.strip(),
        "description": description.strip(),
        "topic": topic.strip() if topic else None,
        "visibility": visibility,
        "status": "active",
        "admin_user_id": creator_sub,
        "cover_image_url": None,
        "member_count": 1,
        "created_at": ts,
        "updated_at": ts,
        # GSI1: discover public groups by created_at
        "GSI1PK": visibility,
        "GSI1SK": ts,
        # GSI2: active groups by member_count
        "GSI2PK": "active",
        "GSI2SK": 1,
    }
    # Remove None values to avoid DynamoDB storing null attributes on GSI keys
    meta = {k: v for k, v in meta.items() if v is not None}
    T.user_groups.put_item(Item=meta)

    # Add creator as admin member
    _add_member(group_id, creator_sub, role="admin", display_name="", ts=ts)

    logger.info("group.created", extra={"group_id": group_id, "creator": creator_sub, "visibility": visibility})
    return meta


def get_group(group_id: str) -> Optional[Dict[str, Any]]:
    """Get group metadata."""
    resp = T.user_groups.get_item(Key={"pk": f"GROUP#{group_id}", "sk": "META"})
    return resp.get("Item")


def get_group_or_404(group_id: str) -> Dict[str, Any]:
    """Get group metadata, raise 404 if not found."""
    meta = get_group(group_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Group not found")
    return meta


def get_group_detail(group_id: str, viewer_sub: Optional[str] = None) -> Dict[str, Any]:
    """Get group metadata with viewer's role if applicable."""
    meta = get_group_or_404(group_id)
    if meta.get("status") == "dissolved":
        raise HTTPException(status_code=410, detail="This group has been dissolved")

    if viewer_sub:
        membership = _get_membership(group_id, viewer_sub)
        if membership and membership.get("status") == "active":
            meta["my_role"] = membership.get("role", "member")

    return meta


def update_group(
    *,
    group_id: str,
    admin_sub: str,
    name: Optional[str] = None,
    description: Optional[str] = None,
    visibility: Optional[str] = None,
    topic: Optional[str] = None,
) -> Dict[str, Any]:
    """Update group settings (admin only)."""
    _require_role(group_id, admin_sub, "admin")
    meta = get_group_or_404(group_id)
    if meta.get("status") == "dissolved":
        raise HTTPException(status_code=410, detail="This group has been dissolved")

    ts = now_ts()
    updates: Dict[str, Any] = {"updated_at": ts}
    if name is not None:
        updates["name"] = name.strip()
    if description is not None:
        updates["description"] = description.strip()
    if visibility is not None:
        updates["visibility"] = visibility
        updates["GSI1PK"] = visibility
    if topic is not None:
        updates["topic"] = topic.strip()

    expr_parts = []
    expr_values: Dict[str, Any] = {}
    expr_names: Dict[str, str] = {}
    for i, (k, v) in enumerate(updates.items()):
        alias = f"#k{i}"
        val_alias = f":v{i}"
        expr_parts.append(f"{alias} = {val_alias}")
        expr_names[alias] = k
        expr_values[val_alias] = v

    T.user_groups.update_item(
        Key={"pk": f"GROUP#{group_id}", "sk": "META"},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
    )
    meta.update(updates)
    return meta


def join_group(
    *,
    group_id: str,
    user_id: str,
    display_name: str = "",
) -> Dict[str, Any]:
    """Join a group (instant for public, pending_approval for private)."""
    meta = get_group_or_404(group_id)
    if meta.get("status") == "dissolved":
        raise HTTPException(status_code=410, detail="This group has been dissolved")

    # Check if already a member
    existing = _get_membership(group_id, user_id)
    if existing:
        if existing.get("status") == "active":
            raise HTTPException(status_code=409, detail="Already a member of this group")
        if existing.get("status") == "pending_approval":
            raise HTTPException(status_code=409, detail="Join request already pending")
        if existing.get("status") == "invited":
            raise HTTPException(status_code=409, detail="Already invited to this group")

    # Check user group limit
    existing_count = _count_user_groups(user_id)
    if existing_count >= S.user_group_max_per_user:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum number of groups reached ({S.user_group_max_per_user})",
        )

    ts = now_ts()
    visibility = meta.get("visibility", "public")

    if visibility == "public":
        _add_member(group_id, user_id, role="member", display_name=display_name, ts=ts)
        _increment_member_count(group_id, 1)
        membership = _get_membership(group_id, user_id)
        return membership or {}
    else:
        # Private group: create pending membership
        member_item: Dict[str, Any] = {
            "pk": f"GROUP#{group_id}",
            "sk": f"MEMBER#{user_id}",
            "user_id": user_id,
            "group_id": group_id,
            "role": "member",
            "status": "pending_approval",
            "display_name": display_name,
            "created_at": ts,
        }
        T.user_groups.put_item(Item=member_item)
        return member_item


def invite_to_group(
    *,
    group_id: str,
    inviter_id: str,
    invitee_id: str,
) -> Dict[str, Any]:
    """Admin/moderator invites a user to the group."""
    _require_role(group_id, inviter_id, "moderator")
    meta = get_group_or_404(group_id)
    if meta.get("status") == "dissolved":
        raise HTTPException(status_code=410, detail="This group has been dissolved")

    # Check if already a member
    existing = _get_membership(group_id, invitee_id)
    if existing:
        if existing.get("status") == "active":
            raise HTTPException(status_code=409, detail="User is already a member")
        if existing.get("status") == "invited":
            raise HTTPException(status_code=409, detail="User already invited")

    ts = now_ts()
    member_item: Dict[str, Any] = {
        "pk": f"GROUP#{group_id}",
        "sk": f"MEMBER#{invitee_id}",
        "user_id": invitee_id,
        "group_id": group_id,
        "role": "member",
        "status": "invited",
        "display_name": "",
        "invited_by": inviter_id,
        "created_at": ts,
    }
    T.user_groups.put_item(Item=member_item)
    return member_item


def respond_to_invite(
    *,
    group_id: str,
    user_id: str,
    accept: bool,
) -> Dict[str, Any]:
    """Accept or decline an invitation."""
    membership = _get_membership(group_id, user_id)
    if not membership or membership.get("status") != "invited":
        raise HTTPException(status_code=404, detail="No pending invitation found")

    ts = now_ts()
    if accept:
        T.user_groups.update_item(
            Key={"pk": f"GROUP#{group_id}", "sk": f"MEMBER#{user_id}"},
            UpdateExpression="SET #s = :s, joined_at = :t, promoted_at = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "active", ":t": ts},
        )
        # Add user-group index record
        _add_user_group_index(group_id, user_id, ts)
        _increment_member_count(group_id, 1)
        return {"ok": True, "status": "active"}
    else:
        # Remove the membership record
        T.user_groups.delete_item(Key={"pk": f"GROUP#{group_id}", "sk": f"MEMBER#{user_id}"})
        return {"ok": True, "status": "declined"}


def approve_join_request(
    *,
    group_id: str,
    approver_id: str,
    applicant_id: str,
    approved: bool,
) -> Dict[str, Any]:
    """Admin/moderator approves or rejects a join request."""
    _require_role(group_id, approver_id, "moderator")

    membership = _get_membership(group_id, applicant_id)
    if not membership or membership.get("status") != "pending_approval":
        raise HTTPException(status_code=404, detail="No pending join request found")

    ts = now_ts()
    if approved:
        T.user_groups.update_item(
            Key={"pk": f"GROUP#{group_id}", "sk": f"MEMBER#{applicant_id}"},
            UpdateExpression="SET #s = :s, joined_at = :t, promoted_at = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "active", ":t": ts},
        )
        _add_user_group_index(group_id, applicant_id, ts)
        _increment_member_count(group_id, 1)
        return {"ok": True, "status": "active"}
    else:
        T.user_groups.delete_item(Key={"pk": f"GROUP#{group_id}", "sk": f"MEMBER#{applicant_id}"})
        return {"ok": True, "status": "rejected"}


def promote_member(
    *,
    group_id: str,
    admin_id: str,
    target_id: str,
    new_role: str,
) -> Dict[str, Any]:
    """Admin promotes/demotes a member."""
    _require_role(group_id, admin_id, "admin")

    membership = _get_membership(group_id, target_id)
    if not membership or membership.get("status") != "active":
        raise HTTPException(status_code=404, detail="Member not found")

    if membership.get("role") == "admin":
        raise HTTPException(status_code=403, detail="Cannot change the admin's role")

    ts = now_ts()
    T.user_groups.update_item(
        Key={"pk": f"GROUP#{group_id}", "sk": f"MEMBER#{target_id}"},
        UpdateExpression="SET #r = :r, promoted_at = :t",
        ExpressionAttributeNames={"#r": "role"},
        ExpressionAttributeValues={":r": new_role, ":t": ts},
    )

    membership["role"] = new_role
    membership["promoted_at"] = ts
    return membership


def remove_member(
    *,
    group_id: str,
    remover_id: str,
    target_id: str,
) -> Dict[str, Any]:
    """Admin removes anyone; moderator removes non-admin members."""
    remover = _get_membership(group_id, remover_id)
    if not remover or remover.get("status") != "active":
        raise HTTPException(status_code=403, detail="Not a member of this group")

    remover_role = remover.get("role", "member")
    if remover_role not in ("admin", "moderator"):
        raise HTTPException(status_code=403, detail="Only admins and moderators can remove members")

    target = _get_membership(group_id, target_id)
    if not target or target.get("status") != "active":
        raise HTTPException(status_code=404, detail="Member not found")

    if target.get("role") == "admin":
        raise HTTPException(status_code=403, detail="Moderators cannot remove the admin")

    if remover_role == "moderator" and target.get("role") == "moderator":
        raise HTTPException(status_code=403, detail="Moderators cannot remove other moderators")

    T.user_groups.delete_item(Key={"pk": f"GROUP#{group_id}", "sk": f"MEMBER#{target_id}"})
    _remove_user_group_index(group_id, target_id)
    _increment_member_count(group_id, -1)

    return {"ok": True}


def leave_group(
    *,
    group_id: str,
    user_id: str,
) -> Dict[str, Any]:
    """User leaves a group. Triggers admin succession if admin leaves."""
    membership = _get_membership(group_id, user_id)
    if not membership or membership.get("status") != "active":
        raise HTTPException(status_code=404, detail="Not a member of this group")

    is_admin = membership.get("role") == "admin"

    T.user_groups.delete_item(Key={"pk": f"GROUP#{group_id}", "sk": f"MEMBER#{user_id}"})
    _remove_user_group_index(group_id, user_id)
    _increment_member_count(group_id, -1)

    result: Dict[str, Any] = {"ok": True}

    if is_admin:
        result.update(_admin_succession(group_id))

    logger.info("group.member_left", extra={"group_id": group_id, "user_id": user_id, "was_admin": is_admin})
    return result


def list_members(group_id: str) -> List[Dict[str, Any]]:
    """List all active members of a group."""
    resp = T.user_groups.query(
        KeyConditionExpression=Key("pk").eq(f"GROUP#{group_id}") & Key("sk").begins_with("MEMBER#"),
    )
    items = resp.get("Items", [])
    # Filter to only active members
    return [m for m in items if m.get("status") == "active"]


def list_all_members(group_id: str) -> List[Dict[str, Any]]:
    """List all members regardless of status."""
    resp = T.user_groups.query(
        KeyConditionExpression=Key("pk").eq(f"GROUP#{group_id}") & Key("sk").begins_with("MEMBER#"),
    )
    return resp.get("Items", [])


def list_pending(group_id: str) -> List[Dict[str, Any]]:
    """List pending invites and join requests."""
    all_members = list_all_members(group_id)
    return [m for m in all_members if m.get("status") in ("invited", "pending_approval")]


def list_user_groups(user_id: str) -> List[Dict[str, Any]]:
    """List all groups a user belongs to."""
    resp = T.user_groups.query(
        KeyConditionExpression=Key("pk").eq(f"USERGROUPS#{user_id}") & Key("sk").begins_with("GROUP#"),
    )
    return resp.get("Items", [])


def search_public_groups(
    query: Optional[str] = None,
    topic: Optional[str] = None,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    """Search public, active groups."""
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI1",
        "KeyConditionExpression": Key("GSI1PK").eq("public"),
        "ScanIndexForward": False,
        "Limit": min(limit * 3, 200),  # fetch more than needed for filtering
    }
    resp = T.user_groups.query(**kwargs)
    items = resp.get("Items", [])

    # Filter to META records and active status
    results = [i for i in items if i.get("sk") == "META" and i.get("status") == "active"]

    # Apply text filters
    if query:
        q_lower = query.lower()
        results = [
            i for i in results
            if q_lower in i.get("name", "").lower()
            or q_lower in i.get("description", "").lower()
            or q_lower in (i.get("topic") or "").lower()
        ]

    if topic:
        t_lower = topic.lower()
        results = [i for i in results if (i.get("topic") or "").lower() == t_lower]

    return results[:limit]


def dissolve_group(
    *,
    group_id: str,
    admin_id: str,
) -> Dict[str, Any]:
    """Dissolve a group (admin only)."""
    _require_role(group_id, admin_id, "admin")
    meta = get_group_or_404(group_id)
    if meta.get("status") == "dissolved":
        raise HTTPException(status_code=410, detail="This group has been dissolved")

    ts = now_ts()
    T.user_groups.update_item(
        Key={"pk": f"GROUP#{group_id}", "sk": "META"},
        UpdateExpression="SET #s = :s, updated_at = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "dissolved", ":t": ts},
    )

    # Clean up all member records and user-group indexes
    all_members = list_all_members(group_id)
    for m in all_members:
        uid = m.get("user_id", "")
        T.user_groups.delete_item(Key={"pk": f"GROUP#{group_id}", "sk": f"MEMBER#{uid}"})
        _remove_user_group_index(group_id, uid)

    logger.info("group.dissolved", extra={"group_id": group_id, "admin": admin_id})
    return {"ok": True, "status": "dissolved"}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_meta(group_id: str) -> Dict[str, Any]:
    """Get group metadata, raise 404 if not found."""
    return get_group_or_404(group_id)


def _get_membership(group_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Get a single membership record."""
    resp = T.user_groups.get_item(Key={"pk": f"GROUP#{group_id}", "sk": f"MEMBER#{user_id}"})
    return resp.get("Item")


def require_membership(group_id: str, user_id: str) -> Dict[str, Any]:
    """Public: require user is an active member. Returns membership or raises 403."""
    return _require_role(group_id, user_id, "member")


def require_admin(group_id: str, user_id: str) -> Dict[str, Any]:
    """Public: require user is the group admin. Returns membership or raises 403."""
    return _require_role(group_id, user_id, "admin")


def _require_role(group_id: str, user_id: str, min_role: str) -> Dict[str, Any]:
    """Require user has at least the specified role. Returns membership."""
    membership = _get_membership(group_id, user_id)
    if not membership or membership.get("status") != "active":
        raise HTTPException(status_code=403, detail="Not a member of this group")

    role = membership.get("role", "member")
    role_hierarchy = {"admin": 3, "moderator": 2, "member": 1}

    if role_hierarchy.get(role, 0) < role_hierarchy.get(min_role, 0):
        raise HTTPException(status_code=403, detail="Only the group admin can perform this action")

    return membership


def _add_member(
    group_id: str,
    user_id: str,
    role: str = "member",
    display_name: str = "",
    ts: Optional[int] = None,
) -> None:
    """Add a member to the group."""
    if ts is None:
        ts = now_ts()

    member_item: Dict[str, Any] = {
        "pk": f"GROUP#{group_id}",
        "sk": f"MEMBER#{user_id}",
        "user_id": user_id,
        "group_id": group_id,
        "role": role,
        "status": "active",
        "display_name": display_name,
        "joined_at": ts,
        "promoted_at": ts,
        "created_at": ts,
    }
    T.user_groups.put_item(Item=member_item)

    # Write user-group index for "my groups" listing
    _add_user_group_index(group_id, user_id, ts)


def _add_user_group_index(group_id: str, user_id: str, ts: int) -> None:
    """Add a user-group index record."""
    meta = get_group(group_id)
    group_name = meta.get("name", "") if meta else ""

    index_item: Dict[str, Any] = {
        "pk": f"USERGROUPS#{user_id}",
        "sk": f"GROUP#{group_id}",
        "group_id": group_id,
        "group_name": group_name,
        "joined_at": ts,
    }
    T.user_groups.put_item(Item=index_item)


def _remove_user_group_index(group_id: str, user_id: str) -> None:
    """Remove a user-group index record."""
    T.user_groups.delete_item(Key={"pk": f"USERGROUPS#{user_id}", "sk": f"GROUP#{group_id}"})


def _count_user_groups(user_id: str) -> int:
    """Count how many groups a user belongs to."""
    resp = T.user_groups.query(
        KeyConditionExpression=Key("pk").eq(f"USERGROUPS#{user_id}"),
        Select="COUNT",
    )
    return resp.get("Count", 0)


def _increment_member_count(group_id: str, delta: int) -> None:
    """Atomically increment or decrement member count."""
    T.user_groups.update_item(
        Key={"pk": f"GROUP#{group_id}", "sk": "META"},
        UpdateExpression="SET member_count = member_count + :d, GSI2SK = GSI2SK + :d",
        ExpressionAttributeValues={":d": delta},
    )


def _admin_succession(group_id: str) -> Dict[str, Any]:
    """Transfer admin role when admin leaves."""
    members = list_members(group_id)

    if not members:
        # No members left: dissolve
        ts = now_ts()
        T.user_groups.update_item(
            Key={"pk": f"GROUP#{group_id}", "sk": "META"},
            UpdateExpression="SET #s = :s, updated_at = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "dissolved", ":t": ts},
        )
        logger.info("group.dissolved_by_succession", extra={"group_id": group_id})
        return {"dissolved": True}

    # Priority: oldest moderator, then oldest member
    moderators = [m for m in members if m.get("role") == "moderator"]
    moderators.sort(key=lambda m: int(m.get("promoted_at", 0) or 0))

    regular_members = [m for m in members if m.get("role") == "member"]
    regular_members.sort(key=lambda m: int(m.get("joined_at", 0) or 0))

    new_admin = moderators[0] if moderators else regular_members[0]
    new_admin_id = new_admin["user_id"]

    ts = now_ts()
    # Update the member's role to admin
    T.user_groups.update_item(
        Key={"pk": f"GROUP#{group_id}", "sk": f"MEMBER#{new_admin_id}"},
        UpdateExpression="SET #r = :r, promoted_at = :t",
        ExpressionAttributeNames={"#r": "role"},
        ExpressionAttributeValues={":r": "admin", ":t": ts},
    )

    # Update group metadata with new admin
    T.user_groups.update_item(
        Key={"pk": f"GROUP#{group_id}", "sk": "META"},
        UpdateExpression="SET admin_user_id = :a, updated_at = :t",
        ExpressionAttributeValues={":a": new_admin_id, ":t": ts},
    )

    logger.info("group.admin_succession", extra={
        "group_id": group_id,
        "new_admin": new_admin_id,
        "new_role": new_admin.get("role"),
    })
    return {"dissolved": False, "new_admin_user_id": new_admin_id}
