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


def get_membership(group_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Get a single membership record (public wrapper)."""
    return _get_membership(group_id, user_id)


def require_membership(group_id: str, user_id: str) -> Dict[str, Any]:
    """Require active membership, raise 403 if not."""
    membership = _get_membership(group_id, user_id)
    if not membership or membership.get("status") != "active":
        raise HTTPException(status_code=403, detail="Not a member of this group")
    return membership


def require_admin(group_id: str, user_id: str) -> Dict[str, Any]:
    """Require admin role in the group."""
    return _require_role(group_id, user_id, "admin")


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

    ts = now_ts()
    visibility = meta.get("visibility", "public")

    if visibility == "public":
        _add_member(group_id, user_id, role="member", display_name=display_name, ts=ts)
        _increment_member_count(group_id, 1)
        membership = _get_membership(group_id, user_id)
        return membership or {}
    else:
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


def list_members(group_id: str) -> List[Dict[str, Any]]:
    """List all active members of a group."""
    resp = T.user_groups.query(
        KeyConditionExpression=Key("pk").eq(f"GROUP#{group_id}") & Key("sk").begins_with("MEMBER#"),
    )
    items = resp.get("Items", [])
    return [m for m in items if m.get("status") == "active"]


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

    # Dissolve treasury before cleaning up membership
    try:
        from app.services.group_treasury import dissolve_treasury
        dissolve_treasury(group_id)
    except Exception:
        logger.exception("treasury.dissolution_error", extra={"group_id": group_id})

    ts = now_ts()
    T.user_groups.update_item(
        Key={"pk": f"GROUP#{group_id}", "sk": "META"},
        UpdateExpression="SET #s = :s, updated_at = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "dissolved", ":t": ts},
    )

    # Clean up member records
    all_members = _list_all_members(group_id)
    for m in all_members:
        uid = m.get("user_id", "")
        T.user_groups.delete_item(Key={"pk": f"GROUP#{group_id}", "sk": f"MEMBER#{uid}"})
        _remove_user_group_index(group_id, uid)

    logger.info("group.dissolved", extra={"group_id": group_id, "admin": admin_id})
    return {"ok": True, "status": "dissolved"}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_membership(group_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Get a single membership record."""
    resp = T.user_groups.get_item(Key={"pk": f"GROUP#{group_id}", "sk": f"MEMBER#{user_id}"})
    return resp.get("Item")


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


def _list_all_members(group_id: str) -> List[Dict[str, Any]]:
    """List all members regardless of status."""
    resp = T.user_groups.query(
        KeyConditionExpression=Key("pk").eq(f"GROUP#{group_id}") & Key("sk").begins_with("MEMBER#"),
    )
    return resp.get("Items", [])
