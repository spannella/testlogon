"""Syndicate creation, membership, and lifecycle management (SYND-001)."""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

MAX_MEMBERS = 50
# Per-user cap on *active* syndicate memberships. Archived/dissolved syndicates
# do not count (see count_active_user_syndicates). Env-overridable.
MAX_SYNDICATES_PER_USER = int(os.environ.get("MAX_SYNDICATES_PER_USER", "10"))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_syndicate(
    *,
    creator_sub: str,
    name: str,
    description: str = "",
) -> Dict[str, Any]:
    """Create a new syndicate. Creator becomes admin."""
    ts = now_ts()
    syndicate_id = f"synd_{uuid4().hex[:12]}"

    # Check user isn't already in too many *active* syndicates. Archived/dissolved
    # syndicates leave a stale USER_SYND# index row behind, so a plain count of
    # list_user_syndicates over-counts and wrongly blocks creation.
    active_count = count_active_user_syndicates(creator_sub)
    if active_count >= MAX_SYNDICATES_PER_USER:
        raise HTTPException(status_code=400, detail=f"User already in {MAX_SYNDICATES_PER_USER} syndicates")

    meta: Dict[str, Any] = {
        "pk": f"SYND#{syndicate_id}",
        "sk": "META",
        "syndicate_id": syndicate_id,
        "name": name.strip(),
        "description": description.strip(),
        "admin_user_id": creator_sub,
        "status": "active",
        "member_count": 1,
        "created_at": ts,
        "updated_at": ts,
        "GSI1PK": "STATUS#active",
        "GSI1SK": ts,
    }
    T.syndicates.put_item(Item=meta)

    # Add creator as admin member
    _add_member(syndicate_id, creator_sub, role="admin", ts=ts)

    _write_audit(syndicate_id, creator_sub, "syndicate_created", creator_sub)
    return meta


def update_syndicate(
    *,
    syndicate_id: str,
    admin_sub: str,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """Update syndicate metadata (admin only)."""
    _require_admin(syndicate_id, admin_sub)
    meta = _get_meta(syndicate_id)
    ts = now_ts()

    updates: Dict[str, Any] = {"updated_at": ts}
    if name is not None:
        updates["name"] = name.strip()
    if description is not None:
        updates["description"] = description.strip()

    expr_parts = []
    expr_values: Dict[str, Any] = {}
    expr_names: Dict[str, str] = {}
    for i, (k, v) in enumerate(updates.items()):
        alias = f"#k{i}"
        val_alias = f":v{i}"
        expr_parts.append(f"{alias} = {val_alias}")
        expr_names[alias] = k
        expr_values[val_alias] = v

    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": "META"},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
    )
    meta.update(updates)
    return meta


def get_syndicate(syndicate_id: str) -> Optional[Dict[str, Any]]:
    """Get syndicate metadata."""
    resp = T.syndicates.get_item(Key={"pk": f"SYND#{syndicate_id}", "sk": "META"})
    return resp.get("Item")


def get_syndicate_detail(syndicate_id: str) -> Dict[str, Any]:
    """Get syndicate metadata + member list."""
    meta = _get_meta(syndicate_id)
    members = list_members(syndicate_id)
    meta["members"] = members
    return meta


def list_user_syndicates(user_id: str) -> List[Dict[str, Any]]:
    """List all syndicates a user belongs to (includes stale rows for archived/dissolved syndicates)."""
    resp = T.syndicates.query(
        KeyConditionExpression=Key("pk").eq(f"USER_SYND#{user_id}") & Key("sk").begins_with("SYND#"),
    )
    return resp.get("Items", [])


def count_active_user_syndicates(user_id: str) -> int:
    """Count the user's memberships that point to a syndicate whose META status is 'active'.

    Dissolution/archival (see _archive_syndicate) only flips the META status and removes
    the leaving user's index row; other members keep a stale USER_SYND# row. Filtering by
    the referenced syndicate's status avoids over-counting against MAX_SYNDICATES_PER_USER.
    """
    count = 0
    for row in list_user_syndicates(user_id):
        sid = row.get("syndicate_id")
        if not sid:
            continue
        meta = get_syndicate(sid)
        if meta and meta.get("status") == "active":
            count += 1
    return count


def list_members(syndicate_id: str) -> List[Dict[str, Any]]:
    """List all active members of a syndicate."""
    resp = T.syndicates.query(
        KeyConditionExpression=Key("pk").eq(f"SYND#{syndicate_id}") & Key("sk").begins_with("MEMBER#"),
    )
    return resp.get("Items", [])


def invite_member(
    *,
    syndicate_id: str,
    admin_sub: str,
    invitee_user_id: str,
) -> Dict[str, Any]:
    """Admin invites a creator to join the syndicate."""
    _require_admin(syndicate_id, admin_sub)
    meta = _get_meta(syndicate_id)

    if meta["member_count"] >= MAX_MEMBERS:
        raise HTTPException(status_code=400, detail=f"Syndicate already has {MAX_MEMBERS} members")

    _require_not_member(syndicate_id, invitee_user_id)

    # Check for existing pending invite
    existing = T.syndicates.get_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"INVITE#{invitee_user_id}"}
    ).get("Item")
    if existing and existing.get("status") == "pending":
        raise HTTPException(status_code=409, detail="Invite already pending")

    ts = now_ts()
    invite: Dict[str, Any] = {
        "pk": f"SYND#{syndicate_id}",
        "sk": f"INVITE#{invitee_user_id}",
        "syndicate_id": syndicate_id,
        "syndicate_name": meta.get("name", ""),
        "user_id": invitee_user_id,
        "invited_by": admin_sub,
        "invited_at": ts,
        "status": "pending",
        "GSI2PK": f"INVITEE#{invitee_user_id}",
        "GSI2SK": ts,
    }
    T.syndicates.put_item(Item=invite)
    _write_audit(syndicate_id, admin_sub, "invite_sent", invitee_user_id)
    return invite


def respond_to_invite(
    *,
    syndicate_id: str,
    user_id: str,
    accept: bool,
) -> Dict[str, Any]:
    """Invitee accepts or declines an invite."""
    invite = T.syndicates.get_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"INVITE#{user_id}"}
    ).get("Item")
    if not invite or invite.get("status") != "pending":
        raise HTTPException(status_code=404, detail="No pending invite found")

    ts = now_ts()
    new_status = "accepted" if accept else "declined"

    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"INVITE#{user_id}"},
        UpdateExpression="SET #s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": new_status},
    )

    if accept:
        meta = _get_meta(syndicate_id)
        if meta["member_count"] >= MAX_MEMBERS:
            raise HTTPException(status_code=400, detail="Syndicate is full")
        _add_member(syndicate_id, user_id, role="member", ts=ts)
        _increment_member_count(syndicate_id, 1)
        _write_audit(syndicate_id, user_id, "member_joined", user_id)
        _on_member_joined_hook(syndicate_id, user_id)
    else:
        _write_audit(syndicate_id, user_id, "invite_declined", user_id)

    invite["status"] = new_status
    return invite


def request_to_join(
    *,
    syndicate_id: str,
    user_id: str,
    message: str = "",
) -> Dict[str, Any]:
    """Creator requests to join a syndicate."""
    _get_meta(syndicate_id)  # ensure syndicate exists
    _require_not_member(syndicate_id, user_id)

    # Check for existing pending request
    existing = T.syndicates.get_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"REQUEST#{user_id}"}
    ).get("Item")
    if existing and existing.get("status") == "pending":
        raise HTTPException(status_code=409, detail="Request already pending")

    ts = now_ts()
    request_item: Dict[str, Any] = {
        "pk": f"SYND#{syndicate_id}",
        "sk": f"REQUEST#{user_id}",
        "syndicate_id": syndicate_id,
        "user_id": user_id,
        "requested_at": ts,
        "message": message,
        "status": "pending",
        "GSI2PK": f"REQUESTER#{user_id}",
        "GSI2SK": ts,
    }
    T.syndicates.put_item(Item=request_item)
    _write_audit(syndicate_id, user_id, "join_requested", user_id)
    return request_item


def approve_request(
    *,
    syndicate_id: str,
    admin_sub: str,
    requester_user_id: str,
) -> Dict[str, Any]:
    """Admin approves a join request."""
    _require_admin(syndicate_id, admin_sub)

    request_item = T.syndicates.get_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"REQUEST#{requester_user_id}"}
    ).get("Item")
    if not request_item or request_item.get("status") != "pending":
        raise HTTPException(status_code=404, detail="No pending request found")

    meta = _get_meta(syndicate_id)
    if meta["member_count"] >= MAX_MEMBERS:
        raise HTTPException(status_code=400, detail="Syndicate is full")

    ts = now_ts()
    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"REQUEST#{requester_user_id}"},
        UpdateExpression="SET #s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "approved"},
    )

    _add_member(syndicate_id, requester_user_id, role="member", ts=ts)
    _increment_member_count(syndicate_id, 1)
    _write_audit(syndicate_id, admin_sub, "request_approved", requester_user_id)
    _on_member_joined_hook(syndicate_id, requester_user_id)

    request_item["status"] = "approved"
    return request_item


def reject_request(
    *,
    syndicate_id: str,
    admin_sub: str,
    requester_user_id: str,
) -> Dict[str, Any]:
    """Admin rejects a join request."""
    _require_admin(syndicate_id, admin_sub)

    request_item = T.syndicates.get_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"REQUEST#{requester_user_id}"}
    ).get("Item")
    if not request_item or request_item.get("status") != "pending":
        raise HTTPException(status_code=404, detail="No pending request found")

    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"REQUEST#{requester_user_id}"},
        UpdateExpression="SET #s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "rejected"},
    )

    _write_audit(syndicate_id, admin_sub, "request_rejected", requester_user_id)
    request_item["status"] = "rejected"
    return request_item


def transfer_admin(
    *,
    syndicate_id: str,
    current_admin_sub: str,
    new_admin_user_id: str,
) -> Dict[str, Any]:
    """Transfer admin role to another member."""
    _require_admin(syndicate_id, current_admin_sub)
    _require_is_member(syndicate_id, new_admin_user_id)

    if current_admin_sub == new_admin_user_id:
        raise HTTPException(status_code=400, detail="Already the admin")

    ts = now_ts()

    # Update META admin_user_id
    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": "META"},
        UpdateExpression="SET admin_user_id = :new, updated_at = :ts",
        ExpressionAttributeValues={":new": new_admin_user_id, ":ts": ts},
    )

    # Update old admin MEMBER role to "member"
    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"MEMBER#{current_admin_sub}"},
        UpdateExpression="SET #r = :r",
        ExpressionAttributeNames={"#r": "role"},
        ExpressionAttributeValues={":r": "member"},
    )

    # Update new admin MEMBER role to "admin"
    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"MEMBER#{new_admin_user_id}"},
        UpdateExpression="SET #r = :r",
        ExpressionAttributeNames={"#r": "role"},
        ExpressionAttributeValues={":r": "admin"},
    )

    # Update USER_SYND index for both users
    T.syndicates.update_item(
        Key={"pk": f"USER_SYND#{current_admin_sub}", "sk": f"SYND#{syndicate_id}"},
        UpdateExpression="SET #r = :r",
        ExpressionAttributeNames={"#r": "role"},
        ExpressionAttributeValues={":r": "member"},
    )
    T.syndicates.update_item(
        Key={"pk": f"USER_SYND#{new_admin_user_id}", "sk": f"SYND#{syndicate_id}"},
        UpdateExpression="SET #r = :r",
        ExpressionAttributeNames={"#r": "role"},
        ExpressionAttributeValues={":r": "admin"},
    )

    _write_audit(syndicate_id, current_admin_sub, "admin_transferred", new_admin_user_id)

    meta = _get_meta(syndicate_id)
    return meta


def leave_syndicate(
    *,
    syndicate_id: str,
    user_id: str,
) -> Dict[str, Any]:
    """Member leaves the syndicate. If admin leaves, promote next oldest."""
    meta = _get_meta(syndicate_id)
    _require_is_member(syndicate_id, user_id)
    is_admin = meta["admin_user_id"] == user_id

    # Remove member + user index
    _remove_member(syndicate_id, user_id)
    new_count = int(meta["member_count"]) - 1
    _set_member_count(syndicate_id, new_count)

    if new_count <= 0:
        # Dissolve syndicate
        _archive_syndicate(syndicate_id)
        _write_audit(syndicate_id, user_id, "member_left", user_id)
        _write_audit(syndicate_id, user_id, "syndicate_dissolved", syndicate_id)
        return {"dissolved": True, "syndicate_id": syndicate_id}

    if is_admin:
        # Promote next oldest member
        members = list_members(syndicate_id)
        members.sort(key=lambda m: (int(m.get("joined_at", 0)), m.get("user_id", "")))
        if members:
            new_admin = members[0]["user_id"]
            _promote_to_admin(syndicate_id, new_admin)
            _write_audit(syndicate_id, user_id, "admin_auto_promoted", new_admin)

    _write_audit(syndicate_id, user_id, "member_left", user_id)
    _on_member_left_hook(syndicate_id, user_id)
    return {"dissolved": False, "syndicate_id": syndicate_id}


def remove_member(
    *,
    syndicate_id: str,
    admin_sub: str,
    target_user_id: str,
) -> Dict[str, Any]:
    """Admin removes a member from the syndicate."""
    _require_admin(syndicate_id, admin_sub)
    if admin_sub == target_user_id:
        raise HTTPException(status_code=400, detail="Admin cannot remove themselves; use leave instead")
    _require_is_member(syndicate_id, target_user_id)

    _remove_member(syndicate_id, target_user_id)
    meta = _get_meta(syndicate_id)
    new_count = int(meta["member_count"]) - 1
    _set_member_count(syndicate_id, new_count)

    _write_audit(syndicate_id, admin_sub, "member_removed", target_user_id)
    _on_member_left_hook(syndicate_id, target_user_id)
    return {"ok": True}


def list_pending_invites(user_id: str) -> List[Dict[str, Any]]:
    """List pending invites for a user via GSI2."""
    resp = T.syndicates.query(
        IndexName="GSI2",
        KeyConditionExpression=Key("GSI2PK").eq(f"INVITEE#{user_id}"),
        ScanIndexForward=False,
    )
    items = resp.get("Items", [])
    return [i for i in items if i.get("status") == "pending"]


def list_pending_requests(syndicate_id: str) -> List[Dict[str, Any]]:
    """List pending join requests for a syndicate."""
    resp = T.syndicates.query(
        KeyConditionExpression=Key("pk").eq(f"SYND#{syndicate_id}") & Key("sk").begins_with("REQUEST#"),
    )
    items = resp.get("Items", [])
    return [i for i in items if i.get("status") == "pending"]


def list_active_syndicates(limit: int = 50) -> List[Dict[str, Any]]:
    """List active syndicates for discovery."""
    resp = T.syndicates.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq("STATUS#active"),
        ScanIndexForward=False,
        Limit=limit,
    )
    return resp.get("Items", [])


def get_audit_log(syndicate_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Get audit log for a syndicate."""
    resp = T.syndicates.query(
        KeyConditionExpression=Key("pk").eq(f"SYND#{syndicate_id}") & Key("sk").begins_with("AUDIT#"),
        ScanIndexForward=False,
        Limit=limit,
    )
    return resp.get("Items", [])


# ---------------------------------------------------------------------------
# Open-licensing lifecycle hooks (LICENSE-005)
# ---------------------------------------------------------------------------

def _on_member_joined_hook(syndicate_id: str, user_id: str) -> None:
    """Auto-license existing syndicate content to a newly joined member (LICENSE-005).

    Imported lazily to avoid a circular import (open-licensing imports this module).
    """
    try:
        from app.services import syndicate_open_licensing as sol
        sol.on_member_joined(syndicate_id=syndicate_id, new_member_id=user_id)
    except Exception:
        logger.warning("open-licensing on_member_joined hook failed", exc_info=True)


def _on_member_left_hook(syndicate_id: str, user_id: str) -> None:
    """No-op for licensing (existing auto-licenses persist), kept for audit symmetry."""
    try:
        from app.services import syndicate_open_licensing as sol
        sol.on_member_left(syndicate_id=syndicate_id, member_id=user_id)
    except Exception:
        logger.warning("open-licensing on_member_left hook failed", exc_info=True)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _add_member(
    syndicate_id: str,
    user_id: str,
    *,
    role: str = "member",
    ts: int | None = None,
) -> None:
    """Add member record + user index record."""
    ts = ts or now_ts()

    member_item: Dict[str, Any] = {
        "pk": f"SYND#{syndicate_id}",
        "sk": f"MEMBER#{user_id}",
        "user_id": user_id,
        "display_name": user_id,
        "role": role,
        "joined_at": ts,
    }
    T.syndicates.put_item(Item=member_item)

    # Get syndicate name for user index
    meta = get_syndicate(syndicate_id) or {}
    user_index: Dict[str, Any] = {
        "pk": f"USER_SYND#{user_id}",
        "sk": f"SYND#{syndicate_id}",
        "syndicate_id": syndicate_id,
        "syndicate_name": meta.get("name", ""),
        "role": role,
        "joined_at": ts,
    }
    T.syndicates.put_item(Item=user_index)


def _remove_member(syndicate_id: str, user_id: str) -> None:
    """Delete member record + user index record."""
    T.syndicates.delete_item(Key={"pk": f"SYND#{syndicate_id}", "sk": f"MEMBER#{user_id}"})
    T.syndicates.delete_item(Key={"pk": f"USER_SYND#{user_id}", "sk": f"SYND#{syndicate_id}"})


def _require_admin(syndicate_id: str, user_id: str) -> None:
    """Raise 403 if user is not the syndicate admin."""
    meta = _get_meta(syndicate_id)
    if meta["admin_user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Only the syndicate admin can perform this action")


def _require_is_member(syndicate_id: str, user_id: str) -> None:
    """Raise 404 if user is not a member."""
    resp = T.syndicates.get_item(Key={"pk": f"SYND#{syndicate_id}", "sk": f"MEMBER#{user_id}"})
    if not resp.get("Item"):
        raise HTTPException(status_code=404, detail="User is not a member of this syndicate")


def _require_not_member(syndicate_id: str, user_id: str) -> None:
    """Raise 409 if user is already a member."""
    resp = T.syndicates.get_item(Key={"pk": f"SYND#{syndicate_id}", "sk": f"MEMBER#{user_id}"})
    if resp.get("Item"):
        raise HTTPException(status_code=409, detail="User is already a member")


def _get_meta(syndicate_id: str) -> Dict[str, Any]:
    """Get META item or raise 404."""
    resp = T.syndicates.get_item(Key={"pk": f"SYND#{syndicate_id}", "sk": "META"})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Syndicate not found")
    return item


def _archive_syndicate(syndicate_id: str) -> None:
    """Set status to archived, update GSI1PK."""
    ts = now_ts()
    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": "META"},
        UpdateExpression="SET #s = :s, GSI1PK = :g, updated_at = :ts, member_count = :zero",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "archived",
            ":g": "STATUS#archived",
            ":ts": ts,
            ":zero": 0,
        },
    )


def _promote_to_admin(syndicate_id: str, user_id: str) -> None:
    """Update META admin_user_id + member role to admin."""
    ts = now_ts()
    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": "META"},
        UpdateExpression="SET admin_user_id = :uid, updated_at = :ts",
        ExpressionAttributeValues={":uid": user_id, ":ts": ts},
    )
    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"MEMBER#{user_id}"},
        UpdateExpression="SET #r = :r",
        ExpressionAttributeNames={"#r": "role"},
        ExpressionAttributeValues={":r": "admin"},
    )
    T.syndicates.update_item(
        Key={"pk": f"USER_SYND#{user_id}", "sk": f"SYND#{syndicate_id}"},
        UpdateExpression="SET #r = :r",
        ExpressionAttributeNames={"#r": "role"},
        ExpressionAttributeValues={":r": "admin"},
    )


def _increment_member_count(syndicate_id: str, delta: int) -> None:
    """Atomically increment member_count."""
    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": "META"},
        UpdateExpression="SET member_count = member_count + :d, updated_at = :ts",
        ExpressionAttributeValues={":d": delta, ":ts": now_ts()},
    )


def _set_member_count(syndicate_id: str, count: int) -> None:
    """Set member_count to a specific value."""
    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": "META"},
        UpdateExpression="SET member_count = :c, updated_at = :ts",
        ExpressionAttributeValues={":c": count, ":ts": now_ts()},
    )


def _write_audit(
    syndicate_id: str,
    actor_id: str,
    action: str,
    target_id: str,
    details: Dict[str, Any] | None = None,
) -> None:
    """Write audit log entry."""
    ts = now_ts()
    event_id = uuid4().hex[:12]
    audit_item: Dict[str, Any] = {
        "pk": f"SYND#{syndicate_id}",
        "sk": f"AUDIT#{ts}#{event_id}",
        "event_id": event_id,
        "actor_id": actor_id,
        "action": action,
        "target_id": target_id,
        "details": details or {},
        "ts": ts,
    }
    T.syndicates.put_item(Item=audit_item)
