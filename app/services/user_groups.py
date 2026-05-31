"""User Groups service (GROUP-001).

Single-table design on ``T.user_groups``:

* ``pk=GROUP#{group_id}  sk=META``         -- group metadata
* ``pk=GROUP#{group_id}  sk=MEMBER#{uid}`` -- membership record
* ``pk=USERGROUPS#{uid}  sk=GROUP#{gid}``  -- per-user index
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

_MAX_GROUPS_PER_USER = 50


def _group_pk(group_id: str) -> str:
    return f"GROUP#{group_id}"


def _member_sk(user_id: str) -> str:
    return f"MEMBER#{user_id}"


def _user_groups_pk(user_id: str) -> str:
    return f"USERGROUPS#{user_id}"


def _group_sk(group_id: str) -> str:
    return f"GROUP#{group_id}"


# ── Create group ──────────────────────────────────────────────────────────────

def create_group(
    *,
    creator_sub: str,
    name: str,
    description: str = "",
    visibility: str = "public",
    topic: str | None = None,
) -> Dict[str, Any]:
    ts = now_ts()
    group_id = f"grp_{uuid.uuid4().hex[:12]}"

    meta = {
        "pk": _group_pk(group_id),
        "sk": "META",
        "group_id": group_id,
        "name": name,
        "description": description,
        "topic": topic or "",
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
    T.user_groups.put_item(Item=meta)

    # Admin membership
    member = {
        "pk": _group_pk(group_id),
        "sk": _member_sk(creator_sub),
        "user_id": creator_sub,
        "group_id": group_id,
        "role": "admin",
        "status": "active",
        "display_name": creator_sub,
        "joined_at": ts,
        "promoted_at": ts,
    }
    T.user_groups.put_item(Item=member)

    # User-to-group index
    ug = {
        "pk": _user_groups_pk(creator_sub),
        "sk": _group_sk(group_id),
        "group_id": group_id,
        "group_name": name,
        "role": "admin",
        "joined_at": ts,
    }
    T.user_groups.put_item(Item=ug)

    return {**meta, "my_role": "admin"}


# ── Get group ─────────────────────────────────────────────────────────────────

def get_group(group_id: str, viewer_id: str | None = None) -> Dict[str, Any] | None:
    resp = T.user_groups.get_item(Key={"pk": _group_pk(group_id), "sk": "META"})
    item = resp.get("Item")
    if not item:
        return None
    if viewer_id:
        mem = _get_membership(group_id, viewer_id)
        item["my_role"] = mem["role"] if mem and mem.get("status") == "active" else None
    return item


# ── Update group ──────────────────────────────────────────────────────────────

def update_group(group_id: str, user_id: str, **updates: Any) -> Dict[str, Any]:
    meta = get_group(group_id)
    if not meta:
        raise ValueError("Group not found")
    if meta["admin_user_id"] != user_id:
        raise PermissionError("Only the group admin can perform this action")
    if meta.get("status") == "dissolved":
        raise ValueError("Group has been dissolved")

    expr_parts = ["#updated_at = :updated_at"]
    names: Dict[str, str] = {"#updated_at": "updated_at"}
    values: Dict[str, Any] = {":updated_at": now_ts()}

    for field in ("name", "description", "visibility", "topic"):
        if field in updates and updates[field] is not None:
            expr_parts.append(f"#{field} = :{field}")
            names[f"#{field}"] = field
            values[f":{field}"] = updates[field]

    if "visibility" in updates and updates["visibility"] is not None:
        expr_parts.append("GSI1PK = :gsi1pk")
        values[":gsi1pk"] = updates["visibility"]

    T.user_groups.update_item(
        Key={"pk": _group_pk(group_id), "sk": "META"},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )
    return {**meta, **{k: v for k, v in updates.items() if v is not None}, "updated_at": values[":updated_at"]}


# ── Membership helpers ────────────────────────────────────────────────────────

def _get_membership(group_id: str, user_id: str) -> Dict[str, Any] | None:
    resp = T.user_groups.get_item(Key={"pk": _group_pk(group_id), "sk": _member_sk(user_id)})
    return resp.get("Item")


def get_membership(group_id: str, user_id: str) -> Dict[str, Any] | None:
    return _get_membership(group_id, user_id)


def list_members(group_id: str, *, active_only: bool = True) -> List[Dict[str, Any]]:
    resp = T.user_groups.query(
        KeyConditionExpression=Key("pk").eq(_group_pk(group_id)) & Key("sk").begins_with("MEMBER#"),
    )
    items = resp.get("Items", [])
    if active_only:
        items = [i for i in items if i.get("status") == "active"]
    return items


# ── Join / leave ──────────────────────────────────────────────────────────────

def join_group(group_id: str, user_id: str, display_name: str = "") -> Dict[str, Any]:
    meta = get_group(group_id)
    if not meta:
        raise ValueError("Group not found")
    if meta.get("status") == "dissolved":
        raise ValueError("This group has been dissolved")

    existing = _get_membership(group_id, user_id)
    if existing and existing.get("status") == "active":
        raise ValueError("Already a member of this group")
    if existing and existing.get("status") == "pending_approval":
        raise ValueError("Join request already pending")

    ts = now_ts()
    is_public = meta.get("visibility") == "public"
    status = "active" if is_public else "pending_approval"

    member = {
        "pk": _group_pk(group_id),
        "sk": _member_sk(user_id),
        "user_id": user_id,
        "group_id": group_id,
        "role": "member",
        "status": status,
        "display_name": display_name or user_id,
        "joined_at": ts if is_public else None,
        "promoted_at": None,
    }
    T.user_groups.put_item(Item=member)

    if is_public:
        # Write user-group index and increment member count
        T.user_groups.put_item(Item={
            "pk": _user_groups_pk(user_id),
            "sk": _group_sk(group_id),
            "group_id": group_id,
            "group_name": meta.get("name", ""),
            "role": "member",
            "joined_at": ts,
        })
        _increment_member_count(group_id, 1)

    return member


def leave_group(group_id: str, user_id: str) -> Dict[str, Any]:
    meta = get_group(group_id)
    if not meta:
        raise ValueError("Group not found")
    mem = _get_membership(group_id, user_id)
    if not mem or mem.get("status") != "active":
        raise ValueError("Not a member of this group")

    T.user_groups.delete_item(Key={"pk": _group_pk(group_id), "sk": _member_sk(user_id)})
    T.user_groups.delete_item(Key={"pk": _user_groups_pk(user_id), "sk": _group_sk(group_id)})
    _increment_member_count(group_id, -1)

    if mem.get("role") == "admin":
        _admin_succession(group_id)

    return {"ok": True}


# ── Join request review ───────────────────────────────────────────────────────

def approve_join_request(group_id: str, approver_id: str, applicant_id: str, approved: bool) -> Dict[str, Any]:
    _require_admin_or_mod(group_id, approver_id)
    mem = _get_membership(group_id, applicant_id)
    if not mem or mem.get("status") != "pending_approval":
        raise ValueError("No pending request for this user")

    if not approved:
        T.user_groups.delete_item(Key={"pk": _group_pk(group_id), "sk": _member_sk(applicant_id)})
        return {"ok": True, "status": "rejected"}

    ts = now_ts()
    T.user_groups.update_item(
        Key={"pk": _group_pk(group_id), "sk": _member_sk(applicant_id)},
        UpdateExpression="SET #status = :s, joined_at = :j",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":s": "active", ":j": ts},
    )
    meta = get_group(group_id) or {}
    T.user_groups.put_item(Item={
        "pk": _user_groups_pk(applicant_id),
        "sk": _group_sk(group_id),
        "group_id": group_id,
        "group_name": meta.get("name", ""),
        "role": "member",
        "joined_at": ts,
    })
    _increment_member_count(group_id, 1)
    return {"ok": True, "status": "active"}


# ── Role management ──────────────────────────────────────────────────────────

def promote_member(group_id: str, admin_id: str, target_id: str, new_role: str) -> Dict[str, Any]:
    meta = get_group(group_id)
    if not meta:
        raise ValueError("Group not found")
    if meta["admin_user_id"] != admin_id:
        raise PermissionError("Only the group admin can perform this action")

    mem = _get_membership(group_id, target_id)
    if not mem or mem.get("status") != "active":
        raise ValueError("User is not an active member")

    ts = now_ts()
    T.user_groups.update_item(
        Key={"pk": _group_pk(group_id), "sk": _member_sk(target_id)},
        UpdateExpression="SET #role = :r, promoted_at = :p",
        ExpressionAttributeNames={"#role": "role"},
        ExpressionAttributeValues={":r": new_role, ":p": ts},
    )
    return {"user_id": target_id, "role": new_role, "status": "active", "promoted_at": ts}


def remove_member(group_id: str, remover_id: str, target_id: str) -> Dict[str, Any]:
    meta = get_group(group_id)
    if not meta:
        raise ValueError("Group not found")
    remover_mem = _get_membership(group_id, remover_id)
    if not remover_mem or remover_mem.get("role") not in ("admin", "moderator"):
        raise PermissionError("Only admins and moderators can remove members")
    target_mem = _get_membership(group_id, target_id)
    if not target_mem:
        raise ValueError("User is not a member")
    if target_mem.get("role") == "admin" and remover_mem.get("role") == "moderator":
        raise PermissionError("Moderators cannot remove the admin")

    T.user_groups.delete_item(Key={"pk": _group_pk(group_id), "sk": _member_sk(target_id)})
    T.user_groups.delete_item(Key={"pk": _user_groups_pk(target_id), "sk": _group_sk(group_id)})
    _increment_member_count(group_id, -1)
    return {"ok": True}


# ── Invite ────────────────────────────────────────────────────────────────────

def invite_to_group(group_id: str, inviter_id: str, invitee_id: str) -> Dict[str, Any]:
    _require_admin_or_mod(group_id, inviter_id)
    existing = _get_membership(group_id, invitee_id)
    if existing and existing.get("status") == "active":
        raise ValueError("Already a member of this group")

    ts = now_ts()
    member = {
        "pk": _group_pk(group_id),
        "sk": _member_sk(invitee_id),
        "user_id": invitee_id,
        "group_id": group_id,
        "role": "member",
        "status": "invited",
        "display_name": invitee_id,
        "joined_at": None,
        "promoted_at": None,
        "invited_by": inviter_id,
        "created_at": ts,
    }
    T.user_groups.put_item(Item=member)
    return member


def respond_to_invite(group_id: str, user_id: str, accept: bool) -> Dict[str, Any]:
    mem = _get_membership(group_id, user_id)
    if not mem or mem.get("status") != "invited":
        raise ValueError("No pending invitation")

    if not accept:
        T.user_groups.delete_item(Key={"pk": _group_pk(group_id), "sk": _member_sk(user_id)})
        return {"ok": True, "status": "declined"}

    ts = now_ts()
    T.user_groups.update_item(
        Key={"pk": _group_pk(group_id), "sk": _member_sk(user_id)},
        UpdateExpression="SET #status = :s, joined_at = :j",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":s": "active", ":j": ts},
    )
    meta = get_group(group_id) or {}
    T.user_groups.put_item(Item={
        "pk": _user_groups_pk(user_id),
        "sk": _group_sk(group_id),
        "group_id": group_id,
        "group_name": meta.get("name", ""),
        "role": "member",
        "joined_at": ts,
    })
    _increment_member_count(group_id, 1)
    return {"ok": True, "status": "active"}


# ── Discovery ─────────────────────────────────────────────────────────────────

def list_user_groups(user_id: str) -> List[Dict[str, Any]]:
    resp = T.user_groups.query(
        KeyConditionExpression=Key("pk").eq(_user_groups_pk(user_id)),
    )
    items = resp.get("Items", [])
    groups = []
    for it in items:
        gid = it.get("group_id")
        if gid:
            meta = get_group(gid, viewer_id=user_id)
            if meta:
                groups.append(meta)
    return groups


def search_public_groups(query: str = "", limit: int = 20) -> List[Dict[str, Any]]:
    resp = T.user_groups.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq("public"),
        ScanIndexForward=False,
        Limit=limit * 2 if query else limit,
    )
    items = resp.get("Items", [])
    # Fetch full metadata for each group
    results = []
    for it in items:
        gid = it.get("group_id")
        if not gid:
            continue
        meta = get_group(gid)
        if not meta or meta.get("status") != "active":
            continue
        if query and query.lower() not in meta.get("name", "").lower() and query.lower() not in meta.get("topic", "").lower():
            continue
        results.append(meta)
        if len(results) >= limit:
            break
    return results


# ── Dissolve group ────────────────────────────────────────────────────────────

def dissolve_group(group_id: str, admin_id: str) -> Dict[str, Any]:
    meta = get_group(group_id)
    if not meta:
        raise ValueError("Group not found")
    if meta["admin_user_id"] != admin_id:
        raise PermissionError("Only the group admin can dissolve the group")

    ts = now_ts()
    T.user_groups.update_item(
        Key={"pk": _group_pk(group_id), "sk": "META"},
        UpdateExpression="SET #status = :s, updated_at = :u",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":s": "dissolved", ":u": ts},
    )
    return {"ok": True, "group_id": group_id, "status": "dissolved"}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _require_admin_or_mod(group_id: str, user_id: str) -> Dict[str, Any]:
    mem = _get_membership(group_id, user_id)
    if not mem or mem.get("role") not in ("admin", "moderator"):
        raise PermissionError("Only admins and moderators can perform this action")
    return mem


def _increment_member_count(group_id: str, delta: int) -> None:
    try:
        T.user_groups.update_item(
            Key={"pk": _group_pk(group_id), "sk": "META"},
            UpdateExpression="SET member_count = member_count + :d, GSI2SK = GSI2SK + :d",
            ExpressionAttributeValues={":d": delta},
        )
    except ClientError:
        logger.warning("Failed to update member_count", extra={"group_id": group_id, "delta": delta})


def _admin_succession(group_id: str) -> None:
    """Transfer admin to the oldest moderator or member. Dissolve if empty."""
    members = list_members(group_id)
    if not members:
        # Dissolve directly (bypass admin check)
        ts = now_ts()
        T.user_groups.update_item(
            Key={"pk": _group_pk(group_id), "sk": "META"},
            UpdateExpression="SET #status = :s, updated_at = :u",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":s": "dissolved", ":u": ts},
        )
        return

    # Find oldest moderator
    mods = sorted(
        [m for m in members if m.get("role") == "moderator"],
        key=lambda m: m.get("promoted_at") or m.get("joined_at") or 0,
    )
    if mods:
        new_admin = mods[0]
    else:
        regular = sorted(members, key=lambda m: m.get("joined_at") or 0)
        new_admin = regular[0]

    new_admin_id = new_admin["user_id"]
    ts = now_ts()
    T.user_groups.update_item(
        Key={"pk": _group_pk(group_id), "sk": "META"},
        UpdateExpression="SET admin_user_id = :a, updated_at = :u",
        ExpressionAttributeValues={":a": new_admin_id, ":u": ts},
    )
    T.user_groups.update_item(
        Key={"pk": _group_pk(group_id), "sk": _member_sk(new_admin_id)},
        UpdateExpression="SET #role = :r, promoted_at = :p",
        ExpressionAttributeNames={"#role": "role"},
        ExpressionAttributeValues={":r": "admin", ":p": ts},
    )
    logger.info("group.admin_succession", extra={
        "group_id": group_id, "new_admin": new_admin_id,
    })
