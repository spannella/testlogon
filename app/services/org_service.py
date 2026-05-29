"""Organization / Team Workspaces — core service (ENTERPRISE-003)."""
from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts


# ── Role hierarchy ────────────────────────────────────────────────

ROLE_ORDER = {"viewer": 1, "editor": 2, "member": 2, "admin": 3, "owner": 4}


# ── Helpers ───────────────────────────────────────────────────────

def _generate_slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug[:63] if slug else f"org-{uuid.uuid4().hex[:8]}"


def _plan_storage_limits(plan: str) -> Dict[str, int]:
    limits = {
        "free": {"storage_limit_bytes": 1_073_741_824},
        "team": {"storage_limit_bytes": 107_374_182_400},
        "enterprise": {"storage_limit_bytes": 1_099_511_627_776},
    }
    return limits.get(plan, limits["free"])


# ── CRUD ──────────────────────────────────────────────────────────

def create_org(
    name: str,
    owner_user_sub: str,
    description: str = "",
    billing_mode: str = "individual",
    tenant_id: str = "default",
) -> Dict[str, Any]:
    user_orgs = list_user_orgs(owner_user_sub)
    if len(user_orgs) >= S.org_max_per_user:
        raise HTTPException(409, f"Maximum organizations per user reached ({S.org_max_per_user})")

    org_id = f"org_{uuid.uuid4().hex[:16]}"
    slug = _generate_slug(name)
    now = now_ts()
    plan_limits = _plan_storage_limits("free")
    calendar_id = f"ORG#{org_id}#TEAM"

    meta_item: Dict[str, Any] = {
        "org_id": org_id,
        "sk": "#META",
        "name": name,
        "description": description,
        "slug": slug,
        "owner_user_sub": owner_user_sub,
        "status": "active",
        "plan": "free",
        "member_count": 1,
        "storage_used_bytes": 0,
        "storage_limit_bytes": plan_limits["storage_limit_bytes"],
        "billing_mode": billing_mode,
        "default_file_permission": "editor",
        "team_calendar_id": calendar_id,
        "created_at": now,
        "updated_at": now,
        "tenant_id": tenant_id,
    }
    T.organizations.put_item(Item=meta_item)

    member_item: Dict[str, Any] = {
        "org_id": org_id,
        "sk": f"MEMBER#{owner_user_sub}",
        "user_sub": owner_user_sub,
        "org_role": "owner",
        "status": "active",
        "invited_by": owner_user_sub,
        "joined_at": now,
        "updated_at": now,
        "storage_used_bytes": 0,
    }
    T.organizations.put_item(Item=member_item)

    # Create team calendar meta record
    T.calendar.put_item(Item={
        "calendar_id": calendar_id,
        "sk": "#META",
        "name": f"{name} Team Calendar",
        "owner_user_sub": owner_user_sub,
        "owner_type": "org",
        "org_id": org_id,
        "visibility": "org_members",
        "created_at": now,
    })

    return meta_item


def get_org(org_id: str) -> Optional[Dict[str, Any]]:
    resp = T.organizations.get_item(Key={"org_id": org_id, "sk": "#META"})
    return resp.get("Item")


def list_user_orgs(user_sub: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
    resp = T.organizations.query(
        IndexName="user-orgs-index",
        KeyConditionExpression=Key("user_sub").eq(user_sub),
    )
    memberships = resp.get("Items", [])
    if status:
        memberships = [m for m in memberships if m.get("status") == status]

    result = []
    for m in memberships:
        org = get_org(m["org_id"])
        if org and (not status or org.get("status") == status):
            result.append({**org, "org_role": m["org_role"], "membership_status": m["status"]})
    return result


def get_org_membership(org_id: str, user_sub: str) -> Optional[Dict[str, Any]]:
    resp = T.organizations.get_item(Key={"org_id": org_id, "sk": f"MEMBER#{user_sub}"})
    return resp.get("Item")


def assert_org_membership(org_id: str, user_sub: str, min_role: str = "viewer") -> Dict[str, Any]:
    membership = get_org_membership(org_id, user_sub)
    if not membership or membership.get("status") != "active":
        raise HTTPException(403, "Not a member of this organization")
    if ROLE_ORDER.get(membership["org_role"], 0) < ROLE_ORDER.get(min_role, 0):
        raise HTTPException(403, f"Requires {min_role} role or higher")
    return membership


def update_org(org_id: str, user_sub: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    assert_org_membership(org_id, user_sub, min_role="admin")
    now = now_ts()
    update_parts = ["updated_at = :now"]
    values: Dict[str, Any] = {":now": now}
    names: Dict[str, str] = {}
    allowed = {"name", "description", "billing_mode", "default_file_permission"}
    # DynamoDB reserved words need ExpressionAttributeNames
    _reserved = {"name", "description", "status"}
    for key, val in updates.items():
        if key in allowed and val is not None:
            safe = key.replace("-", "_")
            if safe in _reserved:
                placeholder = f"#{safe}"
                names[placeholder] = safe
                update_parts.append(f"{placeholder} = :{safe}")
            else:
                update_parts.append(f"{safe} = :{safe}")
            values[f":{safe}"] = val
    if "slug" not in [u.split("=")[0].strip() for u in update_parts] and "name" in updates and updates["name"]:
        update_parts.append("slug = :slug")
        values[":slug"] = _generate_slug(updates["name"])

    kwargs: Dict[str, Any] = {
        "Key": {"org_id": org_id, "sk": "#META"},
        "UpdateExpression": "SET " + ", ".join(update_parts),
        "ExpressionAttributeValues": values,
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    T.organizations.update_item(**kwargs)
    org = get_org(org_id)
    return org or {}


def archive_org(org_id: str, user_sub: str) -> None:
    assert_org_membership(org_id, user_sub, min_role="owner")
    T.organizations.update_item(
        Key={"org_id": org_id, "sk": "#META"},
        UpdateExpression="SET #s = :s, updated_at = :now",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "archived", ":now": now_ts()},
    )


# ── Members ───────────────────────────────────────────────────────

def list_members(org_id: str, user_sub: str) -> List[Dict[str, Any]]:
    assert_org_membership(org_id, user_sub, min_role="viewer")
    resp = T.organizations.query(
        KeyConditionExpression=Key("org_id").eq(org_id) & Key("sk").begins_with("MEMBER#"),
    )
    return resp.get("Items", [])


def invite_member(
    org_id: str,
    inviter_sub: str,
    email: str,
    org_role: str = "member",
) -> Dict[str, Any]:
    assert_org_membership(org_id, inviter_sub, min_role="admin")
    org = get_org(org_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    # Check for existing membership or pending invite
    existing = _get_membership_by_email(org_id, email)
    if existing:
        raise HTTPException(409, "User is already a member or has a pending invite")

    invite_id = f"inv_{uuid.uuid4().hex[:16]}"
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = now_ts()
    expires_at = now + S.org_invite_ttl_seconds

    invite_item: Dict[str, Any] = {
        "org_id": org_id,
        "sk": f"INVITE#{invite_id}",
        "invite_id": invite_id,
        "email": email,
        "org_role": org_role,
        "invited_by": inviter_sub,
        "status": "pending",
        "created_at": now,
        "expires_at": expires_at,
        "token_hash": f"sha256:{token_hash}",
    }
    T.organizations.put_item(Item=invite_item)
    return {**invite_item, "token": token, "org_name": org["name"]}


def accept_invite(invite_id: str, user_sub: str, token: str) -> Dict[str, Any]:
    invite = _find_invite(invite_id)
    if not invite:
        raise HTTPException(404, "Invitation not found")
    if invite["status"] != "pending":
        raise HTTPException(409, f"Invitation is already {invite['status']}")

    expected_hash = invite.get("token_hash", "")
    actual_hash = f"sha256:{hashlib.sha256(token.encode()).hexdigest()}"
    if expected_hash != actual_hash:
        raise HTTPException(403, "Invalid invitation token")

    if invite.get("expires_at", 0) < now_ts():
        T.organizations.update_item(
            Key={"org_id": invite["org_id"], "sk": f"INVITE#{invite_id}"},
            UpdateExpression="SET #s = :s",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "expired"},
        )
        raise HTTPException(410, "Invitation has expired")

    org_id = invite["org_id"]
    now = now_ts()

    T.organizations.put_item(Item={
        "org_id": org_id,
        "sk": f"MEMBER#{user_sub}",
        "user_sub": user_sub,
        "org_role": invite["org_role"],
        "status": "active",
        "invited_by": invite["invited_by"],
        "joined_at": now,
        "updated_at": now,
        "storage_used_bytes": 0,
    })

    T.organizations.update_item(
        Key={"org_id": org_id, "sk": f"INVITE#{invite_id}"},
        UpdateExpression="SET #s = :s, accepted_by = :u, accepted_at = :now",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "accepted", ":u": user_sub, ":now": now},
    )

    T.organizations.update_item(
        Key={"org_id": org_id, "sk": "#META"},
        UpdateExpression="SET member_count = member_count + :one, updated_at = :now",
        ExpressionAttributeValues={":one": 1, ":now": now},
    )

    org = get_org(org_id)
    return {
        "org_id": org_id,
        "org_name": org["name"] if org else "",
        "org_role": invite["org_role"],
        "status": "active",
    }


def decline_invite(invite_id: str, user_sub: str) -> None:
    invite = _find_invite(invite_id)
    if not invite:
        raise HTTPException(404, "Invitation not found")
    if invite["status"] != "pending":
        raise HTTPException(409, f"Invitation is already {invite['status']}")
    T.organizations.update_item(
        Key={"org_id": invite["org_id"], "sk": f"INVITE#{invite_id}"},
        UpdateExpression="SET #s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "declined"},
    )


def list_pending_invites(user_sub: str) -> List[Dict[str, Any]]:
    """List pending invites for a user by email (user_sub serves as email in dev)."""
    resp = T.organizations.query(
        IndexName="invite-email-index",
        KeyConditionExpression=Key("email").eq(user_sub),
    )
    items = resp.get("Items", [])
    result = []
    for item in items:
        if item.get("status") == "pending":
            org = get_org(item["org_id"])
            result.append({**item, "org_name": org["name"] if org else ""})
    return result


def remove_member(org_id: str, remover_sub: str, target_sub: str) -> None:
    remover = assert_org_membership(org_id, remover_sub, min_role="admin")
    target = get_org_membership(org_id, target_sub)
    if not target:
        raise HTTPException(404, "Member not found")
    if target["org_role"] == "owner":
        raise HTTPException(409, "Cannot remove the org owner. Transfer ownership first.")
    if target["org_role"] == "admin" and remover["org_role"] != "owner":
        raise HTTPException(403, "Only the owner can remove admins")

    T.organizations.delete_item(Key={"org_id": org_id, "sk": f"MEMBER#{target_sub}"})
    T.organizations.update_item(
        Key={"org_id": org_id, "sk": "#META"},
        UpdateExpression="SET member_count = member_count - :one, updated_at = :now",
        ExpressionAttributeValues={":one": 1, ":now": now_ts()},
    )


def leave_org(org_id: str, user_sub: str) -> None:
    membership = get_org_membership(org_id, user_sub)
    if not membership:
        raise HTTPException(404, "Not a member of this organization")
    if membership["org_role"] == "owner":
        raise HTTPException(409, "Cannot leave org as sole owner. Transfer ownership first.")
    T.organizations.delete_item(Key={"org_id": org_id, "sk": f"MEMBER#{user_sub}"})
    T.organizations.update_item(
        Key={"org_id": org_id, "sk": "#META"},
        UpdateExpression="SET member_count = member_count - :one, updated_at = :now",
        ExpressionAttributeValues={":one": 1, ":now": now_ts()},
    )


def change_member_role(org_id: str, changer_sub: str, target_sub: str, new_role: str) -> Dict[str, Any]:
    changer = assert_org_membership(org_id, changer_sub, min_role="admin")
    target = get_org_membership(org_id, target_sub)
    if not target:
        raise HTTPException(404, "Member not found")
    if target["org_role"] == "owner":
        raise HTTPException(409, "Cannot change the owner's role. Transfer ownership instead.")
    if ROLE_ORDER.get(new_role, 0) >= ROLE_ORDER.get(changer["org_role"], 0):
        raise HTTPException(403, "Cannot promote to a role equal or higher than your own")

    T.organizations.update_item(
        Key={"org_id": org_id, "sk": f"MEMBER#{target_sub}"},
        UpdateExpression="SET org_role = :role, updated_at = :now",
        ExpressionAttributeValues={":role": new_role, ":now": now_ts()},
    )
    target["org_role"] = new_role
    return target


def transfer_ownership(org_id: str, current_owner_sub: str, new_owner_sub: str) -> None:
    assert_org_membership(org_id, current_owner_sub, min_role="owner")
    new_member = get_org_membership(org_id, new_owner_sub)
    if not new_member or new_member["status"] != "active":
        raise HTTPException(404, "New owner must be an active member")

    now = now_ts()
    T.organizations.update_item(
        Key={"org_id": org_id, "sk": f"MEMBER#{new_owner_sub}"},
        UpdateExpression="SET org_role = :role, updated_at = :now",
        ExpressionAttributeValues={":role": "owner", ":now": now},
    )
    T.organizations.update_item(
        Key={"org_id": org_id, "sk": f"MEMBER#{current_owner_sub}"},
        UpdateExpression="SET org_role = :role, updated_at = :now",
        ExpressionAttributeValues={":role": "admin", ":now": now},
    )
    T.organizations.update_item(
        Key={"org_id": org_id, "sk": "#META"},
        UpdateExpression="SET owner_user_sub = :o, updated_at = :now",
        ExpressionAttributeValues={":o": new_owner_sub, ":now": now},
    )


# ── Internal helpers ──────────────────────────────────────────────

def _get_membership_by_email(org_id: str, email: str) -> Optional[Dict[str, Any]]:
    resp = T.organizations.query(
        KeyConditionExpression=Key("org_id").eq(org_id) & Key("sk").begins_with("MEMBER#"),
    )
    for item in resp.get("Items", []):
        if item.get("user_sub", "").lower() == email.lower():
            return item
    resp = T.organizations.query(
        KeyConditionExpression=Key("org_id").eq(org_id) & Key("sk").begins_with("INVITE#"),
    )
    for item in resp.get("Items", []):
        if item.get("email", "").lower() == email.lower() and item.get("status") == "pending":
            return item
    return None


def _find_invite(invite_id: str) -> Optional[Dict[str, Any]]:
    resp = T.organizations.scan(
        FilterExpression="sk = :sk",
        ExpressionAttributeValues={":sk": f"INVITE#{invite_id}"},
        Limit=100,
    )
    items = resp.get("Items", [])
    return items[0] if items else None
