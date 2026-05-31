"""Delegate management and permission enforcement (DELEGATE-001)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

MAX_DELEGATES_DEFAULT = 10
MAX_DELEGATES_HARD_LIMIT = 20

VALID_PERMISSIONS = {
    "chat_read",
    "chat_respond",
    "feed_read",
    "feed_post",
    "feed_moderate",
    "broadcast_moderate",
    "broadcast_control",
}

PERMISSION_PRESETS: Dict[str, Dict[str, Any]] = {
    "full_manager": {
        "label": "Full Manager",
        "permissions": sorted(VALID_PERMISSIONS),
    },
    "chat_agent": {
        "label": "Chat Agent",
        "permissions": ["chat_read", "chat_respond"],
    },
    "content_manager": {
        "label": "Content Manager",
        "permissions": ["feed_read", "feed_post", "feed_moderate"],
    },
    "broadcast_moderator": {
        "label": "Broadcast Moderator",
        "permissions": ["broadcast_moderate"],
    },
    "broadcast_manager": {
        "label": "Broadcast Manager",
        "permissions": ["broadcast_moderate", "broadcast_control"],
    },
    "read_only": {
        "label": "Read Only",
        "permissions": ["chat_read", "feed_read"],
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def add_delegate(
    *,
    creator_id: str,
    delegate_id: str,
    permissions: List[str],
    preset: Optional[str] = None,
    label: str = "",
) -> Dict[str, Any]:
    """Creator adds a delegate with specified permissions."""
    _validate_permissions(permissions)
    _require_not_self(creator_id, delegate_id)
    _require_not_already_delegate(creator_id, delegate_id)
    _enforce_delegate_limit(creator_id)

    ts = now_ts()
    settings = get_creator_settings(creator_id)
    status = "pending" if settings.get("require_acceptance", True) else "active"

    item: Dict[str, Any] = {
        "pk": f"CREATOR#{creator_id}",
        "sk": f"DELEGATE#{delegate_id}",
        "delegate_id": delegate_id,
        "creator_id": creator_id,
        "permissions": permissions,
        "preset": preset or _detect_preset(permissions),
        "status": status,
        "label": label,
        "show_delegate_tag": settings.get("delegate_tag_enabled", True),
        "delegate_tag_format": settings.get(
            "delegate_tag_format", "[via @{delegate_name}]"
        ),
        "invited_at": ts,
        "accepted_at": ts if status == "active" else 0,
        "updated_at": ts,
        "GSI1PK": f"DELEGATE#{delegate_id}",
        "GSI1SK": ts if status == "active" else 0,
    }
    T.delegates.put_item(Item=item)
    _write_audit(
        creator_id,
        creator_id,
        "creator",
        "delegate_invited",
        delegate_id,
        {"permissions": permissions, "preset": preset},
    )
    return item


def respond_to_invite(
    *,
    creator_id: str,
    delegate_id: str,
    accept: bool,
) -> Optional[Dict[str, Any]]:
    """Delegate accepts or declines a delegation invite."""
    item = get_delegate(creator_id, delegate_id)
    if not item:
        raise HTTPException(404, "Delegation invite not found")
    if item.get("status") != "pending":
        raise HTTPException(400, "Invite is not pending")

    if accept:
        ts = now_ts()
        T.delegates.update_item(
            Key={"pk": f"CREATOR#{creator_id}", "sk": f"DELEGATE#{delegate_id}"},
            UpdateExpression="SET #st = :s, accepted_at = :a, updated_at = :u, GSI1SK = :g",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":s": "active",
                ":a": ts,
                ":u": ts,
                ":g": ts,
            },
        )
        _write_audit(
            creator_id, delegate_id, "delegate", "invite_accepted", creator_id
        )
        item["status"] = "active"
        item["accepted_at"] = ts
        item["updated_at"] = ts
        return item
    else:
        T.delegates.delete_item(
            Key={"pk": f"CREATOR#{creator_id}", "sk": f"DELEGATE#{delegate_id}"}
        )
        _write_audit(
            creator_id, delegate_id, "delegate", "invite_declined", creator_id
        )
        return None


def update_delegate_permissions(
    *,
    creator_id: str,
    delegate_id: str,
    permissions: List[str],
    preset: Optional[str] = None,
) -> Dict[str, Any]:
    """Creator updates a delegate's permissions."""
    _validate_permissions(permissions)
    item = get_delegate(creator_id, delegate_id)
    if not item:
        raise HTTPException(404, "Delegate not found")

    old_permissions = item.get("permissions", [])
    ts = now_ts()
    resolved_preset = preset or _detect_preset(permissions)
    T.delegates.update_item(
        Key={"pk": f"CREATOR#{creator_id}", "sk": f"DELEGATE#{delegate_id}"},
        UpdateExpression="SET permissions = :p, preset = :pr, updated_at = :u",
        ExpressionAttributeValues={
            ":p": permissions,
            ":pr": resolved_preset,
            ":u": ts,
        },
    )
    _write_audit(
        creator_id,
        creator_id,
        "creator",
        "permissions_updated",
        delegate_id,
        {"old_permissions": old_permissions, "new_permissions": permissions},
    )
    item["permissions"] = permissions
    item["preset"] = resolved_preset
    item["updated_at"] = ts
    return item


def revoke_delegate(*, creator_id: str, delegate_id: str) -> None:
    """Creator revokes a delegate's access. Immediate effect."""
    item = get_delegate(creator_id, delegate_id)
    if not item:
        raise HTTPException(404, "Delegate not found")
    T.delegates.delete_item(
        Key={"pk": f"CREATOR#{creator_id}", "sk": f"DELEGATE#{delegate_id}"}
    )
    _write_audit(creator_id, creator_id, "creator", "delegate_revoked", delegate_id)


def list_delegates(creator_id: str) -> List[Dict[str, Any]]:
    """List all delegates for a creator."""
    resp = T.delegates.query(
        KeyConditionExpression=Key("pk").eq(f"CREATOR#{creator_id}")
        & Key("sk").begins_with("DELEGATE#"),
    )
    return resp.get("Items", [])


def list_managed_creators(delegate_id: str) -> List[Dict[str, Any]]:
    """List all creators a delegate manages (active only)."""
    resp = T.delegates.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"DELEGATE#{delegate_id}"),
    )
    # Filter to only active (GSI1SK > 0 means accepted)
    return [i for i in resp.get("Items", []) if i.get("status") == "active"]


def list_pending_invites(delegate_id: str) -> List[Dict[str, Any]]:
    """List pending delegation invites for the delegate."""
    resp = T.delegates.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"DELEGATE#{delegate_id}"),
    )
    return [i for i in resp.get("Items", []) if i.get("status") == "pending"]


def get_delegate(creator_id: str, delegate_id: str) -> Optional[Dict[str, Any]]:
    """Get a specific delegate relationship."""
    resp = T.delegates.get_item(
        Key={"pk": f"CREATOR#{creator_id}", "sk": f"DELEGATE#{delegate_id}"}
    )
    return resp.get("Item")


def check_delegate_permission(
    *,
    creator_id: str,
    delegate_id: str,
    required_permission: str,
) -> bool:
    """Check if delegate has a specific permission for a creator."""
    item = get_delegate(creator_id, delegate_id)
    if not item or item.get("status") != "active":
        return False
    return required_permission in item.get("permissions", [])


def require_delegate_permission(
    *,
    creator_id: str,
    delegate_id: str,
    required_permission: str,
) -> Dict[str, Any]:
    """Raise 403 if delegate lacks the required permission."""
    item = get_delegate(creator_id, delegate_id)
    if not item or item.get("status") != "active":
        raise HTTPException(403, "Not a delegate for this creator")
    if required_permission not in item.get("permissions", []):
        raise HTTPException(
            403, f"Missing delegation permission: {required_permission}"
        )
    return item


def get_creator_settings(creator_id: str) -> Dict[str, Any]:
    """Get or create default creator delegation settings."""
    resp = T.delegates.get_item(
        Key={"pk": f"CREATOR#{creator_id}", "sk": "SETTINGS"}
    )
    item = resp.get("Item")
    if item:
        return item
    return {
        "pk": f"CREATOR#{creator_id}",
        "sk": "SETTINGS",
        "require_acceptance": True,
        "max_delegates": MAX_DELEGATES_DEFAULT,
        "default_preset": "chat_agent",
        "delegate_tag_enabled": True,
        "delegate_tag_format": "[via @{delegate_name}]",
    }


def update_creator_settings(
    *,
    creator_id: str,
    require_acceptance: bool = True,
    max_delegates: int = MAX_DELEGATES_DEFAULT,
    default_preset: Optional[str] = None,
    delegate_tag_enabled: bool = True,
    delegate_tag_format: str = "[via @{delegate_name}]",
) -> Dict[str, Any]:
    """Update creator delegation settings."""
    if max_delegates < 1 or max_delegates > MAX_DELEGATES_HARD_LIMIT:
        raise HTTPException(400, f"max_delegates must be 1-{MAX_DELEGATES_HARD_LIMIT}")
    if default_preset and default_preset not in PERMISSION_PRESETS:
        raise HTTPException(400, f"Invalid preset: {default_preset}")

    item: Dict[str, Any] = {
        "pk": f"CREATOR#{creator_id}",
        "sk": "SETTINGS",
        "require_acceptance": require_acceptance,
        "max_delegates": max_delegates,
        "default_preset": default_preset,
        "delegate_tag_enabled": delegate_tag_enabled,
        "delegate_tag_format": delegate_tag_format,
    }
    T.delegates.put_item(Item=item)
    return item


def get_audit_log(
    creator_id: str,
    *,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Get delegation audit log for a creator."""
    resp = T.delegates.query(
        KeyConditionExpression=Key("pk").eq(f"CREATOR#{creator_id}")
        & Key("sk").begins_with("AUDIT#"),
        ScanIndexForward=False,
        Limit=limit,
    )
    return resp.get("Items", [])


def get_presets() -> List[Dict[str, Any]]:
    """Return all available permission presets."""
    return [
        {"key": k, "label": v["label"], "permissions": v["permissions"]}
        for k, v in PERMISSION_PRESETS.items()
    ]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _validate_permissions(permissions: List[str]) -> None:
    invalid = set(permissions) - VALID_PERMISSIONS
    if invalid:
        raise HTTPException(400, f"Invalid permissions: {sorted(invalid)}")


def _require_not_self(creator_id: str, delegate_id: str) -> None:
    if creator_id == delegate_id:
        raise HTTPException(400, "Cannot delegate to yourself")


def _require_not_already_delegate(creator_id: str, delegate_id: str) -> None:
    existing = get_delegate(creator_id, delegate_id)
    if existing:
        raise HTTPException(409, "Delegate relationship already exists")


def _enforce_delegate_limit(creator_id: str) -> None:
    settings = get_creator_settings(creator_id)
    max_d = int(settings.get("max_delegates", MAX_DELEGATES_DEFAULT))
    current = list_delegates(creator_id)
    if len(current) >= max_d:
        raise HTTPException(400, f"Delegate limit reached ({max_d})")


def _detect_preset(permissions: List[str]) -> Optional[str]:
    perm_set = set(permissions)
    for key, info in PERMISSION_PRESETS.items():
        if perm_set == set(info["permissions"]):
            return key
    return None


def _write_audit(
    creator_id: str,
    actor_id: str,
    actor_type: str,
    action: str,
    target_id: str,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    ts = now_ts()
    event_id = f"evt_{uuid4().hex[:12]}"
    item: Dict[str, Any] = {
        "pk": f"CREATOR#{creator_id}",
        "sk": f"AUDIT#{ts}#{event_id}",
        "event_id": event_id,
        "actor_id": actor_id,
        "actor_type": actor_type,
        "action": action,
        "target_id": target_id,
        "details": details or {},
        "ts": ts,
        "GSI2PK": f"ACTOR#{actor_id}",
        "GSI2SK": ts,
    }
    T.delegates.put_item(Item=item)
