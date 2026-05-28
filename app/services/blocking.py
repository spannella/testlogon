"""User blocking service — block/unblock, blocked list, bidirectional checks."""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from boto3.dynamodb.conditions import Key

from app.core.aws import ddb
from app.core.tables import T

logger = logging.getLogger(__name__)

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
tbl = ddb.Table(APP_TABLE)


def pk_user(user_id: str) -> str:
    return f"USER#{user_id}"


# ---------------------------------------------------------------------------
# Block / Unblock
# ---------------------------------------------------------------------------


def block_user(blocker_id: str, blocked_id: str, reason: str | None = None) -> dict:
    """Create forward + reverse block entities; auto-unfollow both directions."""
    if blocker_id == blocked_id:
        raise ValueError("self_block")
    if _is_blocked(blocker_id, blocked_id):
        raise ValueError("already_blocked")

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Forward entity: blocker's record of blocking someone
    tbl.put_item(Item={
        "pk": pk_user(blocker_id),
        "sk": f"BLOCKED#{blocked_id}",
        "Entity": "Block",
        "blocker_id": blocker_id,
        "blocked_id": blocked_id,
        "state": "blocked",
        "created_at": now,
        "reason": reason or "",
    })
    # Reverse entity: blocked user's record of being blocked
    tbl.put_item(Item={
        "pk": pk_user(blocked_id),
        "sk": f"BLOCKEDBY#{blocker_id}",
        "Entity": "BlockedBy",
        "blocker_id": blocker_id,
        "blocked_id": blocked_id,
        "state": "blocked",
        "created_at": now,
    })

    # Auto-unfollow both directions (import here to avoid circular imports)
    from app.services.social import is_following, unfollow_user
    try:
        if is_following(blocker_id, blocked_id):
            unfollow_user(blocker_id, blocked_id)
    except Exception:
        logger.exception("Failed to auto-unfollow %s -> %s on block", blocker_id, blocked_id)
    try:
        if is_following(blocked_id, blocker_id):
            unfollow_user(blocked_id, blocker_id)
    except Exception:
        logger.exception("Failed to auto-unfollow %s -> %s on block", blocked_id, blocker_id)

    return {"ok": True, "status": "blocked", "target_user_id": blocked_id}


def unblock_user(blocker_id: str, blocked_id: str) -> dict:
    """Remove forward + reverse block entities."""
    tbl.delete_item(Key={"pk": pk_user(blocker_id), "sk": f"BLOCKED#{blocked_id}"})
    tbl.delete_item(Key={"pk": pk_user(blocked_id), "sk": f"BLOCKEDBY#{blocker_id}"})
    return {"ok": True, "status": "unblocked", "target_user_id": blocked_id}


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


def get_blocked_users(user_id: str, limit: int = 20, cursor: Optional[str] = None) -> Tuple[List[Dict], Optional[Dict], int]:
    """List users blocked by user_id, returning (items, last_evaluated_key, count)."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            Key("pk").eq(pk_user(user_id))
            & Key("sk").begins_with("BLOCKED#")
        ),
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = cursor

    resp = tbl.query(**kwargs)
    items = resp.get("Items", [])

    # Filter out BLOCKEDBY# items (should not appear due to begins_with, but be safe)
    block_items = [it for it in items if it.get("sk", "").startswith("BLOCKED#") and not it.get("sk", "").startswith("BLOCKEDBY#")]

    enriched: List[Dict] = []
    for item in block_items:
        blocked_id = item.get("blocked_id", "")
        profile = T.profile.get_item(Key={"user_sub": blocked_id}).get("Item") or {}
        enriched.append({
            "user_id": blocked_id,
            "display_name": profile.get("display_name") or blocked_id,
            "profile_photo_url": profile.get("profile_photo_url"),
            "blocked_at": item.get("created_at", ""),
        })

    return enriched, resp.get("LastEvaluatedKey"), len(enriched)


def get_block_status(viewer_id: str, target_id: str) -> Dict[str, bool]:
    """Check bidirectional block status between viewer and target."""
    return {
        "is_blocked_by_me": _is_blocked(viewer_id, target_id),
        "is_blocking_me": _is_blocked(target_id, viewer_id),
    }


def is_any_block(user_a: str, user_b: str) -> bool:
    """Check if there is a block in either direction between two users."""
    return _is_blocked(user_a, user_b) or _is_blocked(user_b, user_a)


def get_blocked_set(user_id: str) -> Set[str]:
    """Load all user IDs that user_id has blocked."""
    items: List[Dict] = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("pk").eq(pk_user(user_id))
                & Key("sk").begins_with("BLOCKED#")
            ),
            "Limit": 500,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        r = tbl.query(**kwargs)
        for it in r.get("Items", []):
            if it.get("sk", "").startswith("BLOCKEDBY#"):
                continue
            items.append(it)
        last_key = r.get("LastEvaluatedKey")
        if not last_key:
            break
    return {it.get("blocked_id", "") for it in items if it.get("blocked_id")}


def get_blocked_by_set(user_id: str) -> Set[str]:
    """Load all user IDs that have blocked user_id."""
    items: List[Dict] = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("pk").eq(pk_user(user_id))
                & Key("sk").begins_with("BLOCKEDBY#")
            ),
            "Limit": 500,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        r = tbl.query(**kwargs)
        items.extend(r.get("Items", []))
        last_key = r.get("LastEvaluatedKey")
        if not last_key:
            break
    return {it.get("blocker_id", "") for it in items if it.get("blocker_id")}


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------


def _is_blocked(blocker_id: str, blocked_id: str) -> bool:
    """Check if blocker has blocked blocked_id."""
    item = tbl.get_item(
        Key={"pk": pk_user(blocker_id), "sk": f"BLOCKED#{blocked_id}"}
    ).get("Item")
    return bool(item and item.get("state") == "blocked")
