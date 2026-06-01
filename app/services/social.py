"""Social graph service — follow/unfollow, follower/following lists, counts, mutual detection."""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
tbl = ddb.Table(APP_TABLE)


def pk_user(user_id: str) -> str:
    return f"USER#{user_id}"


# ---------------------------------------------------------------------------
# Follow / Unfollow
# ---------------------------------------------------------------------------

def follow_user(follower_id: str, followed_id: str) -> Dict[str, Any]:
    """Create or reactivate a follow relationship.

    Returns dict with ok, status, follower_count, following_count.
    Raises ValueError for self_follow, blocked, user_not_found, rate_limited.
    """
    if follower_id == followed_id:
        raise ValueError("self_follow")

    # Check block relationship (bidirectional)
    from app.services.blocking import is_any_block
    if is_any_block(follower_id, followed_id):
        raise ValueError("blocked")

    # Check target user exists
    target_profile = T.profile.get_item(Key={"user_sub": followed_id}).get("Item")
    if not target_profile:
        raise ValueError("user_not_found")

    # Read existing follow record
    existing = tbl.get_item(
        Key={"pk": pk_user(follower_id), "sk": f"FOLLOWING#{followed_id}"}
    ).get("Item")

    if existing and existing.get("state") == "following":
        counts = get_follow_counts(followed_id)
        my_counts = get_follow_counts(follower_id)
        return {
            "ok": True,
            "status": "already_following",
            "follower_count": counts["follower_count"],
            "following_count": my_counts["following_count"],
        }

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    created_at = existing.get("created_at", now) if existing else now

    item = {
        "pk": pk_user(follower_id),
        "sk": f"FOLLOWING#{followed_id}",
        "Entity": "Following",
        "user_id": follower_id,
        "target_user_id": followed_id,
        "state": "following",
        "created_at": created_at,
        "updated_at": now,
        "GSI5PK": f"FOLLOWERS#{followed_id}",
        "GSI5SK": f"{created_at}#{follower_id}",
    }
    tbl.put_item(Item=item)

    # Increment counts atomically
    _increment_counts(follower_id, followed_id)

    # Backfill recent posts from followed user into follower's feed
    try:
        from app.services.newsfeed_fanout import backfill_feed_on_follow
        backfill_feed_on_follow(follower_id=follower_id, followed_id=followed_id)
    except Exception:
        logger.exception("Feed backfill failed for %s -> %s", follower_id, followed_id)

    counts = get_follow_counts(followed_id)
    my_counts = get_follow_counts(follower_id)
    return {
        "ok": True,
        "status": "followed",
        "follower_count": counts["follower_count"],
        "following_count": my_counts["following_count"],
    }


def unfollow_user(follower_id: str, followed_id: str) -> Dict[str, Any]:
    """Deactivate a follow relationship."""
    existing = tbl.get_item(
        Key={"pk": pk_user(follower_id), "sk": f"FOLLOWING#{followed_id}"}
    ).get("Item")

    if not existing or existing.get("state") != "following":
        return {"ok": True, "status": "not_following"}

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    tbl.update_item(
        Key={"pk": pk_user(follower_id), "sk": f"FOLLOWING#{followed_id}"},
        UpdateExpression=(
            "SET #state = :unfollowed, updated_at = :now "
            "REMOVE GSI5PK, GSI5SK"
        ),
        ExpressionAttributeNames={"#state": "state"},
        ExpressionAttributeValues={
            ":unfollowed": "unfollowed",
            ":now": now,
        },
    )

    _decrement_counts(follower_id, followed_id)

    # Remove fan-out feed refs
    try:
        from app.services.newsfeed_fanout import remove_feed_on_unfollow
        remove_feed_on_unfollow(follower_id=follower_id, followed_id=followed_id)
    except Exception:
        logger.exception("Feed cleanup failed for unfollow %s -> %s", follower_id, followed_id)

    return {"ok": True, "status": "unfollowed"}


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

def get_followers(
    user_id: str, *, limit: int = 20, cursor: Optional[str] = None
) -> Tuple[List[Dict], Optional[str]]:
    """Query GSI5 for FOLLOWERS#{user_id} with pagination."""
    eks = decode_cursor(cursor)
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI5",
        "KeyConditionExpression": Key("GSI5PK").eq(f"FOLLOWERS#{user_id}"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if eks:
        kwargs["ExclusiveStartKey"] = eks

    resp = tbl.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))

    followers = [
        it for it in items
        if it.get("state", "following") == "following"
    ]
    return followers, next_cursor


def get_following(
    user_id: str, *, limit: int = 20, cursor: Optional[str] = None
) -> Tuple[List[Dict], Optional[str]]:
    """Query PK=USER#{user_id}, SK begins_with FOLLOWING#, filter state=following."""
    eks = decode_cursor(cursor)
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            Key("pk").eq(pk_user(user_id))
            & Key("sk").begins_with("FOLLOWING#")
        ),
        "FilterExpression": Attr("state").eq("following"),
        "Limit": limit,
    }
    if eks:
        kwargs["ExclusiveStartKey"] = eks

    resp = tbl.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return items, next_cursor


def get_follow_counts(user_id: str) -> Dict[str, int]:
    """Read follower_count and following_count from profiles table."""
    item = T.profile.get_item(Key={"user_sub": user_id}).get("Item") or {}
    return {
        "follower_count": int(item.get("follower_count", 0)),
        "following_count": int(item.get("following_count", 0)),
    }


def is_following(follower_id: str, target_id: str) -> bool:
    """Check if follower_id follows target_id. Convenience wrapper."""
    fwd = tbl.get_item(
        Key={"pk": pk_user(follower_id), "sk": f"FOLLOWING#{target_id}"}
    ).get("Item")
    return bool(fwd and fwd.get("state") == "following")


def get_follow_status(viewer_id: str, target_id: str) -> Dict[str, bool]:
    """Check bidirectional follow status."""
    fwd = tbl.get_item(
        Key={"pk": pk_user(viewer_id), "sk": f"FOLLOWING#{target_id}"}
    ).get("Item")
    is_following = bool(fwd and fwd.get("state") == "following")

    rev = tbl.get_item(
        Key={"pk": pk_user(target_id), "sk": f"FOLLOWING#{viewer_id}"}
    ).get("Item")
    is_followed_by = bool(rev and rev.get("state") == "following")

    return {
        "is_following": is_following,
        "is_followed_by": is_followed_by,
        "is_mutual": is_following and is_followed_by,
    }


# ---------------------------------------------------------------------------
# Snooze Following (SOCIAL-007)
# ---------------------------------------------------------------------------

# Maximum snooze duration in days (matches Pydantic validation in models.py).
SNOOZE_MAX_DAYS = 90


def _get_follow_item(follower_id: str, followed_id: str) -> Optional[Dict[str, Any]]:
    """Return the raw FOLLOWING# record if an active follow exists, else None."""
    item = tbl.get_item(
        Key={"pk": pk_user(follower_id), "sk": f"FOLLOWING#{followed_id}"}
    ).get("Item")
    if not item or item.get("state") != "following":
        return None
    return item


def _snooze_remaining_hours(snoozed_until: int, now: int) -> int:
    """Whole hours remaining until snooze expiry (>= 0)."""
    remaining = int(snoozed_until) - int(now)
    if remaining <= 0:
        return 0
    return remaining // 3600


def snooze_following(follower_id: str, followed_id: str, days: int) -> Dict[str, Any]:
    """Snooze a following for N days. Raises ValueError on validation failures.

    Errors: self_snooze, not_following, invalid_duration.
    """
    if follower_id == followed_id:
        raise ValueError("self_snooze")
    if not isinstance(days, int) or days <= 0 or days > SNOOZE_MAX_DAYS:
        raise ValueError("invalid_duration")

    follow = _get_follow_item(follower_id, followed_id)
    if not follow:
        raise ValueError("not_following")

    snoozed_until = now_ts() + (days * 86400)
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    tbl.update_item(
        Key={"pk": pk_user(follower_id), "sk": f"FOLLOWING#{followed_id}"},
        UpdateExpression="SET snoozed_until = :su, updated_at = :now",
        ConditionExpression="attribute_exists(pk)",
        ExpressionAttributeValues={":su": snoozed_until, ":now": now_iso},
    )

    logger.info(
        "social.snooze_set follower=%s following=%s days=%s snoozed_until=%s",
        follower_id, followed_id, days, snoozed_until,
    )
    return {"ok": True, "snoozed_until": snoozed_until}


def unsnooze_following(follower_id: str, followed_id: str) -> Dict[str, Any]:
    """Remove snooze from a following. Idempotent — succeeds even if not snoozed
    or not following (no-op)."""
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        tbl.update_item(
            Key={"pk": pk_user(follower_id), "sk": f"FOLLOWING#{followed_id}"},
            UpdateExpression="REMOVE snoozed_until SET updated_at = :now",
            ConditionExpression="attribute_exists(pk)",
            ExpressionAttributeValues={":now": now_iso},
        )
        logger.info(
            "social.snooze_cleared follower=%s following=%s", follower_id, followed_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
        # No follow record at all — nothing to clear; remain idempotent.
    return {"ok": True}


def list_snoozed_followings(follower_id: str) -> List[Dict[str, Any]]:
    """List all currently-snoozed followings (snoozed_until > now).

    Loops LastEvaluatedKey since FilterExpression does not reduce page size.
    """
    now = now_ts()
    results: List[Dict[str, Any]] = []
    last_key = None
    while True:
        kw: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("pk").eq(pk_user(follower_id))
                & Key("sk").begins_with("FOLLOWING#")
            ),
            "FilterExpression": Attr("state").eq("following"),
            "Limit": 500,
        }
        if last_key:
            kw["ExclusiveStartKey"] = last_key
        resp = tbl.query(**kw)
        for it in resp.get("Items", []):
            su = it.get("snoozed_until")
            if su is None:
                continue
            su = int(su)
            if su <= now:
                continue
            following_sub = it.get("target_user_id", "")
            profile = T.profile.get_item(Key={"user_sub": following_sub}).get("Item") or {}
            results.append({
                "following_sub": following_sub,
                "following_name": profile.get("display_name") or following_sub,
                "following_avatar_url": profile.get("profile_photo_url"),
                "followed_at": 0,
                "snoozed_until": su,
                "snooze_remaining_hours": _snooze_remaining_hours(su, now),
            })
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    results.sort(key=lambda r: r["snoozed_until"])
    return results


def get_snoozed_following_ids(follower_id: str) -> Set[str]:
    """Return the set of followed user IDs currently snoozed by follower_id.

    Used by feed filtering. Loops LastEvaluatedKey.
    """
    now = now_ts()
    snoozed: Set[str] = set()
    last_key = None
    while True:
        kw: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("pk").eq(pk_user(follower_id))
                & Key("sk").begins_with("FOLLOWING#")
            ),
            "Limit": 500,
        }
        if last_key:
            kw["ExclusiveStartKey"] = last_key
        resp = tbl.query(**kw)
        for it in resp.get("Items", []):
            su = it.get("snoozed_until")
            if su is None:
                continue
            if int(su) > now and it.get("target_user_id"):
                snoozed.add(it["target_user_id"])
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return snoozed


def is_snoozed(follower_id: str, followed_id: str) -> bool:
    """Check if a following is currently snoozed (snoozed_until > now)."""
    item = tbl.get_item(
        Key={"pk": pk_user(follower_id), "sk": f"FOLLOWING#{followed_id}"}
    ).get("Item")
    if not item:
        return False
    su = item.get("snoozed_until")
    return su is not None and int(su) > now_ts()


def get_mutual_followers(
    viewer_id: str,
    target_id: str,
    *,
    limit: int = 20,
    cursor: Optional[str] = None,
) -> Tuple[List[Dict], Optional[str]]:
    """Compute intersection of viewer's following and target's followers."""
    viewer_following: Set[str] = set()
    last_key = None
    while len(viewer_following) < 2000:
        kw: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("pk").eq(pk_user(viewer_id))
                & Key("sk").begins_with("FOLLOWING#")
            ),
            "FilterExpression": Attr("state").eq("following"),
            "Limit": 500,
        }
        if last_key:
            kw["ExclusiveStartKey"] = last_key
        r = tbl.query(**kw)
        for it in r.get("Items", []):
            tid = it.get("target_user_id")
            if tid:
                viewer_following.add(tid)
        last_key = r.get("LastEvaluatedKey")
        if not last_key:
            break

    target_follower_ids: Set[str] = set()
    last_key = None
    while len(target_follower_ids) < 2000:
        kw2: Dict[str, Any] = {
            "IndexName": "GSI5",
            "KeyConditionExpression": Key("GSI5PK").eq(f"FOLLOWERS#{target_id}"),
            "Limit": 500,
        }
        if last_key:
            kw2["ExclusiveStartKey"] = last_key
        r2 = tbl.query(**kw2)
        for it in r2.get("Items", []):
            uid = it.get("user_id")
            if uid:
                target_follower_ids.add(uid)
        last_key = r2.get("LastEvaluatedKey")
        if not last_key:
            break

    mutual_ids = sorted(viewer_following & target_follower_ids)

    offset = 0
    if cursor:
        try:
            offset = int(cursor)
        except (ValueError, TypeError):
            offset = 0
    page = mutual_ids[offset: offset + limit]
    next_cursor_val: Optional[str] = None
    if offset + limit < len(mutual_ids):
        next_cursor_val = str(offset + limit)

    results = [{"user_id": uid} for uid in page]
    return results, next_cursor_val


# ---------------------------------------------------------------------------
# Count reconciliation
# ---------------------------------------------------------------------------

def reconcile_follow_counts(user_id: str) -> Dict[str, int]:
    """Recompute follower_count and following_count from actual follow records."""
    following_count = 0
    last_key = None
    while True:
        kw: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("pk").eq(pk_user(user_id))
                & Key("sk").begins_with("FOLLOWING#")
            ),
            "FilterExpression": Attr("state").eq("following"),
            "Select": "COUNT",
            "Limit": 1000,
        }
        if last_key:
            kw["ExclusiveStartKey"] = last_key
        r = tbl.query(**kw)
        following_count += r.get("Count", 0)
        last_key = r.get("LastEvaluatedKey")
        if not last_key:
            break

    follower_count = 0
    last_key = None
    while True:
        kw2: Dict[str, Any] = {
            "IndexName": "GSI5",
            "KeyConditionExpression": Key("GSI5PK").eq(f"FOLLOWERS#{user_id}"),
            "Select": "COUNT",
            "Limit": 1000,
        }
        if last_key:
            kw2["ExclusiveStartKey"] = last_key
        r2 = tbl.query(**kw2)
        follower_count += r2.get("Count", 0)
        last_key = r2.get("LastEvaluatedKey")
        if not last_key:
            break

    T.profile.update_item(
        Key={"user_sub": user_id},
        UpdateExpression="SET follower_count = :fc, following_count = :fgc",
        ExpressionAttributeValues={":fc": follower_count, ":fgc": following_count},
    )
    return {"follower_count": follower_count, "following_count": following_count}


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _increment_counts(follower_id: str, followed_id: str) -> None:
    """Atomic ADD +1 to following_count and follower_count."""
    try:
        T.profile.update_item(
            Key={"user_sub": followed_id},
            UpdateExpression="ADD follower_count :one",
            ExpressionAttributeValues={":one": 1},
        )
    except ClientError:
        logger.exception("Failed to increment follower_count for %s", followed_id)

    try:
        T.profile.update_item(
            Key={"user_sub": follower_id},
            UpdateExpression="ADD following_count :one",
            ExpressionAttributeValues={":one": 1},
        )
    except ClientError:
        logger.exception("Failed to increment following_count for %s", follower_id)


def _decrement_counts(follower_id: str, followed_id: str) -> None:
    """Atomic ADD -1 to following_count and follower_count, clamped at 0."""
    for user_sub, field in [
        (followed_id, "follower_count"),
        (follower_id, "following_count"),
    ]:
        try:
            T.profile.update_item(
                Key={"user_sub": user_sub},
                UpdateExpression=f"ADD {field} :neg_one",
                ConditionExpression=Attr(field).gt(0),
                ExpressionAttributeValues={":neg_one": -1},
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                try:
                    T.profile.update_item(
                        Key={"user_sub": user_sub},
                        UpdateExpression=f"SET {field} = :zero",
                        ExpressionAttributeValues={":zero": 0},
                    )
                except ClientError:
                    logger.exception("Failed to clamp %s for %s", field, user_sub)
            else:
                logger.exception("Failed to decrement %s for %s", field, user_sub)


def _is_blocked(blocker_id: str, blocked_id: str) -> bool:
    """Check if blocker has blocked blocked_id."""
    item = tbl.get_item(
        Key={"pk": pk_user(blocker_id), "sk": f"BLOCKED#{blocked_id}"}
    ).get("Item")
    return bool(item and item.get("state") == "blocked")
