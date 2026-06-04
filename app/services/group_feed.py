"""Group Feed service (GROUP-002).

Group posts are stored in ``app_single_table`` alongside regular posts,
with additional ``group_id`` and ``audience`` fields.  A separate
``GROUPFEED#{group_id}`` partition in ``app_single_table`` indexes posts
for efficient group-scoped feed queries.
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services.user_groups import get_membership, get_group

logger = logging.getLogger(__name__)

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")

# Max pinned posts per group
_MAX_PINNED = 3


def _pk_post(post_id: str) -> str:
    return f"POST#{post_id}"


def _sk_post() -> str:
    return "META"


def _pk_groupfeed(group_id: str) -> str:
    return f"GROUPFEED#{group_id}"


def _new_post_id() -> str:
    return f"post_{uuid.uuid4().hex[:12]}"


def _get_app_table():
    """Get a handle to the app_single_table."""
    from app.core.aws import ddb
    return ddb.Table(APP_TABLE)


def _is_member(group_id: str, user_id: str) -> bool:
    mem = get_membership(group_id, user_id)
    return mem is not None and mem.get("status") == "active"


def _get_member_role(group_id: str, user_id: str) -> Optional[str]:
    mem = get_membership(group_id, user_id)
    if mem and mem.get("status") == "active":
        return mem.get("role")
    return None


# ── Create group post ─────────────────────────────────────────────────────────

def create_group_post(
    *,
    group_id: str,
    user_id: str,
    text: str,
    body_format: str = "plain",
    image_url: str | None = None,
    audience: str = "public",
    unlock_price_cents: int | None = None,
) -> Dict[str, Any]:
    # Verify group exists and is active
    group = get_group(group_id)
    if not group:
        raise ValueError("Group not found")
    if group.get("status") == "dissolved":
        raise ValueError("This group has been dissolved")

    # Verify membership
    if not _is_member(group_id, user_id):
        raise PermissionError("Not a member of this group")

    ts = now_ts()
    post_id = _new_post_id()
    locked = unlock_price_cents is not None and unlock_price_cents > 0

    tbl = _get_app_table()

    # Write post record
    post_item: Dict[str, Any] = {
        "pk": _pk_post(post_id),
        "sk": _sk_post(),
        "post_id": post_id,
        "user_id": user_id,
        "text": text,
        "body_format": body_format,
        "image_url": image_url,
        "group_id": group_id,
        "audience": audience,
        "pinned": False,
        "locked": locked,
        "unlock_price_cents": unlock_price_cents,
        "like_count": 0,
        "comment_count": 0,
        "tip_total_cents": 0,
        "created_at": ts,
        "updated_at": ts,
    }
    # Remove None values for DDB
    post_item = {k: v for k, v in post_item.items() if v is not None}
    tbl.put_item(Item=post_item)

    # Write group feed index record
    feed_item: Dict[str, Any] = {
        "pk": _pk_groupfeed(group_id),
        "sk": f"{ts}#{post_id}",
        "post_id": post_id,
        "user_id": user_id,
        "audience": audience,
        "pinned": False,
        "created_at": ts,
    }
    tbl.put_item(Item=feed_item)

    logger.info("group_feed.post_created", extra={
        "group_id": group_id, "post_id": post_id, "user_id": user_id,
        "audience": audience, "body_format": body_format,
    })

    return _post_out(post_item, viewer_id=user_id)


# ── List group feed ───────────────────────────────────────────────────────────

def list_group_feed(
    *,
    group_id: str,
    viewer_id: str | None = None,
    cursor: str | None = None,
    limit: int = 20,
) -> Dict[str, Any]:
    from app.core.cursor import encode_cursor, decode_cursor

    group = get_group(group_id)
    if not group:
        raise ValueError("Group not found")
    if group.get("status") == "dissolved":
        raise ValueError("This group has been dissolved")

    is_member = viewer_id is not None and _is_member(group_id, viewer_id)

    tbl = _get_app_table()

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(_pk_groupfeed(group_id)),
        "ScanIndexForward": False,
        "Limit": limit * 2,  # fetch extra to account for audience filtering
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = tbl.query(**kwargs)
    index_records = resp.get("Items", [])

    # On the first page, always include pinned posts even if they are older than
    # the most recent `limit` posts. Feed-index records are ordered by recency
    # (SK = "{ts}#{post_id}"), so an old-but-pinned post would otherwise be
    # sliced off below before the pinned-first sort runs.
    #
    # Pinned state is read from the authoritative *post* items (see below), not
    # from the feed-index `pinned` flag, which is maintained by a separate write
    # and can drift out of sync. We therefore identify pinned posts via the post
    # items themselves rather than trusting the index record's stale flag.
    if not cursor:
        seen_ids = {r.get("post_id") for r in index_records}
        for pinned_rec in _pinned_index_records(tbl, group_id):
            if pinned_rec.get("post_id") not in seen_ids:
                index_records.append(pinned_rec)
                seen_ids.add(pinned_rec.get("post_id"))

    # Filter by audience
    if not is_member:
        index_records = [r for r in index_records if r.get("audience") == "public"]

    # Batch fetch full posts (authoritative source of the `pinned` flag).
    post_ids = [r["post_id"] for r in index_records]
    posts = _batch_get_posts(tbl, post_ids)
    post_map = {p["post_id"]: p for p in posts}

    # Take only the requested limit, but always keep pinned posts (determined
    # from the authoritative post item) even when slicing to the page limit.
    has_more = len(index_records) > limit or "LastEvaluatedKey" in resp
    pinned_records = [
        r for r in index_records if bool(post_map.get(r["post_id"], {}).get("pinned"))
    ]
    other_records = [
        r for r in index_records if not bool(post_map.get(r["post_id"], {}).get("pinned"))
    ]
    index_records = (pinned_records + other_records)[: max(limit, len(pinned_records))]

    # Build result sorted: pinned first by pinned_at desc, then by created_at desc
    result_posts = []
    for idx in index_records:
        pid = idx["post_id"]
        post = post_map.get(pid)
        if not post:
            continue
        result_posts.append(_post_out(post, viewer_id=viewer_id))

    # Sort: pinned first
    pinned = [p for p in result_posts if p.get("pinned")]
    unpinned = [p for p in result_posts if not p.get("pinned")]
    pinned.sort(key=lambda p: p.get("pinned_at") or 0, reverse=True)
    unpinned.sort(key=lambda p: p.get("created_at") or 0, reverse=True)
    sorted_posts = pinned + unpinned

    next_cursor = None
    if has_more and index_records:
        last = index_records[-1]
        next_cursor = encode_cursor({"pk": last["pk"], "sk": last["sk"]})

    return {
        "posts": sorted_posts,
        "cursor": next_cursor,
        "has_more": has_more,
    }


# ── Pin / Unpin ───────────────────────────────────────────────────────────────

def pin_post(*, group_id: str, post_id: str, user_id: str) -> Dict[str, Any]:
    _require_admin_or_mod(group_id, user_id)

    tbl = _get_app_table()
    post = _get_post(tbl, post_id)
    if not post or post.get("group_id") != group_id:
        raise ValueError("Post not found in this group")

    if post.get("pinned"):
        raise ValueError("Post is already pinned")

    # Check max pinned
    pinned_count = _count_pinned(tbl, group_id)
    if pinned_count >= _MAX_PINNED:
        raise ValueError("Maximum of 3 pinned posts reached")

    ts = now_ts()
    tbl.update_item(
        Key={"pk": _pk_post(post_id), "sk": _sk_post()},
        UpdateExpression="SET pinned = :p, pinned_at = :pa, pinned_by = :pb",
        ExpressionAttributeValues={":p": True, ":pa": ts, ":pb": user_id},
    )

    # Update feed index
    _update_feed_index_pinned(tbl, group_id, post_id, True)

    return {"post_id": post_id, "pinned": True, "pinned_at": ts, "pinned_by": user_id}


def unpin_post(*, group_id: str, post_id: str, user_id: str) -> Dict[str, Any]:
    _require_admin_or_mod(group_id, user_id)

    tbl = _get_app_table()
    post = _get_post(tbl, post_id)
    if not post or post.get("group_id") != group_id:
        raise ValueError("Post not found in this group")

    tbl.update_item(
        Key={"pk": _pk_post(post_id), "sk": _sk_post()},
        UpdateExpression="SET pinned = :p REMOVE pinned_at, pinned_by",
        ExpressionAttributeValues={":p": False},
    )

    _update_feed_index_pinned(tbl, group_id, post_id, False)

    return {"post_id": post_id, "pinned": False, "pinned_at": None, "pinned_by": None}


# ── Delete group post ─────────────────────────────────────────────────────────

def delete_group_post(*, group_id: str, post_id: str, user_id: str) -> Dict[str, Any]:
    tbl = _get_app_table()
    post = _get_post(tbl, post_id)
    if not post:
        raise ValueError("Post not found")
    if post.get("group_id") != group_id:
        raise ValueError("Post not found in this group")

    # Check permissions: author, admin, or moderator
    is_author = post.get("user_id") == user_id
    role = _get_member_role(group_id, user_id)
    if not is_author and role not in ("admin", "moderator"):
        raise PermissionError("Only the author, admin, or moderator can delete this post")

    # Delete post record
    tbl.delete_item(Key={"pk": _pk_post(post_id), "sk": _sk_post()})

    # Delete feed index record
    _delete_feed_index(tbl, group_id, post_id)

    return {"ok": True, "post_id": post_id, "deleted_by": user_id}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _require_admin_or_mod(group_id: str, user_id: str) -> str:
    role = _get_member_role(group_id, user_id)
    if role not in ("admin", "moderator"):
        raise PermissionError("Only admins and moderators can pin posts")
    return role


def _get_post(tbl, post_id: str) -> Dict[str, Any] | None:
    resp = tbl.get_item(Key={"pk": _pk_post(post_id), "sk": _sk_post()})
    return resp.get("Item")


def _batch_get_posts(tbl, post_ids: List[str]) -> List[Dict[str, Any]]:
    if not post_ids:
        return []
    from app.core.aws import ddb
    keys = [{"pk": _pk_post(pid), "sk": _sk_post()} for pid in post_ids]
    # DDB BatchGetItem limit is 100 items; chunk if needed
    results = []
    for i in range(0, len(keys), 25):
        chunk = keys[i:i + 25]
        raw = ddb.batch_get_item(RequestItems={APP_TABLE: {"Keys": chunk}})
        results.extend(raw.get("Responses", {}).get(APP_TABLE, []))
    return results


def _all_feed_index_records(tbl, group_id: str) -> List[Dict[str, Any]]:
    """Return every feed-index record for a group (paginated)."""
    records: List[Dict[str, Any]] = []
    start_key: Dict[str, Any] | None = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(_pk_groupfeed(group_id)),
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = tbl.query(**kwargs)
        records.extend(resp.get("Items", []))
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    return records


def _count_pinned(tbl, group_id: str) -> int:
    """Count pinned posts in a group.

    Pinned state is read from the authoritative *post* items, not the
    feed-index `pinned` flag (which is maintained by a separate write and can
    drift out of sync — leaving the count wrong and the pin-limit check leaky).
    """
    return len(_pinned_index_records(tbl, group_id))


def _pinned_index_records(tbl, group_id: str) -> List[Dict[str, Any]]:
    """Return feed-index records whose underlying post is pinned.

    Determined from the authoritative post item rather than the index record's
    own `pinned` flag, which can be stale.
    """
    index_records = _all_feed_index_records(tbl, group_id)
    if not index_records:
        return []
    posts = _batch_get_posts(tbl, [r["post_id"] for r in index_records])
    pinned_ids = {p["post_id"] for p in posts if bool(p.get("pinned"))}
    return [r for r in index_records if r.get("post_id") in pinned_ids]


def _update_feed_index_pinned(tbl, group_id: str, post_id: str, pinned: bool) -> None:
    """Update the pinned flag on the feed index record.

    DynamoDB applies FilterExpression *after* reading a page (up to 1MB), so a
    single query can miss the target record on a busy feed — leaving the index
    `pinned` flag stale and corrupting the pinned count. Loop on
    LastEvaluatedKey so the right record is always found and updated.
    """
    start_key: Dict[str, Any] | None = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(_pk_groupfeed(group_id)),
            "FilterExpression": "post_id = :pid",
            "ExpressionAttributeValues": {":pid": post_id},
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = tbl.query(**kwargs)
        for item in resp.get("Items", []):
            tbl.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression="SET pinned = :p",
                ExpressionAttributeValues={":p": pinned},
            )
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break


def _delete_feed_index(tbl, group_id: str, post_id: str) -> None:
    """Delete the feed index record for a post.

    Loop on LastEvaluatedKey: DynamoDB applies FilterExpression after reading a
    page, so a single query can miss the record on a busy feed.
    """
    start_key: Dict[str, Any] | None = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(_pk_groupfeed(group_id)),
            "FilterExpression": "post_id = :pid",
            "ExpressionAttributeValues": {":pid": post_id},
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = tbl.query(**kwargs)
        for item in resp.get("Items", []):
            tbl.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break


def _post_out(post: Dict[str, Any], viewer_id: str | None = None) -> Dict[str, Any]:
    """Map a DDB post item to the GroupFeedPostOut shape."""
    is_locked = bool(post.get("locked"))
    is_author = viewer_id is not None and post.get("user_id") == viewer_id
    viewer_unlocked = is_author  # Simplified: author always sees unlocked

    text = post.get("text")
    if is_locked and not viewer_unlocked:
        text = None

    return {
        "post_id": post.get("post_id", ""),
        "user_id": post.get("user_id", ""),
        "user_display_name": post.get("user_id", ""),  # Simplified
        "user_avatar_url": None,
        "text": text,
        "body_format": post.get("body_format", "plain"),
        "image_url": post.get("image_url"),
        "group_id": post.get("group_id", ""),
        "audience": post.get("audience", "public"),
        "pinned": bool(post.get("pinned")),
        "pinned_at": int(post["pinned_at"]) if post.get("pinned_at") else None,
        "pinned_by": post.get("pinned_by"),
        "unlock_price_cents": int(post["unlock_price_cents"]) if post.get("unlock_price_cents") is not None else None,
        "unlocked": viewer_unlocked,
        "tip_total_cents": int(post.get("tip_total_cents", 0)),
        "reactions_counts": {},
        "my_reactions": [],
        "comment_count": int(post.get("comment_count", 0)),
        "created_at": int(post.get("created_at", 0)),
        "updated_at": int(post["updated_at"]) if post.get("updated_at") else None,
    }
