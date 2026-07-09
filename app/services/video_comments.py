"""Video comments service (VOD-017 / GAP-0380).

Stores comments in a DEDICATED ``video_comments`` table (no TTL — comments are
durable). Previously comments lived in the VideoViews table under a
``VCOMMENT#`` prefix, which co-mingled them with view records that carry a
90-day TTL, silently deleting comments after 90 days. The dedicated table fixes
that data-loss bug.

Key schema (PK=``pk``, SK=``sk``):
  pk = VIDEO#{video_id}
  sk = COMMENT#{ts:012d}#{comment_id}   (zero-padded ts → chronological order)
A ``created_at`` numeric attribute backs the ByVideoCreatedAt GSI.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def add_comment(
    *,
    video_id: str,
    user_id: str,
    text: str,
) -> Dict[str, Any]:
    """Add a comment to a video. Increments comment_count on video metadata."""
    if not text or not text.strip():
        raise HTTPException(400, "Comment text is required")
    if len(text) > 2000:
        raise HTTPException(400, "Comment text too long (max 2000 chars)")

    ts = now_ts()
    comment_id = f"vc_{uuid.uuid4().hex[:16]}"
    # SK uses zero-padded timestamp for chronological ordering
    sk = f"COMMENT#{ts:012d}#{comment_id}"

    item = {
        "pk": f"VIDEO#{video_id}",
        "sk": sk,
        "comment_id": comment_id,
        "video_id": video_id,
        "user_id": user_id,
        "text": text.strip(),
        "created_at": ts,
    }

    T.video_comments.put_item(Item=item)

    # Increment comment_count on video metadata (best-effort)
    try:
        T.video_metadata.update_item(
            Key={"video_id": video_id},
            UpdateExpression="SET comment_count = if_not_exists(comment_count, :z) + :one",
            ExpressionAttributeValues={":z": 0, ":one": 1},
        )
    except Exception:
        logger.warning("comment_count_increment_failed", extra={"video_id": video_id})

    return {
        "comment_id": comment_id,
        "video_id": video_id,
        "user_id": user_id,
        "text": text.strip(),
        "created_at": ts,
    }


def list_comments(
    *,
    video_id: str,
    viewer_id: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """List comments for a video, newest first."""
    limit = min(limit, 100)

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(f"VIDEO#{video_id}"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        # cursor is the SK of the last seen item
        kwargs["ExclusiveStartKey"] = {
            "pk": f"VIDEO#{video_id}",
            "sk": cursor,
        }

    resp = T.video_comments.query(**kwargs)
    items_raw = resp.get("Items", [])

    comments = []
    for item in items_raw:
        if (item.get("moderation_hidden") or item.get("moderation_removed")) and item.get("user_id") != viewer_id:
            continue
        comments.append({
            "comment_id": item.get("comment_id", ""),
            "video_id": item.get("video_id", video_id),
            "user_id": item.get("user_id", ""),
            "text": item.get("text", ""),
            "created_at": int(item.get("created_at", 0)),
        })

    new_cursor: Optional[str] = None
    last_key = resp.get("LastEvaluatedKey")
    if last_key:
        new_cursor = last_key.get("sk", "")

    return {"comments": comments, "cursor": new_cursor}


def get_comment(*, video_id: str, comment_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a single comment's raw item by id (the SK embeds a timestamp so a
    direct GetItem is impossible; page the partition like delete_comment).
    Returns None if not found."""
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(f"VIDEO#{video_id}"),
            "FilterExpression": "comment_id = :cid",
            "ExpressionAttributeValues": {":cid": comment_id},
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.video_comments.query(**kwargs)
        items = resp.get("Items", [])
        if items:
            return items[0]
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            return None


def bump_comment_tip_total(*, video_id: str, comment: Dict[str, Any], amount_cents: int) -> int:
    """Additively bump tip_total_cents on a video comment row; returns new total."""
    upd = T.video_comments.update_item(
        Key={"pk": comment["pk"], "sk": comment["sk"]},
        UpdateExpression="SET tip_total_cents = if_not_exists(tip_total_cents, :z) + :amt",
        ExpressionAttributeValues={":z": 0, ":amt": amount_cents},
        ReturnValues="UPDATED_NEW",
    )
    return int(upd.get("Attributes", {}).get("tip_total_cents", amount_cents))


def delete_comment(
    *,
    video_id: str,
    comment_id: str,
    user_id: str,
) -> None:
    """Delete a comment. Only the comment author can delete."""
    # Find the comment by scanning the video's comments for this comment_id.
    # NOTE: DynamoDB applies FilterExpression *after* reading up to `Limit`
    # items, so a `Limit=1` query would read a single (likely non-matching)
    # comment and then filter it out, yielding a spurious 404 whenever the
    # partition already holds other comments. Page through LastEvaluatedKey so
    # the target comment is found regardless of how many comments exist.
    item = None
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(f"VIDEO#{video_id}"),
            "FilterExpression": "comment_id = :cid",
            "ExpressionAttributeValues": {":cid": comment_id},
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.video_comments.query(**kwargs)
        items = resp.get("Items", [])
        if items:
            item = items[0]
            break
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    if item is None:
        raise HTTPException(404, "Comment not found")

    if item.get("user_id") != user_id:
        raise HTTPException(403, "Not your comment")

    T.video_comments.delete_item(
        Key={"pk": item["pk"], "sk": item["sk"]}
    )

    # Decrement comment_count on video metadata (best-effort)
    try:
        T.video_metadata.update_item(
            Key={"video_id": video_id},
            UpdateExpression="SET comment_count = if_not_exists(comment_count, :one) - :one",
            ExpressionAttributeValues={":one": 1},
        )
    except Exception:
        logger.warning("comment_count_decrement_failed", extra={"video_id": video_id})
