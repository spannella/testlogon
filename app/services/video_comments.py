"""Video comments service (VOD-017).

Stores comments in the VideoViews table using PK=VCOMMENT#{video_id},
SK={timestamp}#{comment_id} pattern to avoid needing a new DDB table.
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
    sk = f"{ts:012d}#{comment_id}"

    item = {
        "pk": f"VCOMMENT#{video_id}",
        "sk": sk,
        "comment_id": comment_id,
        "video_id": video_id,
        "user_id": user_id,
        "text": text.strip(),
        "created_at": ts,
    }

    T.video_views.put_item(Item=item)

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
    cursor: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """List comments for a video, newest first."""
    limit = min(limit, 100)

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(f"VCOMMENT#{video_id}"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        # cursor is the SK of the last seen item
        kwargs["ExclusiveStartKey"] = {
            "pk": f"VCOMMENT#{video_id}",
            "sk": cursor,
        }

    resp = T.video_views.query(**kwargs)
    items_raw = resp.get("Items", [])

    comments = []
    for item in items_raw:
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


def delete_comment(
    *,
    video_id: str,
    comment_id: str,
    user_id: str,
) -> None:
    """Delete a comment. Only the comment author can delete."""
    # Find the comment by scanning the video's comments for this comment_id
    resp = T.video_views.query(
        KeyConditionExpression=Key("pk").eq(f"VCOMMENT#{video_id}"),
        FilterExpression="comment_id = :cid",
        ExpressionAttributeValues={":cid": comment_id},
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items:
        raise HTTPException(404, "Comment not found")

    item = items[0]
    if item.get("user_id") != user_id:
        raise HTTPException(403, "Not your comment")

    T.video_views.delete_item(
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
