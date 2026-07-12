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

# Mirror the newsfeed comment reaction allowlist (app/routers/newsfeed.py
# ALLOWED_REACTION_EMOJIS). Kept identical so the two surfaces share the same
# reaction vocabulary and the same nested-map storage shape.
ALLOWED_REACTION_EMOJIS = ("👍", "❤️", "😂", "🔥", "😮")


def _reaction_summaries(reactions_map: Dict, viewer_id: Optional[str] = None):
    """Compute per-emoji counts and the viewer's own reactions from a DDB reactions map.

    Mirrors ``app.routers.newsfeed._reaction_summaries`` (replicated minimally to
    avoid importing the heavy newsfeed router module at video service import time).
    """
    counts: Dict[str, int] = {}
    mine: List[str] = []
    for emoji, users in (reactions_map or {}).items():
        if isinstance(users, dict) and users:
            counts[emoji] = len(users)
            if viewer_id and users.get(viewer_id):
                mine.append(emoji)
    return counts, mine


def _comment_projection(item: Dict[str, Any], viewer_id: Optional[str] = None) -> Dict[str, Any]:
    """Project a stored video-comment item into the API response shape.

    Mirrors the newsfeed ``_comment_to_dict`` projection: legacy items lack the
    additive fields, so every field is read defensively with sensible defaults.
    """
    reactions_counts, my_reactions = _reaction_summaries(item.get("reactions") or {}, viewer_id)
    return {
        "comment_id": item.get("comment_id", ""),
        "video_id": item.get("video_id", ""),
        "user_id": item.get("user_id", ""),
        "text": item.get("text"),
        "created_at": int(item.get("created_at", 0)),
        "edited_at": int(item["edited_at"]) if item.get("edited_at") is not None else None,
        "parent_comment_id": item.get("parent_comment_id"),
        "kind": item.get("kind", "text"),
        "gif_url": item.get("gif_url"),
        "gif_alt_text": item.get("gif_alt_text"),
        "gif_width": int(item["gif_width"]) if item.get("gif_width") is not None else None,
        "gif_height": int(item["gif_height"]) if item.get("gif_height") is not None else None,
        "sticker_id": item.get("sticker_id"),
        "sticker_collection_id": item.get("sticker_collection_id"),
        "sticker_url": item.get("sticker_url"),
        "sticker_alt_text": item.get("sticker_alt_text"),
        # Image comment fields (kind="image")
        "image_url": item.get("image_url"),
        "image_alt_text": item.get("image_alt_text"),
        "image_width": int(item["image_width"]) if item.get("image_width") is not None else None,
        "image_height": int(item["image_height"]) if item.get("image_height") is not None else None,
        "reactions_counts": reactions_counts,
        "my_reactions": my_reactions,
    }


def _find_comment_item(video_id: str, comment_id: str) -> Optional[Dict[str, Any]]:
    """Locate a comment's raw DDB item by paging the video's comment partition.

    DynamoDB applies FilterExpression *after* reading up to ``Limit`` items, so we
    page via LastEvaluatedKey (same pattern as ``delete_comment``)."""
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


def get_comment(video_id: str, comment_id: str) -> Optional[Dict[str, Any]]:
    """Public lookup used by moderation content-existence validation."""
    return _find_comment_item(video_id, comment_id)


def _notify_parent_author(*, video_id: str, parent_comment_id: str, comment_id: str, from_user_id: str) -> None:
    """Best-effort reply notification to the parent comment's author.

    Mirrors the newsfeed reply notification (put_notification with
    notif_type="reply_to_comment"). Never raises — a notification failure must
    not break comment creation."""
    try:
        parent = _find_comment_item(video_id, parent_comment_id)
        if not parent:
            return
        parent_user = parent.get("user_id")
        if not parent_user or parent_user == from_user_id:
            return
        from app.routers.newsfeed import put_notification

        put_notification(
            recipient_user_id=parent_user,
            notif_type="reply_to_comment",
            payload={
                "video_id": video_id,
                "parent_comment_id": parent_comment_id,
                "comment_id": comment_id,
                "from_user_id": from_user_id,
            },
        )
    except Exception:
        logger.warning("video reply notification failed", extra={"video_id": video_id})


def add_comment(
    *,
    video_id: str,
    user_id: str,
    text: Optional[str] = None,
    parent_comment_id: Optional[str] = None,
    kind: str = "text",
    gif_url: Optional[str] = None,
    gif_alt_text: Optional[str] = None,
    gif_width: Optional[int] = None,
    gif_height: Optional[int] = None,
    sticker_id: Optional[str] = None,
    sticker_collection_id: Optional[str] = None,
    sticker_url: Optional[str] = None,
    sticker_alt_text: Optional[str] = None,
    image_url: Optional[str] = None,
    image_alt_text: Optional[str] = None,
    image_width: Optional[int] = None,
    image_height: Optional[int] = None,
) -> Dict[str, Any]:
    """Add a comment to a video. Increments comment_count on video metadata.

    Supports text/gif/sticker comments (mirrors newsfeed CreateCommentRequest)
    and optional reply threading via ``parent_comment_id``. Media validation is
    performed by the request model (VideoCommentIn) before reaching here; this
    function applies the same text guards as before for the text path.
    """
    if kind == "text":
        if not text or not text.strip():
            raise HTTPException(400, "Comment text is required")
        if len(text) > 2000:
            raise HTTPException(400, "Comment text too long (max 2000 chars)")
        body_text = text.strip()
    else:
        body_text = None

    ts = now_ts()
    comment_id = f"vc_{uuid.uuid4().hex[:16]}"
    # SK uses zero-padded timestamp for chronological ordering
    sk = f"COMMENT#{ts:012d}#{comment_id}"

    item: Dict[str, Any] = {
        "pk": f"VIDEO#{video_id}",
        "sk": sk,
        "comment_id": comment_id,
        "video_id": video_id,
        "user_id": user_id,
        "text": body_text,
        "created_at": ts,
        "kind": kind,
    }
    if parent_comment_id:
        item["parent_comment_id"] = parent_comment_id
    # Sparse media attributes (only persisted when present).
    for key, val in (
        ("gif_url", gif_url),
        ("gif_alt_text", gif_alt_text),
        ("gif_width", gif_width),
        ("gif_height", gif_height),
        ("sticker_id", sticker_id),
        ("sticker_collection_id", sticker_collection_id),
        ("sticker_url", sticker_url),
        ("sticker_alt_text", sticker_alt_text),
        ("image_url", image_url),
        ("image_alt_text", image_alt_text),
        ("image_width", image_width),
        ("image_height", image_height),
    ):
        if val is not None:
            item[key] = val

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

    # Best-effort reply notification to the parent author (mirror newsfeed).
    if parent_comment_id:
        _notify_parent_author(
            video_id=video_id,
            parent_comment_id=parent_comment_id,
            comment_id=comment_id,
            from_user_id=user_id,
        )

    return _comment_projection(item, viewer_id=user_id)


def edit_comment(
    *,
    video_id: str,
    comment_id: str,
    user_id: str,
    text: str,
) -> Dict[str, Any]:
    """Edit a text comment's body. Author-only (403 otherwise); sets edited_at.

    Mirrors the newsfeed edit_comment author check + edited_at marker.
    """
    if not text or not text.strip():
        raise HTTPException(400, "Comment text is required")
    if len(text) > 2000:
        raise HTTPException(400, "Comment text too long (max 2000 chars)")

    item = _find_comment_item(video_id, comment_id)
    if item is None:
        raise HTTPException(404, "Comment not found")
    if item.get("user_id") != user_id:
        raise HTTPException(403, "Not your comment")
    # Media comments (gif/sticker/image) cannot be edited via text editor.
    if item.get("kind", "text") in ("gif", "sticker", "image"):
        raise HTTPException(400, "Media comments cannot be edited")

    edited_at = now_ts()
    T.video_comments.update_item(
        Key={"pk": item["pk"], "sk": item["sk"]},
        UpdateExpression="SET #t = :t, edited_at = :e",
        ExpressionAttributeNames={"#t": "text"},
        ExpressionAttributeValues={":t": text.strip(), ":e": edited_at},
    )
    item["text"] = text.strip()
    item["edited_at"] = edited_at
    return _comment_projection(item, viewer_id=user_id)


def add_reaction(
    *,
    video_id: str,
    comment_id: str,
    user_id: str,
    emoji: str,
) -> Dict[str, Any]:
    """Add a reaction to a comment (nested-map storage, mirrors newsfeed)."""
    item = _find_comment_item(video_id, comment_id)
    if item is None:
        raise HTTPException(404, "Comment not found")

    reactions = dict(item.get("reactions") or {})
    emoji_map = dict(reactions.get(emoji, {}))
    emoji_map[user_id] = True
    reactions[emoji] = emoji_map

    T.video_comments.update_item(
        Key={"pk": item["pk"], "sk": item["sk"]},
        UpdateExpression="SET reactions = :r",
        ExpressionAttributeValues={":r": reactions},
    )
    item["reactions"] = reactions
    return _comment_projection(item, viewer_id=user_id)


def remove_reaction(
    *,
    video_id: str,
    comment_id: str,
    user_id: str,
    emoji: str,
) -> Dict[str, Any]:
    """Remove a reaction from a comment (mirrors newsfeed unreact)."""
    item = _find_comment_item(video_id, comment_id)
    if item is None:
        raise HTTPException(404, "Comment not found")

    reactions = dict(item.get("reactions") or {})
    if emoji in reactions:
        emoji_map = dict(reactions[emoji])
        emoji_map.pop(user_id, None)
        if emoji_map:
            reactions[emoji] = emoji_map
        else:
            del reactions[emoji]
        T.video_comments.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression="SET reactions = :r",
            ExpressionAttributeValues={":r": reactions},
        )
        item["reactions"] = reactions
    return _comment_projection(item, viewer_id=user_id)


def list_comments(
    *,
    video_id: str,
    viewer_id: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """List comments for a video, newest first.

    Replies are returned in the same flat list (carrying ``parent_comment_id``);
    clients render the thread by grouping on ``parent_comment_id`` (mirrors the
    newsfeed flat-list-with-parent_comment_id contract)."""
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
        comments.append(_comment_projection(item, viewer_id=viewer_id))

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
