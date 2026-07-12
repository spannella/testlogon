from __future__ import annotations

"""MOD-A4/A5/A6: the terminal HARD-DELETE primitive per reportable surface.

This is the ONLY place content is actually removed. Everything upstream is a
non-destructive flag (see moderation_hide). Delete fires exclusively at a case's
terminal DELETE (admin final-call delete, poster close/withdraw, or the 30-day
sweep). Returns the resolved content owner id so callers can notify + record the
violation.
"""

import logging
import os
from typing import Any, Dict, Optional

from boto3.dynamodb.conditions import Attr, Key

from app.core.aws import ddb
from app.core.tables import T

logger = logging.getLogger(__name__)

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
MESSAGES_TABLE = os.environ.get("DDB_MESSAGES", "Messages")


def _feed_post_owner(post_id: str) -> Optional[str]:
    item = ddb.Table(APP_TABLE).get_item(Key={"pk": f"POST#{post_id}", "sk": "META"}).get("Item") or {}
    return item.get("user_id") if item else None


def _delete_feed_post(post_id: str) -> Optional[str]:
    if not post_id:
        return None
    owner = _feed_post_owner(post_id)
    ddb.Table(APP_TABLE).delete_item(Key={"pk": f"POST#{post_id}", "sk": "META"})
    return owner


def _find_comment_row(post_id: str, comment_id: str) -> Optional[Dict[str, Any]]:
    resp = ddb.Table(APP_TABLE).query(
        KeyConditionExpression=Key("pk").eq(f"POST#{post_id}#COMMENTS"),
        FilterExpression=Attr("comment_id").eq(comment_id),
        Limit=1,
    )
    return (resp.get("Items") or [None])[0]


def _delete_feed_comment(post_id: str, comment_id: str) -> Optional[str]:
    if not post_id or not comment_id:
        return None
    row = _find_comment_row(post_id, comment_id)
    if not row:
        return None
    owner = row.get("user_id")
    ddb.Table(APP_TABLE).delete_item(Key={"pk": row["pk"], "sk": row["sk"]})
    return owner


def _delete_feed_media(post_id: str, media_index: Optional[int]) -> Optional[str]:
    if not post_id:
        return None
    tbl = ddb.Table(APP_TABLE)
    post = tbl.get_item(Key={"pk": f"POST#{post_id}", "sk": "META"}).get("Item") or {}
    if not post:
        return None
    owner = post.get("user_id")
    images = list(post.get("image_urls") or [])
    if media_index is not None and 0 <= int(media_index) < len(images):
        # Delete just the offending media; the rest of the post is restored to visible.
        images.pop(int(media_index))
        tbl.update_item(
            Key={"pk": f"POST#{post_id}", "sk": "META"},
            UpdateExpression=(
                "SET image_urls = :imgs, moderation_hidden = :f, moderation_removed = :f, "
                "moderation_state = :st"
            ),
            ExpressionAttributeValues={":imgs": images, ":f": False, ":st": "deleted"},
        )
    else:
        tbl.delete_item(Key={"pk": f"POST#{post_id}", "sk": "META"})
    return owner


def _delete_message(conversation_id: str, message_id: str) -> Optional[str]:
    if not conversation_id or not message_id:
        return None
    tbl = ddb.Table(MESSAGES_TABLE)
    item = tbl.get_item(Key={"conversation_id": conversation_id, "message_id": message_id}).get("Item") or {}
    if not item:
        return None
    owner = item.get("sender_id")
    tbl.delete_item(Key={"conversation_id": conversation_id, "message_id": message_id})
    return owner


def _delete_video(video_id: str) -> Optional[str]:
    if not video_id:
        return None
    try:
        item = T.video_metadata.get_item(Key={"video_id": video_id}).get("Item") or {}
    except Exception:
        item = {}
    owner = (item or {}).get("owner_sub") or (item or {}).get("user_id") or (item or {}).get("creator_id")
    try:
        T.video_metadata.delete_item(Key={"video_id": video_id})
    except Exception:
        logger.exception("moderation_delete._delete_video failed for %s", video_id)
    return owner


def _delete_video_comment(video_id: str, comment_id: str) -> Optional[str]:
    if not video_id or not comment_id:
        return None
    try:
        from app.services.video_comments import get_comment
        row = get_comment(video_id=video_id, comment_id=comment_id)
    except Exception:
        row = None
    if not row:
        return None
    owner = row.get("user_id")
    T.video_comments.delete_item(Key={"pk": row["pk"], "sk": row["sk"]})
    return owner


def _delete_profile_photo(user_sub: str) -> Optional[str]:
    if not user_sub:
        return None
    item = T.profile.get_item(Key={"user_sub": user_sub}).get("Item") or {}
    profile = dict(item.get("profile") or {})
    profile["profile_photo_url"] = None
    T.profile.put_item(Item={**item, "user_sub": user_sub, "profile": profile})
    return user_sub


def _delete_syndicate_post(syndicate_id: str, post_id: str) -> Optional[str]:
    # MOD-SYND: terminal hard-delete in the syndicate's own store.
    if not syndicate_id or not post_id:
        return None
    key = {"pk": f"SYND#{syndicate_id}", "sk": f"POST#{post_id}"}
    item = T.syndicate_posts.get_item(Key=key).get("Item") or {}
    if not item:
        return None
    owner = item.get("author_id")
    T.syndicate_posts.delete_item(Key=key)
    return owner


def delete_content(*, content_type: str, content_id: str, metadata: Optional[Dict[str, Any]] = None, case_id: Optional[str] = None) -> Optional[str]:
    """Hard-delete content for a terminal moderation case. Returns owner id."""
    md = metadata or {}
    try:
        if content_type == "feed_post":
            return _delete_feed_post(str(md.get("post_id") or content_id))
        if content_type == "feed_comment":
            return _delete_feed_comment(str(md.get("post_id") or ""), content_id)
        if content_type == "feed_media":
            mi = md.get("media_index")
            return _delete_feed_media(str(md.get("post_id") or content_id), int(mi) if mi is not None else None)
        if content_type in ("message", "message_media"):
            return _delete_message(str(md.get("conversation_id") or ""), content_id)
        if content_type == "video":
            return _delete_video(str(md.get("video_id") or content_id))
        if content_type == "video_comment":
            return _delete_video_comment(str(md.get("video_id") or ""), content_id)
        if content_type == "syndicate_post":
            return _delete_syndicate_post(str(md.get("syndicate_id") or ""), str(md.get("post_id") or content_id))
        if content_type == "profile_photo":
            return _delete_profile_photo(content_id)
    except Exception:
        logger.exception("moderation_delete.delete_content failed for %s/%s", content_type, content_id)
        return None
    logger.warning("moderation_delete: unsupported content_type %s", content_type)
    return None
