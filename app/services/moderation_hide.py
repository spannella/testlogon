from __future__ import annotations

"""MOD-A2: NON-DESTRUCTIVE, owner-aware hide primitive for every reportable surface.

Hiding NEVER nulls a body. It writes flags over the intact row so a later
reinstate restores the content byte-for-byte:
  - moderation_hidden          (bool)   the surface-agnostic hidden flag
  - moderation_removed         (bool)   back-compat flag the existing read filters honor
  - moderation_case_id         (str)    link back to the moderation_case
  - moderation_hidden_at       (iso)
  - moderation_state           (str)    mirror of the case state (e.g. under_review)

``hide_content`` also RESOLVES + returns the content owner so callers can notify
the poster. ``unhide_content`` clears the flags (the inverse). Hard delete lives
in the admin final-call path (MOD-A4), never here.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from boto3.dynamodb.conditions import Attr, Key

from app.core.aws import ddb
from app.core.tables import T

logger = logging.getLogger(__name__)

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
MESSAGES_TABLE = os.environ.get("DDB_MESSAGES", "Messages")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── shared hidden-for-viewer predicate (owner + admin always see) ────────────
def is_hidden_flag(item: Dict[str, Any]) -> bool:
    return bool(item.get("moderation_hidden") or item.get("moderation_removed") or item.get("moderation_removed_at"))


def is_hidden_for_viewer(item: Dict[str, Any], viewer_id: Optional[str], owner_field: str = "user_id") -> bool:
    """True when this content should be HIDDEN from ``viewer_id``.

    Non-destructive hide: the owner (and admins, handled at the board) always
    see their own hidden content so they can respond; everyone else does not.
    """
    if not is_hidden_flag(item):
        return False
    owner = item.get(owner_field)
    if viewer_id and owner and str(owner) == str(viewer_id):
        return False
    return True


# ── per-surface non-destructive flag writers ────────────────────────────────
def _flag_values(case_id: str, state: str, hidden: bool) -> Dict[str, Any]:
    if hidden:
        return {
            ":hidden": True,
            ":removed": True,
            ":case": case_id,
            ":state": state,
            ":ts": _now_iso(),
        }
    return {
        ":hidden": False,
        ":removed": False,
        ":case": case_id,
        ":state": state,
        ":ts": _now_iso(),
    }


_SET_EXPR = (
    "SET moderation_hidden = :hidden, moderation_removed = :removed, "
    "moderation_case_id = :case, moderation_state = :state, moderation_hidden_at = :ts"
)


def _feed_post_owner(post_id: str) -> Optional[str]:
    item = ddb.Table(APP_TABLE).get_item(Key={"pk": f"POST#{post_id}", "sk": "META"}).get("Item") or {}
    return item.get("user_id") if item else None


def _hide_feed_post(*, post_id: str, case_id: str, state: str, hidden: bool) -> Optional[str]:
    if not post_id:
        return None
    owner = _feed_post_owner(post_id)
    ddb.Table(APP_TABLE).update_item(
        Key={"pk": f"POST#{post_id}", "sk": "META"},
        UpdateExpression=_SET_EXPR,
        ExpressionAttributeValues=_flag_values(case_id, state, hidden),
    )
    return owner


def _find_comment_row(post_id: str, comment_id: str) -> Optional[Dict[str, Any]]:
    resp = ddb.Table(APP_TABLE).query(
        KeyConditionExpression=Key("pk").eq(f"POST#{post_id}#COMMENTS"),
        FilterExpression=Attr("comment_id").eq(comment_id),
        Limit=1,
    )
    return (resp.get("Items") or [None])[0]


def _hide_feed_comment(*, post_id: str, comment_id: str, case_id: str, state: str, hidden: bool) -> Optional[str]:
    if not post_id or not comment_id:
        return None
    row = _find_comment_row(post_id, comment_id)
    if not row:
        return None
    # NON-DESTRUCTIVE: only flags are written; body / body_* / deleted are untouched.
    ddb.Table(APP_TABLE).update_item(
        Key={"pk": row["pk"], "sk": row["sk"]},
        UpdateExpression=_SET_EXPR,
        ExpressionAttributeValues=_flag_values(case_id, state, hidden),
    )
    return row.get("user_id")


def _hide_feed_media(*, post_id: str, case_id: str, state: str, hidden: bool) -> Optional[str]:
    # Non-destructive: flag the post; image_urls is NOT mutated (unlike the legacy
    # destructive removal). The media_index is retained on the case for the final call.
    return _hide_feed_post(post_id=post_id, case_id=case_id, state=state, hidden=hidden)


def _hide_message(*, conversation_id: str, message_id: str, case_id: str, state: str, hidden: bool) -> Optional[str]:
    if not conversation_id or not message_id:
        return None
    table = ddb.Table(MESSAGES_TABLE)
    item = table.get_item(Key={"conversation_id": conversation_id, "message_id": message_id}).get("Item") or {}
    if not item:
        return None
    # NON-DESTRUCTIVE: keep text + attachments intact; only write flags.
    ts_epoch = int(datetime.now(timezone.utc).timestamp())
    vals = _flag_values(case_id, state, hidden)
    vals[":ts"] = ts_epoch  # message rows use epoch timestamps
    table.update_item(
        Key={"conversation_id": conversation_id, "message_id": message_id},
        UpdateExpression=_SET_EXPR,
        ExpressionAttributeValues=vals,
    )
    return item.get("sender_id")


def _hide_video(*, video_id: str, case_id: str, state: str, hidden: bool) -> Optional[str]:
    if not video_id:
        return None
    try:
        item = T.video_metadata.get_item(Key={"video_id": video_id}).get("Item") or {}
    except Exception:
        item = {}
    try:
        T.video_metadata.update_item(
            Key={"video_id": video_id},
            UpdateExpression=_SET_EXPR,
            ExpressionAttributeValues=_flag_values(case_id, state, hidden),
        )
    except Exception:
        logger.exception("moderation_hide._hide_video failed for %s", video_id)
    return (item or {}).get("owner_sub") or (item or {}).get("user_id") or (item or {}).get("creator_id")


def _hide_video_comment(*, video_id: str, comment_id: str, case_id: str, state: str, hidden: bool) -> Optional[str]:
    if not video_id or not comment_id:
        return None
    try:
        from app.services.video_comments import get_comment
        row = get_comment(video_id=video_id, comment_id=comment_id)
    except TypeError:
        from app.services.video_comments import get_comment
        row = get_comment(video_id, comment_id)
    except Exception:
        row = None
    if not row:
        return None
    T.video_comments.update_item(
        Key={"pk": row["pk"], "sk": row["sk"]},
        UpdateExpression=_SET_EXPR,
        ExpressionAttributeValues=_flag_values(case_id, state, hidden),
    )
    return row.get("user_id")


def _apply(*, content_type: str, content_id: str, metadata: Dict[str, Any], case_id: str, state: str, hidden: bool) -> Optional[str]:
    md = metadata or {}
    if content_type == "feed_post":
        post_id = str(md.get("post_id") or content_id)
        return _hide_feed_post(post_id=post_id, case_id=case_id, state=state, hidden=hidden)
    if content_type == "feed_comment":
        return _hide_feed_comment(post_id=str(md.get("post_id") or ""), comment_id=content_id, case_id=case_id, state=state, hidden=hidden)
    if content_type == "feed_media":
        return _hide_feed_media(post_id=str(md.get("post_id") or content_id), case_id=case_id, state=state, hidden=hidden)
    if content_type in ("message", "message_media"):
        return _hide_message(conversation_id=str(md.get("conversation_id") or ""), message_id=content_id, case_id=case_id, state=state, hidden=hidden)
    if content_type == "video":
        return _hide_video(video_id=str(md.get("video_id") or content_id), case_id=case_id, state=state, hidden=hidden)
    if content_type == "video_comment":
        return _hide_video_comment(video_id=str(md.get("video_id") or ""), comment_id=content_id, case_id=case_id, state=state, hidden=hidden)
    if content_type == "profile_photo":
        # Profile photos already have a dedicated non-destructive revert path; no flag write here.
        return content_id
    logger.warning("moderation_hide: unsupported content_type %s", content_type)
    return None


def hide_content(*, content_type: str, content_id: str, metadata: Optional[Dict[str, Any]], case_id: str, state: str = "under_review") -> Optional[str]:
    """Hide content non-destructively. Returns the resolved content owner id (or None)."""
    return _apply(content_type=content_type, content_id=content_id, metadata=metadata or {}, case_id=case_id, state=state, hidden=True)


def unhide_content(*, content_type: str, content_id: str, metadata: Optional[Dict[str, Any]], case_id: str, state: str = "visible") -> Optional[str]:
    """Reverse of hide_content: clears the flags, restoring the intact content."""
    return _apply(content_type=content_type, content_id=content_id, metadata=metadata or {}, case_id=case_id, state=state, hidden=False)


def resolve_owner(*, content_type: str, content_id: str, metadata: Optional[Dict[str, Any]]) -> Optional[str]:
    """Resolve the content owner WITHOUT mutating anything (for notify-only paths)."""
    md = metadata or {}
    try:
        if content_type == "feed_post":
            return _feed_post_owner(str(md.get("post_id") or content_id))
        if content_type in ("feed_media",):
            return _feed_post_owner(str(md.get("post_id") or content_id))
        if content_type == "feed_comment":
            row = _find_comment_row(str(md.get("post_id") or ""), content_id)
            return (row or {}).get("user_id")
        if content_type in ("message", "message_media"):
            item = ddb.Table(MESSAGES_TABLE).get_item(
                Key={"conversation_id": str(md.get("conversation_id") or ""), "message_id": content_id}
            ).get("Item") or {}
            return item.get("sender_id")
    except Exception:
        logger.exception("moderation_hide.resolve_owner failed")
    return None
