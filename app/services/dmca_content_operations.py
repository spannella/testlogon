"""DMCA content hiding/restoration operations (MOD-002).

MOD-6: coverage extended beyond feed_post/feed_media/video/syndicate_post to
``message_media`` and (feed / video) ``comment``. Those surfaces are hidden +
restored NON-DESTRUCTIVELY by delegating to ``moderation_hide`` (the same intact-row
flag writer the moderation state-machine uses), so a licensing/DMCA claim on a DM
attachment or a comment actually hides it and a favourable resolution restores it
byte-for-byte. For message_media / comment the ``content_id`` is a composite that
carries the parent key: ``conversation_id|message_id`` (message_media),
``post_id|comment_id`` (comment) or ``video_id|comment_id`` (video_comment).
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional, Tuple

from app.core.aws import ddb
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)
APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
MESSAGES_TABLE = os.environ.get("DDB_MESSAGES", "Messages")


def _dmca_case_id(claim_id: str) -> str:
    """Namespaced moderation case id so a DMCA hide never collides with a real
    moderation case id and restore can prove DMCA still owns the hide."""
    return "dmca:%s" % (claim_id or "")


def _split_parent_child(content_id: str) -> Tuple[str, str]:
    """Parse a composite content_id ``parent<sep>child`` (sep = '|' preferred,
    ':' accepted). Returns ("", content_id) when no separator is present."""
    cid = str(content_id or "")
    for sep in ("|", ":"):
        if sep in cid:
            parent, _, child = cid.partition(sep)
            return parent.strip(), child.strip()
    return "", cid


def resolve_content_owner(content_type: str, content_id: str) -> str:
    """Look up the owner user_id for a piece of content. Returns "" if unknown."""
    if not content_id:
        return ""
    try:
        if content_type in ("feed_post", "feed_media"):
            tbl = ddb.Table(APP_TABLE)
            pk = f"POST#{content_id}" if content_type == "feed_post" else f"MEDIA#{content_id}"
            item = tbl.get_item(Key={"pk": pk, "sk": "META"}).get("Item", {})
            return str(item.get("user_id") or "")
        if content_type == "video":
            item = T.video_metadata.get_item(Key={"video_id": content_id}).get("Item")
            if item:
                return str(item.get("user_id") or item.get("owner_id") or "")
        if content_type in ("message_media", "comment", "video_comment"):
            # MOD-6: owner is resolved non-destructively by moderation_hide.
            from app.services import moderation_hide
            parent, child = _split_parent_child(content_id)
            if content_type == "message_media":
                return str(moderation_hide.resolve_owner(
                    content_type="message", content_id=child,
                    metadata={"conversation_id": parent}) or "")
            if content_type == "comment":
                return str(moderation_hide.resolve_owner(
                    content_type="feed_comment", content_id=child,
                    metadata={"post_id": parent}) or "")
            if content_type == "video_comment":
                return str(moderation_hide.resolve_owner(
                    content_type="video_comment", content_id=child,
                    metadata={"video_id": parent}) or "")
    except Exception:
        logger.exception("Failed to resolve content owner for %s/%s", content_type, content_id)
    return ""


def resolve_content_from_url(content_url: str) -> Tuple[str, str]:
    """Parse a content URL/path to extract content_type and content_id.

    Supports formats:
    - /feed/post/<id> or /posts/<id> -> ("feed_post", id)
    - /videos/<id> -> ("video", id)
    - /feed/media/<id> -> ("feed_media", id)
    - /messages/media/<id> -> ("message_media", id)
    - /posts/<post_id>/comments/<comment_id> -> ("comment", "<post_id>|<comment_id>")
    - /videos/<video_id>/comments/<comment_id> -> ("video_comment", "<video_id>|<comment_id>")

    Returns ("other", "") if not resolvable.
    """
    url = content_url.strip().rstrip("/")
    parts = [p for p in url.split("/") if p]

    # MOD-6: comment URLs (.../<parent>/comments/<comment_id>)
    if len(parts) >= 4 and parts[-2] == "comments":
        parent_kind = parts[-4]
        parent_id = parts[-3]
        comment_id = parts[-1]
        if parent_kind in ("post", "posts", "feed"):
            return "comment", f"{parent_id}|{comment_id}"
        if parent_kind in ("videos", "video"):
            return "video_comment", f"{parent_id}|{comment_id}"

    if len(parts) >= 2:
        if parts[-2] in ("post", "posts"):
            return "feed_post", parts[-1]
        if parts[-2] == "videos":
            return "video", parts[-1]
        if parts[-2] == "media" and len(parts) >= 3:
            if parts[-3] == "feed":
                return "feed_media", parts[-1]
            if parts[-3] in ("messages", "message"):
                return "message_media", parts[-1]
    if len(parts) >= 1 and parts[0] == "videos":
        return "video", parts[-1]

    return "other", ""


def hide_content_for_dmca(*, claim_id: str, content_type: str, content_id: str) -> Dict[str, Any]:
    """Hide content immediately upon DMCA claim. Returns pre-removal snapshot."""
    snapshot: Dict[str, Any] = {}
    if not content_id:
        return snapshot

    try:
        if content_type == "video":
            snapshot = _hide_video(content_id, claim_id)
        elif content_type in ("feed_post", "feed_media"):
            snapshot = _hide_feed_content(content_type, content_id, claim_id)
        elif content_type == "message_media":
            snapshot = _hide_message(content_id, claim_id)
        elif content_type in ("comment", "video_comment"):
            snapshot = _hide_comment(content_type, content_id, claim_id)
        else:
            logger.warning("Unsupported content_type for DMCA hiding: %s", content_type)
    except Exception:
        logger.exception(
            "Failed to hide content type=%s id=%s for DMCA claim %s",
            content_type, content_id, claim_id,
        )
    return snapshot


def restore_content_after_dmca(*, claim: Dict[str, Any]) -> None:
    """Restore content when claim is resolved in creator's favor. NON-DESTRUCTIVE."""
    content_type = claim.get("content_type", "")
    content_id = claim.get("content_id", "")
    claim_id = str(claim.get("claim_id", ""))
    snapshot = claim.get("content_snapshot") or {}

    try:
        if content_type == "video":
            _restore_video(content_id, snapshot)
        elif content_type in ("feed_post", "feed_media"):
            _restore_feed_content(content_type, content_id)
        elif content_type == "message_media":
            _restore_message(content_id, claim_id, snapshot)
        elif content_type in ("comment", "video_comment"):
            _restore_comment(content_type, content_id, claim_id, snapshot)
    except Exception:
        logger.exception("Failed to restore content type=%s id=%s", content_type, content_id)


# ---------------------------------------------------------------------------
# Video
# ---------------------------------------------------------------------------

def _hide_video(video_id: str, claim_id: str) -> Dict[str, Any]:
    item = T.video_metadata.get_item(Key={"video_id": video_id}).get("Item")
    if not item:
        return {}
    original_status = str(item.get("status", ""))
    snapshot = {"original_status": original_status, "video_id": video_id}
    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET dmca_hidden = :t, dmca_claim_id = :claim, "
                         "dmca_hidden_at = :ts, dmca_original_status = :orig, "
                         "#status = :hidden, updated_at = :ts",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":t": True, ":claim": claim_id, ":ts": now_ts(),
            ":orig": original_status, ":hidden": "deleted",
        },
    )
    return snapshot


def _restore_video(video_id: str, snapshot: Optional[Dict] = None) -> None:
    original_status = (snapshot or {}).get("original_status", "approved")
    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET dmca_hidden = :f, #status = :orig, updated_at = :ts "
                         "REMOVE dmca_claim_id, dmca_hidden_at, dmca_original_status",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":f": False, ":orig": original_status, ":ts": now_ts()},
    )


# ---------------------------------------------------------------------------
# Feed (posts / media)
# ---------------------------------------------------------------------------

def _hide_feed_content(content_type: str, content_id: str, claim_id: str) -> Dict[str, Any]:
    tbl = ddb.Table(APP_TABLE)
    pk = f"POST#{content_id}" if content_type == "feed_post" else f"MEDIA#{content_id}"
    sk = "META"
    item = tbl.get_item(Key={"pk": pk, "sk": sk}).get("Item", {})
    snapshot = {k: v for k, v in item.items() if k in ("pk", "sk", "status", "visibility")}
    tbl.update_item(
        Key={"pk": pk, "sk": sk},
        UpdateExpression="SET dmca_hidden = :t, dmca_claim_id = :claim, "
                         "dmca_hidden_at = :ts, updated_at = :ts",
        ExpressionAttributeValues={":t": True, ":claim": claim_id, ":ts": now_ts()},
    )
    return snapshot


def _restore_feed_content(content_type: str, content_id: str) -> None:
    tbl = ddb.Table(APP_TABLE)
    pk = f"POST#{content_id}" if content_type == "feed_post" else f"MEDIA#{content_id}"
    tbl.update_item(
        Key={"pk": pk, "sk": "META"},
        UpdateExpression="SET dmca_hidden = :f, updated_at = :ts "
                         "REMOVE dmca_claim_id, dmca_hidden_at",
        ExpressionAttributeValues={":f": False, ":ts": now_ts()},
    )


# ---------------------------------------------------------------------------
# Message media (MOD-6) -- non-destructive hide via moderation_hide flags, which
# the messaging read path (_filter_message_visible + MOD-2 placeholder) already
# respects. The intact message row (text + attachments) is never mutated.
# ---------------------------------------------------------------------------

def _read_message_flags(conversation_id: str, message_id: str) -> Dict[str, Any]:
    try:
        item = ddb.Table(MESSAGES_TABLE).get_item(
            Key={"conversation_id": conversation_id, "message_id": message_id}
        ).get("Item") or {}
    except Exception:
        item = {}
    return {
        "exists": bool(item),
        "moderation_hidden": bool(item.get("moderation_hidden")),
        "moderation_case_id": str(item.get("moderation_case_id") or ""),
    }


def _hide_message(content_id: str, claim_id: str) -> Dict[str, Any]:
    conversation_id, message_id = _split_parent_child(content_id)
    if not conversation_id or not message_id:
        logger.warning("DMCA message hide needs 'conversation_id|message_id'; got %r", content_id)
        return {}
    prior = _read_message_flags(conversation_id, message_id)
    if not prior["exists"]:
        return {}
    from app.services import moderation_hide
    owner = moderation_hide.hide_content(
        content_type="message", content_id=message_id,
        metadata={"conversation_id": conversation_id},
        case_id=_dmca_case_id(claim_id), state="dmca_removed",
    )
    return {
        "conversation_id": conversation_id,
        "message_id": message_id,
        "owner": str(owner or ""),
        "prior_hidden": prior["moderation_hidden"],
        "prior_case_id": prior["moderation_case_id"],
    }


def _restore_message(content_id: str, claim_id: str, snapshot: Optional[Dict] = None) -> None:
    snapshot = snapshot or {}
    conversation_id = str(snapshot.get("conversation_id") or "")
    message_id = str(snapshot.get("message_id") or "")
    if not conversation_id or not message_id:
        conversation_id, message_id = _split_parent_child(content_id)
    if not conversation_id or not message_id:
        return
    # NON-DESTRUCTIVE: if the message was already hidden by something else BEFORE
    # the DMCA claim, leave it hidden; only clear the flags when the current hide
    # is still the DMCA hide (case ownership) so a later moderation hide is never
    # clobbered.
    if snapshot.get("prior_hidden"):
        return
    cur = _read_message_flags(conversation_id, message_id)
    if cur.get("moderation_case_id") and cur["moderation_case_id"] != _dmca_case_id(claim_id):
        return
    from app.services import moderation_hide
    moderation_hide.unhide_content(
        content_type="message", content_id=message_id,
        metadata={"conversation_id": conversation_id},
        case_id=_dmca_case_id(claim_id), state="visible",
    )


# ---------------------------------------------------------------------------
# Comment (MOD-6) -- feed comment + video comment, non-destructive via moderation_hide.
# ---------------------------------------------------------------------------

def _read_comment_flags(content_type: str, parent: str, comment_id: str) -> Dict[str, Any]:
    from app.services import moderation_hide
    row: Optional[Dict[str, Any]] = None
    try:
        if content_type == "comment":
            row = moderation_hide._find_comment_row(parent, comment_id)
        else:  # video_comment
            from app.services.video_comments import get_comment
            try:
                row = get_comment(video_id=parent, comment_id=comment_id)
            except TypeError:
                row = get_comment(parent, comment_id)
    except Exception:
        row = None
    row = row or {}
    return {
        "exists": bool(row),
        "moderation_hidden": bool(row.get("moderation_hidden")),
        "moderation_case_id": str(row.get("moderation_case_id") or ""),
    }


def _hide_comment(content_type: str, content_id: str, claim_id: str) -> Dict[str, Any]:
    parent, comment_id = _split_parent_child(content_id)
    if not parent or not comment_id:
        logger.warning("DMCA comment hide needs 'parent_id|comment_id'; got %r", content_id)
        return {}
    prior = _read_comment_flags(content_type, parent, comment_id)
    if not prior["exists"]:
        return {}
    from app.services import moderation_hide
    if content_type == "comment":
        owner = moderation_hide.hide_content(
            content_type="feed_comment", content_id=comment_id,
            metadata={"post_id": parent}, case_id=_dmca_case_id(claim_id), state="dmca_removed")
    else:  # video_comment
        owner = moderation_hide.hide_content(
            content_type="video_comment", content_id=comment_id,
            metadata={"video_id": parent}, case_id=_dmca_case_id(claim_id), state="dmca_removed")
    return {
        "parent_id": parent,
        "comment_id": comment_id,
        "owner": str(owner or ""),
        "prior_hidden": prior["moderation_hidden"],
        "prior_case_id": prior["moderation_case_id"],
    }


def _restore_comment(content_type: str, content_id: str, claim_id: str, snapshot: Optional[Dict] = None) -> None:
    snapshot = snapshot or {}
    parent = str(snapshot.get("parent_id") or "")
    comment_id = str(snapshot.get("comment_id") or "")
    if not parent or not comment_id:
        parent, comment_id = _split_parent_child(content_id)
    if not parent or not comment_id:
        return
    if snapshot.get("prior_hidden"):
        return
    cur = _read_comment_flags(content_type, parent, comment_id)
    if cur.get("moderation_case_id") and cur["moderation_case_id"] != _dmca_case_id(claim_id):
        return
    from app.services import moderation_hide
    if content_type == "comment":
        moderation_hide.unhide_content(
            content_type="feed_comment", content_id=comment_id,
            metadata={"post_id": parent}, case_id=_dmca_case_id(claim_id), state="visible")
    else:  # video_comment
        moderation_hide.unhide_content(
            content_type="video_comment", content_id=comment_id,
            metadata={"video_id": parent}, case_id=_dmca_case_id(claim_id), state="visible")
