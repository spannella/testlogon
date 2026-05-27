"""DMCA content hiding/restoration operations (MOD-002)."""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional, Tuple

from app.core.aws import ddb
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)
APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")


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

    Returns ("other", "") if not resolvable.
    """
    url = content_url.strip().rstrip("/")
    parts = [p for p in url.split("/") if p]

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
        else:
            logger.warning("Unsupported content_type for DMCA hiding: %s", content_type)
    except Exception:
        logger.exception(
            "Failed to hide content type=%s id=%s for DMCA claim %s",
            content_type, content_id, claim_id,
        )
    return snapshot


def restore_content_after_dmca(*, claim: Dict[str, Any]) -> None:
    """Restore content when claim is resolved in creator's favor."""
    content_type = claim.get("content_type", "")
    content_id = claim.get("content_id", "")
    snapshot = claim.get("content_snapshot") or {}

    try:
        if content_type == "video":
            _restore_video(content_id, snapshot)
        elif content_type in ("feed_post", "feed_media"):
            _restore_feed_content(content_type, content_id)
        elif content_type == "message_media":
            _restore_message(content_id)
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
# Message media (stub -- no DDB message-level DMCA flag yet)
# ---------------------------------------------------------------------------

def _hide_message(content_id: str, claim_id: str) -> Dict[str, Any]:
    return {}


def _restore_message(content_id: str) -> None:
    pass
