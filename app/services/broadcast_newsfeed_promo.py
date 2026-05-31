"""BCAST-010 — Broadcast Newsfeed Promotion service.

Wires the broadcast subsystem (``app.services.broadcast_store``) together with
the newsfeed (``app.routers.newsfeed`` storage + ``app.services.newsfeed_fanout``).

Promoting a broadcast creates a real newsfeed post that links back to the
broadcast and records a link row in the ``broadcast_promo_posts`` table. The
link row tracks the post id, owner, promotion time and the last broadcast
status it was synced to, so the promoted post can be auto-synced when the
broadcast goes live / ends, and unpromoted.

This module deliberately reuses the existing broadcast + newsfeed primitives
rather than re-implementing either subsystem.
"""
from __future__ import annotations

import logging
from typing import Optional

from app.core.tables import T
from app.core.time import now_ts
from app.models import BroadcastPromoLink, BroadcastPromoLiveItem
from app.services import broadcast_store

logger = logging.getLogger(__name__)


# ─── Link table helpers ───────────────────────────────────────────

def _key(broadcast_id: str) -> dict:
    return {"broadcast_id": broadcast_id}


def _to_link(item: dict) -> BroadcastPromoLink:
    return BroadcastPromoLink(
        broadcast_id=item["broadcast_id"],
        post_id=item.get("post_id", ""),
        owner_user_id=item.get("owner_user_id", ""),
        promoted_at=int(item.get("promoted_at", 0)),
        last_synced_status=item.get("last_synced_status", "idle"),
        removed=bool(item.get("removed", False)),
    )


def get_link(broadcast_id: str) -> Optional[BroadcastPromoLink]:
    res = T.broadcast_promo_posts.get_item(Key=_key(broadcast_id))
    item = res.get("Item")
    if not item:
        return None
    return _to_link(item)


def _save_link(
    *,
    broadcast_id: str,
    post_id: str,
    owner_user_id: str,
    promoted_at: int,
    last_synced_status: str,
    removed: bool,
) -> BroadcastPromoLink:
    item = {
        "broadcast_id": broadcast_id,
        "post_id": post_id,
        "owner_user_id": owner_user_id,
        "promoted_at": promoted_at,
        "last_synced_status": last_synced_status,
        "removed": removed,
    }
    T.broadcast_promo_posts.put_item(Item=item)
    return _to_link(item)


# ─── Broadcast helpers ────────────────────────────────────────────

def _get_session(broadcast_id: str):
    """Return the broadcast session model or ``None`` if it does not exist."""
    try:
        return broadcast_store.get_session(broadcast_id)
    except Exception:
        return None


def _session_title(session) -> str:
    return (getattr(session, "name", None) or f"Broadcast {getattr(session, 'id', '')}").strip()


def _post_body(title: str, status: str, broadcast_id: str) -> str:
    """Render the deterministic newsfeed post body for a broadcast status."""
    link = f"/broadcast/{broadcast_id}"
    if status == "live":
        return f"🔴 LIVE NOW: {title} — watch the broadcast: {link}"
    if status in ("stopped", "ended", "stopping"):
        return f"⏹ Broadcast ended: {title} (replay) — {link}"
    return f"Broadcast promoted: {title} — {link}"


def _broadcast_meta(session, broadcast_id: str, status: str) -> dict:
    return {
        "session_id": broadcast_id,
        "post_type": "broadcast_live" if status == "live" else "broadcast_announcement",
        "session_name": _session_title(session),
        "session_description": getattr(session, "description", None),
        "thumbnail_url": getattr(session, "thumbnail_url", None),
        "is_live": status == "live",
        "broadcast_status": status,
        "broadcast_url": f"/broadcast/{broadcast_id}",
    }


# ─── Newsfeed post write/update/delete (reuses newsfeed storage) ───

def _create_newsfeed_post(*, owner_user_id: str, body: str, meta: dict) -> str:
    """Create a real newsfeed post and fan it out. Returns the post id."""
    from app.routers import newsfeed as nf

    post_id = nf.new_id("post")
    created_at = nf.now_iso()
    post_type = meta.get("post_type", "broadcast_announcement")
    item = {
        "pk": nf.pk_post(post_id),
        "sk": nf.sk_post(),
        "entity_type": "post",
        "post_id": post_id,
        "user_id": owner_user_id,
        "author_id": owner_user_id,
        "body": body,
        "body_plain": body,
        "body_format": "plain",
        "body_version": 1,
        "visibility": "public",
        "status": "published",
        "post_type": post_type,
        "broadcast_meta": meta,
        "like_count": 0,
        "comment_count": 0,
        "tip_total_cents": 0,
        "reactions": {},
        "created_at": created_at,
        "updated_at": created_at,
        # Author index (so the post is discoverable on the author's profile/feed).
        "GSI1PK": f"FEED#{owner_user_id}",
        "GSI1SK": f"{created_at}#POST#{post_id}",
        "GSI2PK": f"POST_AUTHOR#{owner_user_id}",
        "GSI2SK": f"{created_at}#POST#{post_id}",
    }
    nf.tbl.put_item(Item=item)
    # Fan out to followers (SOC-002). Best effort — non-fatal.
    try:
        from app.services.newsfeed_fanout import fan_out_post_to_followers

        fan_out_post_to_followers(owner_user_id, post_id, created_at)
    except Exception:
        logger.exception("broadcast promo fan-out failed for post %s", post_id)
    return post_id


def _update_newsfeed_post(*, post_id: str, body: str, meta: dict) -> None:
    from app.routers import newsfeed as nf

    nf.tbl.update_item(
        Key={"pk": nf.pk_post(post_id), "sk": nf.sk_post()},
        UpdateExpression="SET #b = :b, body_plain = :b, broadcast_meta = :m, post_type = :pt, updated_at = :u",
        ExpressionAttributeNames={"#b": "body"},
        ExpressionAttributeValues={
            ":b": body,
            ":m": meta,
            ":pt": meta.get("post_type", "broadcast_announcement"),
            ":u": nf.now_iso(),
        },
    )


def _delete_newsfeed_post(post_id: str) -> None:
    from app.routers import newsfeed as nf

    nf.tbl.delete_item(Key={"pk": nf.pk_post(post_id), "sk": nf.sk_post()})
    try:
        from app.services.newsfeed_fanout import fan_out_unpublish_post

        fan_out_unpublish_post(post_id)
    except Exception:
        logger.exception("broadcast promo fan-out delete failed for post %s", post_id)


# ─── Public API ───────────────────────────────────────────────────

def promote(broadcast_id: str, owner_user_id: str) -> BroadcastPromoLink:
    """Promote a broadcast to the newsfeed.

    Idempotent: if already promoted (and not removed) the existing post is
    updated and re-synced to the current status instead of duplicating. The
    caller is responsible for verifying ownership.
    """
    session = _get_session(broadcast_id)
    if session is None:
        raise ValueError("broadcast not found")

    status = session.status
    title = _session_title(session)
    body = _post_body(title, status, broadcast_id)
    meta = _broadcast_meta(session, broadcast_id, status)

    existing = get_link(broadcast_id)
    if existing is not None and not existing.removed and existing.post_id:
        _update_newsfeed_post(post_id=existing.post_id, body=body, meta=meta)
        return _save_link(
            broadcast_id=broadcast_id,
            post_id=existing.post_id,
            owner_user_id=existing.owner_user_id,
            promoted_at=existing.promoted_at,
            last_synced_status=status,
            removed=False,
        )

    post_id = _create_newsfeed_post(owner_user_id=owner_user_id, body=body, meta=meta)
    return _save_link(
        broadcast_id=broadcast_id,
        post_id=post_id,
        owner_user_id=owner_user_id,
        promoted_at=now_ts(),
        last_synced_status=status,
        removed=False,
    )


def sync(broadcast_id: str) -> Optional[BroadcastPromoLink]:
    """Re-sync the promoted post to the broadcast's current status.

    Returns ``None`` if the broadcast is not (actively) promoted.
    """
    link = get_link(broadcast_id)
    if link is None or link.removed or not link.post_id:
        return None
    session = _get_session(broadcast_id)
    if session is None:
        return None
    status = session.status
    title = _session_title(session)
    body = _post_body(title, status, broadcast_id)
    meta = _broadcast_meta(session, broadcast_id, status)
    _update_newsfeed_post(post_id=link.post_id, body=body, meta=meta)
    return _save_link(
        broadcast_id=broadcast_id,
        post_id=link.post_id,
        owner_user_id=link.owner_user_id,
        promoted_at=link.promoted_at,
        last_synced_status=status,
        removed=False,
    )


def unpromote(broadcast_id: str) -> bool:
    """Remove the promotion: mark the link removed and delete the post.

    Returns ``True`` if a link existed and was removed, ``False`` otherwise.
    """
    link = get_link(broadcast_id)
    if link is None or link.removed:
        return False
    if link.post_id:
        try:
            _delete_newsfeed_post(link.post_id)
        except Exception:
            logger.exception("broadcast promo post delete failed for %s", link.post_id)
    _save_link(
        broadcast_id=broadcast_id,
        post_id=link.post_id,
        owner_user_id=link.owner_user_id,
        promoted_at=link.promoted_at,
        last_synced_status=link.last_synced_status,
        removed=True,
    )
    return True


def list_live() -> list[BroadcastPromoLiveItem]:
    """List currently-live promoted broadcasts, newest first.

    Scans the small link table and joins against broadcast status in code
    (kept simple + deterministic for E2E).
    """
    res = T.broadcast_promo_posts.scan()
    items = res.get("Items", [])
    out: list[BroadcastPromoLiveItem] = []
    for it in items:
        if bool(it.get("removed", False)):
            continue
        broadcast_id = it.get("broadcast_id")
        if not broadcast_id:
            continue
        session = _get_session(broadcast_id)
        if session is None or session.status != "live":
            continue
        out.append(
            BroadcastPromoLiveItem(
                broadcast_id=broadcast_id,
                post_id=it.get("post_id", ""),
                title=_session_title(session),
                owner_user_id=it.get("owner_user_id", ""),
                promoted_at=int(it.get("promoted_at", 0)),
            )
        )
    out.sort(key=lambda i: i.promoted_at, reverse=True)
    return out
