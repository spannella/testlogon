"""Broadcast Go-Private (visibility + allowlist) service — BCAST-011.

This is the *visibility / access-gating* flavour of "Go Private": a broadcaster
can switch a live session between ``public`` / ``unlisted`` / ``private`` and, when
private, maintain an allowlist of permitted viewers plus invite tokens. Viewer
join/playback is gated against this state.

NOTE: distinct from the existing 1-on-1 paid-call ``broadcast_private.py`` service.
That feature spins up a WebRTC call; this one controls *who can watch the stream*.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger("broadcast.privacy")

VALID_VISIBILITIES = ("public", "unlisted", "private")


def _pk(session_id: str) -> str:
    return f"BCAST#{session_id}"


def _allow_sk(viewer_id: str) -> str:
    return f"ALLOW#{viewer_id}"


def _token_sk(token: str) -> str:
    return f"TOKEN#{token}"


# ─── Allowlist management ───────────────────────────────────────────


def add_to_allowlist(session_id: str, viewer_id: str, *, added_by: str) -> Dict[str, Any]:
    """Add a viewer to the session allowlist. Idempotent."""
    viewer_id = (viewer_id or "").strip()
    if not viewer_id:
        raise HTTPException(status_code=400, detail="viewer_id is required.")
    ts = now_ts()
    item = {
        "pk": _pk(session_id),
        "sk": _allow_sk(viewer_id),
        "kind": "allow",
        "session_id": session_id,
        "viewer_id": viewer_id,
        "added_by": added_by,
        "created_at": ts,
    }
    T.broadcast_allowlist.put_item(Item=item)
    logger.info("broadcast.privacy.allow_add session=%s viewer=%s", session_id, viewer_id)
    return {"session_id": session_id, "viewer_id": viewer_id, "created_at": ts}


def remove_from_allowlist(session_id: str, viewer_id: str) -> bool:
    """Remove a viewer from the allowlist. Returns True if an entry existed."""
    key = {"pk": _pk(session_id), "sk": _allow_sk(viewer_id)}
    existing = T.broadcast_allowlist.get_item(Key=key).get("Item")
    if not existing:
        return False
    T.broadcast_allowlist.delete_item(Key=key)
    logger.info("broadcast.privacy.allow_remove session=%s viewer=%s", session_id, viewer_id)
    return True


def list_allowlist(session_id: str) -> List[Dict[str, Any]]:
    """List allowlisted viewers for a session, oldest-first."""
    resp = T.broadcast_allowlist.query(
        KeyConditionExpression=(
            Key("pk").eq(_pk(session_id)) & Key("sk").begins_with("ALLOW#")
        ),
    )
    items = resp.get("Items", [])
    items.sort(key=lambda x: int(x.get("created_at", 0)))
    return [
        {
            "viewer_id": i.get("viewer_id", ""),
            "added_by": i.get("added_by", ""),
            "created_at": int(i.get("created_at", 0)),
        }
        for i in items
    ]


def is_allowlisted(session_id: str, viewer_id: str) -> bool:
    """True if viewer_id is on the session allowlist."""
    item = T.broadcast_allowlist.get_item(
        Key={"pk": _pk(session_id), "sk": _allow_sk(viewer_id)}
    ).get("Item")
    return bool(item)


# ─── Invite tokens ──────────────────────────────────────────────────


def create_invite_token(session_id: str, *, created_by: str, max_uses: int = 1) -> Dict[str, Any]:
    """Mint a single- or multi-use invite token granting private access."""
    token = secrets.token_urlsafe(16)
    ts = now_ts()
    item = {
        "pk": _pk(session_id),
        "sk": _token_sk(token),
        "kind": "token",
        "session_id": session_id,
        "token": token,
        "created_by": created_by,
        "max_uses": int(max_uses),
        "use_count": 0,
        "created_at": ts,
    }
    T.broadcast_allowlist.put_item(Item=item)
    logger.info("broadcast.privacy.token_create session=%s", session_id)
    return {"token": token, "session_id": session_id, "max_uses": int(max_uses), "created_at": ts}


def list_invite_tokens(session_id: str) -> List[Dict[str, Any]]:
    """List invite tokens for a session."""
    resp = T.broadcast_allowlist.query(
        KeyConditionExpression=(
            Key("pk").eq(_pk(session_id)) & Key("sk").begins_with("TOKEN#")
        ),
    )
    items = resp.get("Items", [])
    items.sort(key=lambda x: int(x.get("created_at", 0)))
    return [
        {
            "token": i.get("token", ""),
            "max_uses": int(i.get("max_uses", 1)),
            "use_count": int(i.get("use_count", 0)),
            "created_at": int(i.get("created_at", 0)),
        }
        for i in items
    ]


def revoke_invite_token(session_id: str, token: str) -> bool:
    """Revoke (delete) an invite token. Returns True if it existed."""
    key = {"pk": _pk(session_id), "sk": _token_sk(token)}
    existing = T.broadcast_allowlist.get_item(Key=key).get("Item")
    if not existing:
        return False
    T.broadcast_allowlist.delete_item(Key=key)
    return True


def redeem_invite_token(session_id: str, token: str, viewer_id: str) -> bool:
    """Validate a token and, if valid + has remaining uses, add viewer to allowlist.

    Returns True on success. Increments use_count atomically.
    """
    token = (token or "").strip()
    if not token:
        return False
    key = {"pk": _pk(session_id), "sk": _token_sk(token)}
    item = T.broadcast_allowlist.get_item(Key=key).get("Item")
    if not item:
        return False
    max_uses = int(item.get("max_uses", 1))
    use_count = int(item.get("use_count", 0))
    if use_count >= max_uses:
        return False
    # Persist the consumption and grant access.
    T.broadcast_allowlist.update_item(
        Key=key,
        UpdateExpression="SET use_count = :n",
        ExpressionAttributeValues={":n": use_count + 1},
    )
    add_to_allowlist(session_id, viewer_id, added_by=f"token:{token}")
    logger.info("broadcast.privacy.token_redeem session=%s viewer=%s", session_id, viewer_id)
    return True


# ─── Visibility + access gating ─────────────────────────────────────


def set_visibility(session_id: str, visibility: str) -> Dict[str, Any]:
    """Set the session visibility. Returns the updated visibility dict.

    Owner-authorization is enforced at the router layer.
    """
    visibility = (visibility or "").strip().lower()
    if visibility not in VALID_VISIBILITIES:
        raise HTTPException(
            status_code=400,
            detail=f"visibility must be one of {', '.join(VALID_VISIBILITIES)}.",
        )
    from datetime import datetime, timezone

    from app.services.broadcast_store import update_session_fields

    update_session_fields(
        session_id,
        {
            "broadcast_privacy_visibility": visibility,
            "broadcast_privacy_updated_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    logger.info("broadcast.privacy.set_visibility session=%s visibility=%s", session_id, visibility)
    return get_privacy_state(session_id)


def get_privacy_state(session_id: str) -> Dict[str, Any]:
    """Return current visibility + allowlist size for a session."""
    from app.services.broadcast_store import get_session

    session = get_session(session_id)
    return {
        "session_id": session_id,
        "visibility": session.broadcast_privacy_visibility or "public",
        "updated_at": session.broadcast_privacy_updated_at,
        "allowlist_count": len(list_allowlist(session_id)),
    }


def check_viewer_access(
    session_id: str,
    viewer_id: str,
    *,
    creator_id: str,
    visibility: str,
    invite_token: Optional[str] = None,
) -> None:
    """Gate viewer join/playback. Raises HTTPException(403) when access is denied.

    - public / unlisted: anyone authenticated may watch.
    - private: only the creator, allowlisted viewers, or holders of a valid
      (still-available) invite token may watch. A valid token auto-enrolls the
      viewer onto the allowlist so subsequent joins succeed.
    """
    # SUB-E3: subscriber-only broadcast gate (independent of visibility).
    if viewer_id != creator_id:
        try:
            from app.core.tables import T as _T
            _raw = _T.broadcast_sessions.get_item(Key={"session_id": session_id}).get("Item", {}) or {}
        except Exception:
            _raw = {}
        if bool(_raw.get("subscriber_only")):
            from app.services.subscription_access import content_locked_for_viewer
            if content_locked_for_viewer(viewer_id, creator_id, subscriber_only=True):
                raise HTTPException(
                    status_code=403,
                    detail={
                        "code": "BROADCAST_SUBSCRIBER_ONLY",
                        "detail": "Subscribe to watch this broadcast.",
                        "creator_id": creator_id,
                    },
                )
    visibility = (visibility or "public").strip().lower()
    if visibility != "private":
        return
    if viewer_id == creator_id:
        return
    if is_allowlisted(session_id, viewer_id):
        return
    if invite_token and redeem_invite_token(session_id, invite_token, viewer_id):
        return
    raise HTTPException(
        status_code=403,
        detail={
            "code": "BROADCAST_PRIVATE_ACCESS_DENIED",
            "detail": "This broadcast is private. You are not on the viewer allowlist.",
        },
    )
