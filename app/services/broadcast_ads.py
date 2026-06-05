"""Broadcast ad breaks service (ADS-006).

Provides:
  * pre-roll / mid-roll ad *selection* (stubbed inline — ADS-002 video creatives
    and ADS-004 ad serving engine do not exist yet, so this returns a deterministic
    house creative)
  * subscriber ad-free resolution
  * ad-break state transitions on the broadcast session
  * ad event tracking (impression / skip / complete / click)

The integration point is the existing broadcast system. Ad-break state lives on the
``broadcast_sessions`` row (fields added by ADS-006); ad events are written to the
``broadcast_ad_events`` table.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from uuid import uuid4

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_store import get_session, update_session_fields
from app.services.broadcast_sse import broadcast_sse_publish

# Allowed mid-roll break durations (seconds)
ALLOWED_MIDROLL_DURATIONS = (15, 30, 60)

# Pre-roll skip is fixed at 5s per ADS-006 spec
PRE_ROLL_SKIP_AFTER_SECONDS = 5


# ─── Subscriber ad-free ─────────────────────────────────────────────


def is_ad_free(viewer_id: str, creator_id: str) -> bool:
    """Return True if the viewer should not see ads on this creator's broadcast.

    The broadcaster themself is always ad-free. Active subscribers of the creator
    are ad-free (subscriber benefit). The check is server-authoritative.
    """
    if viewer_id == creator_id:
        return True
    try:
        from app.services.subscription_access import has_active_subscription

        return has_active_subscription(viewer_id, creator_id)
    except Exception:  # pragma: no cover - never block playback on a check failure
        return False


# ─── Inline ad selection (stub for ADS-004) ─────────────────────────


def serve_broadcast_ad(
    *,
    surface: str,
    creator_id: str,
    content_id: str,
    slot_type: str,
    user_id: str,
) -> Dict[str, Any]:
    """Select an ad for a broadcast surface via the ADS-004 serving engine.

    Delegates to ``app.services.ad_serving.serve_ad`` for targeting, frequency
    caps, and budget enforcement. Falls back to the deterministic house creative
    when the engine raises (e.g. DDB error) or returns an unfilled result, so a
    transient engine failure or empty inventory never breaks broadcast playback.

    Returns a dict with ``filled`` plus creative metadata + tracking URLs.
    """
    try:
        from app.services.ad_serving import serve_ad

        result = serve_ad(
            surface=surface,
            content_type="broadcast",
            creator_id=creator_id,
            content_id=content_id,
            slot_type=slot_type,
            user_id=user_id,
        )
        if result.get("filled"):
            return result
    except Exception:  # graceful degradation — never break playback on engine error
        import logging

        logging.getLogger(__name__).warning(
            "serve_broadcast_ad: engine failed, falling back to house creative "
            "(creator=%s content=%s slot=%s)",
            creator_id,
            content_id,
            slot_type,
            exc_info=True,
        )

    # Fallback: deterministic house creative (engine unfilled or errored).
    creative_id = f"bcast_house_{slot_type}"
    return {
        "filled": True,
        "creative_id": creative_id,
        "format": "video",
        "video_url": f"/mock/s3/ad-creatives/{creative_id}.mp4",
        "image_url": None,
        "cta_url": None,
        "impression_url": f"/broadcast/sessions/{content_id}/ads/{creative_id}/track?event=impression",
        "click_url": f"/broadcast/sessions/{content_id}/ads/{creative_id}/track?event=click",
        "skip_url": f"/broadcast/sessions/{content_id}/ads/{creative_id}/track?event=skip",
    }


def build_pre_roll(session, viewer_id: str) -> Dict[str, Any]:
    """Build the pre-roll payload for a viewer joining ``session``.

    Returns ``{"pre_roll": <obj|None>, "ad_free": bool}``.
    """
    # Ad-free subscribers (and the broadcaster) skip pre-roll entirely.
    if is_ad_free(viewer_id, session.created_by):
        return {"pre_roll": None, "ad_free": True}

    # Global platform kill-switch for pre-roll (BROADCAST_PREROLL_ENABLED).
    if not S.broadcast_preroll_enabled:
        return {"pre_roll": None, "ad_free": True}

    if not session.pre_roll_enabled:
        return {"pre_roll": None, "ad_free": True}

    ad = serve_broadcast_ad(
        surface="broadcast",
        creator_id=session.created_by,
        content_id=session.id,
        slot_type="broadcast_preroll",
        user_id=viewer_id,
    )
    if not ad.get("filled"):
        # No ad available → play stream immediately. ad_free stays False so the
        # client still knows ads *could* have shown (matches VOD semantics).
        return {"pre_roll": None, "ad_free": False}

    pre_roll = {
        "creative_id": ad["creative_id"],
        "format": ad["format"],
        "video_url": ad.get("video_url"),
        "image_url": ad.get("image_url"),
        "cta_url": ad.get("cta_url"),
        "skip_after_seconds": PRE_ROLL_SKIP_AFTER_SECONDS,
        "impression_url": ad["impression_url"],
        "click_url": ad["click_url"],
        "skip_url": ad["skip_url"],
    }
    return {"pre_roll": pre_roll, "ad_free": False}


# ─── Ad-break state ─────────────────────────────────────────────────


def start_ad_break(session) -> Dict[str, Any]:
    """Mark an ad break active on the session and publish the SSE start event.

    Caller is responsible for authorization + state validation. Returns the
    broadcast payload (duration / skip / started_at).
    """
    ts = now_ts()
    duration = int(session.mid_roll_ad_break_duration_seconds)
    skip_after = int(session.mid_roll_skip_after_seconds)

    update_session_fields(
        session.id,
        {
            "ad_break_active": True,
            "ad_break_started_at": ts,
            "total_ad_breaks": int(session.total_ad_breaks) + 1,
        },
    )

    payload = {
        "duration_seconds": duration,
        "skip_after_seconds": skip_after,
        "started_at": ts,
    }
    broadcast_sse_publish(session.id, {"_type": "ad_break:start", **payload})
    return payload


def end_ad_break(session_id: str, *, ended_by: str = "auto") -> None:
    """Clear the ad-break flag and publish the SSE end event (idempotent)."""
    update_session_fields(
        session_id,
        {"ad_break_active": False, "ad_break_started_at": None},
    )
    broadcast_sse_publish(session_id, {"_type": "ad_break:end", "ended_by": ended_by})


async def schedule_ad_break_end(session_id: str, duration: int) -> None:
    """Background task: auto-end an ad break after ``duration`` seconds.

    Re-reads the session before ending so a manual early-end is not clobbered.
    """
    import asyncio

    await asyncio.sleep(max(1, int(duration)))
    try:
        session = get_session(session_id)
    except Exception:
        return
    if session and session.ad_break_active:
        end_ad_break(session_id, ended_by="auto")


# ─── Ad event tracking ──────────────────────────────────────────────

_VALID_EVENTS = {"impression", "skip", "complete", "click"}


def record_ad_event(
    *,
    session_id: str,
    creative_id: str,
    user_id: str,
    event_type: str,
    slot_type: str = "",
) -> Dict[str, Any]:
    """Record a broadcast ad event (impression/skip/complete/click).

    Best-effort: tracking failures must never break playback.
    """
    if event_type not in _VALID_EVENTS:
        event_type = "impression"
    ts = now_ts()
    event_id = f"bae_{uuid4().hex}"
    try:
        T.broadcast_ad_events.put_item(
            Item={
                "session_id": session_id,
                "event_sk": f"{ts}#{event_id}",
                "event_id": event_id,
                "creative_id": creative_id,
                "user_id": user_id,
                "event_type": event_type,
                "slot_type": slot_type,
                "created_at": ts,
            }
        )
    except Exception:  # pragma: no cover - tracking is best-effort
        pass
    return {"ok": True, "event_id": event_id, "event_type": event_type}


def validate_midroll_duration(value: int) -> Optional[str]:
    """Return an error string if the duration is not one of the allowed values."""
    if value not in ALLOWED_MIDROLL_DURATIONS:
        return "mid_roll_ad_break_duration_seconds must be 15, 30, or 60"
    return None
