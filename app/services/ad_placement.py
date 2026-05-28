"""Ad placement service (VOD-018).

Handles ad configuration, placement resolution, impression tracking,
and revenue calculation. In dev mode, ads are static placeholders.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import new_ledger_entry, user_pk

logger = logging.getLogger(__name__)

# Default CPM rate in cents ($5 CPM = 500 cents per 1000 impressions)
DEFAULT_CPM_CENTS = 500

# Dev-mode placeholder ad creatives
DEV_AD_CREATIVES = [
    {
        "creative_id": "dev_ad_preroll_15s",
        "type": "video",
        "duration_seconds": 15,
        "url": "/static/ads/placeholder_preroll.mp4",
        "title": "Placeholder Pre-Roll Ad",
    },
    {
        "creative_id": "dev_ad_midroll_30s",
        "type": "video",
        "duration_seconds": 30,
        "url": "/static/ads/placeholder_midroll.mp4",
        "title": "Placeholder Mid-Roll Ad",
    },
    {
        "creative_id": "dev_ad_overlay",
        "type": "image",
        "duration_seconds": 10,
        "url": "/static/ads/placeholder_overlay.png",
        "title": "Placeholder Overlay Ad",
    },
]


# ─── Ad Config helpers ──────────────────────────────────────────────────────


def get_default_ad_config(duration_seconds: float) -> Dict[str, Any]:
    """Generate default ad configuration based on video duration.

    Rules:
    - Videos < 10 min: pre_roll only
    - Videos >= 10 min: pre_roll + one mid_roll every 5 minutes
    - Skip allowed after 5 seconds by default
    """
    config: Dict[str, Any] = {
        "pre_roll": True,
        "mid_roll_intervals_seconds": [],
        "overlay_enabled": False,
        "skip_after_seconds": 5,
    }

    if duration_seconds >= 600:  # >= 10 minutes
        interval = 300  # 5 minutes
        t = interval
        while t < duration_seconds - 60:  # Stop 60s before end
            config["mid_roll_intervals_seconds"].append(t)
            t += interval

    return config


def validate_ad_config(config: Dict[str, Any], duration_seconds: float) -> Dict[str, Any]:
    """Validate and sanitize creator-provided ad configuration.

    Enforces:
    - pre_roll: boolean
    - mid_roll_intervals_seconds: list of ints, max 1 per 5 min of content
    - Each mid_roll timestamp >= 30s and < (duration - 30s)
    - overlay_enabled: boolean
    - skip_after_seconds: int clamped to [0, 30]

    Returns sanitized config.
    """
    sanitized: Dict[str, Any] = {}

    sanitized["pre_roll"] = bool(config.get("pre_roll", True))
    sanitized["overlay_enabled"] = bool(config.get("overlay_enabled", False))

    skip = int(config.get("skip_after_seconds", 5))
    sanitized["skip_after_seconds"] = max(0, min(30, skip))

    # Validate mid-roll intervals
    mid_rolls = config.get("mid_roll_intervals_seconds", [])
    if not isinstance(mid_rolls, list):
        mid_rolls = []

    max_mid_rolls = max(1, int(duration_seconds / 300))  # 1 per 5 min
    validated_mid_rolls: List[int] = []
    for ts in mid_rolls[:max_mid_rolls]:
        ts_int = int(ts)
        if 30 <= ts_int < duration_seconds - 30:
            validated_mid_rolls.append(ts_int)

    validated_mid_rolls.sort()
    sanitized["mid_roll_intervals_seconds"] = validated_mid_rolls

    return sanitized


def calculate_ad_slots(duration_seconds: float, ad_config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Calculate ad slot positions from config and video duration.

    Returns list of ad slot dicts with type, timestamp, duration, creative info.
    """
    if ad_config is None:
        ad_config = get_default_ad_config(duration_seconds)

    slots: List[Dict[str, Any]] = []
    slot_index = 0

    # Pre-roll
    if ad_config.get("pre_roll"):
        creative = DEV_AD_CREATIVES[0]
        slots.append({
            "type": "pre_roll",
            "timestamp_seconds": 0,
            "duration_seconds": creative["duration_seconds"],
            "creative_id": creative["creative_id"],
            "creative_url": creative["url"],
            "creative_type": creative["type"],
            "skip_after_seconds": ad_config.get("skip_after_seconds", 5),
            "slot_index": slot_index,
        })
        slot_index += 1

    # Mid-rolls
    for ts in ad_config.get("mid_roll_intervals_seconds", []):
        creative = DEV_AD_CREATIVES[1]
        slots.append({
            "type": "mid_roll",
            "timestamp_seconds": ts,
            "duration_seconds": creative["duration_seconds"],
            "creative_id": creative["creative_id"],
            "creative_url": creative["url"],
            "creative_type": creative["type"],
            "skip_after_seconds": ad_config.get("skip_after_seconds", 5),
            "slot_index": slot_index,
        })
        slot_index += 1

    # Overlay
    if ad_config.get("overlay_enabled"):
        creative = DEV_AD_CREATIVES[2]
        slots.append({
            "type": "overlay",
            "timestamp_seconds": 30,  # Show 30s into playback
            "duration_seconds": creative["duration_seconds"],
            "creative_id": creative["creative_id"],
            "creative_url": creative["url"],
            "creative_type": creative["type"],
            "skip_after_seconds": 0,  # Overlays don't have skip
            "slot_index": slot_index,
        })
        slot_index += 1

    return slots


# ─── Ad Placement Resolution ────────────────────────────────────────────────


def get_ad_config(video_id: str, viewer_user_id: str) -> Dict[str, Any]:
    """Return ad placement config for a video.

    If the viewer is a subscriber and the video has ads_free_for_subscribers=True,
    returns {ads_enabled: false}. Otherwise returns the video's ad_config with
    slot timings.
    """
    from app.services.video_metadata_store import get_video

    video = get_video(video_id)

    if video.access_mode != "ad_supported":
        return {"ads_enabled": False, "slots": [], "ad_free": True}

    # Check subscriber ad-free setting
    if getattr(video, "ads_free_for_subscribers", False):
        from app.services.subscription_access import has_active_subscription
        if has_active_subscription(subscriber_id=viewer_user_id, creator_id=video.owner_user_id):
            return {"ads_enabled": False, "slots": [], "ad_free": True}

    # Resolve ad config (creator-configured or default)
    ad_config = video.ad_config
    duration = video.duration_seconds or 60
    if not ad_config:
        ad_config = get_default_ad_config(duration)

    slots = calculate_ad_slots(duration, ad_config)

    return {
        "ads_enabled": True,
        "slots": slots,
        "ad_free": False,
        "skip_after_seconds": ad_config.get("skip_after_seconds", 5),
    }


# ─── Ad Impression Tracking ─────────────────────────────────────────────────


def _date_str(ts: int) -> str:
    """Convert Unix timestamp to YYYY-MM-DD string."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def record_ad_impression(
    *,
    video_id: str,
    user_id: str,
    slot_type: str,
    slot_index: int,
    creative_id: str = "",
    event_type: str = "impression",  # "impression" | "complete" | "skip"
) -> Dict[str, Any]:
    """Record an ad impression/completion/skip event.

    Writes to AdImpressions table for tracking. On "complete" events,
    credits the creator with ad revenue based on CPM rate.

    Returns {"ok": True, "event_id": str}
    """
    ts = now_ts()
    event_id = f"adimp_{uuid.uuid4().hex}"

    # Write impression record
    try:
        T.ad_impressions.put_item(
            Item={
                "pk": f"AD_IMP#{_date_str(ts)}",
                "sk": f"VIDEO#{video_id}#{user_id}#{ts}",
                "event_id": event_id,
                "video_id": video_id,
                "user_id": user_id,
                "slot_type": slot_type,
                "slot_index": slot_index,
                "creative_id": creative_id,
                "event_type": event_type,
                "created_at": ts,
            }
        )
    except Exception:
        logger.warning("ad_impression_write_failed", extra={
            "video_id": video_id, "user_id": user_id, "event_type": event_type,
        })

    # Increment impression count on video metadata (all event types)
    try:
        T.video_metadata.update_item(
            Key={"video_id": video_id},
            UpdateExpression="SET ad_impression_count = if_not_exists(ad_impression_count, :z) + :one",
            ExpressionAttributeValues={":z": 0, ":one": 1},
        )
    except Exception:
        logger.warning("ad_impression_counter_failed", extra={"video_id": video_id})

    # On complete: credit creator with ad revenue
    if event_type == "complete":
        _credit_ad_revenue(video_id=video_id, event_id=event_id, ts=ts)

    return {"ok": True, "event_id": event_id}


def _credit_ad_revenue(*, video_id: str, event_id: str, ts: int) -> None:
    """Credit creator with ad revenue for a completed ad impression.

    Uses configurable CPM rate (default $5 CPM = 500 cents per 1000 impressions).
    Revenue per completed impression = CPM / 1000. Since we track in integer
    cents, we credit max(1, cpm // 1000) per impression (minimum 1 cent).
    """
    from app.services.video_metadata_store import get_video

    video = get_video(video_id)
    cpm = getattr(S, "vod_ad_cpm_cents", DEFAULT_CPM_CENTS)
    revenue_cents = max(1, cpm // 1000)

    # Increment ad_revenue_cents on video metadata
    try:
        T.video_metadata.update_item(
            Key={"video_id": video_id},
            UpdateExpression="SET ad_revenue_cents = if_not_exists(ad_revenue_cents, :z) + :rev",
            ExpressionAttributeValues={":z": 0, ":rev": revenue_cents},
        )
    except Exception:
        logger.warning("ad_revenue_credit_failed", extra={"video_id": video_id})

    # Write ledger credit for creator (best-effort)
    try:
        _sk, credit_item = new_ledger_entry(
            key_name="pk",
            key_value=user_pk(video.owner_user_id),
            entry_type="ad_revenue_credit",
            amount_cents=revenue_cents,
            state="settled",
            reason="Ad revenue",
            meta={
                "video_id": video_id,
                "event_id": event_id,
                "creative_type": "completed_view",
            },
        )
        T.billing.put_item(Item=credit_item)
    except Exception:
        logger.warning("ad_revenue_ledger_failed", extra={
            "video_id": video_id, "creator_id": video.owner_user_id,
        })


# ─── Ad Stats ────────────────────────────────────────────────────────────────


def get_ad_stats(video_id: str) -> Dict[str, Any]:
    """Return impression count, revenue, and CPM for a video.

    Reads directly from the video metadata record (atomic counters).
    """
    from app.services.video_metadata_store import get_video

    video = get_video(video_id)
    cpm = getattr(S, "vod_ad_cpm_cents", DEFAULT_CPM_CENTS)

    return {
        "video_id": video_id,
        "ad_impression_count": video.ad_impression_count,
        "ad_revenue_cents": video.ad_revenue_cents,
        "estimated_cpm_cents": cpm,
    }
