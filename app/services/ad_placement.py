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

    result = {
        "ads_enabled": True,
        "slots": slots,
        "ad_free": False,
        "skip_after_seconds": ad_config.get("skip_after_seconds", 5),
    }

    # ADS-010: per-content ad-control override takes precedence over the
    # video's own ad_config. Backward-compatible: no override → unchanged.
    try:
        from app.services.content_ad_controls import apply_content_override_to_config

        result = apply_content_override_to_config(video_id, result)
    except Exception:  # pragma: no cover - best-effort, never break playback
        logger.warning("content_ad_override_failed", extra={"video_id": video_id})

    return result


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
    # Fraud-signal fields (GAP-0006). Optional for backwards compatibility.
    ip_address: str = "",
    user_agent: str = "",
    view_time_ms: int = 0,
    campaign_id: str = "",
) -> Dict[str, Any]:
    """Record an ad impression/completion/skip event.

    Writes to AdImpressions table for tracking. On "complete" events,
    credits the creator with ad revenue based on CPM rate.

    All events first pass through ad-fraud detection (GAP-0006 / ADS-014),
    mirroring the server-side serving path (``ad_serving.track_ad_event``).
    A flagged event is recorded in the fraud-events table and short-circuits
    before any impression write or revenue credit. The fraud check fails open
    (a fraud-service error never blocks a legitimate impression).

    Returns {"ok": True, "event_id": str} on success, or
    {"ok": False, "event_id": "", "blocked": True, "reason": "fraud_detected"}
    when the event is blocked.
    """
    ts = now_ts()
    event_id = f"adimp_{uuid.uuid4().hex}"

    # ── Fraud detection (GAP-0006) ──────────────────────────────────────
    if getattr(S, "ad_fraud_detection_enabled", True):
        try:
            from app.services import ad_fraud_prevention as fraud

            result = fraud.check_fraud(
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                creative_id=creative_id,
                campaign_id=campaign_id,
                view_time_ms=view_time_ms,
                event_type=event_type,
            )
            if result.flagged:
                fraud.record_fraud_event(
                    event_id=event_id,
                    user_id=user_id,
                    ip_address=ip_address,
                    account_id=user_id,
                    campaign_id=campaign_id,
                    creative_id=creative_id,
                    event_type=event_type,
                    fraud_result=result,
                )
                logger.info(
                    "ad_impression_blocked video=%s user=%s score=%s",
                    video_id, user_id, result.score,
                )
                return {
                    "ok": False,
                    "event_id": "",
                    "blocked": True,
                    "reason": "fraud_detected",
                }
        except Exception:
            # Fail-open: a fraud-service outage must not block legitimate
            # impressions (matches ad_serving.track_ad_event behaviour).
            logger.warning(
                "ad_fraud_check_failed video=%s user=%s", video_id, user_id
            )

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

    # On complete: credit creator with ad revenue — but only ONCE per slot per
    # user per video per calendar day (GAP-0382). A single authenticated user
    # could otherwise POST event_type=complete unboundedly, inflating creator ad
    # revenue. We claim a deterministic dedup record with a DDB conditional write
    # (attribute_not_exists) before crediting; a ConditionalCheckFailedException
    # means the slot was already credited today → skip the credit (non-billable
    # duplicate). The atomic check-and-insert avoids any race between concurrent
    # requests. Same DDB path in dev (moto / DDB Local) and prod (SECOPS-007).
    if event_type == "complete":
        if _claim_complete_slot(
            date_str=_date_str(ts),
            user_id=user_id,
            video_id=video_id,
            slot_index=slot_index,
            event_id=event_id,
            ts=ts,
        ):
            _credit_ad_revenue(video_id=video_id, event_id=event_id, ts=ts)
        else:
            logger.info(
                "ad_impression_duplicate_skipped",
                extra={
                    "video_id": video_id,
                    "user_id": user_id,
                    "slot_index": slot_index,
                },
            )

    return {"ok": True, "event_id": event_id}


def _claim_complete_slot(
    *,
    date_str: str,
    user_id: str,
    video_id: str,
    slot_index: int,
    event_id: str,
    ts: int,
) -> bool:
    """Atomically claim the (user, video, slot, day) completion slot.

    Returns True if this is the first billable ``complete`` event for that slot
    today (caller should credit revenue), or False if a credit was already
    recorded today (duplicate — caller must NOT credit again).

    Uses a deterministic dedup key + a DynamoDB conditional ``put_item``
    (``attribute_not_exists(pk)``) so the check-and-insert is a single atomic
    round-trip with no race. Dedup records carry a 48h ``ttl`` so the once-per-
    day cap resets across calendar days. Fails OPEN on unexpected errors so a
    DDB hiccup never silently drops legitimate revenue.
    """
    from botocore.exceptions import ClientError

    dedup_pk = (
        f"AD_DEDUP#{date_str}#USER#{user_id}"
        f"#VIDEO#{video_id}#SLOT#{slot_index}"
    )
    try:
        T.ad_impressions.put_item(
            Item={
                "pk": dedup_pk,
                "sk": "DEDUP",
                "event_id": event_id,
                "created_at": ts,
                "ttl": ts + 86400 * 2,  # auto-expire after 48h
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
        return True
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        # Unexpected DDB error: fail open (credit) rather than silently drop
        # legitimate revenue. Matches the best-effort posture elsewhere here.
        logger.warning(
            "ad_impression_dedup_claim_failed",
            extra={"video_id": video_id, "user_id": user_id},
        )
        return True
    except Exception:
        logger.warning(
            "ad_impression_dedup_claim_failed",
            extra={"video_id": video_id, "user_id": user_id},
        )
        return True


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
