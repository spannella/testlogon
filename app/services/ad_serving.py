"""Ad serving engine -- selects and serves ads for all surfaces (ADS-004).

When a frontend component needs an ad, it calls serve_ad() with viewer and
content context.  The engine evaluates all eligible campaigns against targeting
rules, applies frequency capping and budget pacing, ranks candidates, and
returns the winning creative with tracking URLs.
"""

from __future__ import annotations

import logging
import random
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ── Frequency cap defaults ──────────────────────────────────────────

DEFAULT_FREQ_CAPS = {"1h": 3, "24h": 10, "7d": 30}
WINDOW_SECONDS = {"1h": 3600, "24h": 86400, "7d": 604800}

# ── House ad (platform self-promotion) ──────────────────────────────

HOUSE_AD: Dict[str, Any] = {
    "creative_id": "house_ad_001",
    "format": "native_post",
    "title": "Discover more on this platform",
    "headline": "Explore creators you'll love",
    "body_text": "Find new content, connect with creators, and join the community.",
    "cta_text": "Explore",
    "cta_url": "/feed",
    "is_house_ad": True,
}


# ── Public API ──────────────────────────────────────────────────────


def serve_ad(
    *,
    surface: str,
    content_type: str,
    creator_id: str,
    content_id: str,
    slot_type: str,
    user_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Select and return the best ad for the given context."""
    from app.services.ad_campaigns import list_campaigns_by_status
    from app.services.ad_creatives import list_approved_creatives
    from app.services.ad_targeting import evaluate_targeting, list_targeting_sets
    from app.services.creator_ad_prefs import get_creator_ad_settings, is_advertiser_blocked

    ctx = dict(user_context or {})
    ctx.update({
        "content_type": surface,
        "creator_id": creator_id,
    })

    # 1. Check creator allows ads
    creator_settings = get_creator_ad_settings(creator_id)
    if not creator_settings.get("allow_ads", True):
        return _empty_response("creator_ads_disabled")

    # 2. Load active campaigns
    active_campaigns = list_campaigns_by_status("active")
    if not active_campaigns:
        return _house_ad_response("no_active_campaigns")

    # 3. Filter + score candidates
    candidates: List[Dict[str, Any]] = []
    for campaign in active_campaigns:
        account_id = campaign["account_id"]

        # Fraud suspension check (ADS-014): suspended accounts serve no ads.
        try:
            from app.services.ad_fraud_prevention import is_account_suspended
            if is_account_suspended(account_id):
                continue
        except Exception:
            pass

        # Creator block check
        if is_advertiser_blocked(creator_id, account_id):
            continue

        # Category whitelist check (ADS-003): when the creator has configured
        # an allowed_ad_categories whitelist, skip campaigns whose category is
        # not in it. An empty list means "no restriction" (the default).
        allowed_categories = creator_settings.get("allowed_ad_categories") or []
        if allowed_categories:
            campaign_category = campaign.get("category", "general")
            if campaign_category not in allowed_categories:
                continue

        # Min CPM floor check (ADS-003): skip campaigns bidding below the
        # creator's configured minimum CPM.
        creator_min_cpm = int(creator_settings.get("min_cpm_cents", 0) or 0)
        if creator_min_cpm > 0:
            campaign_bid = int(campaign.get("bid_cpm_cents", 500))
            if campaign_bid < creator_min_cpm:
                continue

        # Budget check
        if not _has_budget(campaign):
            continue

        # Dayparting / flight check (ADS-016): skip campaigns outside their
        # active dayparts, and skip when flights are configured but none is
        # active right now (gap between flights).
        if not _is_dayparting_eligible(campaign):
            continue

        # Targeting check
        targeting_sets = list_targeting_sets(campaign["campaign_id"])
        if targeting_sets and not any(evaluate_targeting(ts, ctx) for ts in targeting_sets):
            continue

        # Frequency cap check
        if _is_frequency_capped(user_id, campaign["campaign_id"]):
            continue

        # Get approved creatives
        creatives = list_approved_creatives(campaign["campaign_id"])
        if not creatives:
            continue

        # Score: bid_cpm * relevance (mock relevance = 1.0)
        bid_cpm = int(campaign.get("bid_cpm_cents", 500))
        score = bid_cpm * 1.0

        candidates.append({
            "campaign": campaign,
            "creatives": creatives,
            "score": score,
        })

    if not candidates:
        return _house_ad_response("no_eligible_campaigns")

    # 4. Select winner (highest score)
    candidates.sort(key=lambda c: c["score"], reverse=True)
    winner = candidates[0]

    # 5. Select creative (weighted random by rotation_weight)
    creative = _weighted_random_creative(winner["creatives"])

    # 6. Build tracking URLs
    tracking_base = "/ui/ads/track"
    tracking_params = (
        f"creative_id={creative['creative_id']}"
        f"&campaign_id={winner['campaign']['campaign_id']}"
        f"&account_id={winner['campaign']['account_id']}"
        f"&surface={surface}&slot_type={slot_type}"
        f"&content_id={content_id}&creator_id={creator_id}"
    )

    return {
        "filled": True,
        "creative_id": creative["creative_id"],
        "format": creative.get("format", "native_post"),
        "title": creative.get("title", ""),
        "headline": creative.get("headline"),
        "body_text": creative.get("body_text"),
        "cta_text": creative.get("cta_text"),
        "cta_url": creative.get("cta_url"),
        "image_url": creative.get("image_url"),
        "video_url": creative.get("video_url"),
        "thumbnail_url": creative.get("thumbnail_url"),
        "skip_after_seconds": int(creative.get("skip_after_seconds", 5)),
        "impression_url": f"{tracking_base}?event=impression&{tracking_params}",
        "click_url": f"{tracking_base}?event=click&{tracking_params}",
        "skip_url": f"{tracking_base}?event=skip&{tracking_params}",
        "is_house_ad": False,
        "campaign_id": winner["campaign"]["campaign_id"],
        "promo_code_id": creative.get("promo_code_id"),
        "affiliate_link_id": creative.get("affiliate_link_id"),
    }


def track_ad_event(
    *,
    event: str,
    creative_id: str,
    campaign_id: str,
    account_id: str,
    surface: str,
    slot_type: str,
    content_id: str,
    creator_id: str,
    user_id: str,
    ip_address: str = "",
    user_agent: str = "",
    view_time_ms: int = 0,
    geo_country: str = "",
) -> Dict[str, Any]:
    """Record an ad event and process billing.

    All events first pass through ad-fraud detection (ADS-014). Events scoring
    at/above the fraud threshold are recorded in the fraud-events table and
    excluded from the impression record (so they are never billed/credited).
    """
    ts = now_ts()
    event_id = f"evt_{ts}_{creative_id}"

    # ── Fraud detection (ADS-014) ──────────────────────────────────────
    fraud_score = 0
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
                event_type=event,
                geo_country=geo_country,
            )
            fraud_score = result.score
            if result.flagged:
                fraud.record_fraud_event(
                    event_id=event_id,
                    user_id=user_id,
                    ip_address=ip_address,
                    account_id=account_id,
                    campaign_id=campaign_id,
                    creative_id=creative_id,
                    event_type=event,
                    fraud_result=result,
                )
                fraud.maybe_auto_suspend(account_id=account_id)
                return {
                    "ok": True,
                    "event_id": event_id,
                    "flagged": True,
                    "fraud_score": fraud_score,
                }
            # Legitimate event — record account activity for fraud-rate stats.
            fraud.record_account_activity(account_id=account_id, flagged=False)
        except Exception:
            logger.warning("ad_fraud_check_failed event=%s creative=%s", event, creative_id)

    # Write impression record to ad_impressions table
    try:
        date_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
        T.ad_impressions.put_item(
            Item={
                "pk": f"AD_IMP#{date_str}",
                "sk": f"VIDEO#{content_id}#{user_id}#{ts}",
                "event_id": event_id,
                "video_id": content_id,
                "user_id": user_id,
                "slot_type": slot_type,
                "slot_index": 0,
                "creative_id": creative_id,
                "campaign_id": campaign_id,
                "account_id": account_id,
                "surface": surface,
                "event_type": event,
                "creator_id": creator_id,
                "created_at": ts,
            }
        )
    except Exception:
        logger.warning("ad_track_write_failed", extra={
            "event": event, "creative_id": creative_id, "user_id": user_id,
        })

    # Update frequency cap on impression
    if event == "impression":
        _increment_frequency_cap(user_id, campaign_id)

    return {"ok": True, "event_id": event_id, "flagged": False, "fraud_score": fraud_score}


def get_serving_stats(campaign_id: str) -> Dict[str, Any]:
    """Get serving stats for a campaign (impressions, clicks, fill rate)."""
    from boto3.dynamodb.conditions import Key, Attr

    # Count impressions and clicks from ad_impressions table
    # Query by campaign_id across dates -- in dev mode we scan the table
    impressions = 0
    clicks = 0
    skips = 0

    try:
        resp = T.ad_impressions.scan(
            FilterExpression=Attr("campaign_id").eq(campaign_id),
            Select="ALL_ATTRIBUTES",
        )
        items = resp.get("Items", [])
        for item in items:
            et = item.get("event_type", "")
            if et == "impression":
                impressions += 1
            elif et == "click":
                clicks += 1
            elif et == "skip":
                skips += 1
    except Exception:
        logger.warning("ad_stats_scan_failed campaign_id=%s", campaign_id)

    ctr = (clicks / impressions * 100) if impressions > 0 else 0.0

    return {
        "campaign_id": campaign_id,
        "impressions": impressions,
        "clicks": clicks,
        "skips": skips,
        "ctr_pct": round(ctr, 2),
    }


# ── Internal helpers ────────────────────────────────────────────────


def _has_budget(campaign: dict) -> bool:
    budget = int(campaign.get("budget_cents", 0))
    spent = int(campaign.get("lifetime_spent_cents", 0))
    if campaign.get("budget_type") == "lifetime" and spent >= budget:
        return False
    if campaign.get("budget_type") == "daily":
        daily_spent = int(campaign.get("spent_today_cents", 0))
        daily_budget = int(campaign.get("daily_budget_cents", budget))
        if daily_spent >= daily_budget:
            return False
    return True


def _is_dayparting_eligible(campaign: dict) -> bool:
    """Return True if the campaign may serve now per its dayparting / flights.

    A campaign with no dayparting and no flights is always eligible. With
    dayparting, the current local day/hour must be in the schedule. With
    flights configured, at least one flight must be active for the current
    date. Failures fail open (eligible) to avoid silently dropping ads.
    """
    dayparting = campaign.get("dayparting")
    flights = campaign.get("flights")
    if not dayparting and not flights:
        return True
    try:
        from app.services.ad_dayparting import (
            get_active_flight,
            is_campaign_eligible_now,
        )

        if dayparting:
            eligible, _ = is_campaign_eligible_now(
                dayparting=dayparting,
                campaign_timezone=campaign.get("campaign_timezone", "UTC"),
            )
            if not eligible:
                return False
        if flights:
            if get_active_flight(flights=flights) is None:
                return False
        return True
    except Exception:
        logger.warning(
            "ad_dayparting_check_failed campaign_id=%s",
            campaign.get("campaign_id"),
        )
        return True


def _is_frequency_capped(user_id: str, campaign_id: str) -> bool:
    for window, max_count in DEFAULT_FREQ_CAPS.items():
        try:
            resp = T.ad_frequency_caps.get_item(
                Key={"pk": f"USER#{user_id}", "sk": f"CAMPAIGN#{campaign_id}#{window}"}
            )
            item = resp.get("Item")
            if item and int(item.get("count", 0)) >= max_count:
                return True
        except Exception:
            logger.warning("ad_freq_cap_read_failed user=%s campaign=%s window=%s",
                           user_id, campaign_id, window)
    return False


def _increment_frequency_cap(user_id: str, campaign_id: str) -> None:
    ts = now_ts()
    for window, ttl_seconds in WINDOW_SECONDS.items():
        try:
            T.ad_frequency_caps.update_item(
                Key={"pk": f"USER#{user_id}", "sk": f"CAMPAIGN#{campaign_id}#{window}"},
                UpdateExpression="SET #c = if_not_exists(#c, :z) + :one, expires_at = :exp, campaign_id = :cid, #w = :w",
                ExpressionAttributeNames={"#c": "count", "#w": "window"},
                ExpressionAttributeValues={
                    ":z": 0, ":one": 1,
                    ":exp": ts + ttl_seconds,
                    ":cid": campaign_id,
                    ":w": window,
                },
            )
        except Exception:
            logger.warning("ad_freq_cap_write_failed user=%s campaign=%s window=%s",
                           user_id, campaign_id, window)


def _weighted_random_creative(creatives: list[dict]) -> dict:
    if len(creatives) == 1:
        return creatives[0]
    weights = [int(c.get("rotation_weight", 50)) for c in creatives]
    total = sum(weights)
    if total == 0:
        return random.choice(creatives)
    return random.choices(creatives, weights=weights, k=1)[0]


def _house_ad_response(reason: str) -> dict:
    return {"filled": True, "is_house_ad": True, **HOUSE_AD, "fill_reason": reason}


def _empty_response(reason: str) -> dict:
    return {"filled": False, "is_house_ad": False, "fill_reason": reason}
