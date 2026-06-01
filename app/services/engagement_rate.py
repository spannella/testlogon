"""Engagement Rate Calculation service (FIN-012).

Computes a creator-level engagement rate from REAL interaction data that
actually exists in this codebase:

  - Newsfeed posts expose ONLY ``like_count`` and ``comment_count``
    (``app/routers/newsfeed.py:1999-2000``). There is NO ``view_count`` and
    NO ``share_count`` on newsfeed posts.
  - ``share_count`` exists only on broadcast clips
    (``app/services/broadcast_clip.py:141``) and is intentionally optional here.
  - Follower counts come from ``get_follow_counts(user_id)`` in
    ``app/services/social.py:189`` which returns ``{follower_count,
    following_count}``. There is NO ``get_follower_count()``.

The engagement rate is derived from the daily analytics rollups
(PK=``CREATOR#{user_id}``, SK=``DAILY#{date}``) in the ``AnalyticsRollups``
table — the SAME records written by ``creator_analytics.upsert_daily_rollup``.
FIN-012 extends those rollup records with engagement fields
(``engagement_likes``, ``engagement_comments``, ``engagement_shares``,
``engagement_tips``, ``post_count``, ``total_interactions``,
``follower_snapshot`` and the computed ``engagement_rate``).

The rate is stored and returned as **basis points (bps)** — an integer where
``10000`` bps == ``100.0%`` — so it is Decimal-safe in DynamoDB and avoids
floating-point drift. Helper conversions to a percentage are provided.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Valid period windows (days). Mirrors the ticket's period selector.
VALID_PERIOD_DAYS = (7, 14, 30, 60, 90)
DEFAULT_PERIOD_DAYS = 30

# Engagement rate is stored as basis points (bps). 10000 bps == 100.0%.
BPS_PER_PERCENT = 100
MAX_RATE_BPS = 10000  # capped at 100%
_DATE_FMT = "%Y-%m-%d"


# ── coercion helpers ───────────────────────────────────────────────


def _to_int(val: Any) -> int:
    if isinstance(val, Decimal):
        return int(val)
    if isinstance(val, bool):
        return int(val)
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str) and val.lstrip("-").isdigit():
        return int(val)
    return 0


def bps_to_percent(bps: int) -> float:
    """Convert basis points to a percentage (e.g. 420 bps -> 4.2)."""
    return round(_to_int(bps) / BPS_PER_PERCENT, 4)


# ── core deterministic calculations ────────────────────────────────


def calculate_engagement_rate_bps(
    interactions: int,
    followers: int,
    post_count: int,
) -> int:
    """Creator-level engagement rate in basis points.

    Formula (per the ticket, normalized over audience size and posting
    frequency):

        rate = total_interactions / (followers * posts_in_period) * 100

    Returns an integer in basis points (``rate_percent * 100``), capped at
    ``MAX_RATE_BPS`` (100%). Returns ``0`` when ``followers`` or
    ``post_count`` is zero (no division by zero).
    """
    interactions = max(0, _to_int(interactions))
    followers = _to_int(followers)
    post_count = _to_int(post_count)
    if followers <= 0 or post_count <= 0:
        return 0
    # rate (fraction) * 10000 = bps
    bps = int(round(interactions / (followers * post_count) * MAX_RATE_BPS))
    if bps < 0:
        return 0
    return min(bps, MAX_RATE_BPS)


def compute_daily_engagement(
    likes: int,
    comments: int,
    shares: int,
    tips: int,
) -> int:
    """Sum of interactions for a single day.

    ``tips`` is the raw tip count; it is included as a high-signal interaction.
    Shares default to 0 for newsfeed posts (only broadcast clips track shares).
    """
    return (
        max(0, _to_int(likes))
        + max(0, _to_int(comments))
        + max(0, _to_int(shares))
        + max(0, _to_int(tips))
    )


# ── rollup integration ─────────────────────────────────────────────


def build_engagement_rollup_fields(
    *,
    likes: int,
    comments: int,
    shares: int = 0,
    tips: int = 0,
    post_count: int = 0,
    follower_count: int = 0,
) -> Dict[str, Any]:
    """Build the engagement fields to merge into a daily rollup record.

    Called by ``creator_analytics.upsert_daily_rollup`` so that every daily
    rollup carries deterministic engagement data + a computed daily
    engagement_rate (bps). Stored as ints (Decimal-safe).
    """
    interactions = compute_daily_engagement(likes, comments, shares, tips)
    rate_bps = calculate_engagement_rate_bps(
        interactions=interactions,
        followers=follower_count,
        post_count=post_count,
    )
    return {
        "engagement_likes": max(0, _to_int(likes)),
        "engagement_comments": max(0, _to_int(comments)),
        "engagement_shares": max(0, _to_int(shares)),
        "engagement_tips": max(0, _to_int(tips)),
        "post_count": max(0, _to_int(post_count)),
        "total_interactions": interactions,
        "follower_snapshot": max(0, _to_int(follower_count)),
        "engagement_rate_bps": rate_bps,
    }


# ── DDB read helpers ───────────────────────────────────────────────


def _query_rollups(user_id: str, from_date: str, to_date: str) -> List[Dict[str, Any]]:
    """Query daily rollup rows for a creator in a date range (inclusive)."""
    from boto3.dynamodb.conditions import Key

    pk = f"CREATOR#{user_id}"
    key_cond = Key("pk").eq(pk) & Key("sk").between(
        f"DAILY#{from_date}", f"DAILY#{to_date}"
    )
    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {"KeyConditionExpression": key_cond}
    while True:
        try:
            resp = T.analytics_rollups.query(**kwargs)
        except Exception:
            logger.exception("Failed to query rollups for engagement: %s", user_id)
            break
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return items


def _days_ago(n: int) -> str:
    return (datetime.utcnow() - timedelta(days=n)).strftime(_DATE_FMT)


def _today() -> str:
    return datetime.utcnow().strftime(_DATE_FMT)


def _get_follower_count(user_id: str) -> int:
    """Resolve current follower count via the social service."""
    try:
        from app.services.social import get_follow_counts

        return _to_int(get_follow_counts(user_id).get("follower_count", 0))
    except Exception:
        logger.warning("get_follow_counts failed for %s", user_id, exc_info=True)
        return 0


def _aggregate_engagement(items: List[Dict[str, Any]]) -> Dict[str, int]:
    """Sum engagement fields across rollup rows."""
    likes = comments = shares = tips = posts = interactions = 0
    for it in items:
        likes += _to_int(it.get("engagement_likes", 0))
        comments += _to_int(it.get("engagement_comments", 0))
        shares += _to_int(it.get("engagement_shares", 0))
        tips += _to_int(it.get("engagement_tips", 0))
        posts += _to_int(it.get("post_count", 0))
        # Prefer the stored total_interactions; fall back to recomputing.
        stored = _to_int(it.get("total_interactions", 0))
        if stored:
            interactions += stored
        else:
            interactions += compute_daily_engagement(
                it.get("engagement_likes", 0),
                it.get("engagement_comments", 0),
                it.get("engagement_shares", 0),
                it.get("engagement_tips", 0),
            )
    return {
        "likes": likes,
        "comments": comments,
        "shares": shares,
        "tips": tips,
        "posts": posts,
        "interactions": interactions,
    }


# ── public service functions ───────────────────────────────────────


def get_engagement_summary(user_id: str, period_days: int = DEFAULT_PERIOD_DAYS) -> Dict[str, Any]:
    """Compute the creator's engagement rate over the trailing ``period_days``.

    Reads the extended daily rollups, aggregates interactions, and divides by
    ``follower_count * posts_in_period``. Deterministic. Zero-safe.

    Also computes a ``trend`` (up/down/stable) by comparing against the
    immediately preceding window of the same length.
    """
    if period_days not in VALID_PERIOD_DAYS:
        period_days = DEFAULT_PERIOD_DAYS

    to_date = _today()
    from_date = _days_ago(period_days - 1)
    items = _query_rollups(user_id, from_date, to_date)
    agg = _aggregate_engagement(items)

    followers = _get_follower_count(user_id)
    rate_bps = calculate_engagement_rate_bps(
        interactions=agg["interactions"],
        followers=followers,
        post_count=agg["posts"],
    )

    # Previous window for trend.
    prev_to = _days_ago(period_days)
    prev_from = _days_ago(period_days * 2 - 1)
    prev_items = _query_rollups(user_id, prev_from, prev_to)
    prev_agg = _aggregate_engagement(prev_items)
    prev_bps = calculate_engagement_rate_bps(
        interactions=prev_agg["interactions"],
        followers=followers,
        post_count=prev_agg["posts"],
    )

    delta_bps = rate_bps - prev_bps
    if delta_bps > 0:
        trend = "up"
    elif delta_bps < 0:
        trend = "down"
    else:
        trend = "stable"

    return {
        "engagement_rate_bps": rate_bps,
        "engagement_rate": bps_to_percent(rate_bps),
        "period_days": period_days,
        "total_interactions": agg["interactions"],
        "follower_count": followers,
        "posts_in_period": agg["posts"],
        "likes": agg["likes"],
        "comments": agg["comments"],
        "shares": agg["shares"],
        "tips": agg["tips"],
        "trend": trend,
        "trend_delta": bps_to_percent(delta_bps) if delta_bps >= 0 else -bps_to_percent(-delta_bps),
    }


def get_engagement_history(
    user_id: str,
    from_date: str,
    to_date: str,
) -> List[Dict[str, Any]]:
    """Engagement-rate time series from the daily rollups.

    Each item: ``{date, engagement_rate, engagement_rate_bps, interactions,
    post_count}``. Per-day rate is computed against that day's follower
    snapshot (falling back to the current follower count).
    """
    items = _query_rollups(user_id, from_date, to_date)
    current_followers = _get_follower_count(user_id)

    out: List[Dict[str, Any]] = []
    for it in items:
        sk = it.get("sk", "")
        date_str = sk.replace("DAILY#", "")
        likes = _to_int(it.get("engagement_likes", 0))
        comments = _to_int(it.get("engagement_comments", 0))
        shares = _to_int(it.get("engagement_shares", 0))
        tips = _to_int(it.get("engagement_tips", 0))
        post_count = _to_int(it.get("post_count", 0))
        interactions = _to_int(it.get("total_interactions", 0)) or compute_daily_engagement(
            likes, comments, shares, tips
        )
        followers = _to_int(it.get("follower_snapshot", 0)) or current_followers
        stored_bps = it.get("engagement_rate_bps")
        if stored_bps is not None:
            rate_bps = _to_int(stored_bps)
        else:
            rate_bps = calculate_engagement_rate_bps(
                interactions=interactions,
                followers=followers,
                post_count=post_count,
            )
        out.append({
            "date": date_str,
            "engagement_rate": bps_to_percent(rate_bps),
            "engagement_rate_bps": rate_bps,
            "interactions": interactions,
            "post_count": post_count,
        })
    out.sort(key=lambda r: r["date"])
    return out


# ── public-profile visibility toggle ───────────────────────────────


def set_public_engagement_visibility(user_id: str, visible: bool) -> None:
    """Persist whether the engagement rate is shown on the public profile.

    Stored on the SUMMARY sentinel row (PK=CREATOR#{user}, SK=SUMMARY).
    """
    pk = f"CREATOR#{user_id}"
    try:
        T.analytics_rollups.update_item(
            Key={"pk": pk, "sk": "SUMMARY"},
            UpdateExpression="SET show_engagement_public = :v, updated_at = :now",
            ExpressionAttributeValues={":v": bool(visible), ":now": now_ts()},
        )
    except Exception:
        logger.exception("Failed to set public engagement visibility for %s", user_id)


def _get_summary(user_id: str) -> Dict[str, Any]:
    try:
        resp = T.analytics_rollups.get_item(Key={"pk": f"CREATOR#{user_id}", "sk": "SUMMARY"})
        return resp.get("Item") or {}
    except Exception:
        logger.exception("Failed to read engagement summary for %s", user_id)
        return {}


def is_public_engagement_enabled(user_id: str) -> bool:
    return bool(_get_summary(user_id).get("show_engagement_public"))


def get_public_engagement(user_id: str) -> Optional[Dict[str, Any]]:
    """Public-profile engagement payload, or ``None`` if the creator opted out."""
    if not is_public_engagement_enabled(user_id):
        return None
    summary_30 = get_engagement_summary(user_id, 30)
    summary_7 = get_engagement_summary(user_id, 7)
    return {
        "engagement_rate_30d": summary_30["engagement_rate"],
        "engagement_rate_7d": summary_7["engagement_rate"],
        "visible": True,
    }
