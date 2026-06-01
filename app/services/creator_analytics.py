"""Creator Analytics Dashboard service (ANALYTICS-001).

Reads pre-aggregated rollup rows from the analytics_rollups DynamoDB table
and returns structured metrics for the creator dashboard endpoints.
"""

from __future__ import annotations

import logging
import os
from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.aws import ddb
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ISO-3166 country code to name mapping (top countries)
_COUNTRY_NAMES: Dict[str, str] = {
    "US": "United States", "GB": "United Kingdom", "DE": "Germany",
    "CA": "Canada", "AU": "Australia", "FR": "France", "JP": "Japan",
    "BR": "Brazil", "IN": "India", "MX": "Mexico", "IT": "Italy",
    "ES": "Spain", "NL": "Netherlands", "KR": "South Korea", "SE": "Sweden",
    "NO": "Norway", "DK": "Denmark", "FI": "Finland", "PL": "Poland",
    "CH": "Switzerland", "AT": "Austria", "BE": "Belgium", "IE": "Ireland",
    "NZ": "New Zealand", "SG": "Singapore", "HK": "Hong Kong",
    "AR": "Argentina", "CO": "Colombia", "CL": "Chile", "ZA": "South Africa",
}


def _to_int(val: Any) -> int:
    """Coerce DynamoDB Decimal or string to int."""
    if isinstance(val, Decimal):
        return int(val)
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str) and val.lstrip("-").isdigit():
        return int(val)
    return 0


def _to_float(val: Any) -> float:
    if isinstance(val, Decimal):
        return float(val)
    if isinstance(val, (int, float)):
        return float(val)
    return 0.0


def _parse_date(s: str) -> Optional[datetime]:
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except (ValueError, TypeError):
        return None


def _date_range_str(from_date: str, to_date: str) -> List[str]:
    """Generate list of YYYY-MM-DD strings between from_date and to_date inclusive."""
    start = _parse_date(from_date)
    end = _parse_date(to_date)
    if not start or not end or start > end:
        return []
    dates = []
    current = start
    while current <= end:
        dates.append(current.strftime("%Y-%m-%d"))
        current += timedelta(days=1)
    return dates


def _query_rollups(user_id: str, from_date: str, to_date: str) -> List[Dict[str, Any]]:
    """Query daily rollup rows for a creator in a date range."""
    pk = f"CREATOR#{user_id}"
    sk_start = f"DAILY#{from_date}"
    sk_end = f"DAILY#{to_date}"

    key_cond = Key("pk").eq(pk) & Key("sk").between(sk_start, sk_end)

    items: List[Dict[str, Any]] = []
    query_kwargs: Dict[str, Any] = {"KeyConditionExpression": key_cond}

    while True:
        try:
            resp = T.analytics_rollups.query(**query_kwargs)
        except Exception:
            logger.exception("Failed to query analytics rollups for %s", user_id)
            break
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key

    return items


def _get_summary_sentinel(user_id: str) -> Dict[str, Any]:
    """Get the SUMMARY sentinel row for a creator (lifetime totals)."""
    pk = f"CREATOR#{user_id}"
    try:
        resp = T.analytics_rollups.get_item(Key={"pk": pk, "sk": "SUMMARY"})
        return resp.get("Item") or {}
    except Exception:
        logger.exception("Failed to get analytics summary for %s", user_id)
        return {}


def _aggregate_by_granularity(
    items: List[Dict[str, Any]],
    granularity: str,
) -> List[Dict[str, Any]]:
    """Aggregate daily items into weekly or monthly buckets if needed."""
    if granularity == "day" or not items:
        return items

    buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for item in items:
        sk = item.get("sk", "")
        date_str = sk.replace("DAILY#", "")
        dt = _parse_date(date_str)
        if not dt:
            continue
        if granularity == "week":
            # ISO week: Monday start
            week_start = dt - timedelta(days=dt.weekday())
            bucket_key = week_start.strftime("%Y-%m-%d")
        elif granularity == "month":
            bucket_key = dt.strftime("%Y-%m-01")
        else:
            bucket_key = date_str
        buckets[bucket_key].append(item)

    aggregated = []
    for bucket_date in sorted(buckets.keys()):
        bucket_items = buckets[bucket_date]
        merged = _merge_rollup_items(bucket_items, bucket_date)
        aggregated.append(merged)
    return aggregated


def _merge_rollup_items(items: List[Dict[str, Any]], label_date: str) -> Dict[str, Any]:
    """Merge multiple daily rollup items into one aggregated item."""
    merged: Dict[str, Any] = {"sk": f"DAILY#{label_date}"}
    int_fields = [
        "total_views", "unique_viewers", "watch_time_seconds",
        "revenue_cents", "revenue_tips_cents", "revenue_subscriptions_cents",
        "revenue_unlocks_cents", "revenue_vod_cents", "revenue_ads_cents",
        "revenue_calls_cents", "new_subscribers", "churned_subscribers",
        "net_subscribers", "post_reactions", "post_comments",
    ]
    for field in int_fields:
        merged[field] = sum(_to_int(item.get(field, 0)) for item in items)

    # For total_subscribers, take the last day's value
    if items:
        merged["total_subscribers"] = _to_int(items[-1].get("total_subscribers", 0))

    # Merge audience maps
    countries: Dict[str, int] = defaultdict(int)
    devices: Dict[str, int] = defaultdict(int)
    for item in items:
        for code, count in (item.get("audience_countries") or {}).items():
            countries[code] += _to_int(count)
        for dtype, count in (item.get("audience_devices") or {}).items():
            devices[dtype] += _to_int(count)
    merged["audience_countries"] = dict(countries)
    merged["audience_devices"] = dict(devices)

    # Merge top_content_ids (unique, preserve order)
    seen = set()
    top_ids = []
    for item in items:
        for cid in (item.get("top_content_ids") or []):
            if cid not in seen:
                seen.add(cid)
                top_ids.append(cid)
    merged["top_content_ids"] = top_ids[:20]

    return merged


# ── Public query functions ──────────────────────────────────────


def get_overview(user_id: str, from_date: str, to_date: str) -> Dict[str, Any]:
    """Get analytics overview (summary cards)."""
    items = _query_rollups(user_id, from_date, to_date)
    summary = _get_summary_sentinel(user_id)

    period_views = sum(_to_int(i.get("total_views", 0)) for i in items)
    period_revenue = sum(_to_int(i.get("revenue_cents", 0)) for i in items)
    period_new_subs = sum(_to_int(i.get("new_subscribers", 0)) for i in items)
    total_subscribers = _to_int(summary.get("total_subscribers", 0))
    if items:
        # Use the latest day's total_subscribers if available
        total_subscribers = max(total_subscribers, _to_int(items[-1].get("total_subscribers", 0)))

    # Collect top content IDs across the period
    content_scores: Dict[str, Dict[str, int]] = defaultdict(lambda: {"views": 0, "revenue_cents": 0})
    for item in items:
        for cid in (item.get("top_content_ids") or []):
            content_scores[cid]["views"] += _to_int(item.get("total_views", 0))

    top_content = []
    sorted_content = sorted(content_scores.items(), key=lambda x: x[1]["views"], reverse=True)[:5]
    for cid, scores in sorted_content:
        content_type = "vod" if cid.startswith("vid_") else "post"
        top_content.append({
            "content_id": cid,
            "content_type": content_type,
            "title": cid,
            "views": scores["views"],
            "revenue_cents": scores["revenue_cents"],
        })

    return {
        "period_views": period_views,
        "period_revenue_cents": period_revenue,
        "period_new_subscribers": period_new_subs,
        "total_subscribers": total_subscribers,
        "top_content": top_content,
        "currency": "USD",
    }


def get_revenue(
    user_id: str, from_date: str, to_date: str, granularity: str = "day"
) -> Dict[str, Any]:
    """Get revenue breakdown and time series."""
    items = _query_rollups(user_id, from_date, to_date)
    aggregated = _aggregate_by_granularity(items, granularity)

    total_cents = 0
    breakdown = {"tips": 0, "subscriptions": 0, "unlocks": 0, "vod": 0, "ads": 0, "calls": 0}
    time_series = []

    for item in aggregated:
        sk = item.get("sk", "")
        date_str = sk.replace("DAILY#", "")
        tips = _to_int(item.get("revenue_tips_cents", 0))
        subs = _to_int(item.get("revenue_subscriptions_cents", 0))
        unlocks = _to_int(item.get("revenue_unlocks_cents", 0))
        vod = _to_int(item.get("revenue_vod_cents", 0))
        ads = _to_int(item.get("revenue_ads_cents", 0))
        calls = _to_int(item.get("revenue_calls_cents", 0))
        day_total = tips + subs + unlocks + vod + ads + calls

        total_cents += day_total
        breakdown["tips"] += tips
        breakdown["subscriptions"] += subs
        breakdown["unlocks"] += unlocks
        breakdown["vod"] += vod
        breakdown["ads"] += ads
        breakdown["calls"] += calls

        time_series.append({
            "date": date_str,
            "total_cents": day_total,
            "tips_cents": tips,
            "subscriptions_cents": subs,
            "unlocks_cents": unlocks,
            "vod_cents": vod,
            "ads_cents": ads,
            "calls_cents": calls,
        })

    return {
        "total_cents": total_cents,
        "breakdown": breakdown,
        "time_series": time_series,
        "currency": "USD",
    }


def get_views(
    user_id: str, from_date: str, to_date: str, granularity: str = "day"
) -> Dict[str, Any]:
    """Get view metrics time series."""
    items = _query_rollups(user_id, from_date, to_date)
    aggregated = _aggregate_by_granularity(items, granularity)

    total_views = 0
    total_watch_time = 0
    time_series = []

    for item in aggregated:
        sk = item.get("sk", "")
        date_str = sk.replace("DAILY#", "")
        views = _to_int(item.get("total_views", 0))
        unique = _to_int(item.get("unique_viewers", 0))
        watch = _to_int(item.get("watch_time_seconds", 0))

        total_views += views
        total_watch_time += watch

        time_series.append({
            "date": date_str,
            "views": views,
            "unique_viewers": unique,
            "watch_time_seconds": watch,
        })

    return {
        "time_series": time_series,
        "total_views": total_views,
        "total_watch_time_seconds": total_watch_time,
    }


def get_subscribers(
    user_id: str, from_date: str, to_date: str, granularity: str = "day"
) -> Dict[str, Any]:
    """Get subscriber growth time series."""
    items = _query_rollups(user_id, from_date, to_date)
    aggregated = _aggregate_by_granularity(items, granularity)

    summary = _get_summary_sentinel(user_id)
    current_total = _to_int(summary.get("total_subscribers", 0))
    net_change = 0
    time_series = []

    for item in aggregated:
        sk = item.get("sk", "")
        date_str = sk.replace("DAILY#", "")
        new = _to_int(item.get("new_subscribers", 0))
        churned = _to_int(item.get("churned_subscribers", 0))
        net = _to_int(item.get("net_subscribers", 0))
        total = _to_int(item.get("total_subscribers", 0))

        net_change += net

        time_series.append({
            "date": date_str,
            "new": new,
            "churned": churned,
            "net": net,
            "total": total,
        })

    if items:
        current_total = max(current_total, _to_int(items[-1].get("total_subscribers", 0)))

    return {
        "time_series": time_series,
        "current_total": current_total,
        "net_change": net_change,
    }


def _resolve_content_details(content_ids: list) -> Dict[str, Dict[str, Any]]:
    """Batch-resolve title and engagement metrics for content IDs.

    Performs lookups to video_metadata and newsfeed (app_single_table) tables.
    Returns a dict keyed by content_id with title, views, likes, comments.
    """
    if not content_ids:
        return {}

    result: Dict[str, Dict[str, Any]] = {}
    video_ids = [cid for cid in content_ids if cid.startswith("vid_")]
    post_ids = [cid for cid in content_ids if not cid.startswith("vid_")]

    # Batch get video metadata
    if video_ids:
        try:
            table_name = S.video_metadata_table_name
            resp = ddb.batch_get_item(
                RequestItems={
                    table_name: {
                        "Keys": [{"video_id": vid} for vid in video_ids[:100]],
                        "ProjectionExpression": "video_id, title, view_count, like_count, comment_count",
                    }
                }
            )
            for item in resp.get("Responses", {}).get(table_name, []):
                vid = item["video_id"]
                result[vid] = {
                    "title": item.get("title") or vid,
                    "views": _to_int(item.get("view_count", 0)),
                    "likes": _to_int(item.get("like_count", 0)),
                    "comments": _to_int(item.get("comment_count", 0)),
                }
        except Exception:
            logger.warning("batch_get video_metadata failed", exc_info=True)

    # Fill in defaults for missing videos
    for vid in video_ids:
        if vid not in result:
            result[vid] = {"title": vid, "views": 0, "likes": 0, "comments": 0}

    # Get post metadata from newsfeed table (app_single_table)
    app_table_name = os.environ.get("APP_TABLE", "app_single_table")
    app_table = ddb.Table(app_table_name)
    for pid in post_ids:
        try:
            resp = app_table.get_item(
                Key={"pk": f"POST#{pid}", "sk": "META"},
            )
            item = resp.get("Item", {})
            if item:
                body = item.get("body_plain", item.get("body", "")) or ""
                title = (body[:60] + "...") if len(body) > 60 else (body or pid)
                result[pid] = {
                    "title": title,
                    "views": _to_int(item.get("view_count", 0)),
                    "likes": _to_int(item.get("like_count", 0)),
                    "comments": _to_int(item.get("comment_count", 0)),
                }
            else:
                result[pid] = {"title": pid, "views": 0, "likes": 0, "comments": 0}
        except Exception:
            result[pid] = {"title": pid, "views": 0, "likes": 0, "comments": 0}

    return result


def get_top_content(
    user_id: str,
    from_date: str,
    to_date: str,
    sort_by: str = "views",
    limit: int = 20,
) -> Dict[str, Any]:
    """Get top content items ranked by views or revenue."""
    items = _query_rollups(user_id, from_date, to_date)

    # Aggregate content_ids from rollup items
    content_scores: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"views": 0, "revenue_cents": 0}
    )
    for item in items:
        for cid in (item.get("top_content_ids") or []):
            content_scores[cid]["views"] += _to_int(item.get("total_views", 0))
            content_scores[cid]["revenue_cents"] += _to_int(item.get("revenue_cents", 0))

    sort_key = "revenue_cents" if sort_by == "revenue" else "views"
    sorted_content = sorted(
        content_scores.items(), key=lambda x: x[1][sort_key], reverse=True
    )

    total_items = len(sorted_content)
    sorted_content = sorted_content[:limit]

    # Resolve titles and engagement metrics from content metadata tables
    details = _resolve_content_details([cid for cid, _ in sorted_content])

    result_items = []
    for cid, scores in sorted_content:
        content_type = "vod" if cid.startswith("vid_") else "post"
        d = details.get(cid, {})
        views = d.get("views") if d.get("views") is not None else scores["views"]
        likes = d.get("likes", 0)
        comments = d.get("comments", 0)
        engagement = (likes + comments) / views if views > 0 else 0.0

        result_items.append({
            "content_id": cid,
            "content_type": content_type,
            "title": d.get("title", cid),
            "views": views,
            "revenue_cents": scores["revenue_cents"],
            "engagement_rate": round(engagement, 4),
        })

    return {
        "items": result_items,
        "total_items": total_items,
    }


def get_audience(user_id: str, from_date: str, to_date: str) -> Dict[str, Any]:
    """Get audience demographic breakdown."""
    items = _query_rollups(user_id, from_date, to_date)

    countries: Dict[str, int] = defaultdict(int)
    devices: Dict[str, int] = defaultdict(int)
    total_unique = 0

    for item in items:
        total_unique += _to_int(item.get("unique_viewers", 0))
        for code, count in (item.get("audience_countries") or {}).items():
            countries[code] += _to_int(count)
        for dtype, count in (item.get("audience_devices") or {}).items():
            devices[dtype] += _to_int(count)

    total_country_viewers = sum(countries.values()) or 1
    total_device_viewers = sum(devices.values()) or 1

    country_items = []
    for code, viewers in sorted(countries.items(), key=lambda x: x[1], reverse=True):
        country_items.append({
            "code": code,
            "name": _COUNTRY_NAMES.get(code, code),
            "viewers": viewers,
            "percentage": round(viewers / total_country_viewers * 100, 1),
        })

    device_items = []
    for dtype, viewers in sorted(devices.items(), key=lambda x: x[1], reverse=True):
        device_items.append({
            "type": dtype,
            "viewers": viewers,
            "percentage": round(viewers / total_device_viewers * 100, 1),
        })

    return {
        "countries": country_items,
        "devices": device_items,
        "total_unique_viewers": total_unique,
    }


# ── Rollup write functions ──────────────────────────────────────


def upsert_daily_rollup(user_id: str, date_str: str, data: Dict[str, Any]) -> None:
    """Write or update a daily rollup row for a creator.

    FIN-012: extends the rollup with engagement fields (likes, comments,
    shares, tips, post_count, follower snapshot) and a deterministically
    computed daily ``engagement_rate_bps`` (basis points). Engagement inputs
    are read from the caller-supplied ``data`` (or its ``post_reactions`` /
    ``post_comments`` aliases) so the rollup carries everything the engagement
    endpoints need without a second write.
    """
    pk = f"CREATOR#{user_id}"
    sk = f"DAILY#{date_str}"
    now = now_ts()

    item: Dict[str, Any] = {
        "pk": pk,
        "sk": sk,
        "date_scope": f"DATE#{date_str}",
        "created_at": now,
        "updated_at": now,
    }
    item.update(data)

    # ── FIN-012: engagement enrichment ─────────────────────────────
    try:
        from app.services.engagement_rate import (
            build_engagement_rollup_fields,
            _get_follower_count,
        )

        likes = data.get("engagement_likes", data.get("post_reactions", 0))
        comments = data.get("engagement_comments", data.get("post_comments", 0))
        shares = data.get("engagement_shares", 0)
        tips = data.get("engagement_tips", 0)
        post_count = data.get("post_count", 0)
        follower_count = data.get("follower_snapshot")
        if follower_count is None:
            follower_count = _get_follower_count(user_id)

        engagement_fields = build_engagement_rollup_fields(
            likes=likes,
            comments=comments,
            shares=shares,
            tips=tips,
            post_count=post_count,
            follower_count=follower_count,
        )
        # Caller-supplied explicit engagement fields win; otherwise fill in.
        for k, v in engagement_fields.items():
            item.setdefault(k, v)
        # engagement_rate_bps is always recomputed deterministically.
        item["engagement_rate_bps"] = engagement_fields["engagement_rate_bps"]
    except Exception:
        logger.warning("Engagement enrichment failed for %s on %s", user_id, date_str, exc_info=True)

    try:
        T.analytics_rollups.put_item(Item=item)
    except Exception:
        logger.exception("Failed to write analytics rollup for %s on %s", user_id, date_str)


def upsert_summary_sentinel(user_id: str, data: Dict[str, Any]) -> None:
    """Write or update the SUMMARY sentinel for a creator."""
    pk = f"CREATOR#{user_id}"
    now = now_ts()

    item: Dict[str, Any] = {
        "pk": pk,
        "sk": "SUMMARY",
        "updated_at": now,
    }
    item.update(data)

    try:
        T.analytics_rollups.put_item(Item=item)
    except Exception:
        logger.exception("Failed to write analytics summary for %s", user_id)


# ── Per-content detail functions (ANALYTICS-002) ──────────────


def get_content_detail(
    user_id: str,
    content_id: str,
    from_date: str,
    to_date: str,
    granularity: str = "day",
) -> Optional[Dict[str, Any]]:
    """Get per-content analytics: view time series, revenue breakdown, engagement.

    Returns None if content does not exist.
    Returns {"error": "forbidden"} if user is not the content owner.
    """
    is_video = content_id.startswith("vid_")

    # Step 1: Look up content metadata
    if is_video:
        resp = T.video_metadata.get_item(Key={"video_id": content_id})
        item = resp.get("Item")
        if not item:
            return None
        if item.get("owner_user_id") != user_id and item.get("owner_id") != user_id:
            return {"error": "forbidden"}
        title = item.get("title") or content_id
        thumbnail_url = item.get("thumbnail_url")
        published_at = _to_int(item.get("created_at", 0))
        total_views = _to_int(item.get("view_count", 0))
        like_count = _to_int(item.get("like_count", 0))
        comment_count = _to_int(item.get("comment_count", 0))
    else:
        app_table_name = os.environ.get("APP_TABLE", "app_single_table")
        app_table = ddb.Table(app_table_name)
        resp = app_table.get_item(Key={"pk": f"POST#{content_id}", "sk": "META"})
        item = resp.get("Item")
        if not item:
            return None
        if item.get("user_id") != user_id and item.get("author_id") != user_id:
            return {"error": "forbidden"}
        body = item.get("body_plain", item.get("body", "")) or ""
        title = (body[:60] + "...") if len(body) > 60 else (body or content_id)
        thumbnail_url = (item.get("image_urls") or [None])[0]
        published_at = _to_int(item.get("created_at", 0))
        total_views = _to_int(item.get("view_count", 0))
        like_count = _to_int(item.get("like_count", 0))
        comment_count = _to_int(item.get("comment_count", 0))

    engagement_rate = round(
        (like_count + comment_count) / total_views if total_views > 0 else 0.0,
        4,
    )

    # Step 2: View time series
    view_time_series = _get_content_view_time_series(
        content_id, is_video, from_date, to_date, granularity
    )

    # Step 3: Revenue breakdown
    revenue_breakdown = _get_content_revenue_breakdown(user_id, content_id)
    total_revenue_cents = sum(revenue_breakdown.values())

    return {
        "content_id": content_id,
        "content_type": "vod" if is_video else "post",
        "title": title,
        "thumbnail_url": thumbnail_url,
        "published_at": published_at,
        "total_views": total_views,
        "total_revenue_cents": total_revenue_cents,
        "engagement_rate": engagement_rate,
        "like_count": like_count,
        "comment_count": comment_count,
        "view_time_series": view_time_series,
        "revenue_breakdown": revenue_breakdown,
        "currency": "USD",
    }


def _get_content_view_time_series(
    content_id: str,
    is_video: bool,
    from_date: str,
    to_date: str,
    granularity: str,
) -> List[Dict[str, Any]]:
    """Build a view time series for a specific content item."""
    if is_video:
        try:
            from_ts = int(datetime.strptime(from_date, "%Y-%m-%d").timestamp())
            to_ts = int(datetime.strptime(to_date, "%Y-%m-%d").timestamp()) + 86400
            resp = T.video_views.query(
                IndexName="ByVideoViewedAt",
                KeyConditionExpression=(
                    Key("video_id").eq(content_id)
                    & Key("viewed_at").between(from_ts, to_ts)
                ),
                Select="ALL_ATTRIBUTES",
            )
            view_items = resp.get("Items", [])
            # Group by date
            day_counts: Dict[str, int] = defaultdict(int)
            day_unique: Dict[str, set] = defaultdict(set)
            for vi in view_items:
                vat = _to_int(vi.get("viewed_at", 0))
                if vat > 0:
                    d = datetime.utcfromtimestamp(vat).strftime("%Y-%m-%d")
                    day_counts[d] += 1
                    viewer = vi.get("viewer_id", vi.get("user_id", ""))
                    if viewer:
                        day_unique[d].add(viewer)

            # Fill dates
            series = []
            current = datetime.strptime(from_date, "%Y-%m-%d")
            end = datetime.strptime(to_date, "%Y-%m-%d")
            while current <= end:
                ds = current.strftime("%Y-%m-%d")
                series.append({
                    "date": ds,
                    "views": day_counts.get(ds, 0),
                    "unique_viewers": len(day_unique.get(ds, set())),
                })
                if granularity == "week":
                    current += timedelta(days=7)
                elif granularity == "month":
                    current += timedelta(days=30)
                else:
                    current += timedelta(days=1)
            return series
        except Exception:
            logger.warning("Video views query failed for %s", content_id, exc_info=True)

    # Fallback: generate empty time series for the date range
    series = []
    current = datetime.strptime(from_date, "%Y-%m-%d")
    end = datetime.strptime(to_date, "%Y-%m-%d")
    while current <= end:
        series.append({
            "date": current.strftime("%Y-%m-%d"),
            "views": 0,
            "unique_viewers": 0,
        })
        if granularity == "week":
            current += timedelta(days=7)
        elif granularity == "month":
            current += timedelta(days=30)
        else:
            current += timedelta(days=1)
    return series


def _get_content_revenue_breakdown(user_id: str, content_id: str) -> Dict[str, int]:
    """Scan billing ledger for revenue entries attributed to a specific content item."""
    breakdown: Dict[str, int] = {"tips": 0, "unlocks": 0, "vod": 0}
    lek = None
    pages = 0

    while pages < 4:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(f"USER#{user_id}") & Key("sk").begins_with("LEDGER#"),
            "Limit": 500,
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek

        try:
            resp = T.billing.query(**kwargs)
        except Exception:
            logger.warning("Billing query failed for content revenue", exc_info=True)
            break

        for item in resp.get("Items", []):
            meta = item.get("meta") or {}
            if isinstance(meta, str):
                continue
            if meta.get("content_id") != content_id and meta.get("video_id") != content_id:
                continue
            amount = _to_int(item.get("amount_cents", 0))
            reason = (item.get("reason") or "").lower()
            if "tip" in reason:
                breakdown["tips"] += amount
            elif "unlock" in reason:
                breakdown["unlocks"] += amount
            elif "vod" in reason or "purchase" in reason:
                breakdown["vod"] += amount
            else:
                breakdown["tips"] += amount

        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        pages += 1

    return breakdown
