"""Ad analytics — pre-computed rollups, summary, time series, breakdowns, CSV export."""

from __future__ import annotations

import asyncio
import csv
import io
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from boto3.dynamodb.conditions import Attr, Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def get_summary(
    account_id: str,
    campaign_id: Optional[str] = None,
    days: int = 30,
) -> dict:
    """Get aggregated KPI summary for an account or campaign."""
    rollups = _fetch_daily_rollups(account_id, campaign_id, days)

    total_impressions = sum(int(r.get("impressions", 0)) for r in rollups)
    total_clicks = sum(int(r.get("clicks", 0)) for r in rollups)
    total_spend = sum(int(r.get("spend_cents", 0)) for r in rollups)
    total_completes = sum(int(r.get("completes", 0)) for r in rollups)
    total_skips = sum(int(r.get("skips", 0)) for r in rollups)

    ctr = (total_clicks / total_impressions * 100) if total_impressions > 0 else 0.0
    cpa = (total_spend / total_clicks) if total_clicks > 0 else 0
    effective_cpm = (total_spend / total_impressions * 1000) if total_impressions > 0 else 0

    # Previous period comparison
    prev_rollups = _fetch_daily_rollups(account_id, campaign_id, days, offset_days=days)
    prev_impressions = sum(int(r.get("impressions", 0)) for r in prev_rollups)
    prev_clicks = sum(int(r.get("clicks", 0)) for r in prev_rollups)
    prev_spend = sum(int(r.get("spend_cents", 0)) for r in prev_rollups)

    return {
        "impressions": total_impressions,
        "clicks": total_clicks,
        "ctr_pct": round(ctr, 2),
        "spend_cents": total_spend,
        "cpa_cents": cpa,
        "effective_cpm_cents": round(effective_cpm, 2),
        "completes": total_completes,
        "skips": total_skips,
        "completion_rate_pct": round(
            total_completes / max(1, total_impressions) * 100, 2
        ),
        "previous_period": {
            "impressions": prev_impressions,
            "clicks": prev_clicks,
            "spend_cents": prev_spend,
        },
        "impressions_change_pct": _pct_change(prev_impressions, total_impressions),
        "clicks_change_pct": _pct_change(prev_clicks, total_clicks),
        "spend_change_pct": _pct_change(prev_spend, total_spend),
        "days": days,
    }


def get_timeseries(
    account_id: str,
    campaign_id: Optional[str] = None,
    days: int = 30,
    granularity: str = "daily",
) -> list[dict]:
    """Get time-series data points for charting."""
    rollups = _fetch_rollups(account_id, campaign_id, days, granularity)
    points = [
        {
            "date": r.get("date", ""),
            "impressions": int(r.get("impressions", 0)),
            "clicks": int(r.get("clicks", 0)),
            "spend_cents": int(r.get("spend_cents", 0)),
            "completes": int(r.get("completes", 0)),
            "ctr_pct": round(
                int(r.get("clicks", 0))
                / max(1, int(r.get("impressions", 1)))
                * 100,
                2,
            ),
        }
        for r in rollups
    ]
    # Sort ascending by date
    points.sort(key=lambda p: p["date"])
    return points


def get_breakdown(
    account_id: str,
    campaign_id: Optional[str] = None,
    dimension: str = "creative",
    days: int = 30,
) -> list[dict]:
    """Get metrics broken down by a dimension (creative, surface, targeting)."""
    rollups = _fetch_daily_rollups(account_id, campaign_id, days)

    aggregated: Dict[str, Dict[str, int]] = {}
    dim_key = f"by_{dimension}"

    for r in rollups:
        dim_data = r.get(dim_key, {})
        if isinstance(dim_data, dict):
            for key, metrics in dim_data.items():
                if key not in aggregated:
                    aggregated[key] = {
                        "impressions": 0,
                        "clicks": 0,
                        "spend_cents": 0,
                    }
                if isinstance(metrics, dict):
                    aggregated[key]["impressions"] += int(
                        metrics.get("impressions", 0)
                    )
                    aggregated[key]["clicks"] += int(metrics.get("clicks", 0))
                    aggregated[key]["spend_cents"] += int(
                        metrics.get("spend_cents", 0)
                    )

    result = []
    for key, metrics in aggregated.items():
        ctr = metrics["clicks"] / max(1, metrics["impressions"]) * 100
        result.append(
            {
                "dimension_key": key,
                "dimension": dimension,
                **metrics,
                "ctr_pct": round(ctr, 2),
            }
        )

    result.sort(key=lambda x: x["impressions"], reverse=True)
    return result


def export_csv(
    account_id: str,
    campaign_id: Optional[str],
    days: int = 30,
) -> str:
    """Export analytics data as CSV string."""
    timeseries = get_timeseries(account_id, campaign_id, days, "daily")

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "date",
            "impressions",
            "clicks",
            "ctr_pct",
            "spend_cents",
            "completes",
        ],
    )
    writer.writeheader()
    writer.writerows(timeseries)
    return output.getvalue()


def _bump_dim(
    d: Dict[str, Dict[str, int]],
    key: str,
    *,
    impressions: int = 0,
    clicks: int = 0,
    spend: int = 0,
) -> None:
    """Accumulate per-dimension counters into ``d[key]`` (pure, no I/O)."""
    entry = d.setdefault(
        key, {"impressions": 0, "clicks": 0, "spend_cents": 0}
    )
    entry["impressions"] += impressions
    entry["clicks"] += clicks
    entry["spend_cents"] += spend


def compute_hourly_rollup(
    campaign_id: str, account_id: str, hour: str
) -> dict:
    """Compute rollup for a specific campaign and hour.

    hour format: "2026-05-29T14"
    Called by the background rollup loop (``_ad_analytics_rollup_loop``).

    Counts impressions/clicks/spend from the ad_billing ledger and decomposes
    them into the ``by_creative`` / ``by_surface`` / ``by_targeting`` breakdown
    maps (GAP-0051). Only billing entries created within the ``hour`` window are
    counted (GAP-0050).
    """
    from app.services.ad_billing import get_campaign_spending

    # Parse the hour label into a [start, end) Unix-timestamp window so we
    # aggregate only this hour's activity rather than lifetime totals.
    try:
        hour_dt = datetime.strptime(hour, "%Y-%m-%dT%H").replace(
            tzinfo=timezone.utc
        )
        hour_start_ts = int(hour_dt.timestamp())
        hour_end_ts = hour_start_ts + 3600
    except ValueError:
        # Malformed hour label — count nothing rather than crash the loop.
        hour_start_ts = 0
        hour_end_ts = 0

    entries = get_campaign_spending(campaign_id, limit=5000)
    hour_entries = [
        e
        for e in entries
        if hour_start_ts <= int(e.get("created_at", 0)) < hour_end_ts
    ]

    impressions = 0
    clicks = 0
    spend = 0
    by_creative: Dict[str, Dict[str, int]] = {}
    by_surface: Dict[str, Dict[str, int]] = {}
    by_targeting: Dict[str, Dict[str, int]] = {}

    for e in hour_entries:
        etype = e.get("entry_type", "")
        amt = int(e.get("amount_cents", 0))
        spend += amt
        meta = e.get("meta") or {}
        creative_id = meta.get("creative_id") or "unknown"

        if etype == "impression_charge":
            impressions += 1
            _bump_dim(by_creative, creative_id, impressions=1, spend=amt)
        elif etype == "click_charge":
            clicks += 1
            _bump_dim(by_creative, creative_id, clicks=1, spend=amt)

    # Build by_surface / by_targeting from the ad_impressions records for this
    # campaign within the hour. A scan failure degrades to empty maps rather
    # than failing the whole rollup write.
    try:
        for imp in _fetch_campaign_impressions(
            campaign_id, hour_start_ts, hour_end_ts
        ):
            evt = imp.get("event_type", "")
            imp_inc = 1 if evt == "impression" else 0
            clk_inc = 1 if evt == "click" else 0

            surface = imp.get("surface") or "unknown"
            slot_type = imp.get("slot_type") or "unknown"
            _bump_dim(
                by_surface,
                f"{surface}/{slot_type}",
                impressions=imp_inc,
                clicks=clk_inc,
            )

            geo = imp.get("geo_country") or "unknown"
            _bump_dim(
                by_targeting, geo, impressions=imp_inc, clicks=clk_inc
            )
    except Exception:
        logger.warning(
            "ad_analytics_surface_build_failed",
            extra={"campaign_id": campaign_id, "hour": hour},
        )

    rollup: Dict[str, Any] = {
        "pk": f"CAMP#{campaign_id}",
        "sk": f"ROLLUP#hourly#{hour}",
        "campaign_id": campaign_id,
        "account_id": account_id,
        "period": "hourly",
        "date": hour,
        "impressions": impressions,
        "clicks": clicks,
        "skips": 0,
        "completes": 0,
        "spend_cents": spend,
        "revenue_cents": int(spend * 0.7),
        "unique_users": 0,
        "by_creative": by_creative,
        "by_surface": by_surface,
        "by_targeting": by_targeting,
        "computed_at": now_ts(),
    }

    T.ad_analytics_rollups.put_item(
        Item={k: v for k, v in rollup.items() if v is not None}
    )
    logger.info(
        "ad_analytics_rollup_completed",
        extra={
            "hour": hour,
            "campaign_id": campaign_id,
            "impressions": impressions,
            "clicks": clicks,
            "spend_cents": spend,
            "by_creative": len(by_creative),
            "by_surface": len(by_surface),
            "by_targeting": len(by_targeting),
        },
    )
    return rollup


def compute_daily_rollup(
    campaign_id: str, account_id: str, date: str
) -> dict:
    """Aggregate the 24 hourly rollup rows for ``date`` into one daily row.

    date format: "2026-05-29". Daily rows use the ``ROLLUP#daily#`` SK prefix,
    which is what the dashboard read path (``_fetch_daily_rollups``) queries.
    The breakdown maps are merged across the hourly rows.
    """
    resp = T.ad_analytics_rollups.query(
        KeyConditionExpression=Key("pk").eq(f"CAMP#{campaign_id}")
        & Key("sk").between(
            f"ROLLUP#hourly#{date}T00",
            f"ROLLUP#hourly#{date}T23z",
        ),
    )
    hourly_rows = resp.get("Items", [])

    impressions = sum(int(r.get("impressions", 0)) for r in hourly_rows)
    clicks = sum(int(r.get("clicks", 0)) for r in hourly_rows)
    spend = sum(int(r.get("spend_cents", 0)) for r in hourly_rows)
    completes = sum(int(r.get("completes", 0)) for r in hourly_rows)
    skips = sum(int(r.get("skips", 0)) for r in hourly_rows)

    by_creative: Dict[str, Dict[str, int]] = {}
    by_surface: Dict[str, Dict[str, int]] = {}
    by_targeting: Dict[str, Dict[str, int]] = {}
    for r in hourly_rows:
        _merge_dim(by_creative, r.get("by_creative"))
        _merge_dim(by_surface, r.get("by_surface"))
        _merge_dim(by_targeting, r.get("by_targeting"))

    rollup: Dict[str, Any] = {
        "pk": f"CAMP#{campaign_id}",
        "sk": f"ROLLUP#daily#{date}",
        "campaign_id": campaign_id,
        "account_id": account_id,
        "period": "daily",
        "date": date,
        "impressions": impressions,
        "clicks": clicks,
        "skips": skips,
        "completes": completes,
        "spend_cents": spend,
        "revenue_cents": int(spend * 0.7),
        "unique_users": 0,
        "by_creative": by_creative,
        "by_surface": by_surface,
        "by_targeting": by_targeting,
        "computed_at": now_ts(),
    }
    T.ad_analytics_rollups.put_item(
        Item={k: v for k, v in rollup.items() if v is not None}
    )
    return rollup


# ── Internal helpers ──────────────────────────────────────────────────


def _merge_dim(
    dst: Dict[str, Dict[str, int]], src: Any
) -> None:
    """Merge one stored breakdown map ``src`` into ``dst`` (sum counters)."""
    if not isinstance(src, dict):
        return
    for key, metrics in src.items():
        if not isinstance(metrics, dict):
            continue
        _bump_dim(
            dst,
            key,
            impressions=int(metrics.get("impressions", 0)),
            clicks=int(metrics.get("clicks", 0)),
            spend=int(metrics.get("spend_cents", 0)),
        )


def _fetch_campaign_impressions(
    campaign_id: str, start_ts: int, end_ts: int
) -> list[dict]:
    """Return ad_impressions rows for ``campaign_id`` within [start_ts, end_ts).

    Uses a paginated scan with a FilterExpression. This is acceptable for
    low-volume dev/early prod; a ``ByCampaign`` GSI on AdImpressions is the
    documented follow-on to replace the scan with a targeted query.
    """
    items: list[dict] = []
    last_key = None
    while True:
        scan_kwargs: dict = {
            "FilterExpression": Attr("campaign_id").eq(campaign_id)
            & Attr("created_at").gte(start_ts)
            & Attr("created_at").lt(end_ts),
        }
        if last_key:
            scan_kwargs["ExclusiveStartKey"] = last_key
        resp = T.ad_impressions.scan(**scan_kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return items


def _fetch_daily_rollups(
    account_id: str,
    campaign_id: Optional[str],
    days: int,
    offset_days: int = 0,
) -> list[dict]:
    now = datetime.now(timezone.utc) - timedelta(days=offset_days)
    # ``between`` is inclusive on both ends, so a ``days``-day window is
    # [today - (days - 1), today] — that's exactly ``days`` calendar days.
    # Using ``days`` here would span days + 1 days and pull in an extra row.
    start_date = (now - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    end_date = now.strftime("%Y-%m-%d")

    if campaign_id:
        resp = T.ad_analytics_rollups.query(
            KeyConditionExpression=Key("pk").eq(f"CAMP#{campaign_id}")
            & Key("sk").between(
                f"ROLLUP#daily#{start_date}",
                f"ROLLUP#daily#{end_date}z",
            ),
        )
    else:
        resp = T.ad_analytics_rollups.query(
            IndexName="ByAccountDate",
            KeyConditionExpression=Key("account_id").eq(account_id)
            & Key("date").between(start_date, end_date + "z"),
            FilterExpression=Attr("period").eq("daily"),
        )
    return resp.get("Items", [])


def _fetch_rollups(
    account_id: str,
    campaign_id: Optional[str],
    days: int,
    granularity: str,
) -> list[dict]:
    now = datetime.now(timezone.utc)
    # Inclusive ``between`` window: [today - (days - 1), today] == ``days`` days.
    start_date = (now - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    end_date = now.strftime("%Y-%m-%d")
    prefix = f"ROLLUP#{granularity}#"

    if campaign_id:
        resp = T.ad_analytics_rollups.query(
            KeyConditionExpression=Key("pk").eq(f"CAMP#{campaign_id}")
            & Key("sk").between(
                f"{prefix}{start_date}",
                f"{prefix}{end_date}z",
            ),
        )
    else:
        resp = T.ad_analytics_rollups.query(
            IndexName="ByAccountDate",
            KeyConditionExpression=Key("account_id").eq(account_id)
            & Key("date").between(start_date, end_date + "z"),
            FilterExpression=Attr("period").eq(granularity),
        )
    return resp.get("Items", [])


def _pct_change(old: int, new: int) -> float:
    if old == 0:
        return 100.0 if new > 0 else 0.0
    return round((new - old) / old * 100, 1)


# ── Background rollup task (GAP-0050) ──────────────────────────────────


def _run_rollup_for_all_campaigns(period_key: str, rollup_type: str) -> None:
    """Compute the rollup for ``period_key`` across all active campaigns.

    ``rollup_type`` is "hourly" or "daily". Failures for one campaign are
    logged and skipped so a single bad campaign cannot stall the whole tick.
    """
    last_key = None
    while True:
        scan_kwargs: dict = {
            "FilterExpression": Attr("status").eq("active"),
        }
        if last_key:
            scan_kwargs["ExclusiveStartKey"] = last_key
        try:
            resp = T.ad_campaigns.scan(**scan_kwargs)
        except Exception:
            logger.exception("ad_analytics_campaign_scan_failed")
            return
        for item in resp.get("Items", []):
            campaign_id = item.get("campaign_id") or item.get(
                "sk", ""
            ).replace("CAMPAIGN#", "")
            account_id = item.get("account_id") or item.get(
                "pk", ""
            ).replace("ACCT#", "")
            if not campaign_id or not account_id:
                continue
            try:
                if rollup_type == "daily":
                    compute_daily_rollup(campaign_id, account_id, period_key)
                else:
                    compute_hourly_rollup(campaign_id, account_id, period_key)
            except Exception:
                logger.warning(
                    "ad_analytics_campaign_rollup_failed",
                    extra={
                        "campaign_id": campaign_id,
                        "period": period_key,
                        "rollup_type": rollup_type,
                    },
                )
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break


def _seconds_until_next_tick() -> float:
    """Seconds until the next rollup tick boundary.

    Aligns to the next clock-hour for the default 60-minute interval, or to the
    next ``interval`` boundary within the hour for sub-hour dev intervals.
    """
    interval = max(1, S.ad_analytics_rollup_interval_minutes)
    now = datetime.now(timezone.utc)
    if interval >= 60:
        nxt = (now + timedelta(hours=1)).replace(
            minute=2, second=0, microsecond=0
        )
    else:
        # Next interval boundary within the hour (e.g. :01, :06, :11 for 5m).
        next_minute = ((now.minute // interval) + 1) * interval
        if next_minute >= 60:
            nxt = (now + timedelta(hours=1)).replace(
                minute=0, second=0, microsecond=0
            )
        else:
            nxt = now.replace(
                minute=next_minute, second=0, microsecond=0
            )
    return max(1.0, (nxt - now).total_seconds())


async def _ad_analytics_rollup_loop() -> None:
    """Background loop: compute hourly rollups each tick, daily once per day.

    Runs ``compute_hourly_rollup`` for every active campaign for the just-ended
    period, and ``compute_daily_rollup`` for the current day after the final
    hour of that day (UTC hour 23) so the dashboard daily read path is fed.
    """
    while True:
        try:
            await asyncio.sleep(_seconds_until_next_tick())
            now = datetime.now(timezone.utc)
            current_hour = now.strftime("%Y-%m-%dT%H")
            _run_rollup_for_all_campaigns(current_hour, "hourly")
            if now.hour == 23:
                today = now.strftime("%Y-%m-%d")
                _run_rollup_for_all_campaigns(today, "daily")
        except asyncio.CancelledError:  # pragma: no cover - shutdown path
            break
        except Exception:
            logger.exception("ad_analytics_rollup_loop_error")
            await asyncio.sleep(60)


def start_ad_analytics_rollup_task() -> None:
    """Startup handler: schedule the ad-analytics rollup background loop."""
    if not S.ad_serving_enabled:
        logger.info(
            "ad analytics rollup disabled (ad_serving_enabled=False)"
        )
        return
    asyncio.ensure_future(_ad_analytics_rollup_loop())
