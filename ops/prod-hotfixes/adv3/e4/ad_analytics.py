"""Ad analytics — ledger-reconciled KPI summary, time series, breakdowns, CSV export.

ADV3-8/9 reconciliation: the KPI SUMMARY (``get_summary``) is sourced from the
SAME ad_billing ledger path as the /roas report (via ``ad_roas.ledger_metrics``)
so the two totals shown side-by-side on the dashboard can never disagree, and a
currently-spending campaign shows today's activity immediately (no dependence on
the once-a-day rollup write). Engagement metrics (completes / skips / unique
reach) come from the ad_impressions event log. The pre-computed hourly/daily
rollups still feed the time-series + per-dimension breakdown CHARTS, now with
real complete/skip counts, real per-surface / per-geo spend, and no fabricated
revenue_cents / unique_users.
"""

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


def resolve_days(from_date: Optional[str], to_date: Optional[str], days: int) -> int:
    """ADV3-8 (D1): resolve a ``from``/``to`` (YYYY-MM-DD) window sent by the app
    into an inclusive day count, falling back to ``days`` when the range is absent
    or unparseable. A 7-day preset spans today-6..today == 7 inclusive days.
    """
    if from_date and to_date:
        try:
            f = datetime.strptime(from_date, "%Y-%m-%d").date()
            t = datetime.strptime(to_date, "%Y-%m-%d").date()
            span = (t - f).days + 1
            if span >= 1:
                return min(span, 365)
        except ValueError:
            pass
    return days


def _pct_change(old: float, new: float) -> float:
    if old == 0:
        return 100.0 if new > 0 else 0.0
    return round((new - old) / old * 100, 1)


def _engagement_metrics(
    account_id: str,
    campaign_id: Optional[str],
    since_ts: int,
    until_ts: int,
) -> Dict[str, int]:
    """ADV3-9 (D5/D11): count REAL ``complete`` / ``skip`` events and DISTINCT
    reach (unique viewers of an impression) from the ad_impressions event log for
    the account (optionally one campaign) within ``[since_ts, until_ts)``.

    Paginated scan with a FilterExpression — acceptable at dev/early-prod volume;
    a ByCampaign/ByAccount GSI on AdImpressions is the documented follow-on
    (kills the scan). Degrades to zeros on scan error rather than fabricating.
    """
    completes = 0
    skips = 0
    viewers: set[str] = set()
    flt = Attr("created_at").gte(since_ts) & Attr("created_at").lt(until_ts)
    if campaign_id:
        flt = flt & Attr("campaign_id").eq(campaign_id)
    else:
        flt = flt & Attr("account_id").eq(account_id)
    last_key = None
    try:
        while True:
            kwargs: dict = {"FilterExpression": flt}
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.ad_impressions.scan(**kwargs)
            for it in resp.get("Items", []):
                evt = it.get("event_type", "")
                if evt == "complete":
                    completes += 1
                elif evt == "skip":
                    skips += 1
                elif evt == "impression":
                    uid = it.get("user_id")
                    if uid:
                        viewers.add(str(uid))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
    except Exception:
        logger.warning(
            "ad_analytics_engagement_scan_failed",
            extra={"account_id": account_id, "campaign_id": campaign_id},
        )
        return {"completes": 0, "skips": 0, "unique_users": 0}
    return {"completes": completes, "skips": skips, "unique_users": len(viewers)}


def get_summary(
    account_id: str,
    campaign_id: Optional[str] = None,
    days: int = 30,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
) -> dict:
    """Get the aggregated KPI summary for an account or campaign.

    ADV3-8: sourced from the ad_billing LEDGER (via ``ad_roas.ledger_metrics``) —
    the SAME money path as the /roas report — so impressions/clicks/spend/ROAS
    reconcile with the ROAS card shown beside it and include today's activity.
    ``cpc_cents`` (spend / clicks) is the true cost-per-click that was previously
    MISLABELED ``cpa_cents``; ``cpa_cents`` is now the true cost-per-conversion
    (spend / conversions). ``roas`` = attributed conversion value / spend.
    """
    from app.services.ad_roas import ledger_metrics

    days = resolve_days(from_date, to_date, days)
    now = now_ts()
    since = now - days * 86400
    prev_since = since - days * 86400

    # Current window is unbounded on the upper end so activity in the CURRENT
    # second (freshly-charged spend) is never dropped by a coarse now boundary;
    # this also makes the summary reconcile EXACTLY with roas_report (also
    # unbounded). The previous period stays half-open [prev_since, since).
    cur = ledger_metrics(account_id, campaign_id, since, None)
    prev = ledger_metrics(account_id, campaign_id, prev_since, since)
    eng = _engagement_metrics(account_id, campaign_id, since, now + 1)

    impressions = cur["impressions"]
    clicks = cur["clicks"]
    spend = cur["spend_cents"]
    conversions = cur["conversions"]
    value = cur["conversion_value_cents"]
    completes = eng["completes"]
    skips = eng["skips"]
    started = completes + skips

    ctr = (clicks / impressions * 100) if impressions > 0 else 0.0
    # *_cents money fields are integer cents (the wire/DTO treat them as int);
    # ratios (ctr / roas / completion) stay float.
    cpc = round(spend / clicks) if clicks > 0 else 0
    cpa = round(spend / conversions) if conversions > 0 else 0
    ecpm = round(spend / impressions * 1000) if impressions > 0 else 0
    completion_rate = round(completes / started * 100, 2) if started > 0 else 0.0
    roas = round(value / spend, 4) if spend > 0 else 0.0

    prev_impr = prev["impressions"]
    prev_clk = prev["clicks"]
    prev_spend = prev["spend_cents"]
    prev_ctr = (prev_clk / prev_impr * 100) if prev_impr > 0 else 0.0
    prev_cpc = round(prev_spend / prev_clk) if prev_clk > 0 else 0
    prev_ecpm = round(prev_spend / prev_impr * 1000) if prev_impr > 0 else 0

    return {
        "impressions": impressions,
        "clicks": clicks,
        "ctr_pct": round(ctr, 2),
        "spend_cents": spend,
        "cpc_cents": cpc,
        "cpa_cents": cpa,
        "effective_cpm_cents": ecpm,
        "conversions": conversions,
        "conversion_revenue_cents": value,
        "roas": roas,
        "completes": completes,
        "skips": skips,
        "completion_rate_pct": completion_rate,
        "unique_users": eng["unique_users"],
        "previous_period": {
            "impressions": prev_impr,
            "clicks": prev_clk,
            "spend_cents": prev_spend,
        },
        "impressions_change_pct": _pct_change(prev_impr, impressions),
        "clicks_change_pct": _pct_change(prev_clk, clicks),
        "spend_change_pct": _pct_change(prev_spend, spend),
        "ctr_change_pct": _pct_change(prev_ctr, ctr),
        "cpc_change_pct": _pct_change(prev_cpc, cpc),
        "effective_cpm_change_pct": _pct_change(prev_ecpm, ecpm),
        "days": days,
    }


def get_timeseries(
    account_id: str,
    campaign_id: Optional[str] = None,
    days: int = 30,
    granularity: str = "daily",
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
) -> list[dict]:
    """Get time-series data points for charting (from the pre-computed rollups)."""
    days = resolve_days(from_date, to_date, days)
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
    points.sort(key=lambda p: p["date"])
    return points


def get_breakdown(
    account_id: str,
    campaign_id: Optional[str] = None,
    dimension: str = "creative",
    days: int = 30,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
) -> list[dict]:
    """Get metrics broken down by a dimension (creative, surface, targeting).

    ADV3-9 (D6): ``by_surface`` / ``by_targeting`` now carry REAL spend (attributed
    from the ledger meta during the rollup), so a placement/geo breakdown is no
    longer permanently spend=0.
    """
    days = resolve_days(from_date, to_date, days)
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

    hour format: "2026-05-29T14". Called by the background rollup loop.

    Spend + impressions/clicks + per-dimension breakdowns (by_creative /
    by_surface / by_targeting) are decomposed from the ad_billing ledger entries
    written within the hour (surface/geo now stamped on the charge meta — D6).
    complete/skip counts + unique reach come from the ad_impressions event log
    (D5/D11). The fabricated ``revenue_cents = spend*0.7`` field is GONE (D10).
    """
    from app.services.ad_billing import get_campaign_spending

    try:
        hour_dt = datetime.strptime(hour, "%Y-%m-%dT%H").replace(
            tzinfo=timezone.utc
        )
        hour_start_ts = int(hour_dt.timestamp())
        hour_end_ts = hour_start_ts + 3600
    except ValueError:
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
    conversions = 0
    spend = 0
    conversion_value = 0
    by_creative: Dict[str, Dict[str, int]] = {}
    by_surface: Dict[str, Dict[str, int]] = {}
    by_targeting: Dict[str, Dict[str, int]] = {}

    for e in hour_entries:
        etype = e.get("entry_type", "")
        amt = int(e.get("amount_cents", 0))
        meta = e.get("meta") or {}
        creative_id = meta.get("creative_id") or "unknown"
        surface = meta.get("surface") or "unknown"
        slot_type = meta.get("slot_type") or "unknown"
        surface_key = f"{surface}/{slot_type}"
        geo = meta.get("geo_country") or "unknown"

        if etype == "impression_charge":
            spend += amt
            impressions += 1
            _bump_dim(by_creative, creative_id, impressions=1, spend=amt)
            _bump_dim(by_surface, surface_key, impressions=1, spend=amt)
            _bump_dim(by_targeting, geo, impressions=1, spend=amt)
        elif etype == "click_charge":
            spend += amt
            clicks += 1
            _bump_dim(by_creative, creative_id, clicks=1, spend=amt)
            _bump_dim(by_surface, surface_key, clicks=1, spend=amt)
            _bump_dim(by_targeting, geo, clicks=1, spend=amt)
        elif etype == "conversion_charge":
            spend += amt
            conversions += 1
            conversion_value += int(meta.get("conversion_value_cents", 0) or 0)

    eng = _engagement_metrics(account_id, campaign_id, hour_start_ts, hour_end_ts)

    rollup: Dict[str, Any] = {
        "pk": f"CAMP#{campaign_id}",
        "sk": f"ROLLUP#hourly#{hour}",
        "campaign_id": campaign_id,
        "account_id": account_id,
        "period": "hourly",
        "date": hour,
        "impressions": impressions,
        "clicks": clicks,
        "conversions": conversions,
        "skips": eng["skips"],
        "completes": eng["completes"],
        "spend_cents": spend,
        "conversion_value_cents": conversion_value,
        "unique_users": eng["unique_users"],
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
            "completes": eng["completes"],
            "skips": eng["skips"],
        },
    )
    return rollup


def compute_daily_rollup(
    campaign_id: str, account_id: str, date: str
) -> dict:
    """Aggregate the 24 hourly rollup rows for ``date`` into one daily row."""
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
    conversions = sum(int(r.get("conversions", 0)) for r in hourly_rows)
    spend = sum(int(r.get("spend_cents", 0)) for r in hourly_rows)
    conversion_value = sum(int(r.get("conversion_value_cents", 0)) for r in hourly_rows)
    completes = sum(int(r.get("completes", 0)) for r in hourly_rows)
    skips = sum(int(r.get("skips", 0)) for r in hourly_rows)
    # Reach summed across hours is an upper bound (a viewer seen in two hours is
    # counted twice); the authoritative per-window reach is recomputed in
    # get_summary straight from the event log.
    unique_users = sum(int(r.get("unique_users", 0)) for r in hourly_rows)

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
        "conversions": conversions,
        "skips": skips,
        "completes": completes,
        "spend_cents": spend,
        "conversion_value_cents": conversion_value,
        "unique_users": unique_users,
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


def _fetch_daily_rollups(
    account_id: str,
    campaign_id: Optional[str],
    days: int,
    offset_days: int = 0,
) -> list[dict]:
    now = datetime.now(timezone.utc) - timedelta(days=offset_days)
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


# ── Background rollup task (GAP-0050) ──────────────────────────────────


def _run_rollup_for_all_campaigns(period_key: str, rollup_type: str) -> None:
    """Compute the rollup for ``period_key`` across all campaigns that can have
    spend.

    ADV3-9 (D9): includes active / paused / completed campaigns (NOT just active)
    so the FINAL period of a campaign that auto-paused at 100% budget is still
    rolled up and the dashboard no longer under-counts the tail. draft/archived
    campaigns (which never spend) are skipped to bound the scan.
    """
    last_key = None
    while True:
        scan_kwargs: dict = {
            "FilterExpression": Attr("status").is_in(
                ["active", "paused", "completed"]
            ),
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
    """Seconds until the next rollup tick boundary."""
    interval = max(1, S.ad_analytics_rollup_interval_minutes)
    now = datetime.now(timezone.utc)
    if interval >= 60:
        nxt = (now + timedelta(hours=1)).replace(
            minute=2, second=0, microsecond=0
        )
    else:
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
    """Background loop: compute hourly rollups each tick, daily once per day."""
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
