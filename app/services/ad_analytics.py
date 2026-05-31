"""Ad analytics — pre-computed rollups, summary, time series, breakdowns, CSV export."""

from __future__ import annotations

import csv
import io
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from boto3.dynamodb.conditions import Attr, Key

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


def compute_hourly_rollup(
    campaign_id: str, account_id: str, hour: str
) -> dict:
    """Compute rollup for a specific campaign and hour.

    hour format: "2026-05-29T14"
    Called by background rollup job.
    """
    from app.services.ad_billing import get_campaign_spending

    entries = get_campaign_spending(campaign_id, limit=1000)

    impressions = sum(
        1 for e in entries if e.get("entry_type") == "impression_charge"
    )
    clicks = sum(
        1 for e in entries if e.get("entry_type") == "click_charge"
    )
    spend = sum(int(e.get("amount_cents", 0)) for e in entries)

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
        "by_creative": {},
        "by_surface": {},
        "by_targeting": {},
        "computed_at": now_ts(),
    }

    T.ad_analytics_rollups.put_item(
        Item={k: v for k, v in rollup.items() if v is not None}
    )
    return rollup


# ── Internal helpers ──────────────────────────────────────────────────


def _fetch_daily_rollups(
    account_id: str,
    campaign_id: Optional[str],
    days: int,
    offset_days: int = 0,
) -> list[dict]:
    now = datetime.now(timezone.utc) - timedelta(days=offset_days)
    start_date = (now - timedelta(days=days)).strftime("%Y-%m-%d")
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
    start_date = (now - timedelta(days=days)).strftime("%Y-%m-%d")
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
