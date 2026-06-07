"""ROAS (Return on Ad Spend) calculation service (ADS-015 / GAP-0062).

Aggregates affiliate conversion revenue attributed to a campaign and computes
the ROAS ratio: ``conversion_revenue_cents / spend_cents``.

Conversion revenue is sourced from the ``ad_creative_affiliates`` table
(``REDEEM#*`` rows written by ``ad_creative_affiliate.redeem``, keyed
``pk = CREATIVE#{creative_id}``). Spend is sourced from the ad analytics
rollups via ``ad_analytics.get_summary``.

All DynamoDB access uses ``T.*`` table handles (DynamoDB Local in dev, real
DynamoDB in prod) — no AWS-specific divergence (SECOPS-007).

MONEY = int cents.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services.ad_analytics import get_summary
from app.services.ad_campaigns import get_campaign
from app.services.ad_creatives import list_creatives

logger = logging.getLogger(__name__)


def _fetch_campaign_creative_ids(campaign_id: str) -> List[str]:
    """Return all creative IDs belonging to a campaign."""
    return [c["creative_id"] for c in list_creatives(campaign_id) if c.get("creative_id")]


def _fetch_conversion_revenue(creative_id: str, since_ts: int) -> tuple[int, int]:
    """Sum ``final_price_cents`` across REDEEM# rows for a creative since
    ``since_ts``. Returns ``(revenue_cents, conversion_count)``.

    Pages via ``LastEvaluatedKey`` so busy creatives aren't truncated.
    """
    revenue = 0
    count = 0
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            Key("pk").eq(f"CREATIVE#{creative_id}") & Key("sk").begins_with("REDEEM#")
        ),
        "ProjectionExpression": "final_price_cents, created_at",
    }
    while True:
        resp = T.ad_creative_affiliates.query(**kwargs)
        for item in resp.get("Items", []):
            if int(item.get("created_at", 0)) >= since_ts:
                revenue += int(item.get("final_price_cents", 0))
                count += 1
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return revenue, count


def conversion_revenue_for_campaign(campaign_id: str, days: int = 30) -> tuple[int, int]:
    """Return ``(conversion_revenue_cents, conversion_count)`` for a campaign
    over the last ``days`` days, summed across all its creatives' REDEEM# rows.

    Does NOT call ``get_summary`` (so it is safe to call from within
    ``ad_analytics.get_summary`` without recursion).
    """
    since_ts = now_ts() - days * 86400
    revenue = 0
    count = 0
    for creative_id in _fetch_campaign_creative_ids(campaign_id):
        r, c = _fetch_conversion_revenue(creative_id, since_ts)
        revenue += r
        count += c
    return revenue, count


def calculate_campaign_roas(
    *,
    account_id: str,
    campaign_id: str,
    days: int = 30,
) -> Dict[str, Any]:
    """Calculate ROAS for a campaign over the last ``days`` days.

    Returns ``{}`` if the campaign does not exist. Otherwise:
        {
            "campaign_id": str,
            "spend_cents": int,
            "conversion_revenue_cents": int,
            "roas": float,          # revenue / spend; 0.0 if spend == 0
            "conversion_count": int,
            "days": int,
            "computed_at": int,
        }
    """
    campaign = get_campaign(account_id, campaign_id)
    if not campaign:
        return {}

    summary = get_summary(account_id, campaign_id=campaign_id, days=days)
    spend_cents = int(summary.get("spend_cents", 0))

    conversion_revenue_cents, conversion_count = conversion_revenue_for_campaign(
        campaign_id, days=days
    )

    roas = (
        round(conversion_revenue_cents / spend_cents, 4) if spend_cents > 0 else 0.0
    )

    logger.info(
        "roas_calculated campaign_id=%s roas=%.4f spend_cents=%d conversions=%d",
        campaign_id, roas, spend_cents, conversion_count,
    )

    return {
        "campaign_id": campaign_id,
        "spend_cents": spend_cents,
        "conversion_revenue_cents": conversion_revenue_cents,
        "roas": roas,
        "conversion_count": conversion_count,
        "days": days,
        "computed_at": now_ts(),
    }
