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


def ledger_metrics(
    account_id: str,
    campaign_id: str | None = None,
    since_ts: int = 0,
    until_ts: int | None = None,
) -> Dict[str, int]:
    """ADV3-9 (D7): SINGLE SOURCE OF TRUTH for spend / impressions / clicks /
    conversions / attributed conversion value, aggregated straight from the
    ad_billing ledger for ``account_id`` (optionally one ``campaign_id``) within
    ``[since_ts, until_ts)``.

    Every ROAS/KPI surface (the /roas report, ad_analytics.get_summary, and
    calculate_campaign_roas -> the optimizer campaign_roas endpoint) funnels
    through this one aggregation so they can never disagree for the same window.
    Conversion value is read from ledger meta.conversion_value_cents (NOT the
    affiliate REDEEM rows), retiring the second/disagreeing ROAS engine.
    """
    tot = {"impressions": 0, "clicks": 0, "conversions": 0,
           "spend_cents": 0, "conversion_value_cents": 0}
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            Key("pk").eq(f"ACCT#{account_id}") & Key("sk").begins_with("LEDGER#")
        ),
    }
    while True:
        resp = T.ad_billing.query(**kwargs)
        for it in resp.get("Items", []):
            cat = int(it.get("created_at", 0) or 0)
            if cat < since_ts or (until_ts is not None and cat >= until_ts):
                continue
            et = it.get("entry_type", "")
            if et not in ("impression_charge", "click_charge", "conversion_charge"):
                continue
            cid = str(it.get("campaign_id", "") or "unknown")
            if campaign_id and cid != campaign_id:
                continue
            tot["spend_cents"] += int(it.get("amount_cents", 0) or 0)
            if et == "impression_charge":
                tot["impressions"] += 1
            elif et == "click_charge":
                tot["clicks"] += 1
            elif et == "conversion_charge":
                tot["conversions"] += 1
                tot["conversion_value_cents"] += int(
                    (it.get("meta", {}) or {}).get("conversion_value_cents", 0) or 0
                )
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return tot


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

    # ADV3-9 (D7): source spend AND conversion value from the ONE ledger path so
    # this endpoint can never disagree with the /roas report or the KPI summary.
    m = ledger_metrics(account_id, campaign_id, now_ts() - days * 86400)
    spend_cents = int(m["spend_cents"])
    conversion_revenue_cents = int(m["conversion_value_cents"])
    conversion_count = int(m["conversions"])

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


def roas_report(account_id, campaign_id=None, days: int = 30):
    """ADV-501: per-account + per-campaign ROAS report sourced from the ad_billing
    ledger (the single money-path source of truth).

    Aggregates impression/click/conversion CHARGES (spend) and the attributed
    conversion VALUE (recorded on conversion_charge rows as
    meta.conversion_value_cents) then derives impressions, clicks, CTR,
    conversions, CPA and ROAS (= conversion value / spend). When campaign_id is
    given the report is scoped to that campaign; otherwise the account total plus
    a per-campaign breakdown is returned. Returns:
        {account_id, campaign_id, days, computed_at, totals:{...}, campaigns:[...]}
    """
    from boto3.dynamodb.conditions import Key as _Key

    since_ts = now_ts() - days * 86400
    buckets: Dict[str, Dict[str, int]] = {}

    def _bucket(cid: str) -> Dict[str, int]:
        return buckets.setdefault(cid, {
            "impressions": 0, "clicks": 0, "conversions": 0,
            "spend_cents": 0, "conversion_value_cents": 0,
        })

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            _Key("pk").eq(f"ACCT#{account_id}") & _Key("sk").begins_with("LEDGER#")
        ),
    }
    while True:
        resp = T.ad_billing.query(**kwargs)
        for it in resp.get("Items", []):
            if int(it.get("created_at", 0) or 0) < since_ts:
                continue
            et = it.get("entry_type", "")
            if et not in ("impression_charge", "click_charge", "conversion_charge"):
                continue
            cid = str(it.get("campaign_id", "") or "unknown")
            if campaign_id and cid != campaign_id:
                continue
            b = _bucket(cid)
            b["spend_cents"] += int(it.get("amount_cents", 0) or 0)
            if et == "impression_charge":
                b["impressions"] += 1
            elif et == "click_charge":
                b["clicks"] += 1
            elif et == "conversion_charge":
                b["conversions"] += 1
                b["conversion_value_cents"] += int(
                    (it.get("meta", {}) or {}).get("conversion_value_cents", 0) or 0
                )
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek

    def _derive(cid, b: Dict[str, int]) -> Dict[str, Any]:
        imp, clk, conv = b["impressions"], b["clicks"], b["conversions"]
        spend, value = b["spend_cents"], b["conversion_value_cents"]
        row = {
            "impressions": imp, "clicks": clk, "conversions": conv,
            "spend_cents": spend, "conversion_value_cents": value,
            "ctr_pct": round(clk / imp * 100, 2) if imp > 0 else 0.0,
            "cpa_cents": round(spend / conv, 2) if conv > 0 else 0.0,
            "roas": round(value / spend, 4) if spend > 0 else 0.0,
        }
        if cid is not None:
            row = {"campaign_id": cid, **row}
        return row

    per_campaign = [_derive(cid, b) for cid, b in sorted(buckets.items())]
    tot = {"impressions": 0, "clicks": 0, "conversions": 0,
           "spend_cents": 0, "conversion_value_cents": 0}
    for b in buckets.values():
        for k in tot:
            tot[k] += b[k]

    return {
        "account_id": account_id,
        "campaign_id": campaign_id,
        "days": days,
        "computed_at": now_ts(),
        "totals": _derive(None, tot),
        "campaigns": per_campaign,
    }
