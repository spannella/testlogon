"""Syndicate advertising campaign management (SYND-006).

A syndicate runs advertising as a unit: the syndicate admin creates ad campaigns
funded from the syndicate treasury (SYND-004). The treasury is debited at
campaign-creation time (and on budget top-up); cancelling an active/paused
campaign refunds the unspent budget back to the treasury. Spend draws from the
campaign budget as impressions are served; analytics (impressions, clicks, CTR,
spend) are tracked daily and visible to all syndicate members.

Storage lives in the dedicated ``syndicate_ad_campaigns`` DDB table:
- Campaign record:  pk = ``SYND#{syndicate_id}``,           sk = ``CAMPAIGN#{campaign_id}``
- Daily analytics:  pk = ``CAMPAIGN_STATS#{campaign_id}``,   sk = ``DATE#{date}``

This module orchestrates existing infra — it reuses ``syndicates`` (admin/role
checks + audit log) and ``syndicate_treasury`` (treasury debit/refund) rather
than reinventing campaigns or treasury.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services import syndicates as syndicate_svc
from app.services import syndicate_treasury as treasury_svc

logger = logging.getLogger(__name__)

VALID_STATUSES = ("draft", "active", "paused", "completed", "cancelled")

# Valid admin-driven status transitions (auto "completed" handled separately).
_VALID_TRANSITIONS: Dict[str, List[str]] = {
    "draft": ["active", "cancelled"],
    "active": ["paused", "cancelled"],
    "paused": ["active", "cancelled"],
}

# Deterministic cost model for ad serving (1 cent per impression).
COST_PER_IMPRESSION_CENTS = 1


def _campaign_pk(syndicate_id: str) -> str:
    return f"SYND#{syndicate_id}"


def _campaign_sk(campaign_id: str) -> str:
    return f"CAMPAIGN#{campaign_id}"


def _stats_pk(campaign_id: str) -> str:
    return f"CAMPAIGN_STATS#{campaign_id}"


def _date_str(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Campaign creation / mutation (admin only)
# ---------------------------------------------------------------------------


def create_campaign(
    *,
    syndicate_id: str,
    admin_sub: str,
    name: str,
    budget_cents: int,
    creative: Dict[str, Any],
    description: str = "",
    targeting: Optional[Dict[str, Any]] = None,
    start_date: str = "",
    end_date: Optional[str] = None,
) -> Dict[str, Any]:
    """Create an ad campaign funded by the syndicate treasury (admin only)."""
    syndicate_svc._require_admin(syndicate_id, admin_sub)

    if budget_cents <= 0:
        raise HTTPException(status_code=400, detail="Budget must be positive")

    clean_creative = _validate_creative(creative)

    campaign_id = f"camp_{uuid4().hex}"
    ts = now_ts()

    # Debit budget from treasury (rejects overspend with 409). Done first so a
    # failed debit never leaves an orphan campaign record.
    spend = treasury_svc.spend_on_advertising(
        syndicate_id=syndicate_id,
        admin_sub=admin_sub,
        amount_cents=budget_cents,
        campaign_id=campaign_id,
        campaign_name=name,
    )

    campaign = {
        "pk": _campaign_pk(syndicate_id),
        "sk": _campaign_sk(campaign_id),
        "campaign_id": campaign_id,
        "syndicate_id": syndicate_id,
        "name": name,
        "description": description,
        "status": "active",
        "budget_cents": int(budget_cents),
        "spent_cents": 0,
        "remaining_cents": int(budget_cents),
        "creative": clean_creative,
        "targeting": targeting or {"audience": "all"},
        "start_date": start_date or _date_str(ts),
        "end_date": end_date or "",
        "created_by": admin_sub,
        "created_at": ts,
        "updated_at": ts,
        "stats_summary": {"impressions": 0, "clicks": 0, "ctr": 0},
        "treasury_ledger_entry_id": spend.get("ledger_entry_id", ""),
        "GSI1PK": f"SYND_CAMPAIGNS#{syndicate_id}",
        "GSI1SK": ts,
    }
    T.syndicate_ad_campaigns.put_item(Item=campaign)

    syndicate_svc._write_audit(
        syndicate_id, admin_sub, "ad_campaign_created", campaign_id,
        {"budget_cents": int(budget_cents), "name": name},
    )
    logger.info(
        "syndicate_advertising.create_campaign",
        extra={"syndicate_id": syndicate_id, "campaign_id": campaign_id, "budget_cents": int(budget_cents)},
    )
    return campaign


def update_campaign_status(
    *,
    syndicate_id: str,
    campaign_id: str,
    admin_sub: str,
    new_status: str,
) -> Dict[str, Any]:
    """Pause, resume, or cancel a campaign (admin only). Cancelling refunds budget."""
    syndicate_svc._require_admin(syndicate_id, admin_sub)
    campaign = _get_campaign(syndicate_id, campaign_id)

    current = campaign.get("status", "")
    allowed = _VALID_TRANSITIONS.get(current, [])
    if new_status not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot transition campaign from {current} to {new_status}",
        )

    ts = now_ts()

    # Refund remaining budget to treasury on cancellation.
    if new_status == "cancelled":
        remaining = int(campaign.get("remaining_cents", 0))
        if remaining > 0:
            treasury_svc.refund_advertising(
                syndicate_id=syndicate_id,
                admin_sub=admin_sub,
                amount_cents=remaining,
                campaign_id=campaign_id,
            )
        T.syndicate_ad_campaigns.update_item(
            Key={"pk": _campaign_pk(syndicate_id), "sk": _campaign_sk(campaign_id)},
            UpdateExpression="SET #s = :s, remaining_cents = :zero, updated_at = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": new_status, ":zero": 0, ":t": ts},
        )
        campaign["remaining_cents"] = 0
    else:
        T.syndicate_ad_campaigns.update_item(
            Key={"pk": _campaign_pk(syndicate_id), "sk": _campaign_sk(campaign_id)},
            UpdateExpression="SET #s = :s, updated_at = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": new_status, ":t": ts},
        )

    syndicate_svc._write_audit(
        syndicate_id, admin_sub, "ad_campaign_status_changed", campaign_id,
        {"from": current, "to": new_status},
    )

    campaign["status"] = new_status
    campaign["updated_at"] = ts
    return campaign


def add_campaign_budget(
    *,
    syndicate_id: str,
    campaign_id: str,
    admin_sub: str,
    additional_cents: int,
) -> Dict[str, Any]:
    """Add more budget to a campaign from the treasury (admin only)."""
    syndicate_svc._require_admin(syndicate_id, admin_sub)
    campaign = _get_campaign(syndicate_id, campaign_id)

    if additional_cents <= 0:
        raise HTTPException(status_code=400, detail="Additional budget must be positive")
    if campaign.get("status") in ("cancelled", "completed"):
        raise HTTPException(status_code=400, detail="Cannot add budget to a finished campaign")

    # Debit from treasury (rejects overspend with 409).
    treasury_svc.spend_on_advertising(
        syndicate_id=syndicate_id,
        admin_sub=admin_sub,
        amount_cents=additional_cents,
        campaign_id=campaign_id,
        campaign_name=f"{campaign.get('name', '')} (top-up)",
    )

    T.syndicate_ad_campaigns.update_item(
        Key={"pk": _campaign_pk(syndicate_id), "sk": _campaign_sk(campaign_id)},
        UpdateExpression=(
            "SET budget_cents = budget_cents + :add, "
            "remaining_cents = remaining_cents + :add, "
            "updated_at = :t"
        ),
        ExpressionAttributeValues={":add": int(additional_cents), ":t": now_ts()},
    )

    syndicate_svc._write_audit(
        syndicate_id, admin_sub, "ad_campaign_budget_added", campaign_id,
        {"additional_cents": int(additional_cents)},
    )
    return _get_campaign(syndicate_id, campaign_id)


def record_campaign_impression(
    *,
    syndicate_id: str,
    campaign_id: str,
    viewer_user_id: str = "",
    clicked: bool = False,
) -> Dict[str, Any]:
    """Record an ad impression/click; draw spend from the campaign budget.

    Spend is constrained by the remaining budget — when it reaches 0 the
    campaign auto-completes and no further impressions are served.
    """
    campaign = _get_campaign(syndicate_id, campaign_id)
    if campaign.get("status") != "active":
        return {"served": False, "reason": "campaign_not_active"}

    remaining = int(campaign.get("remaining_cents", 0))
    if remaining <= 0:
        return {"served": False, "reason": "budget_exhausted"}

    cost = COST_PER_IMPRESSION_CENTS
    click_incr = 1 if clicked else 0
    ts = now_ts()
    date_str = _date_str(ts)

    # Daily analytics aggregate.
    T.syndicate_ad_campaigns.update_item(
        Key={"pk": _stats_pk(campaign_id), "sk": f"DATE#{date_str}"},
        UpdateExpression=(
            "SET impressions = if_not_exists(impressions, :z) + :one, "
            "clicks = if_not_exists(clicks, :z) + :click, "
            "spend_cents = if_not_exists(spend_cents, :z) + :cost, "
            "unique_viewers = if_not_exists(unique_viewers, :z) + :one, "
            "#d = :date, campaign_id = :cid"
        ),
        ExpressionAttributeNames={"#d": "date"},
        ExpressionAttributeValues={
            ":z": 0,
            ":one": 1,
            ":click": click_incr,
            ":cost": cost,
            ":date": date_str,
            ":cid": campaign_id,
        },
    )

    # Campaign summary + budget draw.
    T.syndicate_ad_campaigns.update_item(
        Key={"pk": _campaign_pk(syndicate_id), "sk": _campaign_sk(campaign_id)},
        UpdateExpression=(
            "SET spent_cents = spent_cents + :cost, "
            "remaining_cents = remaining_cents - :cost, "
            "stats_summary.impressions = if_not_exists(stats_summary.impressions, :z) + :one, "
            "stats_summary.clicks = if_not_exists(stats_summary.clicks, :z) + :click, "
            "updated_at = :t"
        ),
        ExpressionAttributeValues={
            ":cost": cost,
            ":one": 1,
            ":click": click_incr,
            ":z": 0,
            ":t": ts,
        },
    )

    new_remaining = remaining - cost
    if new_remaining <= 0:
        T.syndicate_ad_campaigns.update_item(
            Key={"pk": _campaign_pk(syndicate_id), "sk": _campaign_sk(campaign_id)},
            UpdateExpression="SET #s = :s, updated_at = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "completed", ":t": ts},
        )

    return {"served": True, "clicked": clicked, "spend_cents": cost, "remaining_cents": max(new_remaining, 0)}


# ---------------------------------------------------------------------------
# Read API (members)
# ---------------------------------------------------------------------------


def list_campaigns(
    syndicate_id: str,
    *,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List all campaigns for a syndicate (newest first)."""
    resp = T.syndicate_ad_campaigns.query(
        KeyConditionExpression=(
            Key("pk").eq(_campaign_pk(syndicate_id)) & Key("sk").begins_with("CAMPAIGN#")
        ),
    )
    campaigns = resp.get("Items", [])
    if status:
        campaigns = [c for c in campaigns if c.get("status") == status]
    return sorted(campaigns, key=lambda c: int(c.get("created_at", 0)), reverse=True)


def get_campaign(syndicate_id: str, campaign_id: str) -> Dict[str, Any]:
    """Get a single campaign (404 if missing)."""
    return _get_campaign(syndicate_id, campaign_id)


def get_campaign_analytics(
    syndicate_id: str,
    campaign_id: str,
    *,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
) -> Dict[str, Any]:
    """Daily analytics + totals for a campaign."""
    # Ensure campaign exists (also enforces it belongs to this syndicate).
    _get_campaign(syndicate_id, campaign_id)

    cond = Key("pk").eq(_stats_pk(campaign_id))
    if from_date and to_date:
        cond &= Key("sk").between(f"DATE#{from_date}", f"DATE#{to_date}")
    elif from_date:
        cond &= Key("sk").gte(f"DATE#{from_date}")

    resp = T.syndicate_ad_campaigns.query(KeyConditionExpression=cond)
    daily = sorted(resp.get("Items", []), key=lambda d: d.get("date", ""))

    total_impressions = sum(int(d.get("impressions", 0)) for d in daily)
    total_clicks = sum(int(d.get("clicks", 0)) for d in daily)
    total_spend = sum(int(d.get("spend_cents", 0)) for d in daily)
    ctr = round(total_clicks / total_impressions * 100, 2) if total_impressions > 0 else 0

    return {
        "campaign_id": campaign_id,
        "daily": [
            {
                "date": d.get("date", ""),
                "impressions": int(d.get("impressions", 0)),
                "clicks": int(d.get("clicks", 0)),
                "spend_cents": int(d.get("spend_cents", 0)),
                "unique_viewers": int(d.get("unique_viewers", 0)),
            }
            for d in daily
        ],
        "totals": {
            "impressions": total_impressions,
            "clicks": total_clicks,
            "spend_cents": total_spend,
            "ctr": ctr,
        },
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_campaign(syndicate_id: str, campaign_id: str) -> Dict[str, Any]:
    resp = T.syndicate_ad_campaigns.get_item(
        Key={"pk": _campaign_pk(syndicate_id), "sk": _campaign_sk(campaign_id)}
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return item


def _validate_creative(creative: Dict[str, Any]) -> Dict[str, Any]:
    required = ("headline", "body", "cta_text", "cta_url")
    for field in required:
        if not creative.get(field):
            raise HTTPException(status_code=422, detail=f"Creative missing required field: {field}")
    return {
        "headline": str(creative["headline"])[:100],
        "body": str(creative["body"])[:500],
        "image_url": str(creative.get("image_url") or "")[:300],
        "cta_text": str(creative["cta_text"])[:50],
        "cta_url": str(creative["cta_url"])[:200],
    }
