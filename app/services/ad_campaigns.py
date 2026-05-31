"""Campaign CRUD (ADS-001 stub for ADS-007)."""
from __future__ import annotations

import uuid
from typing import Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.models import CampaignCreateIn


def create_campaign(account_id: str, data: CampaignCreateIn) -> dict:
    """Create a new campaign in draft status."""
    campaign_id = f"camp_{uuid.uuid4().hex[:12]}"
    ts = now_ts()
    daily = data.budget_cents if data.budget_type == "daily" else 0
    item = {
        "pk": f"ACCT#{account_id}",
        "sk": f"CAMPAIGN#{campaign_id}",
        "campaign_id": campaign_id,
        "account_id": account_id,
        "name": data.name,
        "objective": data.objective,
        "budget_cents": data.budget_cents,
        "budget_type": data.budget_type,
        "daily_budget_cents": daily,
        "spent_today_cents": 0,
        "lifetime_spent_cents": 0,
        "status": "draft",
        "created_at": ts,
        "updated_at": ts,
    }
    if data.start_date is not None:
        item["start_date"] = data.start_date
    if data.end_date is not None:
        item["end_date"] = data.end_date
    T.ad_campaigns.put_item(Item=item)
    return item


def get_campaign(account_id: str, campaign_id: str) -> Optional[dict]:
    resp = T.ad_campaigns.get_item(
        Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"}
    )
    return resp.get("Item")


def list_campaigns(account_id: str) -> list[dict]:
    resp = T.ad_campaigns.query(
        KeyConditionExpression=Key("pk").eq(f"ACCT#{account_id}")
        & Key("sk").begins_with("CAMPAIGN#"),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])
