"""Campaign CRUD, lifecycle transitions, and admin review (ADS-001)."""
from __future__ import annotations

import uuid
from typing import Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.models import CampaignCreateIn, CampaignUpdateIn


# ── Valid campaign status transitions ──────────────────────────────

_CAMPAIGN_TRANSITIONS = {
    "draft": {"pending_review", "archived"},
    "pending_review": {"active", "rejected"},
    "active": {"paused", "completed", "archived"},
    "paused": {"active", "archived"},
    "completed": {"archived"},
    "rejected": {"draft"},
    "archived": set(),
}


def _validate_campaign_transition(current: str, target: str) -> None:
    allowed = _CAMPAIGN_TRANSITIONS.get(current, set())
    if target not in allowed:
        raise ValueError(f"Cannot transition campaign from {current} to {target}")


# ── CRUD ───────────────────────────────────────────────────────────

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
        "category": data.category,
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


def list_campaigns_by_status(status: str, limit: int = 2000) -> list[dict]:
    """Return all campaigns with the given status, paginating through all DynamoDB pages.

    A single ``query()`` call returns only the first DynamoDB page (up to 1 MB),
    silently dropping campaigns on subsequent pages. This loops over
    ``LastEvaluatedKey`` so the ad-serving engine sees every eligible campaign.

    Args:
        status: Campaign status to filter by (e.g. "active").
        limit: Hard cap on total items returned to bound memory use. Default 2000.
    """
    items: list[dict] = []
    kwargs: dict = {
        "IndexName": "ByStatusCreatedAt",
        "KeyConditionExpression": Key("status").eq(status),
        "ScanIndexForward": False,
    }
    while True:
        resp = T.ad_campaigns.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key or len(items) >= limit:
            break
        kwargs["ExclusiveStartKey"] = last_key
    return items[:limit]


def update_campaign(account_id: str, campaign_id: str, data: CampaignUpdateIn) -> dict:
    updates = {k: v for k, v in data.model_dump(exclude_none=True).items()}
    updates["updated_at"] = now_ts()

    # Validate status transitions
    if "status" in updates:
        current = get_campaign(account_id, campaign_id)
        if not current:
            raise ValueError("Campaign not found")
        _validate_campaign_transition(current["status"], updates["status"])

    expr_parts: list[str] = []
    attr_values: dict = {}
    attr_names: dict = {}
    for i, (k, v) in enumerate(updates.items()):
        alias = f"#f{i}"
        val_alias = f":v{i}"
        attr_names[alias] = k
        attr_values[val_alias] = v
        expr_parts.append(f"{alias} = {val_alias}")

    T.ad_campaigns.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeNames=attr_names,
        ExpressionAttributeValues=attr_values,
    )
    return {"ok": True}


def submit_campaign_for_review(account_id: str, campaign_id: str) -> dict:
    """Transition campaign from draft to pending_review."""
    T.ad_campaigns.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
        UpdateExpression="SET #s = :s, updated_at = :u",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "pending_review", ":u": now_ts(), ":draft": "draft"},
        ConditionExpression="#s = :draft",
    )
    return {"ok": True}


def review_campaign(
    campaign_id: str, reviewer_sub: str, decision: str, notes: str = ""
) -> Optional[dict]:
    """Admin review: approve or reject a campaign (looks up by campaign_id GSI)."""
    resp = T.ad_campaigns.query(
        IndexName="ByCampaignId",
        KeyConditionExpression=Key("campaign_id").eq(campaign_id),
    )
    items = resp.get("Items", [])
    if not items:
        return None
    item = items[0]
    new_status = "active" if decision == "approve" else "rejected"
    T.ad_campaigns.update_item(
        Key={"pk": item["pk"], "sk": item["sk"]},
        UpdateExpression="SET #s = :s, reviewed_by = :r, review_notes = :n, updated_at = :u",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": new_status,
            ":r": reviewer_sub,
            ":n": notes,
            ":u": now_ts(),
        },
    )
    return {"ok": True, "status": new_status}
