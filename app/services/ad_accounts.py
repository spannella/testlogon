"""Advertiser account CRUD (ADS-001 stub for ADS-007)."""
from __future__ import annotations

import uuid
from typing import Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.models import AdAccountCreateIn


def create_ad_account(owner_sub: str, data: AdAccountCreateIn) -> dict:
    """Create a new advertiser account in pending_review status."""
    account_id = f"adacct_{uuid.uuid4().hex[:12]}"
    ts = now_ts()
    item = {
        "pk": f"ACCT#{account_id}",
        "sk": "META",
        "account_id": account_id,
        "owner_sub": owner_sub,
        "company_name": data.company_name,
        "billing_email": data.billing_email,
        "status": "pending_review",
        "balance_cents": 0,
        "lifetime_spend_cents": 0,
        "created_at": ts,
        "updated_at": ts,
    }
    T.ad_accounts.put_item(Item=item)
    return item


def get_ad_account(account_id: str) -> Optional[dict]:
    resp = T.ad_accounts.get_item(Key={"pk": f"ACCT#{account_id}", "sk": "META"})
    return resp.get("Item")


def list_accounts_by_owner(owner_sub: str) -> list[dict]:
    resp = T.ad_accounts.query(
        IndexName="ByOwner",
        KeyConditionExpression=Key("owner_sub").eq(owner_sub),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])
