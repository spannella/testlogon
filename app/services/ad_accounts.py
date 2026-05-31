"""Advertiser account management (ADS-001 stub).

Provides the minimum get_ad_account function needed by ad_analytics.
Full implementation is in the ADS-001 ticket.
"""

from __future__ import annotations

import uuid
from typing import Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts


def create_ad_account(owner_sub: str, body) -> dict:
    """Create a new advertiser account."""
    account_id = f"adv_{uuid.uuid4().hex[:12]}"
    item = {
        "pk": f"ACCT#{account_id}",
        "sk": "META",
        "account_id": account_id,
        "owner_sub": owner_sub,
        "company_name": body.company_name,
        "billing_email": body.billing_email,
        "status": "active",
        "balance_cents": 0,
        "lifetime_spend_cents": 0,
        "created_at": now_ts(),
        "updated_at": now_ts(),
    }
    T.ad_accounts.put_item(Item=item)
    return item


def get_ad_account(account_id: str) -> Optional[dict]:
    """Get an ad account by ID."""
    resp = T.ad_accounts.get_item(Key={"pk": f"ACCT#{account_id}", "sk": "META"})
    return resp.get("Item")


def list_accounts_by_owner(owner_sub: str) -> list[dict]:
    """List accounts owned by a user."""
    resp = T.ad_accounts.query(
        IndexName="ByOwner",
        KeyConditionExpression=Key("owner_sub").eq(owner_sub),
    )
    return resp.get("Items", [])
