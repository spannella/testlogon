"""Ad billing ledger (ADS-007 stub).

Provides the minimum functions needed by ad_analytics.
Full implementation is in the ADS-007 ticket.
"""

from __future__ import annotations

from boto3.dynamodb.conditions import Key

from app.core.tables import T


def get_campaign_spending(campaign_id: str, limit: int = 100) -> list[dict]:
    """Get spending entries for a specific campaign."""
    resp = T.ad_billing.query(
        IndexName="ByCampaign",
        KeyConditionExpression=Key("campaign_id").eq(campaign_id),
        ScanIndexForward=False,
        Limit=limit,
    )
    return resp.get("Items", [])
