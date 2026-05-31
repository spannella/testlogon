"""Ad feedback service -- records user feedback on sponsored posts (ADS-005).

Stores hide/negative signals in the billing table and provides lookup
for hidden creative IDs to exclude from future feed injection.
"""

from __future__ import annotations

import logging
from typing import Set

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

VALID_FEEDBACK_TYPES = {"hide", "not_relevant", "repetitive", "offensive"}


def record_ad_feedback(
    user_id: str,
    creative_id: str,
    campaign_id: str,
    feedback_type: str,
    reason: str = "",
) -> dict:
    """Record user feedback on an ad (hide, not_relevant, repetitive, offensive)."""
    if feedback_type not in VALID_FEEDBACK_TYPES:
        raise ValueError(
            f"Invalid feedback type: {feedback_type}. Must be one of {VALID_FEEDBACK_TYPES}"
        )

    ts = now_ts()
    T.billing.put_item(Item={
        "pk": f"USER#{user_id}",
        "sk": f"AD_FEEDBACK#{creative_id}#{ts}",
        "creative_id": creative_id,
        "campaign_id": campaign_id,
        "feedback_type": feedback_type,
        "reason": reason,
        "created_at": ts,
    })
    logger.info(
        "sponsored_hidden",
        extra={
            "viewer_id": user_id,
            "creative_id": creative_id,
            "feedback_type": feedback_type,
        },
    )
    return {"ok": True}


def get_hidden_ad_ids(user_id: str) -> Set[str]:
    """Get creative IDs hidden by this user."""
    try:
        resp = T.billing.query(
            KeyConditionExpression=(
                Key("pk").eq(f"USER#{user_id}")
                & Key("sk").begins_with("AD_FEEDBACK#")
            ),
        )
        return {
            item["creative_id"]
            for item in resp.get("Items", [])
            if item.get("feedback_type") == "hide"
        }
    except Exception:
        logger.warning("ad_feedback_read_failed user=%s", user_id)
        return set()
