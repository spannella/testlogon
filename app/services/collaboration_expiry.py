"""Collaboration expiration logic (CREATOR-001)."""

from __future__ import annotations

import logging
from typing import Any, Dict

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def process_expired_collaborations() -> Dict[str, int]:
    """Transition expired pending collaborations to status=expired.

    Returns counts of transitions performed.
    """
    now = now_ts()
    counts = {"expired": 0}

    # Expire pending collabs past expires_at / valid_until
    for status in ("pending", "counter"):
        items = _query_by_status(status)
        for item in items:
            valid_until = item.get("valid_until")
            if valid_until and now > int(valid_until):
                try:
                    T.collaboration_agreements.update_item(
                        Key={"collaboration_id": item["collaboration_id"], "sk": "CURRENT"},
                        UpdateExpression="SET #s = :new, GSI3PK = :gsi, updated_at = :now",
                        ConditionExpression="#s = :old",
                        ExpressionAttributeNames={"#s": "status"},
                        ExpressionAttributeValues={
                            ":new": "expired",
                            ":old": status,
                            ":gsi": "STATUS#expired",
                            ":now": now,
                        },
                    )
                    counts["expired"] += 1
                except Exception:
                    logger.warning("Failed to expire collab %s", item["collaboration_id"])

    return counts


def _query_by_status(status: str):
    """Query ByStatus GSI for items with given status."""
    items = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByStatus",
            "KeyConditionExpression": Key("GSI3PK").eq(f"STATUS#{status}"),
            "Limit": 100,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.collaboration_agreements.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key or len(items) > 1000:
            break
    return items
