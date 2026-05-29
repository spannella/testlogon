"""Dead letter queue management for webhook deliveries (ENTERPRISE-005)."""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def replay_dead_letter(
    delivery_id: str,
    endpoint_id: str,
    user_sub: str,
    replayed_by: str,
) -> dict:
    """Re-enqueue a dead-lettered delivery for immediate processing."""
    resp = T.webhook_deliveries.get_item(
        Key={"pk": f"ENDPOINT#{endpoint_id}", "sk": f"DELIVERY#{delivery_id}"}
    )
    delivery = resp.get("Item")
    if not delivery:
        raise ValueError("Delivery not found")
    if delivery.get("status") != "dead_letter":
        raise ValueError("Can only replay dead-lettered deliveries")

    now = now_ts()
    T.webhook_deliveries.update_item(
        Key={"pk": delivery["pk"], "sk": delivery["sk"]},
        UpdateExpression=(
            "SET #st = :st, attempt_count = :zero, next_retry_at = :now, "
            "replayed_at = :now2, replayed_by = :rb"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":st": "pending",
            ":zero": 0,
            ":now": now,
            ":now2": now,
            ":rb": replayed_by,
        },
    )

    logger.info(
        "Dead letter %s replayed by %s for endpoint %s",
        delivery_id,
        replayed_by,
        endpoint_id,
    )
    return {
        "delivery_id": delivery_id,
        "status": "pending",
        "replayed_at": now,
    }


def replay_all_dead_letters(
    endpoint_id: str,
    user_sub: str,
    replayed_by: str,
    limit: int = 100,
) -> int:
    """Replay all dead-lettered deliveries for an endpoint.

    Returns the count of replayed deliveries.
    """
    resp = T.webhook_deliveries.query(
        KeyConditionExpression=Key("pk").eq(f"ENDPOINT#{endpoint_id}")
        & Key("sk").begins_with("DELIVERY#"),
        FilterExpression="#st = :dl",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":dl": "dead_letter"},
        Limit=limit,
    )

    count = 0
    now = now_ts()
    for item in resp.get("Items", []):
        if item.get("status") != "dead_letter":
            continue
        T.webhook_deliveries.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression=(
                "SET #st = :st, attempt_count = :zero, next_retry_at = :now, "
                "replayed_at = :now2, replayed_by = :rb"
            ),
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": "pending",
                ":zero": 0,
                ":now": now,
                ":now2": now,
                ":rb": replayed_by,
            },
        )
        count += 1

    logger.info(
        "Replayed %d dead letters for endpoint %s by %s",
        count,
        endpoint_id,
        replayed_by,
    )
    return count


def acknowledge_dead_letter(
    delivery_id: str,
    endpoint_id: str,
    user_sub: str,
    acknowledged_by: str,
) -> None:
    """Mark a dead-lettered delivery as acknowledged."""
    now = now_ts()
    T.webhook_deliveries.update_item(
        Key={"pk": f"ENDPOINT#{endpoint_id}", "sk": f"DELIVERY#{delivery_id}"},
        UpdateExpression=(
            "SET #st = :st, acknowledged_at = :ack, acknowledged_by = :ab"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":st": "acknowledged",
            ":ack": now,
            ":ab": acknowledged_by,
        },
    )


def purge_dead_letters(
    endpoint_id: str,
    user_sub: str,
    purged_by: str,
) -> int:
    """Delete all dead-lettered deliveries for an endpoint."""
    resp = T.webhook_deliveries.query(
        KeyConditionExpression=Key("pk").eq(f"ENDPOINT#{endpoint_id}")
        & Key("sk").begins_with("DELIVERY#"),
        FilterExpression="#st = :dl",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":dl": "dead_letter"},
    )

    count = 0
    for item in resp.get("Items", []):
        T.webhook_deliveries.delete_item(
            Key={"pk": item["pk"], "sk": item["sk"]}
        )
        count += 1

    logger.info(
        "Purged %d dead letters for endpoint %s by %s",
        count,
        endpoint_id,
        purged_by,
    )
    return count


def list_endpoint_dead_letters(
    endpoint_id: str,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List dead-lettered deliveries for a specific endpoint."""
    resp = T.webhook_deliveries.query(
        KeyConditionExpression=Key("pk").eq(f"ENDPOINT#{endpoint_id}")
        & Key("sk").begins_with("DELIVERY#"),
        FilterExpression="#st = :dl",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":dl": "dead_letter"},
        ScanIndexForward=False,
        Limit=limit,
    )
    result = []
    for item in resp.get("Items", []):
        payload_preview = ""
        try:
            payload_preview = (item.get("payload", ""))[:200]
        except Exception:
            pass

        result.append({
            "delivery_id": item.get("delivery_id", ""),
            "endpoint_id": item.get("endpoint_id", ""),
            "event_type": item.get("event_type", ""),
            "event_id": item.get("event_id", ""),
            "payload_preview": payload_preview,
            "created_at": int(item.get("created_at", 0)),
            "failed_at": int(item.get("last_attempt_at", 0)),
            "failure_reason": item.get("last_error", ""),
            "attempt_count": int(item.get("attempt_count", 0)),
            "last_http_status": int(item["last_response_code"]) if item.get("last_response_code") else None,
            "last_error_message": item.get("last_response_body"),
        })
    return result
