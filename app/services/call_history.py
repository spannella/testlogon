"""
Call History service — persist and query call log records in DynamoDB.

Table: call_history
  PK = user_id  (string)
  SK = CALL#{created_at}#{call_id}  (string, for descending timestamp ordering)

Each completed/missed/declined/failed call writes TWO records:
one for the caller and one for the callee, so both users see the
call in their history.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor

logger = logging.getLogger(__name__)

VALID_CALL_TYPES = {"audio", "video"}
VALID_STATUSES = {"completed", "missed", "declined", "failed"}


def _make_sk(created_at: int, call_id: str) -> str:
    # Zero-pad timestamp to 13 digits so lexicographic order matches numeric order.
    # Use 9999999999999 - ts for reverse-chronological default ordering.
    inverted = 9999999999999 - created_at
    return f"CALL#{inverted:013d}#{call_id}"


def record_call(
    caller_id: str,
    callee_id: str,
    call_type: str,
    duration_seconds: int,
    status: str,
) -> Dict[str, Any]:
    """Record a call for both caller and callee."""
    if call_type not in VALID_CALL_TYPES:
        raise ValueError(f"Invalid call_type: {call_type}")
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {status}")

    call_id = uuid.uuid4().hex
    ts = now_ts()
    sk = _make_sk(ts, call_id)

    base_item = {
        "call_id": call_id,
        "caller_id": caller_id,
        "callee_id": callee_id,
        "call_type": call_type,
        "duration_seconds": duration_seconds,
        "status": status,
        "created_at": ts,
    }

    # Write record for caller
    caller_item = {**base_item, "user_id": caller_id, "sk": sk, "direction": "outgoing"}
    T.call_history.put_item(Item=caller_item)

    # Write record for callee
    callee_item = {**base_item, "user_id": callee_id, "sk": sk, "direction": "incoming"}
    T.call_history.put_item(Item=callee_item)

    return {**base_item, "direction": "outgoing"}


def list_call_history(
    user_id: str,
    cursor: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """Return paginated call history for a user (newest first)."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": "user_id = :uid AND begins_with(sk, :prefix)",
        "ExpressionAttributeValues": {":uid": user_id, ":prefix": "CALL#"},
        "Limit": min(limit, 100),
        "ScanIndexForward": True,  # SK uses inverted timestamp, so ascending = newest first
    }
    exclusive_start = decode_cursor(cursor)
    if exclusive_start:
        kwargs["ExclusiveStartKey"] = exclusive_start

    resp = T.call_history.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))

    return {
        "items": [_item_to_out(item) for item in items],
        "next_cursor": next_cursor,
    }


def get_call_detail(user_id: str, call_id: str) -> Optional[Dict[str, Any]]:
    """Return a single call record for the given user, or None."""
    # We need to find the SK for this call_id. Query with a filter.
    resp = T.call_history.query(
        KeyConditionExpression="user_id = :uid AND begins_with(sk, :prefix)",
        FilterExpression="call_id = :cid",
        ExpressionAttributeValues={
            ":uid": user_id,
            ":prefix": "CALL#",
            ":cid": call_id,
        },
    )
    items = resp.get("Items", [])
    if not items:
        return None
    return _item_to_out(items[0])


def delete_call_record(user_id: str, call_id: str) -> bool:
    """Delete a call record from the user's history. Returns True if found and deleted."""
    resp = T.call_history.query(
        KeyConditionExpression="user_id = :uid AND begins_with(sk, :prefix)",
        FilterExpression="call_id = :cid",
        ExpressionAttributeValues={
            ":uid": user_id,
            ":prefix": "CALL#",
            ":cid": call_id,
        },
    )
    items = resp.get("Items", [])
    if not items:
        return False
    item = items[0]
    T.call_history.delete_item(Key={"user_id": user_id, "sk": item["sk"]})
    return True


def get_call_stats(user_id: str) -> Dict[str, Any]:
    """Return aggregate call statistics for a user."""
    total_calls = 0
    total_duration = 0
    calls_by_type: Dict[str, int] = {"audio": 0, "video": 0}
    calls_by_status: Dict[str, int] = {
        "completed": 0,
        "missed": 0,
        "declined": 0,
        "failed": 0,
    }

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": "user_id = :uid AND begins_with(sk, :prefix)",
        "ExpressionAttributeValues": {":uid": user_id, ":prefix": "CALL#"},
    }

    while True:
        resp = T.call_history.query(**kwargs)
        for item in resp.get("Items", []):
            total_calls += 1
            total_duration += int(item.get("duration_seconds", 0))
            ct = item.get("call_type", "audio")
            if ct in calls_by_type:
                calls_by_type[ct] += 1
            st = item.get("status", "completed")
            if st in calls_by_status:
                calls_by_status[st] += 1

        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek

    return {
        "total_calls": total_calls,
        "total_duration_seconds": total_duration,
        "calls_by_type": calls_by_type,
        "calls_by_status": calls_by_status,
    }


def _item_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "call_id": item["call_id"],
        "caller_id": item["caller_id"],
        "callee_id": item["callee_id"],
        "call_type": item.get("call_type", "audio"),
        "duration_seconds": int(item.get("duration_seconds", 0)),
        "status": item.get("status", "completed"),
        "direction": item.get("direction", "outgoing"),
        "created_at": int(item.get("created_at", 0)),
    }
