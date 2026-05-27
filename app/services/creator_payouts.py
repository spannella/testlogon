"""Creator Payout service (MON-004).

Manages payout requests, balance calculations, and admin approval workflow.
"""

from __future__ import annotations

import logging
import uuid
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Valid payout states
PAYOUT_STATES = {"requested", "approved", "processing", "completed", "rejected", "cancelled", "failed"}
ACTIVE_PAYOUT_STATES = {"requested", "approved", "processing"}


def _to_int(val: Any) -> int:
    """Coerce DynamoDB Decimal or string to int."""
    if isinstance(val, Decimal):
        return int(val)
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str) and val.isdigit():
        return int(val)
    return 0


def _payout_to_dict(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a DDB payout item to a clean dict."""
    return {
        "payout_id": item.get("payout_id", ""),
        "user_id": item.get("user_id", ""),
        "amount_cents": _to_int(item.get("amount_cents", 0)),
        "method": item.get("method", "bank_transfer"),
        "status": item.get("status", ""),
        "created_at": _to_int(item.get("created_at", 0)),
        "updated_at": _to_int(item.get("updated_at", 0)),
        "notes": item.get("notes", ""),
        "reject_reason": item.get("reject_reason", ""),
        "approved_by": item.get("approved_by", ""),
        "completed_at": _to_int(item.get("completed_at", 0)) or None,
    }


def get_available_balance(user_id: str) -> dict:
    """Calculate available balance from billing ledger credits.

    Queries T.billing for pk=USER#{user_id}, sk begins_with LEDGER#,
    type=credit. Only includes entries where ts + hold_period <= now_ts().
    Subtracts any pending/approved/processing payout amounts.

    Returns: {available_cents, pending_cents, total_earned_cents, hold_cents}
    """
    pk = f"USER#{user_id}"
    now = now_ts()
    hold_period = S.payout_hold_period_seconds

    key_cond = Key("pk").eq(pk) & Key("sk").begins_with("LEDGER#")
    filter_expr = Attr("type").eq("credit")

    total_earned_cents = 0
    available_cents = 0
    hold_cents = 0

    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": key_cond,
        "FilterExpression": filter_expr,
    }

    while True:
        resp = T.billing.query(**query_kwargs)
        items = resp.get("Items", [])

        for item in items:
            amount = _to_int(item.get("amount_cents", 0))
            ts = _to_int(item.get("ts", 0))
            total_earned_cents += amount

            if ts + hold_period <= now:
                available_cents += amount
            else:
                hold_cents += amount

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key

    # Subtract pending/approved/processing payouts
    pending_cents = _get_active_payout_total(user_id)
    available_cents = max(0, available_cents - pending_cents)

    return {
        "available_cents": available_cents,
        "pending_cents": pending_cents,
        "total_earned_cents": total_earned_cents,
        "hold_cents": hold_cents,
    }


def _get_active_payout_total(user_id: str) -> int:
    """Sum of amounts for all active payouts (requested/approved/processing)."""
    total = 0

    query_kwargs: Dict[str, Any] = {
        "IndexName": "ByUserCreatedAt",
        "KeyConditionExpression": Key("user_id").eq(user_id),
        "ScanIndexForward": False,
    }

    while True:
        resp = T.creator_payouts.query(**query_kwargs)
        items = resp.get("Items", [])

        for item in items:
            status = item.get("status", "")
            if status in ACTIVE_PAYOUT_STATES:
                total += _to_int(item.get("amount_cents", 0))

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key

    return total


def _has_active_payout(user_id: str) -> bool:
    """Check if user has any active (requested/approved/processing) payout."""
    query_kwargs: Dict[str, Any] = {
        "IndexName": "ByUserCreatedAt",
        "KeyConditionExpression": Key("user_id").eq(user_id),
        "ScanIndexForward": False,
        "Limit": 50,
    }

    while True:
        resp = T.creator_payouts.query(**query_kwargs)
        items = resp.get("Items", [])

        for item in items:
            status = item.get("status", "")
            if status in ACTIVE_PAYOUT_STATES:
                return True

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key

    return False


def request_payout(user_id: str, amount_cents: int, method: str = "bank_transfer", notes: str = "") -> dict:
    """Create a payout request.

    Validates:
    - amount >= minimum (1000 cents / $10)
    - amount <= available_balance
    - No other active payout exists for user

    Returns: {payout_id, amount_cents, status, created_at}
    """
    minimum = S.payout_minimum_cents
    if amount_cents < minimum:
        raise ValueError(f"Amount must be at least {minimum} cents (${minimum / 100:.2f})")

    # Check for existing active payout
    if _has_active_payout(user_id):
        raise ValueError("DUPLICATE_PAYOUT")

    # Check available balance
    balance = get_available_balance(user_id)
    if amount_cents > balance["available_cents"]:
        raise ValueError(f"Insufficient balance. Available: {balance['available_cents']} cents")

    now = now_ts()
    payout_id = f"payout_{uuid.uuid4().hex}"

    item = {
        "payout_id": payout_id,
        "user_id": user_id,
        "amount_cents": amount_cents,
        "method": method,
        "status": "requested",
        "created_at": now,
        "updated_at": now,
        "notes": notes,
        "reject_reason": "",
        "approved_by": "",
    }

    T.creator_payouts.put_item(Item=item)

    return _payout_to_dict(item)


def cancel_payout(payout_id: str, user_id: str) -> dict:
    """Cancel a payout request (creator only, status must be requested or approved)."""
    resp = T.creator_payouts.get_item(Key={"payout_id": payout_id})
    item = resp.get("Item")
    if not item:
        raise LookupError("Payout not found")

    if item.get("user_id") != user_id:
        raise PermissionError("Not your payout")

    status = item.get("status", "")
    if status not in ("requested", "approved"):
        raise ValueError(f"Cannot cancel payout in '{status}' state")

    now = now_ts()
    T.creator_payouts.update_item(
        Key={"payout_id": payout_id},
        UpdateExpression="SET #s = :status, updated_at = :now",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":status": "cancelled", ":now": now},
    )

    item["status"] = "cancelled"
    item["updated_at"] = now
    return _payout_to_dict(item)


def list_user_payouts(user_id: str, *, limit: int = 25, cursor: Optional[str] = None) -> dict:
    """List user's payout history (ByUserCreatedAt GSI)."""
    query_kwargs: Dict[str, Any] = {
        "IndexName": "ByUserCreatedAt",
        "KeyConditionExpression": Key("user_id").eq(user_id),
        "ScanIndexForward": False,
        "Limit": limit,
    }

    start_key = decode_cursor(cursor)
    if start_key:
        query_kwargs["ExclusiveStartKey"] = start_key

    resp = T.creator_payouts.query(**query_kwargs)
    items = [_payout_to_dict(item) for item in resp.get("Items", [])]
    last_key = resp.get("LastEvaluatedKey")
    next_cursor = encode_cursor(last_key) if last_key else None

    return {"items": items, "next_cursor": next_cursor}


def list_payouts_admin(*, status: Optional[str] = None, limit: int = 25, cursor: Optional[str] = None) -> dict:
    """Admin: list payouts, optionally filtered by status (ByStatusCreatedAt GSI)."""
    if status:
        query_kwargs: Dict[str, Any] = {
            "IndexName": "ByStatusCreatedAt",
            "KeyConditionExpression": Key("status").eq(status),
            "ScanIndexForward": False,
            "Limit": limit,
        }
        start_key = decode_cursor(cursor)
        if start_key:
            query_kwargs["ExclusiveStartKey"] = start_key

        resp = T.creator_payouts.query(**query_kwargs)
        items = [_payout_to_dict(item) for item in resp.get("Items", [])]
        last_key = resp.get("LastEvaluatedKey")
        next_cursor = encode_cursor(last_key) if last_key else None
    else:
        # Scan all payouts (no status filter), sorted by created_at desc
        scan_kwargs: Dict[str, Any] = {
            "Limit": limit,
        }
        start_key = decode_cursor(cursor)
        if start_key:
            scan_kwargs["ExclusiveStartKey"] = start_key

        resp = T.creator_payouts.scan(**scan_kwargs)
        items = [_payout_to_dict(item) for item in resp.get("Items", [])]
        # Sort by created_at desc since scan doesn't guarantee order
        items.sort(key=lambda x: x["created_at"], reverse=True)
        last_key = resp.get("LastEvaluatedKey")
        next_cursor = encode_cursor(last_key) if last_key else None

    return {"items": items, "next_cursor": next_cursor}


def approve_payout(payout_id: str, admin_user_id: str) -> dict:
    """Admin approves payout. status: requested -> approved."""
    resp = T.creator_payouts.get_item(Key={"payout_id": payout_id})
    item = resp.get("Item")
    if not item:
        raise LookupError("Payout not found")

    status = item.get("status", "")
    if status != "requested":
        raise ValueError(f"Cannot approve payout in '{status}' state (must be 'requested')")

    now = now_ts()
    T.creator_payouts.update_item(
        Key={"payout_id": payout_id},
        UpdateExpression="SET #s = :status, updated_at = :now, approved_by = :admin",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":status": "approved",
            ":now": now,
            ":admin": admin_user_id,
        },
    )

    item["status"] = "approved"
    item["updated_at"] = now
    item["approved_by"] = admin_user_id
    return _payout_to_dict(item)


def reject_payout(payout_id: str, admin_user_id: str, reason: str = "") -> dict:
    """Admin rejects payout. status: requested -> rejected."""
    resp = T.creator_payouts.get_item(Key={"payout_id": payout_id})
    item = resp.get("Item")
    if not item:
        raise LookupError("Payout not found")

    status = item.get("status", "")
    if status != "requested":
        raise ValueError(f"Cannot reject payout in '{status}' state (must be 'requested')")

    now = now_ts()
    T.creator_payouts.update_item(
        Key={"payout_id": payout_id},
        UpdateExpression="SET #s = :status, updated_at = :now, reject_reason = :reason, approved_by = :admin",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":status": "rejected",
            ":now": now,
            ":reason": reason,
            ":admin": admin_user_id,
        },
    )

    item["status"] = "rejected"
    item["updated_at"] = now
    item["reject_reason"] = reason
    return _payout_to_dict(item)


def complete_payout(payout_id: str) -> dict:
    """Mark payout as completed (after external transfer).
    In dev mode, auto-transitions approved -> processing -> completed.
    Otherwise: processing -> completed.
    """
    resp = T.creator_payouts.get_item(Key={"payout_id": payout_id})
    item = resp.get("Item")
    if not item:
        raise LookupError("Payout not found")

    status = item.get("status", "")
    now = now_ts()

    if S.dev_mode and status == "approved":
        # Dev mode: auto-transition through processing
        T.creator_payouts.update_item(
            Key={"payout_id": payout_id},
            UpdateExpression="SET #s = :status, updated_at = :now, completed_at = :now",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":status": "completed", ":now": now},
        )
        item["status"] = "completed"
        item["updated_at"] = now
        item["completed_at"] = now
        return _payout_to_dict(item)

    if status not in ("approved", "processing"):
        raise ValueError(f"Cannot complete payout in '{status}' state")

    T.creator_payouts.update_item(
        Key={"payout_id": payout_id},
        UpdateExpression="SET #s = :status, updated_at = :now, completed_at = :now",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":status": "completed", ":now": now},
    )

    item["status"] = "completed"
    item["updated_at"] = now
    item["completed_at"] = now
    return _payout_to_dict(item)


def get_payout_stats() -> dict:
    """Admin: queue stats. Count of requested, total pending amount, etc."""
    stats = {
        "total_requested": 0,
        "total_requested_amount_cents": 0,
        "total_approved": 0,
        "total_processing": 0,
    }

    # Query requested payouts
    query_kwargs: Dict[str, Any] = {
        "IndexName": "ByStatusCreatedAt",
        "KeyConditionExpression": Key("status").eq("requested"),
    }
    while True:
        resp = T.creator_payouts.query(**query_kwargs)
        for item in resp.get("Items", []):
            stats["total_requested"] += 1
            stats["total_requested_amount_cents"] += _to_int(item.get("amount_cents", 0))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key

    # Query approved payouts
    query_kwargs2: Dict[str, Any] = {
        "IndexName": "ByStatusCreatedAt",
        "KeyConditionExpression": Key("status").eq("approved"),
    }
    while True:
        resp = T.creator_payouts.query(**query_kwargs2)
        stats["total_approved"] += len(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs2["ExclusiveStartKey"] = last_key

    # Query processing payouts
    query_kwargs3: Dict[str, Any] = {
        "IndexName": "ByStatusCreatedAt",
        "KeyConditionExpression": Key("status").eq("processing"),
    }
    while True:
        resp = T.creator_payouts.query(**query_kwargs3)
        stats["total_processing"] += len(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs3["ExclusiveStartKey"] = last_key

    return stats
