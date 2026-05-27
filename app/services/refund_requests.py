"""
Refund Requests service — BILLING-001.

Manages the customer self-service refund request lifecycle:
  pending -> approved | denied

Uses the RefundRequests DynamoDB table with GSIs for admin queue, user history,
and dedup checks.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import (
    ddb_get,
    ddb_put,
    new_ledger_entry,
    apply_balance_delta,
    user_pk,
)
from app.services.alerts import audit_event, write_alert

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _rr_pk(request_id: str) -> str:
    return f"REFUND#{request_id}"


def _gen_request_id() -> str:
    return f"rr_{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

def create_refund_request(
    user_id: str,
    transaction_entry_id: str,
    reason: str,
    amount_cents: Optional[int] = None,
) -> Dict[str, Any]:
    """Submit a new refund request. Returns the created item dict."""
    if not S.refund_requests_enabled:
        raise HTTPException(404, "Refund requests are not enabled")

    # 1. Validate the transaction exists and belongs to the user
    pk = user_pk(user_id)
    # The ledger entries are in the billing table with pk=USER#{user_id} and sk starting with LEDGER#
    items = T.billing.query(
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": pk},
    ).get("Items", [])

    ledger_entry = None
    for item in items:
        sk = item.get("sk", "")
        if sk.startswith("LEDGER#") and item.get("entry_id") == transaction_entry_id:
            ledger_entry = item
            break

    if not ledger_entry:
        raise HTTPException(404, "Transaction not found")

    # 2. Check refund window
    entry_ts = int(ledger_entry.get("ts", 0))
    window_seconds = S.refund_request_window_days * 86400
    if now_ts() - entry_ts > window_seconds:
        raise HTTPException(400, f"Transaction is outside the refund window ({S.refund_request_window_days} days)")

    # 3. Determine amount
    original_amount = int(ledger_entry.get("amount_cents", 0))
    if original_amount <= 0:
        raise HTTPException(400, "Transaction is not eligible for refund")

    if amount_cents is None:
        amount_cents = original_amount
    if amount_cents > original_amount:
        raise HTTPException(400, "Refund amount exceeds original transaction amount")

    # 4. Check for duplicate (existing pending/approved request for this transaction)
    try:
        dedup_resp = T.refund_requests.query(
            IndexName="ByTransactionId",
            KeyConditionExpression="transaction_entry_id = :tid",
            ExpressionAttributeValues={":tid": transaction_entry_id},
        )
        existing = dedup_resp.get("Items", [])
        for ex in existing:
            if ex.get("status") in ("pending", "approved", "completed"):
                raise HTTPException(409, "A refund request already exists for this transaction")
    except ClientError:
        pass  # GSI may not exist yet in some envs; skip dedup

    # 5. Check monthly limit
    month_ago = now_ts() - (30 * 86400)
    try:
        user_resp = T.refund_requests.query(
            IndexName="ByRequesterCreatedAt",
            KeyConditionExpression="requester_scope = :rs AND created_at > :since",
            ExpressionAttributeValues={
                ":rs": f"USER#{user_id}",
                ":since": month_ago,
            },
        )
        recent_count = len(user_resp.get("Items", []))
        if recent_count >= S.max_refund_requests_per_month:
            raise HTTPException(400, f"Maximum of {S.max_refund_requests_per_month} refund requests per month exceeded")
    except ClientError:
        pass

    # 6. Create the request
    request_id = _gen_request_id()
    ts = now_ts()
    item = {
        "pk": _rr_pk(request_id),
        "sk": "META",
        "refund_request_id": request_id,
        "requester_user_id": user_id,
        "requester_scope": f"USER#{user_id}",
        "transaction_entry_id": transaction_entry_id,
        "transaction_type": ledger_entry.get("reason", ledger_entry.get("type", "unknown")),
        "original_amount_cents": original_amount,
        "amount_cents": amount_cents,
        "currency": ledger_entry.get("currency", "USD"),
        "reason": reason,
        "status": "pending",
        "status_scope": "STATUS#pending",
        "admin_user_id": "",
        "admin_notes": "",
        "stripe_refund_id": "",
        "created_at": ts,
        "updated_at": ts,
        "completed_at": 0,
    }

    try:
        ddb_put(T.refund_requests, item, condition_expression="attribute_not_exists(pk)")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(409, "Duplicate refund request")
        raise

    return item


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

def get_request(request_id: str) -> Optional[Dict[str, Any]]:
    resp = T.refund_requests.get_item(Key={"pk": _rr_pk(request_id), "sk": "META"})
    return resp.get("Item")


def list_user_requests(user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    try:
        resp = T.refund_requests.query(
            IndexName="ByRequesterCreatedAt",
            KeyConditionExpression="requester_scope = :rs",
            ExpressionAttributeValues={":rs": f"USER#{user_id}"},
            ScanIndexForward=False,
            Limit=min(limit, 100),
        )
        return resp.get("Items", [])
    except ClientError:
        return []


def list_pending_requests(status: str = "pending", limit: int = 50) -> List[Dict[str, Any]]:
    try:
        resp = T.refund_requests.query(
            IndexName="ByStatusCreatedAt",
            KeyConditionExpression="status_scope = :ss",
            ExpressionAttributeValues={":ss": f"STATUS#{status}"},
            ScanIndexForward=False,
            Limit=min(limit, 100),
        )
        return resp.get("Items", [])
    except ClientError:
        return []


# ---------------------------------------------------------------------------
# Admin actions
# ---------------------------------------------------------------------------

def approve_request(
    request_id: str,
    admin_id: str,
    notes: Optional[str] = None,
    override_amount_cents: Optional[int] = None,
    request_obj: Any = None,
) -> Dict[str, Any]:
    """Approve a refund request. Calls the existing Stripe refund flow."""
    item = get_request(request_id)
    if not item:
        raise HTTPException(404, "Refund request not found")
    if item.get("status") != "pending":
        raise HTTPException(400, f"Request is not pending (status={item.get('status')})")

    amount = override_amount_cents or int(item.get("amount_cents", 0))
    if amount <= 0:
        raise HTTPException(400, "Invalid refund amount")

    ts = now_ts()
    user_id = item["requester_user_id"]

    # Create a credit ledger entry for the buyer
    pk = user_pk(user_id)
    led_sk, led_item = new_ledger_entry(
        key_name="pk",
        key_value=pk,
        entry_type="refund_credit",
        amount_cents=amount,
        state="settled",
        reason="Refund approved",
        meta={"refund_request_id": request_id, "admin_notes": notes or ""},
    )
    ddb_put(T.billing, led_item)

    # Apply balance delta (credit back)
    apply_balance_delta(T.billing, pk, {"payments_settled_cents": -amount}, currency=item.get("currency", "usd").lower())

    # Update refund request status
    T.refund_requests.update_item(
        Key={"pk": _rr_pk(request_id), "sk": "META"},
        UpdateExpression="SET #s = :s, status_scope = :ss, admin_user_id = :aid, admin_notes = :an, updated_at = :t, completed_at = :t, amount_cents = :amt",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "approved",
            ":ss": "STATUS#approved",
            ":aid": admin_id,
            ":an": notes or "",
            ":t": ts,
            ":amt": amount,
        },
    )

    # Send alert to customer
    write_alert(
        user_id,
        event="refund_approved",
        outcome="success",
        title=f"Your refund of ${amount / 100:.2f} has been approved",
        details={"refund_request_id": request_id, "amount_cents": amount},
    )

    # Audit event
    audit_event(
        "refund_request_approved",
        admin_id,
        request_obj,
        outcome="success",
        refund_request_id=request_id,
        requester_user_id=user_id,
        amount_cents=amount,
        admin_notes=notes or "",
    )

    item["status"] = "approved"
    item["admin_user_id"] = admin_id
    item["admin_notes"] = notes or ""
    item["completed_at"] = ts
    item["amount_cents"] = amount
    return item


def reject_request(
    request_id: str,
    admin_id: str,
    notes: str,
    request_obj: Any = None,
) -> Dict[str, Any]:
    """Deny a refund request with notes."""
    item = get_request(request_id)
    if not item:
        raise HTTPException(404, "Refund request not found")
    if item.get("status") != "pending":
        raise HTTPException(400, f"Request is not pending (status={item.get('status')})")

    ts = now_ts()
    user_id = item["requester_user_id"]

    T.refund_requests.update_item(
        Key={"pk": _rr_pk(request_id), "sk": "META"},
        UpdateExpression="SET #s = :s, status_scope = :ss, admin_user_id = :aid, admin_notes = :an, updated_at = :t, completed_at = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "denied",
            ":ss": "STATUS#denied",
            ":aid": admin_id,
            ":an": notes,
            ":t": ts,
        },
    )

    write_alert(
        user_id,
        event="refund_denied",
        outcome="info",
        title="Your refund request was denied",
        details={"refund_request_id": request_id, "admin_notes": notes},
    )

    audit_event(
        "refund_request_denied",
        admin_id,
        request_obj,
        outcome="success",
        refund_request_id=request_id,
        requester_user_id=user_id,
        admin_notes=notes,
    )

    item["status"] = "denied"
    item["admin_user_id"] = admin_id
    item["admin_notes"] = notes
    item["completed_at"] = ts
    return item
