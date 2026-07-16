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

from boto3.dynamodb.types import TypeSerializer
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

_ddb_serializer = TypeSerializer()


def _serialize_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a resource-level item dict to low-level DynamoDB AttributeValue
    form for use with the client-level transact_write_items API."""
    return {k: _ddb_serializer.serialize(v) for k, v in item.items()}


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

    # ── ECOMX-16 (A9): close the refund window once the order has SHIPPED. A
    # cart buyer-debit carries the order_id in meta; if any ship-group of that
    # order has reached packed/shipped/completed the buyer must use the RETURN
    # flow, not a straight refund (otherwise they get product AND money back).
    _order_id = str((ledger_entry.get("meta") or {}).get("order_id") or "")
    if _order_id:
        try:
            from app.services.order_store import get_order_header as _goh
            _hdr = _goh(_order_id) or {}
            _lc = str(_hdr.get("lifecycle_status") or "")
            if _lc in ("packed", "shipped", "completed"):
                raise HTTPException(
                    400,
                    {"code": "refund_window_closed",
                     "message": f"Order has shipped (status={_lc}); use the return flow."},
                )
        except HTTPException:
            raise
        except Exception:
            pass  # order lookup best-effort; never block a legit refund on a lookup glitch

    # 3. Determine amount
    # ECOM fix: cart-purchase buyer ledger debits are stored with a NEGATIVE
    # amount_cents (signed debit), so use abs() to derive the refundable amount;
    # otherwise every shop purchase is wrongly "not eligible for refund".
    original_amount = abs(int(ledger_entry.get("amount_cents", 0)))
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
    currency = item.get("currency", "usd").lower()
    transaction_entry_id = item.get("transaction_entry_id", "")

    # Create a credit ledger entry for the buyer
    pk = user_pk(user_id)

    # GAP-0132 / ECOMX-13: For marketplace transactions (tip/unlock/shop/livecom)
    # the original purchase wrote a buyer debit + one-or-more seller/host credits.
    # Refunding only credits the buyer; without matching seller/host DEBITS the
    # ledger no longer balances and the recipients keep the funds
    # (double-enrichment). Recover the buyer-debit meta so we can reverse EVERY
    # credited party — the single recipient (tip/unlock), ALL sellers of a
    # multi-seller cart, AND the livecom host commission.
    debit_meta: Dict[str, Any] = {}
    if transaction_entry_id:
        for entry in T.billing.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": pk},
        ).get("Items", []):
            if str(entry.get("sk", "")).startswith("LEDGER#") and entry.get("entry_id") == transaction_entry_id:
                debit_meta = dict(entry.get("meta") or {})
                break

    # Assemble the set of parties to claw back. recipient_user_id keeps the legacy
    # single-recipient path (tip/unlock); refund_seller_ids + refund_host_id add
    # the shop/livecom multi-party clawback.
    order_id_ref = str(debit_meta.get("order_id") or "")
    party_ids: List[str] = []
    for cand in (
        [debit_meta.get("recipient_user_id")]
        + list(debit_meta.get("refund_seller_ids") or [])
        + [debit_meta.get("refund_host_id")]
    ):
        if cand and cand != user_id and cand not in party_ids:
            party_ids.append(cand)

    # For each party, claw back the ACTUAL net cents they were credited for THIS
    # order (net-of-platform-fee, host commission, etc.) — never the gross buyer
    # amount, which would over-claw. Sum every settled *credit* entry for the
    # order on that party's ledger.
    def _party_credit_cents(party_id: str) -> int:
        if not order_id_ref:
            return amount  # no order linkage (legacy tip/unlock) -> full amount
        total = 0
        for e in T.billing.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": user_pk(party_id)},
        ).get("Items", []):
            if not str(e.get("sk", "")).startswith("LEDGER#"):
                continue
            m = e.get("meta") or {}
            if str(m.get("order_id") or "") != order_id_ref:
                continue
            # new_ledger_entry persists the entry type under "type" (not
            # "entry_type"). Only reverse the original seller/host CREDIT, never
            # a prior refund_debit / other row for the same order.
            if str(e.get("type") or "") != "credit":
                continue
            try:
                total += int(e.get("amount_cents") or 0)
            except (TypeError, ValueError):
                continue
        return total

    led_sk, led_item = new_ledger_entry(
        key_name="pk",
        key_value=pk,
        entry_type="refund_credit",
        amount_cents=amount,
        state="settled",
        reason="Refund approved",
        meta={
            "refund_request_id": request_id,
            "admin_notes": notes or "",
            "original_entry_id": transaction_entry_id,
            "order_id": order_id_ref,
        },
    )

    # Build one debit per credited party (reversing their exact net), then commit
    # the buyer credit + all party debits ATOMICALLY. ECOMX-16 (A8/A9): route the
    # transact through ddb_transact_client() with NATIVE AttributeValue items —
    # the resource client's document transform re-serializes pre-serialized maps
    # and 500s on DDB-Local (the tip-transact bug). On a transact failure we fall
    # back to sequential puts guarded so a partial write can't leave the ledger
    # half-reversed (compensating deletes on any exception mid-sequence).
    party_debits: List[Dict[str, Any]] = []
    for party_id in party_ids:
        claw = _party_credit_cents(party_id)
        if claw <= 0:
            continue
        _, party_debit_item = new_ledger_entry(
            key_name="pk",
            key_value=user_pk(party_id),
            entry_type="refund_debit",
            amount_cents=claw,
            state="settled",
            reason="Refund clawback",
            meta={
                "refund_request_id": request_id,
                "buyer_user_id": user_id,
                "original_entry_id": transaction_entry_id,
                "order_id": order_id_ref,
                "clawed_cents": claw,
            },
        )
        party_debits.append({"party_id": party_id, "claw": claw, "item": party_debit_item})

    if party_debits:
        transact_items = [{"Put": {"TableName": T.billing.name, "Item": _serialize_item(led_item)}}]
        for pd in party_debits:
            transact_items.append(
                {"Put": {"TableName": T.billing.name, "Item": _serialize_item(pd["item"])}}
            )
        committed_atomic = False
        try:
            from app.core.aws_clients import ddb_transact_client
            ddb_transact_client().transact_write_items(TransactItems=transact_items)
            committed_atomic = True
        except Exception:
            logger.warning("refund transact fell back to sequential request_id=%s", request_id, exc_info=True)
        if not committed_atomic:
            _written: List[Dict[str, Any]] = []
            try:
                ddb_put(T.billing, led_item)
                _written.append(led_item)
                for pd in party_debits:
                    ddb_put(T.billing, pd["item"])
                    _written.append(pd["item"])
            except Exception:
                # Compensating deletes so a partial sequence cannot leave the
                # ledger half-reversed (buyer credited but a party un-clawed).
                for w in _written:
                    try:
                        T.billing.delete_item(Key={"pk": w["pk"], "sk": w["sk"]})
                    except Exception:
                        logger.exception("compensating delete failed request_id=%s", request_id)
                raise HTTPException(500, "Refund clawback failed atomically")
        # Reverse each party's earned credit on their balance row.
        for pd in party_debits:
            apply_balance_delta(T.billing, user_pk(pd["party_id"]), {"owed_settled_cents": -pd["claw"]}, currency=currency)
            logger.info(
                "refund_party_clawback request_id=%s party=%s clawed_cents=%s",
                request_id, pd["party_id"], pd["claw"],
            )
    else:
        ddb_put(T.billing, led_item)
        logger.info(
            "refund_no_party request_id=%s transaction_entry_id=%s "
            "(no party debit written; non-marketplace or unattributed transaction)",
            request_id, transaction_entry_id,
        )

    # Apply balance delta (credit back)
    apply_balance_delta(T.billing, pk, {"payments_settled_cents": -amount}, currency=currency)

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

    # ECOMX-22: return flow. If this refund is against an order that already
    # SHIPPED (or completed), the header can't just cancel — it must move to
    # `returned` and the inventory must be restocked. mark_returned no-ops on a
    # pre-ship order (that path stays a cancel). Best-effort; never fails the
    # refund that already committed above.
    if order_id_ref:
        try:
            from app.services import order_fulfillment_bridge as _bridge
            _bridge.mark_returned(order_id_ref, actor=f"refund:{admin_id}")
        except Exception:
            logger.exception("refund return-flow bridge failed order=%s", order_id_ref)

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
