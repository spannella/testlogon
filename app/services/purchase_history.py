from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from uuid import uuid4

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.profile import get_profile
from app.services.billing_shared import new_ledger_entry, ddb_put, user_pk
from app.services.carrier_tracking import build_tracking_url, detect_carrier


def _safe_profile(user_sub: str) -> Dict[str, Any]:
    try:
        return get_profile(user_sub)
    except Exception:
        return {}


def _search_tokens(text: str) -> List[str]:
    return [t for t in re.findall(r"[a-z0-9@._-]+", (text or "").lower()) if t]


def _metadata_strings(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        parts: List[str] = []
        for key, val in value.items():
            parts.extend([str(key), *(_metadata_strings(val))])
        return parts
    if isinstance(value, list):
        parts = []
        for entry in value:
            parts.extend(_metadata_strings(entry))
        return parts
    return [str(value)]


def _transaction_haystack(item: Dict[str, Any]) -> str:
    metadata_parts = _metadata_strings(item.get("metadata"))
    cancel_parts = _metadata_strings(item.get("cancel"))
    shipping_parts = _metadata_strings(item.get("shipping"))
    return " ".join(
        [
            str(item.get("txn_id", "")),
            str(item.get("status", "")),
            str(item.get("merchant_id", "")),
            str(item.get("external_ref", "")),
            str(item.get("description", "")),
            str(item.get("processor_ref", "")),
            str(item.get("completion_note", "")),
            str(item.get("revert_reason", "")),
            " ".join(metadata_parts),
            " ".join(cancel_parts),
            " ".join(shipping_parts),
        ]
    ).lower()


def _transaction_matches(query_tokens: List[str], item: Dict[str, Any]) -> bool:
    if not query_tokens:
        return False
    haystack = _transaction_haystack(item)
    return all(token in haystack for token in query_tokens)

def _txn_sk(created_at: int, txn_id: str) -> str:
    return f"TXN#{created_at}#{txn_id}"


def _event_sk(ts: int, event_id: str) -> str:
    return f"EVENT#{ts}#{event_id}"


def _record_event(txn_id: str, user_sub: str, event_name: str, payload: Dict[str, Any]) -> None:
    ts = now_ts()
    event_id = uuid4().hex
    try:
        T.purchase_events.put_item(
            Item={
                "pk": f"TXN#{txn_id}",
                "sk": _event_sk(ts, event_id),
                "txn_id": txn_id,
                "user_sub": user_sub,
                "event_name": event_name,
                "payload": payload,
                "created_at": ts,
            },
        )
    except Exception:
        return


def _item_to_summary(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "txn_id": item["txn_id"],
        "created_at": int(item["created_at"]),
        "updated_at": int(item["updated_at"]),
        "status": item["status"],
        "amount": float(item["amount"]),
        "currency": item["currency"],
        "merchant_id": item.get("merchant_id"),
        "external_ref": item.get("external_ref"),
        "description": item.get("description"),
    }


def _item_to_info(item: Dict[str, Any]) -> Dict[str, Any]:
    summary = _item_to_summary(item)
    summary.update(
        {
            "buyer_id": item["buyer_id"],
            "buyer_profile": item.get("buyer_profile"),
            "shipping": item.get("shipping"),
            "cancel": item.get("cancel"),
            "completed_at": item.get("completed_at"),
            "reverted_at": item.get("reverted_at"),
            "version": int(item.get("version", 0)),
            "metadata": item.get("metadata"),
            "receipt_path": item.get("receipt_path"),
            "receipt_generated_at": item.get("receipt_generated_at"),
        },
    )
    return summary


def _fetch_txn(user_sub: str, txn_id: str) -> Optional[Dict[str, Any]]:
    resp = T.purchase_transactions.query(
        KeyConditionExpression="user_sub = :u AND begins_with(sk, :p)",
        ExpressionAttributeValues={":u": user_sub, ":p": "TXN#", ":t": txn_id},
        FilterExpression="txn_id = :t",
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def _fetch_txn_by_idempotency_key(user_sub: str, idempotency_key: str) -> Optional[Dict[str, Any]]:
    resp = T.purchase_transactions.query(
        KeyConditionExpression="user_sub = :u AND begins_with(sk, :p)",
        ExpressionAttributeValues={":u": user_sub, ":p": "TXN#", ":idem": idempotency_key},
        FilterExpression="request_idempotency_key = :idem",
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def get_transaction_item(user_sub: str, txn_id: str) -> Dict[str, Any]:
    item = _fetch_txn(user_sub, txn_id)
    if not item:
        raise HTTPException(404, "Transaction not found")
    return item


def set_receipt_info(user_sub: str, txn_id: str, receipt_path: str, generated_at: int) -> None:
    item = _fetch_txn(user_sub, txn_id)
    if not item:
        raise HTTPException(404, "Transaction not found")
    try:
        T.purchase_transactions.update_item(
            Key={"user_sub": item["user_sub"], "sk": item["sk"]},
            UpdateExpression=(
                "SET receipt_path = :p, receipt_generated_at = :g, "
                "updated_at = :u, version = version + :one"
            ),
            ConditionExpression="version = :v",
            ExpressionAttributeValues={
                ":p": receipt_path,
                ":g": int(generated_at),
                ":u": now_ts(),
                ":one": 1,
                ":v": int(item.get("version", 0)),
            },
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(409, "Conflict: transaction was updated by someone else") from exc
        raise HTTPException(500, f"DDB error: {exc.response.get('Error', {}).get('Message')}") from exc
    _record_event(
        txn_id,
        user_sub,
        "receipt_generated",
        {"receipt_path": receipt_path, "receipt_generated_at": int(generated_at)},
    )


def record_receipt_download(user_sub: str, txn_id: str, receipt_path: str) -> None:
    _record_event(
        txn_id,
        user_sub,
        "receipt_downloaded",
        {"receipt_path": receipt_path},
    )


def create_transaction(user_sub: str, body: Dict[str, Any], *, idempotency_key: str | None = None) -> Dict[str, Any]:
    request_idempotency_key = str(idempotency_key or "").strip()
    if request_idempotency_key:
        existing = _fetch_txn_by_idempotency_key(user_sub, request_idempotency_key)
        if existing:
            return {
                "txn_id": existing["txn_id"],
                "status": existing.get("status", "PENDING"),
                "created_at": int(existing.get("created_at") or now_ts()),
            }
    txn_id = uuid4().hex
    created_at = now_ts()
    profile = _safe_profile(user_sub)
    buyer_profile = profile if any(profile.values()) else None
    item = {
        "user_sub": user_sub,
        "sk": _txn_sk(created_at, txn_id),
        "txn_id": txn_id,
        "buyer_id": user_sub,
        "buyer_profile": buyer_profile,
        "created_at": created_at,
        "updated_at": created_at,
        "status": "PENDING",
        "amount": str(body["money"]["amount"]),
        "currency": body["money"]["currency"],
        "version": 1,
        "request_idempotency_key": request_idempotency_key or None,
    }
    for key in ("merchant_id", "external_ref", "description", "metadata"):
        if body.get(key) is not None:
            item[key] = body[key]
    try:
        T.purchase_transactions.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(user_sub) AND attribute_not_exists(sk)",
        )
    except ClientError as exc:
        raise HTTPException(500, f"DDB error: {exc.response.get('Error', {}).get('Message')}") from exc
    except Exception:
        pass

    _record_event(txn_id, user_sub, "transaction_created", {"txn_id": txn_id, "status": "PENDING"})
    return {"txn_id": txn_id, "status": "PENDING", "created_at": created_at}


def record_cart_purchase(
    *,
    user_sub: str,
    cart_id: str,
    order_id: str,
    total_cents: int,
    currency: str,
    items: List[Dict[str, Any]],
    buyer: Optional[Dict[str, Any]],
) -> str:
    txn_id = uuid4().hex
    created_at = now_ts()
    amount = total_cents / 100.0
    item = {
        "user_sub": user_sub,
        "sk": _txn_sk(created_at, txn_id),
        "txn_id": txn_id,
        "buyer_id": user_sub,
        "buyer_profile": buyer,
        "created_at": created_at,
        "updated_at": created_at,
        "completed_at": created_at,
        "status": "COMPLETED",
        "amount": str(amount),
        "currency": currency,
        "merchant_id": "shopping_cart",
        "external_ref": order_id,
        "description": f"Shopping cart {cart_id}",
        "version": 1,
        "metadata": {
            "cart_id": cart_id,
            "order_id": order_id,
            "items": items,
            "buyer": buyer,
        },
    }
    try:
        T.purchase_transactions.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(user_sub) AND attribute_not_exists(sk)",
        )
    except ClientError as exc:
        raise HTTPException(500, f"DDB error: {exc.response.get('Error', {}).get('Message')}") from exc
    except Exception:
        pass

    _record_event(txn_id, user_sub, "cart_purchased", {"cart_id": cart_id, "order_id": order_id})

    # Write a billing ledger entry so the purchase appears in the billing ledger
    try:
        led_sk, led_item = new_ledger_entry(
            key_name="pk",
            key_value=user_pk(user_sub),
            entry_type="purchase",
            amount_cents=-total_cents,
            state="settled",
            reason=f"Cart purchase – order {order_id}",
            meta={"cart_id": cart_id, "order_id": order_id, "txn_id": txn_id},
        )
        ddb_put(T.billing, led_item)
    except Exception:
        pass  # Ledger write failure is non-fatal

    return txn_id


def record_billing_transaction(
    *,
    user_sub: str,
    amount_cents: int,
    currency: str,
    description: str,
    status: str,
    external_ref: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    txn_id = uuid4().hex
    created_at = now_ts()
    profile = _safe_profile(user_sub)
    buyer_profile = profile if any(profile.values()) else None
    item = {
        "user_sub": user_sub,
        "sk": _txn_sk(created_at, txn_id),
        "txn_id": txn_id,
        "buyer_id": user_sub,
        "buyer_profile": buyer_profile,
        "created_at": created_at,
        "updated_at": created_at,
        "status": status,
        "amount": str(amount_cents / 100.0),
        "currency": currency,
        "merchant_id": "billing",
        "external_ref": external_ref,
        "description": description,
        "version": 1,
    }
    if metadata:
        item["metadata"] = metadata
    if status == "COMPLETED":
        item["completed_at"] = created_at
    try:
        T.purchase_transactions.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(user_sub) AND attribute_not_exists(sk)",
        )
    except ClientError as exc:
        raise HTTPException(500, f"DDB error: {exc.response.get('Error', {}).get('Message')}") from exc
    except Exception:
        pass

    _record_event(txn_id, user_sub, "billing_transaction_recorded", {"status": status, "external_ref": external_ref})
    return txn_id


def list_transactions(user_sub: str, limit: int, status: Optional[str]) -> List[Dict[str, Any]]:
    resp = T.purchase_transactions.query(
        KeyConditionExpression="user_sub = :u AND begins_with(sk, :p)",
        ExpressionAttributeValues={":u": user_sub, ":p": "TXN#"},
        Limit=limit,
    )
    items = resp.get("Items", [])
    summaries = [_item_to_summary(item) for item in items]
    if status:
        summaries = [summary for summary in summaries if summary["status"] == status]
    return summaries


def search_transactions(user_sub: str, query: str, limit: int) -> List[Dict[str, Any]]:
    query_tokens = _search_tokens(query)
    if not query_tokens:
        return []
    resp = T.purchase_transactions.query(
        KeyConditionExpression="user_sub = :u AND begins_with(sk, :p)",
        ExpressionAttributeValues={":u": user_sub, ":p": "TXN#"},
    )
    items = resp.get("Items", [])
    matches = [item for item in items if _transaction_matches(query_tokens, item)]
    return [_item_to_summary(item) for item in matches[:limit]]


def get_transaction_info(user_sub: str, txn_id: str) -> Dict[str, Any]:
    item = _fetch_txn(user_sub, txn_id)
    if not item:
        raise HTTPException(404, "Transaction not found")
    info = _item_to_info(item)
    # Enrich shipping with tracking URL (computed, not stored)
    if info.get("shipping"):
        carrier = info["shipping"].get("carrier")
        tracking_number = info["shipping"].get("tracking_number")
        if carrier and tracking_number:
            info["shipping"]["tracking_url"] = build_tracking_url(carrier, tracking_number)
    return info


def update_shipping(user_sub: str, txn_id: str, shipping: Dict[str, Any]) -> Dict[str, Any]:
    item = _fetch_txn(user_sub, txn_id)
    if not item:
        raise HTTPException(404, "Transaction not found")
    if item["status"] == "CANCELLED":
        raise HTTPException(409, "Cannot update shipping for cancelled transactions")
    updated_at = now_ts()
    shipping = {k: v for k, v in shipping.items() if v is not None}

    # Auto-detect carrier if tracking_number provided but carrier is not
    if shipping.get("tracking_number") and not shipping.get("carrier"):
        detected = detect_carrier(shipping["tracking_number"])
        if detected:
            shipping["carrier"] = detected

    # Store tracking_number at top level for GSI (TrackingIndex) lookup
    update_expr = "SET shipping = :s, updated_at = :u, version = version + :one"
    expr_values: Dict[str, Any] = {":s": shipping, ":u": updated_at, ":one": 1, ":v": int(item.get("version", 0))}
    if shipping.get("tracking_number"):
        update_expr += ", tracking_number = :tn"
        expr_values[":tn"] = shipping["tracking_number"]

    try:
        T.purchase_transactions.update_item(
            Key={"user_sub": item["user_sub"], "sk": item["sk"]},
            UpdateExpression=update_expr,
            ConditionExpression="version = :v",
            ExpressionAttributeValues=expr_values,
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(409, "Conflict: transaction was updated by someone else") from exc
        raise HTTPException(500, f"DDB error: {exc.response.get('Error', {}).get('Message')}") from exc
    _record_event(txn_id, user_sub, "shipping_updated", {"shipping": shipping})
    return get_transaction_info(user_sub, txn_id)


def mark_completed(user_sub: str, txn_id: str, processor_ref: Optional[str], note: Optional[str]) -> Dict[str, Any]:
    item = _fetch_txn(user_sub, txn_id)
    if not item:
        raise HTTPException(404, "Transaction not found")
    if item["status"] not in {"PENDING", "CANCEL_DENIED"}:
        raise HTTPException(409, f"Cannot complete from status {item['status']}")
    updated_at = now_ts()
    processor_ref = processor_ref or item.get("external_ref") or ""
    try:
        T.purchase_transactions.update_item(
            Key={"user_sub": item["user_sub"], "sk": item["sk"]},
            UpdateExpression=(
                "SET #st = :st, updated_at = :u, completed_at = :u, "
                "processor_ref = :pr, completion_note = :n, version = version + :one"
            ),
            ConditionExpression="version = :v",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": "COMPLETED",
                ":u": updated_at,
                ":pr": processor_ref,
                ":n": note or "",
                ":one": 1,
                ":v": int(item.get("version", 0)),
            },
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(409, "Conflict: transaction was updated by someone else") from exc
        raise HTTPException(500, f"DDB error: {exc.response.get('Error', {}).get('Message')}") from exc
    _record_event(txn_id, user_sub, "transaction_completed", {"processor_ref": processor_ref, "note": note})
    return get_transaction_info(user_sub, txn_id)


def mark_reverted(user_sub: str, txn_id: str, reason: Optional[str]) -> Dict[str, Any]:
    item = _fetch_txn(user_sub, txn_id)
    if not item:
        raise HTTPException(404, "Transaction not found")
    if item["status"] not in {"COMPLETED", "PENDING"}:
        raise HTTPException(409, f"Cannot revert from status {item['status']}")
    updated_at = now_ts()
    try:
        T.purchase_transactions.update_item(
            Key={"user_sub": item["user_sub"], "sk": item["sk"]},
            UpdateExpression=(
                "SET #st = :st, updated_at = :u, reverted_at = :u, "
                "revert_reason = :rr, version = version + :one"
            ),
            ConditionExpression="version = :v",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": "REVERTED",
                ":u": updated_at,
                ":rr": reason or "",
                ":one": 1,
                ":v": int(item.get("version", 0)),
            },
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(409, "Conflict: transaction was updated by someone else") from exc
        raise HTTPException(500, f"DDB error: {exc.response.get('Error', {}).get('Message')}") from exc
    _record_event(txn_id, user_sub, "transaction_reverted", {"reason": reason})
    return get_transaction_info(user_sub, txn_id)


def request_cancel(user_sub: str, txn_id: str, reason: Optional[str]) -> Dict[str, Any]:
    item = _fetch_txn(user_sub, txn_id)
    if not item:
        raise HTTPException(404, "Transaction not found")
    if item["status"] not in {"PENDING", "COMPLETED"}:
        raise HTTPException(409, f"Cannot request cancel from status {item['status']}")
    updated_at = now_ts()
    cancel_obj = {
        "requested_by": user_sub,
        "requested_at": updated_at,
        "reason": reason or "",
        "status": "OPEN",
    }
    try:
        T.purchase_transactions.update_item(
            Key={"user_sub": item["user_sub"], "sk": item["sk"]},
            UpdateExpression="SET #st = :st, cancel = :c, updated_at = :u, version = version + :one",
            ConditionExpression="version = :v AND #st <> :already",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": "CANCEL_REQUESTED",
                ":c": cancel_obj,
                ":u": updated_at,
                ":one": 1,
                ":v": int(item.get("version", 0)),
                ":already": "CANCEL_REQUESTED",
            },
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(409, "Conflict or already requested") from exc
        raise HTTPException(500, f"DDB error: {exc.response.get('Error', {}).get('Message')}") from exc
    _record_event(txn_id, user_sub, "cancel_requested", {"reason": reason})
    return get_transaction_info(user_sub, txn_id)


def respond_cancel(user_sub: str, txn_id: str, decision: str, note: Optional[str]) -> Dict[str, Any]:
    item = _fetch_txn(user_sub, txn_id)
    if not item:
        raise HTTPException(404, "Transaction not found")
    if item["status"] != "CANCEL_REQUESTED":
        raise HTTPException(409, "No active cancel request to respond to")
    if decision not in {"APPROVE", "DENY"}:
        raise HTTPException(400, "decision must be APPROVE or DENY")
    updated_at = now_ts()
    if decision == "APPROVE":
        new_status = "CANCELLED"
        cancel_status = "APPROVED"
    else:
        new_status = "CANCEL_DENIED"
        cancel_status = "DENIED"
    cancel_obj = item.get("cancel") or {}
    cancel_obj.update(
        {
            "responded_by": user_sub,
            "responded_at": updated_at,
            "decision": decision,
            "status": cancel_status,
            "note": note or "",
        },
    )
    try:
        T.purchase_transactions.update_item(
            Key={"user_sub": item["user_sub"], "sk": item["sk"]},
            UpdateExpression="SET #st = :st, cancel = :c, updated_at = :u, version = version + :one",
            ConditionExpression="version = :v AND #st = :expected",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": new_status,
                ":c": cancel_obj,
                ":u": updated_at,
                ":one": 1,
                ":v": int(item.get("version", 0)),
                ":expected": "CANCEL_REQUESTED",
            },
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(409, "Conflict: status/version changed") from exc
        raise HTTPException(500, f"DDB error: {exc.response.get('Error', {}).get('Message')}") from exc
    _record_event(txn_id, user_sub, "cancel_responded", {"decision": decision, "note": note})
    return get_transaction_info(user_sub, txn_id)


def list_events(user_sub: str, txn_id: str, limit: int) -> List[Dict[str, Any]]:
    _ = get_transaction_info(user_sub, txn_id)
    resp = T.purchase_events.query(
        KeyConditionExpression="pk = :p",
        ExpressionAttributeValues={":p": f"TXN#{txn_id}"},
        Limit=limit,
    )
    return resp.get("Items", [])


def find_transaction_by_tracking(tracking_number: str) -> Optional[Dict[str, Any]]:
    """Look up a transaction by its tracking number.

    Uses a scan with FilterExpression on the tracking_number attribute.
    For production, a GSI (TrackingIndex) would be more efficient.
    """
    if not tracking_number or tracking_number == "unknown":
        return None

    # DynamoDB applies FilterExpression AFTER the page Limit, so a single
    # scan() with Limit=1 almost always misses the matching row on a busy
    # table. Loop via LastEvaluatedKey until we find the match or exhaust the
    # table.
    scan_kwargs: Dict[str, Any] = {
        "FilterExpression": "tracking_number = :tn",
        "ExpressionAttributeValues": {":tn": tracking_number},
    }
    while True:
        resp = T.purchase_transactions.scan(**scan_kwargs)
        items = resp.get("Items", [])
        if items:
            return items[0]
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            return None
        scan_kwargs["ExclusiveStartKey"] = last_key
