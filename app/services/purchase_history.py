from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import uuid4

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts

def _txn_sk(created_at: int, txn_id: str) -> str:
    return f"TXN#{created_at}#{txn_id}"


def _event_sk(ts: int, event_id: str) -> str:
    return f"EVENT#{ts}#{event_id}"


def _record_event(txn_id: str, user_sub: str, event_name: str, payload: Dict[str, Any]) -> None:
    ts = now_ts()
    event_id = uuid4().hex
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
            "shipping": item.get("shipping"),
            "cancel": item.get("cancel"),
            "completed_at": item.get("completed_at"),
            "reverted_at": item.get("reverted_at"),
            "version": int(item.get("version", 0)),
            "metadata": item.get("metadata"),
        },
    )
    return summary


def _fetch_txn(user_sub: str, txn_id: str) -> Optional[Dict[str, Any]]:
    resp = T.purchase_transactions.query(
        KeyConditionExpression="user_sub = :u AND begins_with(sk, :p)",
        ExpressionAttributeValues={":u": user_sub, ":p": "TXN#", ":t": txn_id},
        FilterExpression="txn_id = :t",
        Limit=1,
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def create_transaction(user_sub: str, body: Dict[str, Any]) -> Dict[str, Any]:
    txn_id = uuid4().hex
    created_at = now_ts()
    item = {
        "user_sub": user_sub,
        "sk": _txn_sk(created_at, txn_id),
        "txn_id": txn_id,
        "buyer_id": user_sub,
        "created_at": created_at,
        "updated_at": created_at,
        "status": "PENDING",
        "amount": str(body["money"]["amount"]),
        "currency": body["money"]["currency"],
        "version": 1,
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

    _record_event(txn_id, user_sub, "transaction_created", {"txn_id": txn_id, "status": "PENDING"})
    return {"txn_id": txn_id, "status": "PENDING", "created_at": created_at}


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


def get_transaction_info(user_sub: str, txn_id: str) -> Dict[str, Any]:
    item = _fetch_txn(user_sub, txn_id)
    if not item:
        raise HTTPException(404, "Transaction not found")
    return _item_to_info(item)


def update_shipping(user_sub: str, txn_id: str, shipping: Dict[str, Any]) -> Dict[str, Any]:
    item = _fetch_txn(user_sub, txn_id)
    if not item:
        raise HTTPException(404, "Transaction not found")
    if item["status"] == "CANCELLED":
        raise HTTPException(409, "Cannot update shipping for cancelled transactions")
    updated_at = now_ts()
    shipping = {k: v for k, v in shipping.items() if v is not None}
    try:
        T.purchase_transactions.update_item(
            Key={"user_sub": item["user_sub"], "sk": item["sk"]},
            UpdateExpression="SET shipping = :s, updated_at = :u, version = version + :one",
            ConditionExpression="version = :v",
            ExpressionAttributeValues={":s": shipping, ":u": updated_at, ":one": 1, ":v": int(item.get("version", 0))},
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
