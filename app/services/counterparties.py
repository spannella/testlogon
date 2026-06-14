"""OBP PAY-001 — Counterparty / beneficiary entity service.

Per-user stored payee (the destination COUNTERPARTY Transaction Requests, standing
orders, and mandates all point at). Sensitive routing numbers (IBAN / account number)
are persisted last-4-only and returned masked — same SEC-004 discipline as
``creator_payouts.add_payout_method``. Per-user ``ByUserCreatedAt`` GSI for newest-first
cursor-paginated listing (mirrors ``creator_payouts.list_payout_methods``).

Ownership is enforced by the ``Key={user_sub, counterparty_id}`` access pattern — a
foreign id simply isn't found (→ 404 at the router).
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.core.time import now_ts


class CounterpartyError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code


def _cp_id() -> str:
    return f"cp_{uuid.uuid4().hex}"


def _last4(value: Optional[str]) -> str:
    s = "".join(ch for ch in (value or "") if ch.isalnum())
    return s[-4:] if s else ""


def _to_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _validate_routing(routing: Dict[str, Any]) -> None:
    scheme = routing.get("scheme")
    if scheme == "IBAN" and not routing.get("iban"):
        raise CounterpartyError("invalid_routing", "IBAN scheme requires iban")
    if scheme == "ACCOUNT_SORT_CODE" and not (routing.get("account_number") and routing.get("sort_code")):
        raise CounterpartyError("invalid_routing", "ACCOUNT_SORT_CODE requires account_number + sort_code")
    if scheme == "ACCOUNT_NUMBER" and not routing.get("account_number"):
        raise CounterpartyError("invalid_routing", "ACCOUNT_NUMBER scheme requires account_number")
    if scheme == "BANK" and not (routing.get("bank_code") or routing.get("bank_name")):
        raise CounterpartyError("invalid_routing", "BANK scheme requires bank_code or bank_name")


def _routing_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "scheme": item.get("scheme", ""),
        "iban_last4": item.get("iban_last4") or None,
        "account_number_last4": item.get("account_number_last4") or None,
        "sort_code": item.get("sort_code") or None,
        "bank_code": item.get("bank_code") or None,
        "bank_name": item.get("bank_name") or None,
        "account_holder": item.get("account_holder") or None,
        "currency": item.get("currency", "usd"),
    }


def _to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "counterparty_id": item.get("counterparty_id", ""),
        "name": item.get("name", ""),
        "is_beneficiary": bool(item.get("is_beneficiary", True)),
        "routing": _routing_out(item),
        "description": item.get("description") or None,
        "bespoke": item.get("bespoke") or None,
        "created_at": _to_int(item.get("created_at", 0)),
        "updated_at": _to_int(item.get("updated_at", 0)),
    }


def create_counterparty(user_sub: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    routing = dict(payload.get("routing") or {})
    _validate_routing(routing)
    ts = now_ts()
    cp_id = _cp_id()
    item: Dict[str, Any] = {
        "user_sub": user_sub,
        "counterparty_id": cp_id,
        "name": payload["name"],
        "is_beneficiary": bool(payload.get("is_beneficiary", True)),
        "scheme": routing.get("scheme", ""),
        # Sensitive numbers persisted last-4-only (SEC-004) — never stored in clear.
        "iban_last4": _last4(routing.get("iban")),
        "account_number_last4": _last4(routing.get("account_number")),
        "sort_code": routing.get("sort_code") or "",
        "bank_code": routing.get("bank_code") or "",
        "bank_name": routing.get("bank_name") or "",
        "account_holder": routing.get("account_holder") or "",
        "currency": (routing.get("currency") or "usd"),
        "description": payload.get("description") or "",
        "bespoke": payload.get("bespoke") or {},
        "created_at": ts,
        "updated_at": ts,
    }
    T.counterparties.put_item(Item=item)
    _audit("counterparty.created", user_sub, counterparty_id=cp_id, scheme=item["scheme"])
    return _to_out(item)


def get_counterparty(user_sub: str, counterparty_id: str) -> Optional[Dict[str, Any]]:
    resp = T.counterparties.get_item(Key={"user_sub": user_sub, "counterparty_id": counterparty_id})
    item = resp.get("Item")
    return item if item else None


def get_counterparty_out(user_sub: str, counterparty_id: str) -> Optional[Dict[str, Any]]:
    item = get_counterparty(user_sub, counterparty_id)
    return _to_out(item) if item else None


def list_counterparties(
    user_sub: str, *, limit: int = 50, cursor: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    query_kwargs: Dict[str, Any] = {
        "IndexName": "ByUserCreatedAt",
        "KeyConditionExpression": Key("user_sub").eq(user_sub),
        "ScanIndexForward": False,
        "Limit": max(1, min(limit, 200)),
    }
    start = decode_cursor(cursor)
    if start:
        query_kwargs["ExclusiveStartKey"] = start
    resp = T.counterparties.query(**query_kwargs)
    out = [_to_out(it) for it in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return out, next_cursor


def update_counterparty(user_sub: str, counterparty_id: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    existing = get_counterparty(user_sub, counterparty_id)
    if not existing:
        return None
    sets: Dict[str, Any] = {"updated_at": now_ts()}
    if payload.get("name") is not None:
        sets["name"] = payload["name"]
    if payload.get("is_beneficiary") is not None:
        sets["is_beneficiary"] = bool(payload["is_beneficiary"])
    if payload.get("description") is not None:
        sets["description"] = payload["description"]
    if payload.get("bespoke") is not None:
        sets["bespoke"] = payload["bespoke"]
    expr_parts = []
    names: Dict[str, str] = {}
    values: Dict[str, Any] = {}
    for i, (k, v) in enumerate(sets.items()):
        nk, vk = f"#f{i}", f":v{i}"
        names[nk] = k
        values[vk] = v
        expr_parts.append(f"{nk} = {vk}")
    T.counterparties.update_item(
        Key={"user_sub": user_sub, "counterparty_id": counterparty_id},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ConditionExpression="attribute_exists(counterparty_id)",
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )
    _audit("counterparty.updated", user_sub, counterparty_id=counterparty_id)
    return get_counterparty_out(user_sub, counterparty_id)


def delete_counterparty(user_sub: str, counterparty_id: str) -> bool:
    existing = get_counterparty(user_sub, counterparty_id)
    if not existing:
        return False
    T.counterparties.delete_item(Key={"user_sub": user_sub, "counterparty_id": counterparty_id})
    _audit("counterparty.deleted", user_sub, counterparty_id=counterparty_id)
    return True


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event

        audit_event(event, user_sub, None, **fields)
    except Exception:
        pass
