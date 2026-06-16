"""AOS Sales Quote entity service (QUO-001).

Quote CRUD + stage machine on the ``aos_quotes`` DynamoDB table. Money is
always integer cents. Gated behind ``S.aos_quotes_enabled`` (default OFF) —
every public function returns ``None`` when the flag is off so the router can
raise 404.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event

logger = logging.getLogger(__name__)

VALID_STAGES = {"draft", "sent", "accepted", "rejected", "expired", "converted"}

ALLOWED_TRANSITIONS: Dict[str, set] = {
    "draft": {"sent", "expired"},
    "sent": {"accepted", "rejected", "expired"},
    "accepted": {"converted", "expired"},
    "rejected": set(),
    "expired": set(),
    "converted": set(),
}


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _user_pk(user_sub: str) -> str:
    return f"USER#{user_sub}"


def _quote_sk(quote_id: str) -> str:
    return f"QUOTE#{quote_id}"


def _next_quote_number() -> str:
    """Atomic counter on the aos_quotes table → ``AOS-NNNNN``."""
    result = T.aos_quotes.update_item(
        Key={"pk": "COUNTER", "sk": "QUOTE_SEQ"},
        UpdateExpression="ADD next_seq :inc",
        ExpressionAttributeValues={":inc": 1},
        ReturnValues="UPDATED_NEW",
    )
    seq = int(result["Attributes"]["next_seq"])
    return f"AOS-{seq:05d}"


def _normalize_line_item(li: Dict[str, Any]) -> Dict[str, Any]:
    qty = _coerce_int(li.get("qty"), 1)
    unit = _coerce_int(li.get("unit_price_cents"))
    discount_bps = _coerce_int(li.get("discount_bps"))
    tax_rate_bps = _coerce_int(li.get("tax_rate_bps"))
    if qty < 1:
        raise ValueError("qty must be >= 1")
    if unit < 0:
        raise ValueError("unit_price_cents must be >= 0")
    if not (0 <= discount_bps <= 10000):
        raise ValueError("discount_bps must be in [0, 10000]")
    if not (0 <= tax_rate_bps <= 10000):
        raise ValueError("tax_rate_bps must be in [0, 10000]")
    return {
        "catalog_item_id": str(li.get("catalog_item_id") or ""),
        "description": str(li.get("description") or ""),
        "qty": qty,
        "unit_price_cents": unit,
        "discount_bps": discount_bps,
        "tax_rate_bps": tax_rate_bps,
    }


def _compute_totals(line_items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Pure integer-arithmetic totals. Returns totals + line_items with
    ``line_total_cents`` filled in on each item."""
    subtotal = 0
    discount_total = 0
    tax_total = 0
    out_items: List[Dict[str, Any]] = []
    for raw in line_items:
        li = _normalize_line_item(raw)
        gross = li["qty"] * li["unit_price_cents"]
        discount = gross * li["discount_bps"] // 10000
        net = gross - discount
        tax = net * li["tax_rate_bps"] // 10000
        li["line_total_cents"] = net + tax
        subtotal += gross
        discount_total += discount
        tax_total += tax
        out_items.append(li)
    total = subtotal - discount_total + tax_total
    return {
        "subtotal_cents": subtotal,
        "discount_cents": discount_total,
        "tax_cents": tax_total,
        "total_cents": total,
        "line_items": out_items,
    }


def _serialize(item: Dict[str, Any]) -> Dict[str, Any]:
    line_items = []
    for li in item.get("line_items") or []:
        line_items.append({
            "catalog_item_id": str(li.get("catalog_item_id") or ""),
            "description": str(li.get("description") or ""),
            "qty": _coerce_int(li.get("qty"), 1),
            "unit_price_cents": _coerce_int(li.get("unit_price_cents")),
            "discount_bps": _coerce_int(li.get("discount_bps")),
            "tax_rate_bps": _coerce_int(li.get("tax_rate_bps")),
            "line_total_cents": _coerce_int(li.get("line_total_cents")),
        })
    valid_until = item.get("valid_until")
    return {
        "quote_id": str(item.get("quote_id") or ""),
        "quote_number": str(item.get("quote_number") or ""),
        "title": str(item.get("title") or ""),
        "stage": str(item.get("stage") or "draft"),
        "valid_until": _coerce_int(valid_until) if valid_until is not None else None,
        "assigned_user_sub": str(item.get("assigned_user_sub") or ""),
        "account_id": str(item.get("account_id") or ""),
        "contact_id": str(item.get("contact_id") or ""),
        "currency": str(item.get("currency") or "usd"),
        "billing_address": dict(item.get("billing_address") or {}),
        "shipping_address": dict(item.get("shipping_address") or {}),
        "notes": str(item.get("notes") or ""),
        "line_items": line_items,
        "subtotal_cents": _coerce_int(item.get("subtotal_cents")),
        "discount_cents": _coerce_int(item.get("discount_cents")),
        "tax_cents": _coerce_int(item.get("tax_cents")),
        "total_cents": _coerce_int(item.get("total_cents")),
        "converted_to_invoice_number": str(item.get("converted_to_invoice_number") or ""),
        "converted_to_contract_id": str(item.get("converted_to_contract_id") or ""),
        "created_at": _coerce_int(item.get("created_at")),
        "updated_at": _coerce_int(item.get("updated_at")),
    }


def create_quote(
    user_sub: str,
    title: str,
    *,
    valid_until: Optional[int] = None,
    assigned_user_sub: str = "",
    account_id: str = "",
    contact_id: str = "",
    currency: str = "usd",
    billing_address: Optional[Dict[str, Any]] = None,
    shipping_address: Optional[Dict[str, Any]] = None,
    notes: str = "",
    line_items: Optional[List[Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    if not S.aos_quotes_enabled:
        return None
    title = (title or "").strip()
    if not title:
        raise ValueError("title is required")
    currency = (currency or "usd").lower()
    if len(currency) != 3:
        raise ValueError("currency must be a 3-character code")
    if not line_items:
        raise ValueError("at least one line item is required")

    totals = _compute_totals(line_items)
    quote_id = "quo_" + uuid.uuid4().hex[:16]
    quote_number = _next_quote_number()
    ts = now_ts()
    stage = "draft"
    item: Dict[str, Any] = {
        "pk": _user_pk(user_sub),
        "sk": _quote_sk(quote_id),
        "quote_id": quote_id,
        "quote_number": quote_number,
        "user_sub": user_sub,
        "title": title,
        "stage": stage,
        "assigned_user_sub": assigned_user_sub or "",
        "account_id": account_id or "",
        "contact_id": contact_id or "",
        "currency": currency,
        "billing_address": dict(billing_address or {}),
        "shipping_address": dict(shipping_address or {}),
        "notes": notes or "",
        "line_items": totals["line_items"],
        "subtotal_cents": totals["subtotal_cents"],
        "discount_cents": totals["discount_cents"],
        "tax_cents": totals["tax_cents"],
        "total_cents": totals["total_cents"],
        "created_at": ts,
        "updated_at": ts,
        "GSI1PK": "QUOTES#ALL",
        "GSI1SK": ts,
        "GSI2PK": f"USER#{user_sub}#STAGE#{stage}",
        "GSI2SK": ts,
    }
    if valid_until is not None:
        item["valid_until"] = _coerce_int(valid_until)

    T.aos_quotes.put_item(Item=item)
    audit_event("quote.created", user_sub, quote_id=quote_id, quote_number=quote_number)
    return _serialize(item)


def _get_raw(user_sub: str, quote_id: str) -> Optional[Dict[str, Any]]:
    resp = T.aos_quotes.get_item(Key={"pk": _user_pk(user_sub), "sk": _quote_sk(quote_id)})
    return resp.get("Item")


def get_quote(user_sub: str, quote_id: str) -> Optional[Dict[str, Any]]:
    if not S.aos_quotes_enabled:
        return None
    item = _get_raw(user_sub, quote_id)
    return _serialize(item) if item else None


def list_quotes(
    user_sub: str,
    stage: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    if not S.aos_quotes_enabled:
        return None
    limit = max(1, min(int(limit or 50), 200))
    query: Dict[str, Any] = {"ScanIndexForward": False, "Limit": limit}
    if stage:
        query["IndexName"] = "GSI2"
        query["KeyConditionExpression"] = "GSI2PK = :pk"
        query["ExpressionAttributeValues"] = {":pk": f"USER#{user_sub}#STAGE#{stage}"}
    else:
        query["KeyConditionExpression"] = "pk = :pk AND begins_with(sk, :sk)"
        query["ExpressionAttributeValues"] = {":pk": _user_pk(user_sub), ":sk": "QUOTE#"}
    start_key = decode_cursor(cursor)
    if start_key:
        query["ExclusiveStartKey"] = start_key
    resp = T.aos_quotes.query(**query)
    quotes = [_serialize(it) for it in resp.get("Items", [])]
    return {"quotes": quotes, "next_cursor": encode_cursor(_clean_lek(resp.get("LastEvaluatedKey")))}


def _clean_lek(lek: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not lek:
        return None
    from decimal import Decimal
    return {k: (int(v) if isinstance(v, Decimal) else v) for k, v in lek.items()}


def update_quote(user_sub: str, quote_id: str, **patch_fields: Any) -> Optional[Dict[str, Any]]:
    if not S.aos_quotes_enabled:
        return None
    item = _get_raw(user_sub, quote_id)
    if not item:
        return None
    if str(item.get("stage")) == "converted":
        raise ValueError("quote already converted")
    if "stage" in patch_fields:
        raise ValueError("use transition_stage to change stage")

    changed = []
    for key, value in patch_fields.items():
        if value is None:
            continue
        if key == "line_items":
            totals = _compute_totals(value)
            item["line_items"] = totals["line_items"]
            item["subtotal_cents"] = totals["subtotal_cents"]
            item["discount_cents"] = totals["discount_cents"]
            item["tax_cents"] = totals["tax_cents"]
            item["total_cents"] = totals["total_cents"]
        elif key in ("billing_address", "shipping_address"):
            item[key] = dict(value)
        elif key == "currency":
            item[key] = str(value).lower()
        else:
            item[key] = value
        changed.append(key)

    item["updated_at"] = now_ts()
    T.aos_quotes.put_item(Item=item)
    audit_event("quote.updated", user_sub, quote_id=quote_id, changed_fields=changed)
    return _serialize(item)


def transition_stage(user_sub: str, quote_id: str, new_stage: str) -> Optional[Dict[str, Any]]:
    if not S.aos_quotes_enabled:
        return None
    item = _get_raw(user_sub, quote_id)
    if not item:
        return None
    current = str(item.get("stage") or "draft")
    if new_stage == current:
        return _serialize(item)
    if new_stage not in ALLOWED_TRANSITIONS.get(current, set()):
        raise ValueError(f"invalid transition: {current} -> {new_stage}")
    item["stage"] = new_stage
    item["GSI2PK"] = f"USER#{user_sub}#STAGE#{new_stage}"
    item["updated_at"] = now_ts()
    T.aos_quotes.put_item(Item=item)
    audit_event(
        "quote.stage_changed", user_sub,
        quote_id=quote_id, from_stage=current, to_stage=new_stage,
    )
    return _serialize(item)


def admin_list_quotes(limit: int = 50, cursor: Optional[str] = None) -> Optional[Dict[str, Any]]:
    if not S.aos_quotes_enabled:
        return None
    limit = max(1, min(int(limit or 50), 200))
    query: Dict[str, Any] = {
        "IndexName": "GSI1",
        "KeyConditionExpression": "GSI1PK = :pk",
        "ExpressionAttributeValues": {":pk": "QUOTES#ALL"},
        "ScanIndexForward": False,
        "Limit": limit,
    }
    start_key = decode_cursor(cursor)
    if start_key:
        query["ExclusiveStartKey"] = start_key
    resp = T.aos_quotes.query(**query)
    quotes = [_serialize(it) for it in resp.get("Items", [])]
    return {"quotes": quotes, "next_cursor": encode_cursor(_clean_lek(resp.get("LastEvaluatedKey")))}
