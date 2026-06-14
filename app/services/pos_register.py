"""
POS-004/POS-005 — Register & session service, cart binding & line-item mutations.

All functions short-circuit with HTTPException(404) when S.pos_enabled is False.
No calls to T.billing, T.orders, or T.catalog are made directly — those only
happen via the shoppingcart / billing_shared / commerce_order_service collaborators
in pos_tender.py (POS-006+).
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts


# ── flag guard ────────────────────────────────────────────────────────────────

def _flag_on() -> bool:
    return bool(getattr(S, "pos_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="POS is not enabled")


# ── audit helper ──────────────────────────────────────────────────────────────

def _audit(event: str, user_sub: str, **fields: Any) -> None:
    """Fire-and-forget audit event; never raises."""
    try:
        from app.services.alerts import audit_event  # lazy import (RULE-1)
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


# ── key helpers ───────────────────────────────────────────────────────────────

def _register_pk(register_id: str) -> Dict[str, str]:
    return {"pos_pk": f"REGISTER#{register_id}", "pos_sk": "META"}


def _session_pk(session_id: str) -> Dict[str, str]:
    return {"pos_pk": f"SESSION#{session_id}", "pos_sk": "META"}


def _sentinel_pk(register_id: str) -> Dict[str, str]:
    return {"pos_pk": f"OPEN_SENTINEL#REGISTER#{register_id}", "pos_sk": "OPEN"}


def _txn_pk(txn_id: str) -> Dict[str, str]:
    return {"pos_pk": f"TXN#{txn_id}", "pos_sk": "META"}


def _tender_pk(session_id: str, txn_id: str) -> Dict[str, str]:
    return {"pos_pk": f"SESSION#{session_id}", "pos_sk": f"TENDER#{txn_id}"}


def _session_id_from_key(idempotency_key: Optional[str]) -> str:
    if idempotency_key:
        return "sess_" + hashlib.sha256(idempotency_key.encode()).hexdigest()[:12]
    return "sess_" + uuid.uuid4().hex[:12]


def _to_int(v: Any, default: int = 0) -> int:
    try:
        return int(v) if v is not None else default
    except (TypeError, ValueError):
        return default


def _session_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Projection to RegisterSessionOut-compatible dict."""
    return {
        "session_id":          item.get("session_id"),
        "register_id":         item.get("register_id"),
        "cashier_sub":         item.get("cashier_sub"),
        "status":              item.get("status"),
        "opening_float_cents": _to_int(item.get("opening_float_cents")),
        "closing_float_cents": item.get("closing_float_cents"),
        "expected_cash_cents": item.get("expected_cash_cents"),
        "counted_cash_cents":  item.get("counted_cash_cents"),
        "over_short_cents":    item.get("over_short_cents"),
        "opened_at":           _to_int(item.get("opened_at")),
        "closed_at":           item.get("closed_at"),
    }


def _txn_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Projection to PosTxnDraftOut-compatible dict."""
    return {
        "txn_id":          item.get("txn_id", ""),
        "session_id":      item.get("session_id", ""),
        "cashier_sub":     item.get("cashier_sub", ""),
        "status":          item.get("status", "draft"),
        "cart_id":         item.get("cart_id", ""),
        "subtotal_cents":  _to_int(item.get("subtotal_cents")),
        "tax_cents":       _to_int(item.get("tax_cents")),
        "discount_cents":  _to_int(item.get("discount_cents")),
        "total_cents":     _to_int(item.get("total_cents")),
        "created_at":      _to_int(item.get("created_at")),
        "updated_at":      _to_int(item.get("updated_at")),
    }


# ── register CRUD ─────────────────────────────────────────────────────────────

def create_register(
    *,
    user_sub: str,
    label: str,
    location_id: str,
    default_currency: str = "USD",
) -> Dict[str, Any]:
    """Create a new POS register (terminal) record."""
    _require_enabled()
    register_id = "reg_" + uuid.uuid4().hex[:12]
    now = now_ts()
    item = {
        "pos_pk": f"REGISTER#{register_id}",
        "pos_sk": "META",
        "register_id": register_id,
        "label": label,
        "location_id": location_id,
        "default_currency": default_currency.upper(),
        "created_at": now,
        "updated_at": now,
        "created_by": user_sub,
    }
    T.pos.put_item(Item=item)
    _audit("pos_register_created", user_sub,
           register_id=register_id, label=label, location_id=location_id)
    return {
        "register_id": register_id,
        "label": label,
        "location_id": location_id,
        "default_currency": default_currency.upper(),
        "created_at": now,
        "updated_at": now,
        "created_by": user_sub,
    }


def get_register(register_id: str) -> Optional[Dict[str, Any]]:
    """Return register config or None."""
    _require_enabled()
    item = T.pos.get_item(Key=_register_pk(register_id)).get("Item")
    if not item:
        return None
    return {
        "register_id": item.get("register_id"),
        "label": item.get("label"),
        "location_id": item.get("location_id"),
        "default_currency": item.get("default_currency", "USD"),
        "created_at": _to_int(item.get("created_at")),
        "updated_at": _to_int(item.get("updated_at")),
        "created_by": item.get("created_by"),
    }


# ── session lifecycle ─────────────────────────────────────────────────────────

def open_session(
    *,
    cashier_sub: str,
    register_id: str,
    opening_float_cents: int,
    idempotency_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Open a register session (till).

    Invariant: at most one OPEN session per register.  Enforced by a conditional
    put on the sentinel row; concurrent second opener receives 409.
    """
    _require_enabled()

    # Validate register exists.
    reg_resp = T.pos.get_item(Key=_register_pk(register_id))
    if not reg_resp.get("Item"):
        raise HTTPException(status_code=404, detail="Register not found")

    session_id = _session_id_from_key(idempotency_key)
    now = now_ts()

    # Idempotency: if this session_id already exists (replay), return it.
    existing = T.pos.get_item(Key=_session_pk(session_id)).get("Item")
    if existing:
        return _session_out(existing)

    # Enforce one-open-per-register via sentinel conditional put.
    sentinel = {
        "pos_pk": f"OPEN_SENTINEL#REGISTER#{register_id}",
        "pos_sk": "OPEN",
        "register_id": register_id,
        "session_id": session_id,
        "opened_at": now,
    }
    try:
        T.pos.put_item(
            Item=sentinel,
            ConditionExpression="attribute_not_exists(pos_pk)",
        )
    except ClientError as exc:
        code = exc.response["Error"].get("Code", "")
        if code == "ConditionalCheckFailedException":
            raise HTTPException(
                status_code=409,
                detail="Register already has an open session",
            ) from exc
        raise

    # Write session row.
    session_item: Dict[str, Any] = {
        "pos_pk": f"SESSION#{session_id}",
        "pos_sk": "META",
        "session_id": session_id,
        "register_id": register_id,
        "cashier_sub": cashier_sub,
        "status": "open",
        "opening_float_cents": opening_float_cents,
        "cash_in_cents": 0,
        "change_out_cents": 0,
        "opened_at": now,
    }
    if idempotency_key:
        session_item["idempotency_key"] = idempotency_key
    T.pos.put_item(Item=session_item)

    _audit(
        "pos_session_opened",
        cashier_sub,
        session_id=session_id,
        register_id=register_id,
        opening_float_cents=opening_float_cents,
    )
    return _session_out(session_item)


def get_open_session(register_id: str) -> Optional[Dict[str, Any]]:
    """Return the open session for register_id, or None if no session is open."""
    _require_enabled()
    sentinel = T.pos.get_item(Key=_sentinel_pk(register_id)).get("Item")
    if not sentinel:
        return None
    session_id = sentinel.get("session_id")
    if not session_id:
        return None
    item = T.pos.get_item(Key=_session_pk(session_id)).get("Item")
    if not item or item.get("status") != "open":
        return None
    return _session_out(item)


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Return any session by ID (open or closed)."""
    _require_enabled()
    item = T.pos.get_item(Key=_session_pk(session_id)).get("Item")
    return _session_out(item) if item else None


def close_session(
    *,
    session_id: str,
    counted_cash_cents: int,
    actor_sub: str,
) -> Dict[str, Any]:
    """Close a register session.  Computes expected_cash and over_short.

    expected_cash_cents = opening_float_cents + cash_in_cents − change_out_cents
    over_short_cents    = counted_cash_cents  − expected_cash_cents  (signed)

    Double-close is rejected with 409 (status already 'closed').
    """
    _require_enabled()
    item = T.pos.get_item(Key=_session_pk(session_id)).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Session not found")

    status = item.get("status")
    if status == "closed":
        raise HTTPException(status_code=409, detail="Session is already closed")
    if status != "open":
        raise HTTPException(status_code=409, detail=f"Session status is '{status}'; cannot close")

    register_id = item.get("register_id", "")
    opening_float = _to_int(item.get("opening_float_cents"))
    cash_in       = _to_int(item.get("cash_in_cents"))
    change_out    = _to_int(item.get("change_out_cents"))

    expected_cash = opening_float + cash_in - change_out
    over_short    = counted_cash_cents - expected_cash
    now           = now_ts()

    try:
        T.pos.update_item(
            Key=_session_pk(session_id),
            UpdateExpression=(
                "SET #status = :closed, "
                "closing_float_cents = :counted, "
                "expected_cash_cents = :expected, "
                "counted_cash_cents  = :counted, "
                "over_short_cents    = :os, "
                "closed_at           = :now"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":closed":   "closed",
                ":counted":  counted_cash_cents,
                ":expected": expected_cash,
                ":os":       over_short,
                ":now":      now,
                ":open":     "open",
            },
            ConditionExpression="#status = :open",
        )
    except ClientError as exc:
        code = exc.response["Error"].get("Code", "")
        if code == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Session is already closed") from exc
        raise

    # Remove the open sentinel so the register can accept a new session.
    T.pos.delete_item(Key=_sentinel_pk(register_id))

    _audit(
        "pos_session_closed",
        actor_sub,
        session_id=session_id,
        register_id=register_id,
        opening_float_cents=opening_float,
        cash_in_cents=cash_in,
        change_out_cents=change_out,
        expected_cash_cents=expected_cash,
        counted_cash_cents=counted_cash_cents,
        over_short_cents=over_short,
    )

    updated = T.pos.get_item(Key=_session_pk(session_id)).get("Item", item)
    return _session_out(updated)


# ── over/short helper (also used by tests directly) ──────────────────────────

def _compute_over_short(
    *,
    opening_float_cents: int,
    cash_tenders: List[Dict[str, Any]],
    cash_refunds_cents: int,
    counted_cash_cents: int,
) -> int:
    """Compute over/short for a session given raw tender records.

    expected = opening_float + sum(cash_in) - sum(change_out) - cash_refunds
    over_short = counted - expected  (positive = over, negative = short)
    """
    cash_in = sum(_to_int(t.get("amount_cents")) for t in cash_tenders)
    change_out = sum(_to_int(t.get("change_due_cents")) for t in cash_tenders)
    expected = opening_float_cents + cash_in - change_out - cash_refunds_cents
    return counted_cash_cents - expected


# ── TXN draft (cart binding) ──────────────────────────────────────────────────

def bind_txn_draft(
    cashier_sub: str,
    session_id: str,
    correlation_id: str,
) -> Dict[str, Any]:
    """Idempotently create or return an open POS transaction draft."""
    _require_enabled()

    # Validate session exists and is open.
    sess_item = T.pos.get_item(Key=_session_pk(session_id)).get("Item")
    if not sess_item:
        raise HTTPException(status_code=404, detail="Session not found")
    if sess_item.get("status") != "open":
        raise HTTPException(status_code=409, detail="Session is not open")
    if sess_item.get("cashier_sub") != cashier_sub:
        raise HTTPException(status_code=403, detail="Cashier does not own this session")

    txn_id = hashlib.sha256(
        f"pos_txn:{session_id}:{correlation_id}".encode()
    ).hexdigest()[:32]
    now = now_ts()

    # Idempotent: if TXN row already exists, return it.
    existing = T.pos.get_item(Key=_txn_pk(txn_id)).get("Item")
    if existing:
        return _txn_out(existing)

    # Start a shopping cart for this txn.
    try:
        from app.services.shoppingcart import start_cart  # lazy import (RULE-1)
        cart_result = start_cart(cashier_sub)
        cart_id = cart_result["cart_id"]
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to create cart") from exc

    txn_item: Dict[str, Any] = {
        "pos_pk": f"TXN#{txn_id}",
        "pos_sk": "META",
        "txn_id": txn_id,
        "session_id": session_id,
        "cashier_sub": cashier_sub,
        "status": "draft",
        "cart_id": cart_id,
        "subtotal_cents": 0,
        "tax_cents": 0,
        "discount_cents": 0,
        "total_cents": 0,
        "created_at": now,
        "updated_at": now,
        "correlation_id": correlation_id,
    }

    try:
        T.pos.put_item(
            Item=txn_item,
            ConditionExpression="attribute_not_exists(pos_pk)",
        )
    except ClientError as exc:
        code = exc.response["Error"].get("Code", "")
        if code == "ConditionalCheckFailedException":
            # Another call won; return existing row.
            row = T.pos.get_item(Key=_txn_pk(txn_id)).get("Item")
            if row:
                return _txn_out(row)
        raise

    return _txn_out(txn_item)


def _load_open_txn(cashier_sub: str, txn_id: str) -> Dict[str, Any]:
    """Load a draft TXN row; raise 404/403/409 on problems."""
    item = T.pos.get_item(Key=_txn_pk(txn_id)).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Transaction not found")
    if item.get("cashier_sub") != cashier_sub:
        raise HTTPException(status_code=403, detail="Cashier does not own this transaction")
    if item.get("status") != "draft":
        raise HTTPException(
            status_code=409,
            detail=f"Transaction status is '{item.get('status')}'; cannot mutate",
        )
    return item


def _refresh_txn_subtotal(cashier_sub: str, txn_id: str, cart_id: str) -> int:
    """Recompute and persist subtotal_cents from the live cart."""
    try:
        from app.services.shoppingcart import cart_total_cents  # lazy import
        total = cart_total_cents(cashier_sub, cart_id)
    except Exception:
        total = 0

    T.pos.update_item(
        Key=_txn_pk(txn_id),
        UpdateExpression="SET subtotal_cents = :t, updated_at = :u",
        ExpressionAttributeValues={":t": total, ":u": now_ts()},
    )
    return total


def get_txn_draft(cashier_sub: str, txn_id: str) -> Dict[str, Any]:
    """Return a TXN draft (any status) for this cashier."""
    _require_enabled()
    item = T.pos.get_item(Key=_txn_pk(txn_id)).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Transaction not found")
    if item.get("cashier_sub") != cashier_sub:
        raise HTTPException(status_code=403, detail="Cashier does not own this transaction")
    return _txn_out(item)


def add_line_item(
    cashier_sub: str,
    txn_id: str,
    *,
    sku: Optional[str] = None,
    name: Optional[str] = None,
    unit_price_cents: Optional[int] = None,
    item_id: Optional[str] = None,
    category_id: Optional[str] = None,
    quantity: int = 1,
) -> Dict[str, Any]:
    """Add a line item to the bound cart; refresh TXN subtotal."""
    _require_enabled()
    txn = _load_open_txn(cashier_sub, txn_id)
    cart_id = txn["cart_id"]

    try:
        from app.services.shoppingcart import add_item, add_catalog_item  # lazy import
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="Shopping cart service unavailable") from exc

    if item_id is not None:
        # Catalog path
        if category_id:
            cart_item = add_catalog_item(cashier_sub, cart_id, category_id=category_id, item_id=item_id, quantity=quantity)
        else:
            # Resolve via ByItemId GSI
            resp = T.catalog.query(
                IndexName="ByItemId",
                KeyConditionExpression="item_id = :iid",
                FilterExpression="#entity = :item",
                ExpressionAttributeNames={"#entity": "entity"},
                ExpressionAttributeValues={":iid": item_id, ":item": "item"},
                Limit=1,
            )
            cat_items = resp.get("Items", [])
            if not cat_items:
                raise HTTPException(status_code=404, detail="Catalog item not found")
            cat = cat_items[0]
            cart_item = add_catalog_item(
                cashier_sub, cart_id,
                category_id=cat.get("category_id", ""),
                item_id=item_id,
                quantity=quantity,
            )
    else:
        # Raw-SKU path
        if not name or unit_price_cents is None:
            raise HTTPException(status_code=422, detail="name and unit_price_cents required for raw-SKU add")
        payload = {
            "sku": sku,
            "name": name,
            "quantity": quantity,
            "unit_price_cents": unit_price_cents,
        }
        cart_item = add_item(cashier_sub, cart_id, payload)

    total = _refresh_txn_subtotal(cashier_sub, txn_id, cart_id)
    return {"txn_id": txn_id, "total_cents": total, "item": cart_item}


def set_line_item_qty(
    cashier_sub: str,
    txn_id: str,
    sku: str,
    quantity: int,
) -> Dict[str, Any]:
    """Set exact quantity for a line item (0 = remove)."""
    _require_enabled()
    txn = _load_open_txn(cashier_sub, txn_id)
    cart_id = txn["cart_id"]

    try:
        from app.services.shoppingcart import set_item_quantity  # lazy import
        set_item_quantity(cashier_sub, cart_id, sku, quantity)
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="Shopping cart service unavailable") from exc

    total = _refresh_txn_subtotal(cashier_sub, txn_id, cart_id)
    return {"txn_id": txn_id, "total_cents": total}


def remove_line_item(
    cashier_sub: str,
    txn_id: str,
    sku: str,
    decrement: int = 1,
) -> Dict[str, Any]:
    """Decrement a line item's quantity."""
    _require_enabled()
    txn = _load_open_txn(cashier_sub, txn_id)
    cart_id = txn["cart_id"]

    try:
        from app.services.shoppingcart import decrement_item  # lazy import
        decrement_item(cashier_sub, cart_id, sku, decrement)
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="Shopping cart service unavailable") from exc

    total = _refresh_txn_subtotal(cashier_sub, txn_id, cart_id)
    return {"txn_id": txn_id, "total_cents": total}


def list_txn_items(cashier_sub: str, txn_id: str) -> List[Dict[str, Any]]:
    """List cart items for a draft TXN."""
    _require_enabled()
    txn = _load_open_txn(cashier_sub, txn_id)
    cart_id = txn["cart_id"]

    try:
        from app.services.shoppingcart import list_items  # lazy import
        return list_items(cashier_sub, cart_id)
    except ImportError:
        return []
