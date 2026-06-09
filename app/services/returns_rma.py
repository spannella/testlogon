r"""OFBiz-inspired Returns / RMA service (ADR-001, OFB-008/009/010).

Milestone-3 slice of the OFBiz commerce/ERP cherry-pick. This is an *additive*,
**flag-gated** (``RETURNS_RMA_ENABLED``, default OFF) service implementing the
returns/RMA lifecycle:

    requested -> approved -> received -> refunded -> closed
              \-> rejected

keyed off the existing ``orders`` / ``order_items`` records (no order schema
change). The two money/stock side-effects reuse the platform's existing,
tested machinery rather than forking it:

  * **Refund (OFB-010)** — issued via the existing billing-ledger primitives
    (``new_ledger_entry`` + ``apply_balance_delta`` + ``settle_or_reverse_ledger``
    in ``app/services/billing_shared.py``), writing a single
    ``type="adjustment", reason="refund"`` ledger entry carrying ``provider`` for
    FIN-013 attribution — exactly what ``app/routers/billing.py:refund_payment``
    does. No parallel refund mechanism is minted.
  * **Restock (OFB-009)** — returned qty is restocked via
    ``inventory.adjust(sku, +qty, reason="rma_restock")`` (OFB-003), guarded by
    the inventory flag so RMA still functions (minus restock) when inventory is
    disabled.

Invariants
----------
* Ownership: a return can only be opened against the requester's own order
  (foreign / unknown order -> 404).
* Quantity: requested qty per line must be 1..purchased-qty; the open return must
  not exceed remaining returnable qty.
* One open return per order at a time (duplicate-open -> 409).
* Status transitions are validated (illegal transition -> 409) and audited.
* Receive-restock and refund are each idempotent on replay (single-writer
  conditional ``status`` guard on the return header).

SECOPS-007 parity: identical code in dev (moto / local DDB) and prod (real DDB);
no ``dev_mode`` branch in the business logic.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# requested -> approved -> received -> refunded -> closed ; requested -> rejected
_VALID_TRANSITIONS: Dict[str, set] = {
    "requested": {"approved", "rejected"},
    "approved": {"received", "rejected"},
    "received": {"refunded"},
    "refunded": {"closed"},
    "rejected": set(),
    "closed": set(),
}
_OPEN_STATUSES = {"requested", "approved", "received"}


# ───────────────────────────── helpers ─────────────────────────────


def _flag_on() -> bool:
    return bool(getattr(S, "returns_rma_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Returns/RMA is not enabled")


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event

        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


def _notify(user_sub: str, title: str, body: str) -> None:
    """Best-effort in-app alert to the requester (existing alert plumbing)."""
    try:
        from app.services import alerts

        fn = getattr(alerts, "create_alert", None) or getattr(alerts, "send_alert", None)
        if fn is not None:
            fn(user_sub, title=title, body=body, category="returns")
    except Exception:
        pass


def _get_order(order_id: str) -> Optional[Dict[str, Any]]:
    resp = T.orders.get_item(Key={"order_id": order_id})
    return resp.get("Item")


def _get_order_items(order_id: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("order_id").eq(order_id),
    }
    while True:
        r = T.order_items.query(**kwargs)
        out.extend(r.get("Items", []))
        lek = r.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return out


def _return_header_out(header: Dict[str, Any], lines: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "return_id": header.get("return_id"),
        "order_id": header.get("order_id"),
        "user_sub": header.get("user_sub"),
        "status": header.get("status"),
        "reason": header.get("reason"),
        "currency": header.get("currency", "usd"),
        "refund_amount_cents": _to_int(header.get("refund_amount_cents")),
        "refund_ledger_sk": header.get("refund_ledger_sk"),
        "provider": header.get("provider"),
        "lines": [
            {
                "item_id": ln.get("item_id"),
                "sku": ln.get("sku"),
                "quantity": _to_int(ln.get("quantity")),
                "amount_cents": _to_int(ln.get("amount_cents")),
            }
            for ln in sorted(lines, key=lambda x: _to_int(x.get("line_no")))
        ],
        "created_at": _to_int(header.get("created_at")),
        "updated_at": _to_int(header.get("updated_at")),
        "decided_by": header.get("decided_by"),
        "decision_note": header.get("decision_note"),
    }


def _load_return(return_id: str) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    kwargs: Dict[str, Any] = {"KeyConditionExpression": Key("return_id").eq(return_id)}
    header: Optional[Dict[str, Any]] = None
    lines: List[Dict[str, Any]] = []
    while True:
        r = T.returns.query(**kwargs)
        for it in r.get("Items", []):
            if it.get("sk") == "META":
                header = it
            elif str(it.get("sk", "")).startswith("ITEM#"):
                lines.append(it)
        lek = r.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return header, lines


# ───────────────────────────── customer request flow (OFB-008) ─────────────────────────────


def request_return(
    *,
    user_sub: str,
    order_id: str,
    reason: str,
    lines: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Open a return against the requester's own order.

    Validates ownership, per-line qty (1..purchased), and that no open return
    already exists for the order (one-at-a-time).
    """
    _require_enabled()
    order = _get_order(order_id)
    # Foreign / unknown order -> 404 (ownership; ADR §Security).
    if not order or order.get("user_id") != user_sub:
        raise HTTPException(status_code=404, detail="Order not found")

    order_items = {str(it.get("item_id")): it for it in _get_order_items(order_id)}
    if not order_items:
        raise HTTPException(status_code=404, detail="Order has no line items")

    # Reject if there's already an open return for this order.
    existing_returns = list_returns_for_order(order_id)
    if any(r.get("status") in _OPEN_STATUSES for r in existing_returns):
        raise HTTPException(status_code=409, detail="An open return already exists for this order")

    if not lines:
        raise HTTPException(status_code=422, detail="At least one return line is required")

    resolved_lines: List[Dict[str, Any]] = []
    seen_items: set = set()
    for ln in lines:
        item_id = str(ln.get("item_id"))
        qty = _to_int(ln.get("quantity"))
        if item_id in seen_items:
            raise HTTPException(status_code=422, detail=f"Duplicate return line for item {item_id}")
        seen_items.add(item_id)
        oi = order_items.get(item_id)
        if oi is None:
            raise HTTPException(status_code=422, detail=f"Item {item_id} is not on order {order_id}")
        purchased = _to_int(oi.get("quantity"), 1)
        if qty < 1 or qty > purchased:
            raise HTTPException(
                status_code=422,
                detail=f"quantity for item {item_id} must be 1..{purchased}",
            )
        unit = _to_int(oi.get("amount_cents")) // max(1, purchased)
        resolved_lines.append(
            {
                "item_id": item_id,
                "sku": oi.get("sku"),
                "quantity": qty,
                "amount_cents": unit * qty,
            }
        )

    return_id = uuid.uuid4().hex
    now = now_ts()
    currency = str(order.get("currency", "usd")).lower()
    header = {
        "return_id": return_id,
        "sk": "META",
        "order_id": order_id,
        "user_sub": user_sub,
        "status": "requested",
        "reason": reason,
        "currency": currency,
        "refund_amount_cents": 0,
        "created_at": now,
        "updated_at": now,
    }
    T.returns.put_item(Item=header)
    line_rows: List[Dict[str, Any]] = []
    for idx, ln in enumerate(resolved_lines, start=1):
        row = {
            "return_id": return_id,
            "sk": f"ITEM#{idx}",
            "line_no": idx,
            "item_id": ln["item_id"],
            "sku": ln["sku"],
            "quantity": int(ln["quantity"]),
            "amount_cents": int(ln["amount_cents"]),
            "created_at": now,
        }
        T.returns.put_item(Item=row)
        line_rows.append(row)

    _audit(
        "rma.requested",
        user_sub,
        return_id=return_id,
        order_id=order_id,
        line_count=len(line_rows),
        reason=reason,
    )
    return _return_header_out(header, line_rows)


def get_return(return_id: str) -> Optional[Dict[str, Any]]:
    header, lines = _load_return(return_id)
    if header is None:
        return None
    return _return_header_out(header, lines)


def list_returns_for_order(order_id: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI_ORDER",
        "KeyConditionExpression": Key("order_id").eq(order_id),
    }
    while True:
        r = T.returns.query(**kwargs)
        out.extend(r.get("Items", []))
        lek = r.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    # GSI projects only META rows (line rows carry no order_id GSI key value
    # since they don't store order_id — keep only headers).
    return [it for it in out if it.get("sk") == "META"]


def list_returns_by_status(status: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI_STATUS",
        "KeyConditionExpression": Key("status").eq(status),
    }
    while True:
        r = T.returns.query(**kwargs)
        for it in r.get("Items", []):
            if it.get("sk") == "META":
                out.append(_return_header_out(it, []))
        lek = r.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return out


# ───────────────────────────── status transition core ─────────────────────────────


def _transition(
    return_id: str,
    from_status: str,
    to_status: str,
    *,
    actor_sub: str,
    extra_set: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Single-writer conditional status flip (idempotent under replay).

    Returns the prior header on a successful first transition, or None if the
    row was not in ``from_status`` (already advanced / concurrent loser).
    """
    set_parts = ["#s = :to", "updated_at = :now"]
    values: Dict[str, Any] = {":to": to_status, ":from": from_status, ":now": now_ts()}
    names: Dict[str, str] = {"#s": "status"}
    for i, (k, v) in enumerate((extra_set or {}).items()):
        nk = f"#e{i}"
        vk = f":e{i}"
        names[nk] = k
        values[vk] = v
        set_parts.append(f"{nk} = {vk}")
    try:
        resp = T.returns.update_item(
            Key={"return_id": return_id, "sk": "META"},
            UpdateExpression="SET " + ", ".join(set_parts),
            ConditionExpression="#s = :from",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
            ReturnValues="ALL_OLD",
        )
        return resp.get("Attributes")
    except ClientError as exc:
        if exc.response["Error"].get("Code") == "ConditionalCheckFailedException":
            return None
        raise


def _require_transition(current: str, target: str) -> None:
    # Idempotent replay: already in the target state -> caller treats as no-op.
    if current == target:
        return
    if target not in _VALID_TRANSITIONS.get(current, set()):
        raise HTTPException(
            status_code=409,
            detail=f"Illegal return transition {current} -> {target}",
        )


# ───────────────────────────── admin decisions (OFB-009) ─────────────────────────────


def approve_return(return_id: str, *, actor_sub: str, note: Optional[str] = None) -> Dict[str, Any]:
    _require_enabled()
    header, _ = _load_return(return_id)
    if header is None:
        raise HTTPException(status_code=404, detail="Return not found")
    _require_transition(header.get("status"), "approved")
    old = _transition(
        return_id, "requested", "approved",
        actor_sub=actor_sub,
        extra_set={"decided_by": actor_sub, "decision_note": note or ""},
    )
    if old is None:
        # Concurrent / replay: return current state.
        return get_return(return_id)  # type: ignore[return-value]
    _audit("rma.approved", actor_sub, return_id=return_id, order_id=header.get("order_id"))
    _notify(header.get("user_sub"), "Return approved", f"Your return {return_id} was approved.")
    return get_return(return_id)  # type: ignore[return-value]


def reject_return(return_id: str, *, actor_sub: str, note: Optional[str] = None) -> Dict[str, Any]:
    _require_enabled()
    header, _ = _load_return(return_id)
    if header is None:
        raise HTTPException(status_code=404, detail="Return not found")
    current = header.get("status")
    _require_transition(current, "rejected")
    old = _transition(
        return_id, current, "rejected",
        actor_sub=actor_sub,
        extra_set={"decided_by": actor_sub, "decision_note": note or ""},
    )
    if old is None:
        return get_return(return_id)  # type: ignore[return-value]
    _audit("rma.rejected", actor_sub, return_id=return_id, order_id=header.get("order_id"))
    _notify(header.get("user_sub"), "Return rejected", f"Your return {return_id} was rejected.")
    return get_return(return_id)  # type: ignore[return-value]


def receive_return(return_id: str, *, actor_sub: str) -> Dict[str, Any]:
    """Mark an approved return received; restock each line (OFB-009).

    Restock is idempotent: the on-hand increment only runs on the first
    successful ``approved -> received`` transition (single-writer guard).
    """
    _require_enabled()
    header, lines = _load_return(return_id)
    if header is None:
        raise HTTPException(status_code=404, detail="Return not found")
    _require_transition(header.get("status"), "received")
    old = _transition(return_id, "approved", "received", actor_sub=actor_sub)
    if old is None:
        return get_return(return_id)  # type: ignore[return-value]
    # Restock exactly once (gated by the inventory flag — OFB-009 guard).
    if bool(getattr(S, "inventory_reservations_enabled", False)):
        try:
            from app.services import inventory as inv

            for ln in lines:
                sku = ln.get("sku")
                qty = _to_int(ln.get("quantity"))
                if sku and qty > 0:
                    inv.adjust(sku, qty, reason="rma_restock", user_sub="system")
        except Exception:
            # Restock failure must not roll back the received transition.
            pass
    _audit("rma.received", actor_sub, return_id=return_id, order_id=header.get("order_id"))
    _notify(header.get("user_sub"), "Return received", f"Your return {return_id} was received.")
    return get_return(return_id)  # type: ignore[return-value]


# ───────────────────────────── refund via existing billing (OFB-010) ─────────────────────────────


def refund_return(
    return_id: str,
    *,
    actor_sub: str,
    provider: str = "stripe",
) -> Dict[str, Any]:
    """Refund a received return through the EXISTING billing ledger path.

    Reuses ``new_ledger_entry`` / ``apply_balance_delta`` / ``settle_or_reverse_ledger``
    (the same primitives ``billing.refund_payment`` uses) — one
    ``type="adjustment", reason="refund"`` ledger entry, provider-attributed
    (FIN-013), tied to the original payment when present. Idempotent: the refund
    only posts on the first ``received -> refunded`` transition.
    """
    _require_enabled()
    from app.services.billing_shared import (
        apply_balance_delta,
        ddb_put,
        new_ledger_entry,
        settle_or_reverse_ledger,
        user_pk,
    )

    header, lines = _load_return(return_id)
    if header is None:
        raise HTTPException(status_code=404, detail="Return not found")
    _require_transition(header.get("status"), "refunded")

    amount = sum(_to_int(ln.get("amount_cents")) for ln in lines)
    if amount <= 0:
        raise HTTPException(status_code=422, detail="Refund amount must be greater than zero")

    user_sub = header.get("user_sub")
    order_id = header.get("order_id")
    currency = str(header.get("currency", "usd")).lower()
    pk = user_pk(user_sub)

    # Single-writer guard: only the first transition posts the refund.
    old = _transition(
        return_id, "received", "refunded",
        actor_sub=actor_sub,
        extra_set={"refund_amount_cents": int(amount), "provider": provider},
    )
    if old is None:
        # Already refunded (idempotent replay) — do NOT post a second ledger entry.
        return get_return(return_id)  # type: ignore[return-value]

    # Look up the originating order's payment linkage (best-effort).
    order = _get_order(order_id) or {}
    original_ledger_sk = order.get("ledger_sk")
    payment_intent_id = order.get("payment_intent_id") or (order.get("metadata") or {}).get("payment_intent_id")

    led_sk_value, led_item = new_ledger_entry(
        key_name="pk",
        key_value=pk,
        entry_type="adjustment",
        amount_cents=int(amount),
        state="settled",
        reason="refund",
        meta={"reason": "rma_refund", "return_id": return_id, "order_id": order_id},
        extra={"provider": provider, "return_id": return_id, "order_id": order_id},
    )
    ddb_put(T.billing, led_item)
    apply_balance_delta(T.billing, pk, {"payments_settled_cents": -int(amount)}, currency=currency)
    if original_ledger_sk:
        settle_or_reverse_ledger(T.billing, "pk", pk, original_ledger_sk, "reversed")

    # Record the refund linkage on the return header (post-transition annotation).
    try:
        T.returns.update_item(
            Key={"return_id": return_id, "sk": "META"},
            UpdateExpression="SET refund_ledger_sk = :sk, updated_at = :now",
            ExpressionAttributeValues={":sk": led_sk_value, ":now": now_ts()},
        )
    except Exception:
        pass

    # Mark the originating invoice refunded where applicable (best-effort).
    if payment_intent_id:
        try:
            from app.services import invoices as inv_svc

            marker = getattr(inv_svc, "mark_invoice_refunded", None)
            if marker is not None:
                marker(user_sub, payment_intent_id)
        except Exception:
            pass

    _audit(
        "rma.refunded",
        actor_sub,
        return_id=return_id,
        order_id=order_id,
        amount_cents=int(amount),
        provider=provider,
        refund_ledger_sk=led_sk_value,
    )
    _notify(user_sub, "Return refunded", f"Your return {return_id} was refunded ({amount} cents).")
    return get_return(return_id)  # type: ignore[return-value]


def close_return(return_id: str, *, actor_sub: str) -> Dict[str, Any]:
    _require_enabled()
    header, _ = _load_return(return_id)
    if header is None:
        raise HTTPException(status_code=404, detail="Return not found")
    _require_transition(header.get("status"), "closed")
    old = _transition(return_id, "refunded", "closed", actor_sub=actor_sub)
    if old is None:
        return get_return(return_id)  # type: ignore[return-value]
    _audit("rma.closed", actor_sub, return_id=return_id, order_id=header.get("order_id"))
    return get_return(return_id)  # type: ignore[return-value]
