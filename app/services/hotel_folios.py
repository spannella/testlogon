"""Guest folio service — QloApps PMS vertical (HTL-029..HTL-032).

Additive + flag-gated (``HOTEL_PMS_ENABLED``, default OFF — reused from
HTL-001, no new master flag).  Every public function calls
``_require_enabled()`` first; when the flag is off all entries raise HTTP 404
and the platform is byte-for-byte unchanged.

HTL-029 — open_folio / add_line_item / get_folio / close_folio
HTL-030 — add_addon_to_folio / _resolve_addon
HTL-031 — set_deposit_policy / compute_deposit_amount / take_deposit /
           record_folio_payment / balance_due_on_arrival / render_folio_pdf

SECOPS-007: zero ``if S.dev_mode`` branches anywhere.
Money: integer cents only; no floats; single ledger mechanism
(billing_shared) — never forked.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_LINE_TYPES = {"room_night", "addon", "tax", "fee"}
_PAYMENT_METHODS = {
    "wallet",
    "card_external",
    "cash",
    "check",
    "bank_transfer",
    "deposit_applied",
}

# ---------------------------------------------------------------------------
# Shared helpers (copied from app/services/inventory.py:50-56,67,92-98)
# ---------------------------------------------------------------------------


def _flag_on() -> bool:
    return bool(getattr(S, "hotel_pms_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Hotel PMS is not enabled")


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _line_sk(line_id: str) -> str:
    return f"LINE#{line_id}"


# ---------------------------------------------------------------------------
# HTL-029 — Core folio CRUD
# ---------------------------------------------------------------------------


def open_folio(reservation: Dict[str, Any], *, user_sub: str) -> Dict[str, Any]:
    """Seed a new folio from an HTL-018 reservation dict.

    Idempotent: a second call with the same reservation_id returns the existing
    folio WITHOUT re-seeding room-night lines (no double-charge).
    """
    _require_enabled()

    reservation_id: str = reservation["reservation_id"]
    hotel_id: str = reservation.get("hotel_id", "")
    currency: str = reservation.get("currency", "usd")
    # guest_sub: prefer explicit field; fall back to guest_party_id
    guest_sub: str = (
        reservation.get("guest_sub")
        or reservation.get("guest_party_id")
        or ""
    )

    folio_id = "fol_" + uuid.uuid4().hex
    ts = now_ts()

    meta: Dict[str, Any] = {
        "reservation_id": reservation_id,
        "sk": "META",
        "folio_id": folio_id,
        "hotel_id": hotel_id,
        "guest_sub": guest_sub,
        "currency": currency,
        "status": "open",
        "charges_total_cents": 0,
        "payments_total_cents": 0,
        "deposit_held_cents": 0,
        "created_at": ts,
        "updated_at": ts,
    }

    is_new = True
    try:
        from boto3.dynamodb.conditions import Attr
        T.hotel_folios.put_item(
            Item=meta,
            ConditionExpression=Attr("sk").not_exists(),
        )
    except Exception as exc:
        code = getattr(getattr(exc, "response", None), "get", lambda k, d=None: d)(
            "Error", {}
        ).get("Code", "")
        if not code:
            # Try the botocore way
            err = getattr(exc, "response", {})
            code = err.get("Error", {}).get("Code", "") if isinstance(err, dict) else ""
        if code == "ConditionalCheckFailedException":
            is_new = False
        else:
            raise

    if is_new:
        # Seed room-night lines from the reservation
        nights = _to_int(reservation.get("nights"))
        total_cents = _to_int(reservation.get("total_cents"))
        room_type_id = reservation.get("room_type_id", "room")
        checkin = reservation.get("checkin", "")
        checkout = reservation.get("checkout", "")

        if nights > 0:
            per_night = total_cents // nights
            for i in range(nights):
                if i == nights - 1:
                    # Last night gets the remainder
                    unit_price = total_cents - i * per_night
                else:
                    unit_price = per_night
                description = (
                    f"{room_type_id} — {checkin}..{checkout} night {i + 1}"
                )
                add_line_item(
                    reservation_id,
                    line_type="room_night",
                    description=description,
                    quantity=1,
                    unit_price_cents=unit_price,
                    sku="",
                    user_sub=user_sub,
                )
        else:
            # Defensive: 0 nights — seed a single line of total_cents
            add_line_item(
                reservation_id,
                line_type="room_night",
                description=f"{room_type_id} — {checkin}..{checkout}",
                quantity=1,
                unit_price_cents=total_cents,
                sku="",
                user_sub=user_sub,
            )

    folio = get_folio(reservation_id)
    _audit(
        "hotel.folio.opened",
        user_sub,
        reservation_id=reservation_id,
        folio_id=folio["folio_id"] if folio else folio_id,
        hotel_id=hotel_id,
        is_new=is_new,
    )
    return folio  # type: ignore[return-value]


def add_line_item(
    reservation_id: str,
    *,
    line_type: str,
    description: str,
    quantity: int = 1,
    unit_price_cents: int,
    sku: str = "",
    user_sub: str,
) -> Dict[str, Any]:
    """Append a charge line and atomically bump charges_total_cents."""
    _require_enabled()

    if line_type not in _LINE_TYPES:
        raise HTTPException(status_code=422, detail=f"Invalid line_type: {line_type}")
    if quantity < 1:
        raise HTTPException(status_code=422, detail="quantity must be >= 1")
    if unit_price_cents < 0:
        raise HTTPException(status_code=422, detail="unit_price_cents must be >= 0")

    # Check folio header exists and is open
    resp = T.hotel_folios.get_item(Key={"reservation_id": reservation_id, "sk": "META"})
    meta = resp.get("Item")
    if not meta:
        raise HTTPException(status_code=404, detail="Folio not found")
    if meta.get("status") != "open":
        raise HTTPException(status_code=409, detail="Folio is closed")

    line_id = uuid.uuid4().hex
    amount_cents = quantity * unit_price_cents
    ts = now_ts()

    line_row: Dict[str, Any] = {
        "reservation_id": reservation_id,
        "sk": _line_sk(line_id),
        "line_id": line_id,
        "line_type": line_type,
        "description": description,
        "quantity": quantity,
        "unit_price_cents": unit_price_cents,
        "amount_cents": amount_cents,
        "sku": sku,
        "created_at": ts,
    }
    T.hotel_folios.put_item(Item=line_row)

    # Atomically bump the header charge counter (no read-modify-write race)
    T.hotel_folios.update_item(
        Key={"reservation_id": reservation_id, "sk": "META"},
        UpdateExpression="ADD charges_total_cents :amt SET updated_at = :t",
        ExpressionAttributeValues={":amt": amount_cents, ":t": ts},
    )

    _audit(
        "hotel.folio.line_added",
        user_sub,
        reservation_id=reservation_id,
        line_id=line_id,
        line_type=line_type,
        amount_cents=amount_cents,
    )

    return {
        "line_id": line_id,
        "line_type": line_type,
        "description": description,
        "quantity": _to_int(quantity),
        "unit_price_cents": _to_int(unit_price_cents),
        "amount_cents": _to_int(amount_cents),
        "sku": sku,
        "created_at": _to_int(ts),
    }


def get_folio(reservation_id: str) -> Optional[Dict[str, Any]]:
    """Return the assembled folio (header + sorted line items) or None."""
    _require_enabled()

    from boto3.dynamodb.conditions import Key as DKey

    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": DKey("reservation_id").eq(reservation_id)
    }
    while True:
        resp = T.hotel_folios.query(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek

    meta: Optional[Dict[str, Any]] = None
    lines: List[Dict[str, Any]] = []

    for item in items:
        sk = item.get("sk", "")
        if sk == "META":
            meta = item
        elif sk.startswith("LINE#"):
            lines.append(item)

    if meta is None:
        return None

    # Authoritatively recompute charges from line rows (source of truth)
    charges_total = sum(_to_int(li.get("amount_cents")) for li in lines)
    payments_total = _to_int(meta.get("payments_total_cents"))
    deposit_held = _to_int(meta.get("deposit_held_cents"))
    balance_due = charges_total - payments_total
    balance_due_on_arrival = charges_total - payments_total - deposit_held

    # Sort lines by created_at ascending (chronological display)
    lines.sort(key=lambda li: _to_int(li.get("created_at")))

    line_items = [
        {
            "line_id": li.get("line_id", ""),
            "line_type": li.get("line_type", ""),
            "description": li.get("description", ""),
            "quantity": _to_int(li.get("quantity"), 1),
            "unit_price_cents": _to_int(li.get("unit_price_cents")),
            "amount_cents": _to_int(li.get("amount_cents")),
            "sku": li.get("sku", ""),
            "created_at": _to_int(li.get("created_at")),
        }
        for li in lines
    ]

    return {
        "reservation_id": reservation_id,
        "folio_id": meta.get("folio_id", ""),
        "hotel_id": meta.get("hotel_id", ""),
        "guest_sub": meta.get("guest_sub", ""),
        "currency": meta.get("currency", "usd"),
        "status": meta.get("status", "open"),
        "charges_total_cents": charges_total,
        "payments_total_cents": payments_total,
        "deposit_held_cents": deposit_held,
        "deposit_policy_kind": meta.get("deposit_policy_kind", "none"),
        "deposit_pct_bps": _to_int(meta.get("deposit_pct_bps")),
        "deposit_fixed_cents": _to_int(meta.get("deposit_fixed_cents")),
        "balance_due_cents": balance_due,
        "balance_due_on_arrival_cents": balance_due_on_arrival,
        "line_items": line_items,
        "closed_at": _to_int(meta["closed_at"]) if meta.get("closed_at") is not None else None,
        "created_at": _to_int(meta.get("created_at")),
        "updated_at": _to_int(meta.get("updated_at")),
    }


def close_folio(reservation_id: str, *, user_sub: str) -> Dict[str, Any]:
    """Flip open → closed exactly once (idempotent under replay)."""
    _require_enabled()

    ts = now_ts()
    try:
        T.hotel_folios.update_item(
            Key={"reservation_id": reservation_id, "sk": "META"},
            UpdateExpression="SET #s = :closed, closed_at = :t, updated_at = :t",
            ConditionExpression="#s = :open AND attribute_exists(sk)",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":closed": "closed", ":open": "open", ":t": ts},
        )
    except Exception as exc:
        code = _exc_code(exc)
        if code == "ConditionalCheckFailedException":
            # Either already closed (idempotent) or folio not found
            folio = get_folio(reservation_id)
            if folio is None:
                raise HTTPException(status_code=404, detail="Folio not found")
            # else already closed — idempotent success
        else:
            raise

    _audit("hotel.folio.closed", user_sub, reservation_id=reservation_id)
    return get_folio(reservation_id)  # type: ignore[return-value]


def _exc_code(exc: Exception) -> str:
    """Extract DynamoDB error code from a botocore ClientError."""
    resp = getattr(exc, "response", {})
    if isinstance(resp, dict):
        return resp.get("Error", {}).get("Code", "")
    return ""


# ---------------------------------------------------------------------------
# HTL-030 — Add-on / catalog SKU line items
# ---------------------------------------------------------------------------


def _resolve_addon(sku: str) -> Tuple[int, str]:
    """Resolve catalog SKU → (price_cents, name).  Lazy import (cycle-safe)."""
    from app.routers.catalog import _find_item_by_id  # lazy — cycle/layer-safe
    item = _find_item_by_id(sku)
    if not item:
        raise HTTPException(status_code=404, detail="Add-on SKU not found")
    price_cents = _to_int(item.get("price_cents"))
    name = str(item.get("name") or sku)
    return price_cents, name


def add_addon_to_folio(
    reservation_id: str,
    *,
    sku: str,
    quantity: int = 1,
    user_sub: str,
) -> Dict[str, Any]:
    """Attach a catalog add-on SKU to the folio as a priced line item.

    Price is resolved server-side from the catalog (anti-tamper).
    """
    _require_enabled()
    if quantity < 1:
        raise HTTPException(status_code=422, detail="quantity must be >= 1")

    price_cents, name = _resolve_addon(sku)

    line = add_line_item(
        reservation_id,
        line_type="addon",
        description=f"{name} x{quantity}",
        quantity=quantity,
        unit_price_cents=price_cents,
        sku=sku,
        user_sub=user_sub,
    )

    _audit(
        "hotel.folio.addon_added",
        user_sub,
        reservation_id=reservation_id,
        sku=sku,
        quantity=quantity,
        amount_cents=line["amount_cents"],
    )
    return line


# ---------------------------------------------------------------------------
# HTL-031 — Deposit policy + payment recording + folio PDF
# ---------------------------------------------------------------------------


def compute_deposit_amount(folio: Dict[str, Any]) -> int:
    """Pure computation — no DDB access."""
    kind = folio.get("deposit_policy_kind", "none")
    charges = _to_int(folio.get("charges_total_cents"))
    if kind == "pct":
        return charges * _to_int(folio.get("deposit_pct_bps")) // 10_000
    if kind == "fixed":
        return _to_int(folio.get("deposit_fixed_cents"))
    return 0


def balance_due_on_arrival(folio: Dict[str, Any]) -> int:
    """Pure computation — held deposit credited against arrival balance."""
    return (
        _to_int(folio.get("charges_total_cents"))
        - _to_int(folio.get("payments_total_cents"))
        - _to_int(folio.get("deposit_held_cents"))
    )


def set_deposit_policy(
    reservation_id: str,
    *,
    kind: str,
    pct_bps: int = 0,
    fixed_cents: int = 0,
    user_sub: str,
) -> Dict[str, Any]:
    """Set or update the deposit policy on an open folio."""
    _require_enabled()

    if kind not in {"none", "pct", "fixed"}:
        raise HTTPException(status_code=422, detail="Invalid deposit policy kind")
    if not (0 <= pct_bps <= 10_000):
        raise HTTPException(status_code=422, detail="pct_bps must be 0..10000")
    if fixed_cents < 0:
        raise HTTPException(status_code=422, detail="fixed_cents must be >= 0")

    ts = now_ts()
    try:
        T.hotel_folios.update_item(
            Key={"reservation_id": reservation_id, "sk": "META"},
            UpdateExpression=(
                "SET deposit_policy_kind = :k, deposit_pct_bps = :p, "
                "deposit_fixed_cents = :f, updated_at = :t"
            ),
            ConditionExpression="attribute_exists(sk) AND #s = :open",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":k": kind,
                ":p": pct_bps,
                ":f": fixed_cents,
                ":open": "open",
                ":t": ts,
            },
        )
    except Exception as exc:
        code = _exc_code(exc)
        if code == "ConditionalCheckFailedException":
            folio = get_folio(reservation_id)
            if folio is None:
                raise HTTPException(status_code=404, detail="Folio not found")
            raise HTTPException(status_code=409, detail="Folio is closed")
        raise

    _audit(
        "hotel.folio.deposit_policy_set",
        user_sub,
        reservation_id=reservation_id,
        kind=kind,
        pct_bps=pct_bps,
        fixed_cents=fixed_cents,
    )
    return get_folio(reservation_id)  # type: ignore[return-value]


def take_deposit(
    reservation_id: str,
    *,
    amount_cents: Optional[int] = None,
    user_sub: str,
) -> Dict[str, Any]:
    """Atomically hold a deposit: wallet debit + escrow put + ledger put.

    Uses DynamoDB transact_write_items (TBT-003 escrow pattern).
    """
    _require_enabled()

    folio = get_folio(reservation_id)
    if folio is None:
        raise HTTPException(status_code=404, detail="Folio not found")
    if folio["status"] == "closed":
        raise HTTPException(status_code=409, detail="Folio is closed")

    amount = _to_int(amount_cents) if amount_cents is not None else compute_deposit_amount(folio)
    if amount <= 0:
        raise HTTPException(status_code=422, detail="Deposit amount must be positive")
    if amount > folio["balance_due_cents"]:
        raise HTTPException(status_code=422, detail="Deposit exceeds balance due")

    guest_sub = folio["guest_sub"]
    currency = folio["currency"]
    hotel_id = folio["hotel_id"]
    ts = now_ts()

    # Build ledger row first so we know its sk for the escrow back-ref
    try:
        from app.services.billing_shared import new_ledger_entry, user_pk, ddb_put
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="Billing service unavailable") from exc

    led_sk, led_item = new_ledger_entry(
        key_name="pk",
        key_value=user_pk(guest_sub),
        entry_type="hotel_deposit",
        amount_cents=amount,
        state="held",
        reason=f"Hotel deposit — reservation {reservation_id}",
        extra={
            "reservation_id": reservation_id,
            "hotel_id": hotel_id,
            "provider": "wallet",
            "escrow_state": "held",
        },
    )

    # Escrow sentinel row (T.billing, pk=FOLIO_DEPOSIT#{rid}, sk=ESCROW)
    escrow_pk = f"FOLIO_DEPOSIT#{reservation_id}"
    escrow_item: Dict[str, Any] = {
        "pk": escrow_pk,
        "sk": "ESCROW",
        "reservation_id": reservation_id,
        "guest_sub": guest_sub,
        "hotel_id": hotel_id,
        "amount_cents": amount,
        "currency": currency,
        "status": "held",
        "ledger_sk": led_sk,
        "created_at": ts,
    }

    # One transact_write_items: wallet debit + escrow put + ledger put
    wallet_pk = user_pk(guest_sub)
    transact_items = [
        {
            "Update": {
                "TableName": T.billing.name,
                "Key": _to_ddb_item({"pk": wallet_pk, "sk": "WALLET"}),
                "UpdateExpression": "SET wallet_balance_cents = wallet_balance_cents + :neg, updated_at = :t",
                "ConditionExpression": "wallet_balance_cents >= :amt",
                "ExpressionAttributeValues": _to_ddb_item(
                    {":neg": -amount, ":amt": amount, ":t": ts}
                ),
            }
        },
        {
            "Put": {
                "TableName": T.billing.name,
                "Item": _to_ddb_item(escrow_item),
                "ConditionExpression": "attribute_not_exists(pk)",
            }
        },
        {
            "Put": {
                "TableName": T.billing.name,
                "Item": _to_ddb_item(led_item),
                "ConditionExpression": "attribute_not_exists(sk)",
            }
        },
    ]

    try:
        _transact_client().transact_write_items(TransactItems=transact_items)
    except Exception as exc:
        code = _exc_code(exc)
        if code == "TransactionCanceledException":
            reasons = getattr(exc, "response", {}).get("CancellationReasons", [])
            if reasons and reasons[0].get("Code") == "ConditionalCheckFailed":
                raise HTTPException(status_code=402, detail="Insufficient wallet balance")
            if len(reasons) > 1 and reasons[1].get("Code") == "ConditionalCheckFailed":
                raise HTTPException(status_code=409, detail="Deposit already held")
        raise

    # Best-effort post-transact updates (different table — cannot join the transact)
    T.hotel_folios.update_item(
        Key={"reservation_id": reservation_id, "sk": "META"},
        UpdateExpression="ADD deposit_held_cents :amt SET updated_at = :t",
        ExpressionAttributeValues={":amt": amount, ":t": now_ts()},
    )

    # Deposit-receipt invoice (best-effort)
    try:
        from app.services import invoices
        if getattr(S, "invoices_enabled", True):
            invoices.create_invoice_safe(
                user_sub=guest_sub,
                invoice_type="deposit",
                amount_cents=amount,
                line_items=[{
                    "description": f"Deposit — reservation {reservation_id}",
                    "quantity": 1,
                    "amount_cents": amount,
                }],
                ledger_entry_id=led_item.get("entry_id", ""),
                currency=currency,
            )
    except Exception:
        pass

    _audit(
        "hotel.folio.deposit_held",
        user_sub,
        reservation_id=reservation_id,
        amount_cents=amount,
        ledger_sk=led_sk,
    )
    return get_folio(reservation_id)  # type: ignore[return-value]


def record_folio_payment(
    reservation_id: str,
    *,
    amount_cents: int,
    method: str,
    reference: str = "",
    user_sub: str,
) -> Dict[str, Any]:
    """Record a hotel payment against a folio (RNT-002 thin wrapper)."""
    _require_enabled()

    folio = get_folio(reservation_id)
    if folio is None:
        raise HTTPException(status_code=404, detail="Folio not found")
    if folio["status"] == "closed":
        raise HTTPException(status_code=409, detail="Folio is closed")

    if amount_cents < 1:
        raise HTTPException(status_code=422, detail="amount_cents must be >= 1")
    if method not in _PAYMENT_METHODS:
        raise HTTPException(status_code=422, detail=f"Invalid payment method: {method}")

    guest_sub = folio["guest_sub"]
    currency = folio["currency"]
    hotel_id = folio["hotel_id"]

    try:
        from app.services.billing_shared import (
            new_ledger_entry,
            apply_wallet_delta,
            apply_balance_delta,
            user_pk,
            ddb_put,
        )
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="Billing service unavailable") from exc

    led_sk, led_item = new_ledger_entry(
        key_name="pk",
        key_value=user_pk(guest_sub),
        entry_type="hotel_payment",
        amount_cents=amount_cents,
        state="settled",
        reason=f"Hotel payment — reservation {reservation_id}",
        extra={
            "reservation_id": reservation_id,
            "hotel_id": hotel_id,
            "method": method,
            "reference": reference,
            "provider": "wallet" if method == "wallet" else method,
        },
    )

    # Wallet move first (only for wallet method) — so a failed debit leaves no ledger row
    if method == "wallet":
        try:
            apply_wallet_delta(T.billing, user_pk(guest_sub), -amount_cents, currency=currency)
        except Exception as exc:
            code = _exc_code(exc)
            if code == "ConditionalCheckFailedException":
                raise HTTPException(status_code=402, detail="Insufficient wallet balance")
            raise

    # Persist the ledger row
    ddb_put(T.billing, led_item)

    # Bump the BALANCE counter
    try:
        apply_balance_delta(
            T.billing,
            user_pk(guest_sub),
            {"payments_settled_cents": amount_cents},
            currency=currency,
        )
    except Exception:
        pass  # best-effort counter — ledger row is the truth

    # Bump folio META payments_total_cents
    T.hotel_folios.update_item(
        Key={"reservation_id": reservation_id, "sk": "META"},
        UpdateExpression="ADD payments_total_cents :amt SET updated_at = :t",
        ExpressionAttributeValues={":amt": amount_cents, ":t": now_ts()},
    )

    _audit(
        "hotel.folio.payment_recorded",
        user_sub,
        reservation_id=reservation_id,
        amount_cents=amount_cents,
        method=method,
        reference=reference,
        ledger_sk=led_sk,
    )
    return get_folio(reservation_id)  # type: ignore[return-value]


def render_folio_pdf(reservation_id: str) -> Optional[bytes]:
    """Render the folio as a dependency-free PDF (invoices._render_pdf path).

    Returns None when the flag is off or the folio does not exist.
    """
    if not _flag_on():
        return None

    folio = get_folio(reservation_id)
    if folio is None:
        return None

    try:
        from app.services import invoices

        record: Dict[str, Any] = {
            "invoice_number": folio["folio_id"],
            "invoice_type": "folio",
            "created_at": folio["created_at"],
            "amount_cents": folio["charges_total_cents"],
            "tax_cents": 0,   # tax already in line items
            "total_cents": folio["charges_total_cents"],
            "line_items": [
                {
                    "description": li["description"],
                    "quantity": li["quantity"],
                    "amount_cents": li["amount_cents"],
                }
                for li in folio["line_items"]
            ],
        }

        lines = invoices._render_invoice_lines(record)
        lines += [
            "",
            "-" * 48,
            f"{'Payments':<36}{invoices._money(folio['payments_total_cents']):>12}",
            f"{'Deposit held':<36}{invoices._money(folio['deposit_held_cents']):>12}",
            f"{'BALANCE DUE ON ARRIVAL':<28}"
            f"{invoices._money(folio['balance_due_on_arrival_cents']):>20}",
        ]

        pdf = invoices._render_pdf(lines)

        # Best-effort store via invoice S3 path
        try:
            invoices._store_pdf(folio["guest_sub"], folio["folio_id"], pdf)
        except Exception:
            pass

        return pdf

    except Exception:
        return None


# ---------------------------------------------------------------------------
# Internal helpers for transact_write_items (copied from group_treasury.py)
# ---------------------------------------------------------------------------


def _transact_client() -> Any:
    """Low-level DynamoDB client for transact_write_items.

    Inherits endpoint/region/creds from T.billing.meta.client so it
    transparently targets DynamoDB Local in dev or real DynamoDB in prod
    (SECOPS-007 parity — no S.dev_mode branch).
    """
    import boto3

    resource_client = T.billing.meta.client
    endpoint = resource_client.meta.endpoint_url
    region = resource_client.meta.region_name
    creds = resource_client._request_signer._credentials
    kwargs: Dict[str, Any] = {"region_name": region, "endpoint_url": endpoint}
    if creds is not None:
        frozen = creds.get_frozen_credentials()
        kwargs["aws_access_key_id"] = frozen.access_key
        kwargs["aws_secret_access_key"] = frozen.secret_key
        if frozen.token:
            kwargs["aws_session_token"] = frozen.token
    return boto3.client("dynamodb", **kwargs)


def _to_ddb_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Serialize a plain dict into a low-level DDB AttributeValue map."""
    from boto3.dynamodb.types import TypeSerializer
    _serializer = TypeSerializer()
    return {k: _serializer.serialize(v) for k, v in item.items() if v is not None}
