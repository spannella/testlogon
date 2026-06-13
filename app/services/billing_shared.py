from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.core.time import now_ts

logger = logging.getLogger(__name__)


# D1 / CROSS_TICKET_AUDIT §A4: canonical entry_type -> sign map for the billing
# ledger. ``amount_cents`` is ALWAYS stored unsigned (for display); direction is
# carried by ``signed_amount_cents`` = sign * amount. Credits move the platform
# balance positively (+1); charges/debits negatively (-1). Refunds / adjustments
# / void-reversals are credits (+1) — they return money to the user.
#
# This is the single source of truth for sign derivation. Readers prefer the
# persisted ``signed_amount_cents`` and fall back to this map only for legacy /
# unstamped rows. Unknown entry_types default to +1 (safe credit) and are logged.
LEDGER_ENTRY_SIGN: Dict[str, int] = {
    # --- credits (+1): money returned to / accruing for the user ---
    "credit": 1,
    "refund": 1,
    "refund_credit": 1,
    "shipping_refund": 1,
    "adjustment": 1,
    "invoice_void_reversal": 1,
    "refund_reversal": 1,
    "sponsorship_escrow_refund": 1,
    "ad_revenue_credit": 1,
    "vod_rental_credit": 1,
    "vod_purchase_credit": 1,
    "license_revenue_credit": 1,
    "license_fixed_fee_credit": 1,
    "affiliate_withdrawal_credit": 1,
    "sponsorship_payout": 1,
    # --- charges / debits (-1): money owed by / charged to the user ---
    "debit": -1,
    "charge": -1,
    "purchase": -1,
    "refund_debit": -1,
    "vod_rental_debit": -1,
    "vod_purchase_debit": -1,
    "license_revenue_debit": -1,
    "license_fixed_fee_debit": -1,
    "impression_charge": -1,
    "conversion_charge": -1,
    "click_charge": -1,
    "sponsorship_escrow_hold": -1,
    "sponsorship_commission": -1,
}

# Default sign for entry_types not in the map. Positive (credit) is the safe
# default per ACC-002: a missing/unknown type should never silently invent a
# debit against the user.
LEDGER_ENTRY_SIGN_DEFAULT = 1


def sign_for_entry_type(entry_type: str) -> int:
    """Return +1 (credit) or -1 (charge/debit) for an entry_type using the
    canonical :data:`LEDGER_ENTRY_SIGN` map. Unknown types fall back to
    :data:`LEDGER_ENTRY_SIGN_DEFAULT` (+1) and are logged at WARNING."""
    if entry_type in LEDGER_ENTRY_SIGN:
        return LEDGER_ENTRY_SIGN[entry_type]
    logger.warning(
        "ledger entry_type %r not in LEDGER_ENTRY_SIGN; defaulting sign to %+d",
        entry_type,
        LEDGER_ENTRY_SIGN_DEFAULT,
    )
    return LEDGER_ENTRY_SIGN_DEFAULT


def derive_signed_amount_cents(entry_type: str, amount_cents: int) -> int:
    """Derive ``signed_amount_cents`` = sign(entry_type) * abs(amount_cents).

    ``amount_cents`` is treated as a magnitude (its absolute value is used) so a
    caller that already passed a negative amount still yields the correct sign
    from the type map."""
    return sign_for_entry_type(entry_type) * abs(int(amount_cents))


def ledger_date_for_ts(ts: int) -> str:
    """UTC date string (YYYY-MM-DD) for a Unix timestamp. Used by FIN-013
    to bucket ledger entries by day for platform financial aggregation."""
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")

BAL_FIELDS = [
    "owed_pending_cents",
    "owed_settled_cents",
    "payments_pending_cents",
    "payments_settled_cents",
]


def user_pk(user_id: str) -> str:
    return f"USER#{user_id}"


def ddb_get(table: Any, pk: str, sk: str) -> Optional[Dict[str, Any]]:
    resp = table.get_item(Key={"pk": pk, "sk": sk})
    return resp.get("Item")


def ddb_put(table: Any, item: Dict[str, Any], *, condition_expression: Optional[str] = None) -> None:
    kwargs: Dict[str, Any] = {"Item": item}
    if condition_expression:
        kwargs["ConditionExpression"] = condition_expression
    table.put_item(**kwargs)


def ddb_del(table: Any, pk: str, sk: str) -> None:
    table.delete_item(Key={"pk": pk, "sk": sk})


def ddb_query_pk(table: Any, pk: str) -> List[Dict[str, Any]]:
    resp = table.query(
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": pk},
    )
    return resp.get("Items", [])


def ddb_update(
    table: Any,
    pk: str,
    sk: str,
    expr: str,
    values: Dict[str, Any],
    names: Optional[Dict[str, str]] = None,
) -> None:
    kwargs: Dict[str, Any] = {
        "Key": {"pk": pk, "sk": sk},
        "UpdateExpression": expr,
        "ExpressionAttributeValues": values,
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    table.update_item(**kwargs)


def ensure_balance_row(table: Any, pk: str, currency: str) -> None:
    if not ddb_get(table, pk, "BALANCE"):
        ddb_put(
            table,
            {
                "pk": pk,
                "sk": "BALANCE",
                "currency": currency,
                **{k: 0 for k in BAL_FIELDS},
                "updated_at": now_ts(),
            },
        )


def apply_balance_delta(table: Any, pk: str, delta: Dict[str, int], *, currency: str = "usd") -> None:
    ensure_balance_row(table, pk, currency)

    sets = []
    values: Dict[str, Any] = {":z": 0, ":t": now_ts()}
    names: Dict[str, str] = {}

    i = 0
    for key, value in delta.items():
        if value == 0:
            continue
        i += 1
        nk = f"#k{i}"
        dv = f":d{i}"
        names[nk] = key
        values[dv] = int(value)
        sets.append(f"{nk} = if_not_exists({nk}, :z) + {dv}")

    names["#u"] = "updated_at"
    sets.append("#u = :t")

    expr = "SET " + ", ".join(sets)
    ddb_update(table, pk, "BALANCE", expr, values, names=names)


def ensure_balance_row_for_key(table: Any, key_name: str, key_value: str, currency: str) -> None:
    if not table.get_item(Key={key_name: key_value, "sk": "BALANCE"}).get("Item"):
        table.put_item(
            Item={
                key_name: key_value,
                "sk": "BALANCE",
                "currency": currency,
                **{k: 0 for k in BAL_FIELDS},
                "updated_at": now_ts(),
            },
        )


def apply_balance_delta_for_key(
    table: Any,
    key_name: str,
    key_value: str,
    delta: Dict[str, int],
    *,
    currency: str = "usd",
) -> None:
    ensure_balance_row_for_key(table, key_name, key_value, currency)

    sets = []
    values: Dict[str, Any] = {":z": 0, ":t": now_ts()}
    names: Dict[str, str] = {}

    i = 0
    for key, value in delta.items():
        if value == 0:
            continue
        i += 1
        nk = f"#k{i}"
        dv = f":d{i}"
        names[nk] = key
        values[dv] = int(value)
        sets.append(f"{nk} = if_not_exists({nk}, :z) + {dv}")

    names["#u"] = "updated_at"
    sets.append("#u = :t")

    expr = "SET " + ", ".join(sets)
    table.update_item(
        Key={key_name: key_value, "sk": "BALANCE"},
        UpdateExpression=expr,
        ExpressionAttributeValues=values,
        ExpressionAttributeNames=names,
    )


def compute_due(balance_item: Dict[str, Any]) -> Dict[str, int]:
    owed_settled = int(balance_item.get("owed_settled_cents", 0))
    owed_pending = int(balance_item.get("owed_pending_cents", 0))
    pay_settled = int(balance_item.get("payments_settled_cents", 0))
    pay_pending = int(balance_item.get("payments_pending_cents", 0))

    due_settled = owed_settled - pay_settled
    due_if_all_settles = (owed_settled + owed_pending) - (pay_settled + pay_pending)

    return {
        "due_settled_cents": due_settled,
        "due_if_all_settles_cents": due_if_all_settles,
    }


WALLET_SK = "WALLET"


def get_wallet_balance(table: Any, pk: str) -> Dict[str, Any]:
    row = ddb_get(table, pk, WALLET_SK) or {}
    return {
        "wallet_balance_cents": int(row.get("wallet_balance_cents", 0)),
        "currency": row.get("currency", "usd"),
        "updated_at": row.get("updated_at"),
    }


def apply_wallet_delta(table: Any, pk: str, delta_cents: int, *, currency: str = "usd") -> int:
    """Atomically add delta_cents to wallet balance.

    For deposits (delta > 0): uses if_not_exists to create row if needed.
    For withdrawals (delta < 0): requires existing balance >= abs(delta);
    raises ConditionalCheckFailedException if insufficient.
    """
    if delta_cents >= 0:
        # Deposit: create row if it doesn't exist, add to balance
        result = table.update_item(
            Key={"pk": pk, "sk": WALLET_SK},
            UpdateExpression=(
                "SET wallet_balance_cents = if_not_exists(wallet_balance_cents, :z) + :d, "
                "currency = :c, updated_at = :t"
            ),
            ExpressionAttributeValues={":z": 0, ":d": delta_cents, ":c": currency, ":t": now_ts()},
            ReturnValues="ALL_NEW",
        )
    else:
        # Withdrawal: only succeed if existing balance >= needed amount
        needed = abs(delta_cents)
        result = table.update_item(
            Key={"pk": pk, "sk": WALLET_SK},
            UpdateExpression="SET wallet_balance_cents = wallet_balance_cents + :d, updated_at = :t",
            ConditionExpression="wallet_balance_cents >= :needed",
            ExpressionAttributeValues={":d": delta_cents, ":t": now_ts(), ":needed": needed},
            ReturnValues="ALL_NEW",
        )
    return int(result["Attributes"].get("wallet_balance_cents", 0))


def ulidish() -> str:
    return f"{int(now_ts() * 1000)}_{secrets.token_hex(8)}"


def ledger_sk(ts: int, entry_id: str) -> str:
    return f"LEDGER#{ts}#{entry_id}"


def new_ledger_entry(
    *,
    key_name: str,
    key_value: str,
    entry_type: str,
    amount_cents: int,
    state: str,
    reason: str,
    meta: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
    signed_amount_cents: Optional[int] = None,
) -> Tuple[str, Dict[str, Any]]:
    # GAP-0203 / FIN-013: provider-originating transactions MUST pass
    # ``extra={"provider": "stripe"|"paypal"|"ccbill"}`` so the platform
    # financial dashboard provider breakdown can attribute the entry. The
    # ``extra`` dict is a pass-through onto the persisted item (see below).
    ts = now_ts()
    entry_id = ulidish()
    sk = ledger_sk(ts, entry_id)
    # D1 / CROSS_TICKET_AUDIT §A4: persist a signed_amount_cents at write time.
    # ``amount_cents`` STAYS UNSIGNED (display). When the caller passes an
    # explicit signed value we persist it verbatim; otherwise we derive it from
    # the canonical entry_type -> sign map.
    if signed_amount_cents is None:
        signed_value = derive_signed_amount_cents(entry_type, amount_cents)
    else:
        signed_value = int(signed_amount_cents)
    item = {
        key_name: key_value,
        "sk": sk,
        "entry_id": entry_id,
        "ts": ts,
        "type": entry_type,
        "amount_cents": int(amount_cents),
        "signed_amount_cents": signed_value,
        "state": state,
        "reason": reason,
        # FIN-013: denormalized UTC date for platform financial dashboard
        # aggregation. Lets cross-user scans bucket entries by day cheaply.
        "ledger_date": ledger_date_for_ts(ts),
    }
    if extra:
        item.update(extra)
    if meta:
        item["meta"] = meta
    return sk, item


def settle_or_reverse_ledger(
    table: Any,
    key_name: str,
    key_value: str,
    ledger_sk_value: str,
    new_state: str,
) -> None:
    table.update_item(
        Key={key_name: key_value, "sk": ledger_sk_value},
        UpdateExpression="SET #s = :s",
        ExpressionAttributeNames={"#s": "state"},
        ExpressionAttributeValues={":s": new_state},
    )
