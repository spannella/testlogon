"""License revenue sharing -- split calculation and ledger integration (LICENSE-003)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key, Attr

from app.core.tables import T
from app.core.time import now_ts
from app.core.settings import S
from app.core.cursor import encode_cursor, decode_cursor
from app.services.billing_shared import (
    new_ledger_entry,
    apply_wallet_delta,
    user_pk,
)

logger = logging.getLogger(__name__)

SAFETY_CAP_PCT = 80  # Max 80% of source can go to license splits


# ---------------------------------------------------------------------------
# Pure calculation (no I/O)
# ---------------------------------------------------------------------------

def calculate_split(
    source_amount_cents: int,
    platform_fee_pct: int,
    revenue_share_pct: int,
    profit_share_pct: int,
) -> tuple[int, int]:
    """Return (revenue_share_cents, profit_share_cents)."""
    revenue_split = (source_amount_cents * revenue_share_pct) // 100
    net_profit = source_amount_cents - (source_amount_cents * platform_fee_pct) // 100
    profit_split = (net_profit * profit_share_pct) // 100
    return revenue_split, profit_split


def calculate_split_preview(
    source_amount_cents: int,
    platform_fee_pct: int,
    revenue_share_pct: int = 0,
    profit_share_pct: int = 0,
    fixed_cost_cents: int = 0,
) -> Dict[str, int]:
    """Return a preview dict (no DB writes)."""
    revenue_share_cents, profit_share_cents = calculate_split(
        source_amount_cents, platform_fee_pct, revenue_share_pct, profit_share_pct,
    )
    total = revenue_share_cents + profit_share_cents + fixed_cost_cents
    cap = (source_amount_cents * SAFETY_CAP_PCT) // 100
    if total > cap:
        total = cap
        # proportionally reduce
        if revenue_share_cents + profit_share_cents > 0:
            ratio = cap / (revenue_share_cents + profit_share_cents + fixed_cost_cents)
            revenue_share_cents = int(revenue_share_cents * ratio)
            profit_share_cents = int(profit_share_cents * ratio)
            fixed_cost_cents = total - revenue_share_cents - profit_share_cents

    platform_fee_cents = (source_amount_cents * platform_fee_pct) // 100
    licensee_net = source_amount_cents - platform_fee_cents - total

    return {
        "source_amount_cents": source_amount_cents,
        "platform_fee_cents": platform_fee_cents,
        "revenue_share_cents": revenue_share_cents,
        "profit_share_cents": profit_share_cents,
        "total_licensor_share_cents": total,
        "licensee_net_cents": licensee_net,
    }


# ---------------------------------------------------------------------------
# Revenue split processing
# ---------------------------------------------------------------------------

def process_revenue_split(
    *,
    content_id: str,
    licensee_id: str,
    source_type: str,
    source_amount_cents: int,
    source_txn_id: str,
    currency: str = "usd",
) -> List[Dict[str, Any]]:
    """Process revenue splits for all active licenses on a content item.

    Called by billing hooks whenever revenue is generated from content that
    uses licensed material.  Returns list of split transactions created.
    """
    licenses = list_licenses_for_content(content_id=content_id)
    if not licenses:
        return []

    platform_fee_pct = S.license_revenue_platform_fee_pct
    splits: List[Dict[str, Any]] = []
    ts = now_ts()
    total_split_cents = 0
    cap = (source_amount_cents * SAFETY_CAP_PCT) // 100

    for lic in licenses:
        licensor_id = lic["licensor_id"]
        if licensor_id == licensee_id:
            continue  # no self-split

        if lic.get("status") != "active":
            continue

        # Fixed fee (one-time per license+content pair)
        fixed_cost = int(lic.get("fixed_cost_cents", 0))
        if fixed_cost > 0:
            _process_fixed_fee(lic, licensee_id, content_id, fixed_cost, currency, ts)

        # Revenue / profit share
        rev_pct = int(lic.get("revenue_share_pct", 0))
        prof_pct = int(lic.get("profit_share_pct", 0))
        rev_cents, prof_cents = calculate_split(
            source_amount_cents, platform_fee_pct, rev_pct, prof_pct,
        )
        split_cents = rev_cents + prof_cents
        if split_cents <= 0:
            continue

        # Safety cap
        if total_split_cents + split_cents > cap:
            split_cents = max(0, cap - total_split_cents)
            if split_cents <= 0:
                break

        total_split_cents += split_cents
        txn_id = f"lrtxn_{uuid4().hex[:16]}"
        split_type = "revenue_share" if rev_pct > 0 else "profit_share"

        # Write revenue records (4 partitions)
        for prefix, uid in [
            ("LICENSOR", licensor_id),
            ("LICENSEE", licensee_id),
        ]:
            _write_revenue_record(
                prefix=prefix,
                user_id=uid,
                txn_id=txn_id,
                issued_license_id=lic.get("issued_license_id", ""),
                content_id=content_id,
                counterparty_id=licensee_id if prefix == "LICENSOR" else licensor_id,
                source_type=source_type,
                source_amount_cents=source_amount_cents,
                split_amount_cents=split_cents,
                split_type=split_type,
                currency=currency,
                ts=ts,
                licensor_id=licensor_id,
                licensee_id=licensee_id,
            )

        # Also write per-license and per-content records
        _write_revenue_record(
            prefix="LICENSE",
            user_id=lic.get("issued_license_id", ""),
            txn_id=txn_id,
            issued_license_id=lic.get("issued_license_id", ""),
            content_id=content_id,
            counterparty_id=licensee_id,
            source_type=source_type,
            source_amount_cents=source_amount_cents,
            split_amount_cents=split_cents,
            split_type=split_type,
            currency=currency,
            ts=ts,
            licensor_id=licensor_id,
            licensee_id=licensee_id,
        )

        # Bilateral ledger entries
        _sk_cr, item_cr = new_ledger_entry(
            key_name="pk",
            key_value=user_pk(licensor_id),
            entry_type="license_revenue_credit",
            amount_cents=split_cents,
            state="settled",
            reason=f"License revenue share from {source_type}",
            meta={
                "license_id": lic.get("issued_license_id", ""),
                "content_id": content_id,
                "source_txn_id": source_txn_id,
            },
        )
        T.billing.put_item(Item=item_cr)
        try:
            apply_wallet_delta(T.billing, user_pk(licensor_id), split_cents, currency=currency)
        except Exception:
            logger.warning("Failed to apply wallet credit for licensor %s", licensor_id)

        _sk_db, item_db = new_ledger_entry(
            key_name="pk",
            key_value=user_pk(licensee_id),
            entry_type="license_revenue_debit",
            amount_cents=split_cents,
            state="settled",
            reason=f"License revenue share to {licensor_id}",
            meta={
                "license_id": lic.get("issued_license_id", ""),
                "content_id": content_id,
                "source_txn_id": source_txn_id,
            },
        )
        T.billing.put_item(Item=item_db)

        # Update summaries
        _update_summary("LICENSOR", licensor_id, split_cents, ts)
        _update_summary("LICENSEE", licensee_id, split_cents, ts)

        splits.append({
            "txn_id": txn_id,
            "licensor_id": licensor_id,
            "licensee_id": licensee_id,
            "split_cents": split_cents,
            "split_type": split_type,
        })

    return splits


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

def get_revenue_summary(*, user_id: str, role: str) -> Dict[str, Any]:
    """Get aggregate revenue summary for a user as licensor or licensee."""
    prefix = role.upper()  # "LICENSOR" or "LICENSEE"
    resp = T.license_revenue.get_item(Key={"pk": f"{prefix}#{user_id}", "sk": "SUMMARY"})
    item = resp.get("Item")
    if not item:
        return {
            "total_cents": 0,
            "total_transactions": 0,
            "last_transaction_at": None,
            "currency": "usd",
        }
    return {
        "total_cents": int(item.get("total_cents", 0)),
        "total_transactions": int(item.get("total_transactions", 0)),
        "last_transaction_at": int(item["last_transaction_at"]) if item.get("last_transaction_at") else None,
        "currency": item.get("currency", "usd"),
    }


def list_revenue_transactions(
    *,
    user_id: str,
    role: str,
    source_type: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List revenue transactions for a user."""
    prefix = role.upper()
    pk = f"{prefix}#{user_id}"

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(pk) & Key("sk").begins_with("TXN#"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
    if source_type:
        kwargs["FilterExpression"] = Attr("source_type").eq(source_type)

    resp = T.license_revenue.query(**kwargs)
    items = resp.get("Items", [])
    txns = [_txn_from_item(it) for it in items]

    next_cursor = None
    if resp.get("LastEvaluatedKey"):
        next_cursor = encode_cursor(resp["LastEvaluatedKey"])

    summary = get_revenue_summary(user_id=user_id, role=role)
    return {"summary": summary, "transactions": txns, "next_cursor": next_cursor}


def list_license_transactions(
    *,
    issued_license_id: str,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List all transactions for a specific license."""
    pk = f"LICENSE#{issued_license_id}"
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(pk) & Key("sk").begins_with("TXN#"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.license_revenue.query(**kwargs)
    items = resp.get("Items", [])
    txns = [_txn_from_item(it) for it in items]

    next_cursor = None
    if resp.get("LastEvaluatedKey"):
        next_cursor = encode_cursor(resp["LastEvaluatedKey"])
    return {"transactions": txns, "next_cursor": next_cursor}


def admin_list_platform_revenue(
    *,
    limit: int = 100,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Admin: list platform-wide license revenue transactions."""
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI1",
        "KeyConditionExpression": Key("GSI1PK").eq("PLATFORM_REV"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.license_revenue.query(**kwargs)
    items = resp.get("Items", [])
    txns = []
    for it in items:
        txns.append({
            "txn_id": it.get("txn_id", ""),
            "licensor_id": it.get("licensor_id", ""),
            "licensee_id": it.get("licensee_id", ""),
            "content_id": it.get("content_id", ""),
            "source_type": it.get("source_type", ""),
            "source_amount_cents": int(it.get("source_amount_cents", 0)),
            "split_amount_cents": int(it.get("split_amount_cents", 0)),
            "created_at": int(it.get("created_at", 0)),
        })

    next_cursor = None
    if resp.get("LastEvaluatedKey"):
        next_cursor = encode_cursor(resp["LastEvaluatedKey"])
    return {"transactions": txns, "next_cursor": next_cursor}


# ---------------------------------------------------------------------------
# License content mapping (simple DDB-backed store, replaces missing LICENSE-002)
# ---------------------------------------------------------------------------

def register_content_license(
    *,
    issued_license_id: str,
    content_id: str,
    licensor_id: str,
    licensee_id: str,
    revenue_share_pct: int = 0,
    profit_share_pct: int = 0,
    fixed_cost_cents: int = 0,
    status: str = "active",
) -> Dict[str, Any]:
    """Register a license mapping for a content item.

    This is a lightweight replacement for the LICENSE-002 issued_licenses
    table.  It stores license terms in the license_revenue table under
    CONTENT_LIC#{content_id} / LIC#{issued_license_id}.
    """
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": f"CONTENT_LIC#{content_id}",
        "sk": f"LIC#{issued_license_id}",
        "issued_license_id": issued_license_id,
        "content_id": content_id,
        "licensor_id": licensor_id,
        "licensee_id": licensee_id,
        "revenue_share_pct": revenue_share_pct,
        "profit_share_pct": profit_share_pct,
        "fixed_cost_cents": fixed_cost_cents,
        "status": status,
        "created_at": ts,
        "updated_at": ts,
    }
    T.license_revenue.put_item(Item=item)
    return item


def list_licenses_for_content(*, content_id: str) -> List[Dict[str, Any]]:
    """Return active license records for a content item."""
    resp = T.license_revenue.query(
        KeyConditionExpression=Key("pk").eq(f"CONTENT_LIC#{content_id}") & Key("sk").begins_with("LIC#"),
    )
    return [it for it in resp.get("Items", []) if it.get("status") == "active"]


def revoke_content_license(*, content_id: str, issued_license_id: str) -> None:
    """Set a license mapping to revoked."""
    T.license_revenue.update_item(
        Key={"pk": f"CONTENT_LIC#{content_id}", "sk": f"LIC#{issued_license_id}"},
        UpdateExpression="SET #s = :s, updated_at = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "revoked", ":t": now_ts()},
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _txn_from_item(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "txn_id": item.get("txn_id", ""),
        "issued_license_id": item.get("issued_license_id", ""),
        "content_id": item.get("content_id", ""),
        "counterparty_id": item.get("counterparty_id", ""),
        "source_type": item.get("source_type", ""),
        "source_amount_cents": int(item.get("source_amount_cents", 0)),
        "split_amount_cents": int(item.get("split_amount_cents", 0)),
        "split_type": item.get("split_type", ""),
        "currency": item.get("currency", "usd"),
        "created_at": int(item.get("created_at", 0)),
    }


def _write_revenue_record(
    *,
    prefix: str,
    user_id: str,
    txn_id: str,
    issued_license_id: str,
    content_id: str,
    counterparty_id: str,
    source_type: str,
    source_amount_cents: int,
    split_amount_cents: int,
    split_type: str,
    currency: str,
    ts: int,
    licensor_id: str,
    licensee_id: str,
) -> None:
    item: Dict[str, Any] = {
        "pk": f"{prefix}#{user_id}",
        "sk": f"TXN#{ts}#{txn_id}",
        "txn_id": txn_id,
        "issued_license_id": issued_license_id,
        "content_id": content_id,
        "counterparty_id": counterparty_id,
        "licensor_id": licensor_id,
        "licensee_id": licensee_id,
        "source_type": source_type,
        "source_amount_cents": source_amount_cents,
        "split_amount_cents": split_amount_cents,
        "split_type": split_type,
        "currency": currency,
        "created_at": ts,
        "GSI1PK": "PLATFORM_REV",
        "GSI1SK": ts,
        "GSI2PK": f"SOURCE#{source_type}",
        "GSI2SK": ts,
    }
    T.license_revenue.put_item(Item=item)


def _update_summary(prefix: str, user_id: str, amount_cents: int, ts: int) -> None:
    """Atomically increment summary totals."""
    T.license_revenue.update_item(
        Key={"pk": f"{prefix}#{user_id}", "sk": "SUMMARY"},
        UpdateExpression=(
            "SET currency = :c, last_transaction_at = :t "
            "ADD total_cents :a, total_transactions :one"
        ),
        ExpressionAttributeValues={
            ":a": amount_cents,
            ":one": 1,
            ":c": "usd",
            ":t": ts,
        },
    )


def _process_fixed_fee(
    license_item: Dict[str, Any],
    licensee_id: str,
    content_id: str,
    fixed_cost: int,
    currency: str,
    ts: int,
) -> bool:
    """Process one-time fixed fee.  Returns True if fee was charged."""
    issued_license_id = license_item.get("issued_license_id", "")
    usage_pk = f"LICENSE#{issued_license_id}"
    usage_sk = f"USAGE#{content_id}"

    # Conditional put -- only if not exists (idempotent)
    try:
        T.license_revenue.put_item(
            Item={
                "pk": usage_pk,
                "sk": usage_sk,
                "content_id": content_id,
                "licensee_id": licensee_id,
                "fixed_fee_paid": True,
                "first_used_at": ts,
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
    except T.license_revenue.meta.client.exceptions.ConditionalCheckFailedException:
        return False  # Already paid

    licensor_id = license_item["licensor_id"]

    # Credit licensor
    _sk, item = new_ledger_entry(
        key_name="pk",
        key_value=user_pk(licensor_id),
        entry_type="license_fixed_fee_credit",
        amount_cents=fixed_cost,
        state="settled",
        reason="License fixed fee",
        meta={"license_id": issued_license_id, "content_id": content_id},
    )
    T.billing.put_item(Item=item)
    try:
        apply_wallet_delta(T.billing, user_pk(licensor_id), fixed_cost, currency=currency)
    except Exception:
        logger.warning("Failed to apply fixed fee wallet credit for %s", licensor_id)

    # Debit licensee
    _sk2, item2 = new_ledger_entry(
        key_name="pk",
        key_value=user_pk(licensee_id),
        entry_type="license_fixed_fee_debit",
        amount_cents=fixed_cost,
        state="settled",
        reason=f"License fixed fee to {licensor_id}",
        meta={"license_id": issued_license_id, "content_id": content_id},
    )
    T.billing.put_item(Item=item2)

    return True
