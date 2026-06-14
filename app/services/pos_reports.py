"""
POS-010 — X/Z session reports (till summary).

X report  : mid-shift, non-finalizing snapshot; requires an OPEN session.
Z report  : end-of-shift, finalizing; requires a CLOSED session.  Sets
            ``z_report_printed_at`` on the session row (idempotent first-writer
            wins; replays return the same data and do NOT re-fire the audit
            event).

Always queries ``GSI_SESSION_TXN`` for the session partition (loops via
``LastEvaluatedKey``); never scans the ``pos`` table.  Cash float math is read
from the session row (authoritative, maintained atomically by POS-006), with a
tender-row fallback for resilience.  The by-tender breakdown and gross/refund/
void subtotals are aggregated from the queried rows.

SECOPS-007: read-mostly; the only write is the idempotent ``z_report_printed_at``
conditional update — same code path dev (DDB local) + prod (real DynamoDB).
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any, Dict, List

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.pos_register import _require_enabled, _audit, _session_pk


def _to_int(v: Any) -> int:
    if v is None:
        return 0
    if isinstance(v, Decimal):
        return int(v)
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _query_session_txn_rows(session_id: str) -> List[Dict[str, Any]]:
    """Query all rows for a session via GSI_SESSION_TXN; loop to exhaustion."""
    out: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI_SESSION_TXN",
        "KeyConditionExpression": "session_id = :sid",
        "ExpressionAttributeValues": {":sid": session_id},
        "ScanIndexForward": True,
    }
    while True:
        resp = T.pos.query(**kwargs)
        out.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return out


def _aggregate_rows(rows: List[Dict[str, Any]], session: Dict[str, Any], *, kind: str) -> Dict[str, Any]:
    """Pure aggregation (no DDB calls). Returns the report body dict."""
    gross_sales_cents = 0
    discount_cents = 0
    tax_cents = 0
    transaction_count = 0
    void_count = 0
    refund_total_cents = 0

    # tender_breakdown[kind] -> {gross_cents, refund_cents, transaction_count}
    tb: Dict[str, Dict[str, int]] = {}

    def _bucket(k: str) -> Dict[str, int]:
        return tb.setdefault(k, {"gross_cents": 0, "refund_cents": 0, "transaction_count": 0})

    # Fallback cash counters derived from tender rows.
    cash_in_from_tenders = 0
    change_out_from_tenders = 0

    for row in rows:
        sk = str(row.get("pos_sk", ""))
        pk = str(row.get("pos_pk", ""))
        if sk.startswith("TENDER#"):
            k = (row.get("kind") or "cash").lower()
            amount = _to_int(row.get("amount_cents")) or _to_int(row.get("amount_tendered_cents"))
            b = _bucket(k)
            b["gross_cents"] += amount
            b["transaction_count"] += 1
            if k == "cash":
                cash_in_from_tenders += _to_int(row.get("amount_tendered_cents")) or amount
                change_out_from_tenders += _to_int(row.get("change_due_cents"))
        elif sk.startswith("REFUND#"):
            # Refund kind may be "cash_refund" / "card_refund" / "wallet_refund"
            raw_kind = (row.get("kind") or "cash").lower()
            base_kind = raw_kind.replace("_refund", "")
            amount = _to_int(row.get("amount_cents")) or _to_int(row.get("amount_tendered_cents"))
            refund_total_cents += amount
            _bucket(base_kind)["refund_cents"] += amount
        elif pk.startswith("TXN#") and sk == "META":
            status = row.get("status")
            if status == "voided":
                void_count += 1
                continue
            if status in ("tendered", "refunded"):
                transaction_count += 1
                gross_sales_cents += _to_int(row.get("total_cents"))
                discount_cents += _to_int(row.get("discount_cents"))
                tax_cents += _to_int(row.get("tax_cents"))

    tender_breakdown = []
    for k in sorted(tb.keys()):
        b = tb[k]
        tender_breakdown.append({
            "kind": k,
            "gross_cents": b["gross_cents"],
            "refund_cents": b["refund_cents"],
            "net_cents": b["gross_cents"] - b["refund_cents"],
            "transaction_count": b["transaction_count"],
        })

    # ── cash drawer reconciliation ──
    opening_float = _to_int(session.get("opening_float_cents"))
    # Prefer authoritative session counters; fall back to tender-derived sums.
    if "cash_in_cents" in session:
        cash_in = _to_int(session.get("cash_in_cents"))
    else:
        cash_in = cash_in_from_tenders
    if "change_out_cents" in session:
        change_out = _to_int(session.get("change_out_cents"))
    else:
        change_out = change_out_from_tenders

    if kind == "z" and session.get("expected_cash_cents") is not None:
        expected_cash = _to_int(session.get("expected_cash_cents"))
    else:
        expected_cash = opening_float + cash_in - change_out

    if kind == "z":
        counted_cash = (
            _to_int(session.get("counted_cash_cents"))
            if session.get("counted_cash_cents") is not None else None
        )
        over_short = (
            _to_int(session.get("over_short_cents"))
            if session.get("over_short_cents") is not None else None
        )
    else:
        counted_cash = None
        over_short = None

    cash_section = {
        "opening_float_cents": opening_float,
        "cash_in_cents": cash_in,
        "change_out_cents": change_out,
        "expected_cash_cents": expected_cash,
        "counted_cash_cents": counted_cash,
        "over_short_cents": over_short,
    }

    net_sales_cents = gross_sales_cents - discount_cents

    return {
        "gross_sales_cents": gross_sales_cents,
        "discount_cents": discount_cents,
        "tax_cents": tax_cents,
        "net_sales_cents": net_sales_cents,
        "refund_total_cents": refund_total_cents,
        "void_count": void_count,
        "transaction_count": transaction_count,
        "tender_breakdown": tender_breakdown,
        "cash": cash_section,
    }


def _is_privileged(role: Any) -> bool:
    """True for admin/root callers (role may be a Role enum or its value string)."""
    val = getattr(role, "value", role)
    return val in ("admin", "root")


def session_report(
    session_id: str,
    kind: str,
    *,
    cashier_sub: str,
    role: Any = "user",
) -> Dict[str, Any]:
    """Produce an X or Z till summary for ``session_id``.

    X-report: non-resetting mid-shift snapshot; session must be ``"open"``.
    Z-report: end-of-shift; session must be ``"closed"``; sets
              ``z_report_printed_at`` (idempotent).
    """
    _require_enabled()

    kind = (kind or "").lower()
    if kind not in ("x", "z"):
        raise HTTPException(status_code=400, detail="invalid_report_kind")

    session = T.pos.get_item(Key=_session_pk(session_id)).get("Item")
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if not _is_privileged(role) and session.get("cashier_sub") != cashier_sub:
        raise HTTPException(status_code=403, detail="You may only report on your own session")

    status = session.get("status")
    if kind == "x" and status != "open":
        raise HTTPException(
            status_code=409,
            detail="Session is closed; use kind=z for the final report",
        )
    if kind == "z" and status != "closed":
        raise HTTPException(
            status_code=409,
            detail="Session must be closed for a Z report",
        )

    rows = _query_session_txn_rows(session_id)
    body = _aggregate_rows(rows, session, kind=kind)

    z_printed_at = _to_int(session.get("z_report_printed_at")) or None
    if kind == "z":
        # Idempotent first-writer-wins on z_report_printed_at.
        if session.get("z_report_printed_at") is None:
            now = now_ts()
            try:
                T.pos.update_item(
                    Key=_session_pk(session_id),
                    UpdateExpression="SET z_report_printed_at = :now",
                    ConditionExpression="attribute_not_exists(z_report_printed_at)",
                    ExpressionAttributeValues={":now": now},
                )
                z_printed_at = now
                _audit("pos_z_report_printed", cashier_sub,
                       session_id=session_id, register_id=session.get("register_id", ""))
            except ClientError as exc:
                code = exc.response["Error"].get("Code", "")
                if code == "ConditionalCheckFailedException":
                    fresh = T.pos.get_item(Key=_session_pk(session_id)).get("Item", session)
                    z_printed_at = _to_int(fresh.get("z_report_printed_at")) or None
                else:
                    raise

    report = {
        "report_kind": kind,
        "session_id": session_id,
        "register_id": session.get("register_id", ""),
        "cashier_sub": session.get("cashier_sub", ""),
        "opened_at": _to_int(session.get("opened_at")),
        "closed_at": _to_int(session.get("closed_at")) or None,
        "generated_at": now_ts(),
        "z_report_printed_at": z_printed_at,
        **body,
    }
    return report
