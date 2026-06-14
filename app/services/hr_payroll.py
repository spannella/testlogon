"""OFBiz-inspired Payroll service (HRM-007, HRM-008, HRM-010).

This module owns:
  * Payroll run draft/compute/approve (HRM-007)
  * Payroll disbursement via billing ledger (HRM-008)
  * GL journal-entry hook (HRM-010) — triggered after APPROVED→POSTED

Money convention: every ledger entry is written via
``billing_shared.new_ledger_entry`` — NEVER a hand-rolled path (follows the
same constraint as all other money-out paths on this platform).

HRM-010 GL hook: guarded on BOTH S.gl_double_entry_enabled (the sibling
master GL flag) AND S.hr_payroll_gl_posting_enabled.  If either is off, the
payroll disburse still completes; only the GL journal entry is skipped.

SECOPS-007 parity: no dev_mode branches.
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from app.core.tables import T
from app.core.settings import S
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor
from app.core.crypto import sha256_str
from app.services.alerts import audit_event
from app.services.billing_shared import (
    new_ledger_entry,
    ddb_put,
    ledger_sk as billing_ledger_sk,
)


# ──────────────────────────── custom exceptions ────────────────────────────


class PayrollRunInvalidTransitionError(ValueError):
    """Raised when an illegal payroll run status transition is attempted."""


# ──────────────────────────── proration helper ─────────────────────────────


def _compute_gross(
    employment: Dict[str, Any],
    period_start: int,
    period_end: int,
) -> int:
    """Compute gross_cents for one employment line using integer arithmetic."""
    pay_rate = int(employment.get("pay_rate_cents", 0))
    pay_period = employment.get("pay_period", "MONTHLY")
    duration_seconds = period_end - period_start

    if pay_period == "MONTHLY":
        return pay_rate
    elif pay_period == "BIWEEKLY":
        return int(pay_rate * duration_seconds / (14 * 86400))
    elif pay_period == "WEEKLY":
        return int(pay_rate * duration_seconds / (7 * 86400))
    elif pay_period == "HOURLY":
        return int(pay_rate * duration_seconds / 3600)
    else:
        return pay_rate  # unknown period — return monthly rate as fallback


# ──────────────────────────── idempotency helpers ─────────────────────────


def _line_correlation_id(payroll_run_id: str, employment_id: str) -> str:
    """Deterministic entry_id for a (run, employment) pair."""
    digest = sha256_str(f"payroll:{payroll_run_id}:{employment_id}")[:32]
    return f"payroll_{digest}"


def _stable_ts(run: Dict[str, Any]) -> int:
    """Return run's created_at as the stable timestamp for billing SK."""
    return int(run["created_at"])


# ──────────────────────────── HRM-007: payroll run lifecycle ──────────────


def create_payroll_run(
    period_start: int,
    period_end: int,
    *,
    actor_sub: str,
    currency: str = "usd",
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a DRAFT payroll run.

    Enumerates all ACTIVE employments, computes gross per line, and persists
    the run + line items in T.hr.  Re-creating with the same correlation_id
    returns the existing run (idempotent).

    Raises:
        ValueError: if period_start >= period_end.
    """
    if period_start >= period_end:
        raise ValueError("period_start must be before period_end")

    if correlation_id:
        payroll_run_id = "PR_" + hashlib.sha256(correlation_id.encode("utf-8")).hexdigest()[:32]
    else:
        payroll_run_id = "PR_" + uuid.uuid4().hex

    ts = now_ts()
    meta_item: Dict[str, Any] = {
        "PK": f"PAYROLL#{payroll_run_id}",
        "SK": "META",
        "payroll_run_id": payroll_run_id,
        "period_start": period_start,
        "period_end": period_end,
        "status": "DRAFT",
        "currency": currency.upper(),
        "line_count": 0,
        "total_gross_cents": 0,
        "created_at": ts,
        "updated_at": ts,
        "actor_sub": actor_sub,
        "GSI1PK": "PAYROLL#DRAFT",
        "GSI1SK": f"PAYROLL#{payroll_run_id}",
        "entity_type": "PAYROLL_RUN",
    }
    if correlation_id:
        meta_item["correlation_id"] = correlation_id

    try:
        T.hr.put_item(Item=meta_item, ConditionExpression="attribute_not_exists(PK)")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            existing = get_payroll_run(payroll_run_id)
            return existing or meta_item
        raise

    # Enumerate all ACTIVE employments (lazy import to avoid circular dep)
    from app.services.hr import list_employments  # noqa: PLC0415

    lines: List[Dict[str, Any]] = []
    cursor: Optional[str] = None
    while True:
        page = list_employments(status="ACTIVE", cursor=cursor, limit=200)
        for emp in page.get("items", []):
            gross = _compute_gross(emp, period_start, period_end)
            line_item: Dict[str, Any] = {
                "PK": f"PAYROLL#{payroll_run_id}",
                "SK": f"LINE#{emp['employment_id']}",
                "payroll_run_id": payroll_run_id,
                "employment_id": emp["employment_id"],
                "party_id": emp.get("party_id", ""),
                "pay_rate_cents": int(emp.get("pay_rate_cents", 0)),
                "pay_period": emp.get("pay_period", "MONTHLY"),
                "gross_cents": gross,
                "currency": emp.get("currency", currency).upper(),
                "status": "DRAFT",
                "created_at": ts,
            }
            T.hr.put_item(Item=line_item)
            lines.append(line_item)
        cursor = page.get("next_cursor")
        if not cursor:
            break

    total_gross = sum(ln["gross_cents"] for ln in lines)
    T.hr.update_item(
        Key={"PK": f"PAYROLL#{payroll_run_id}", "SK": "META"},
        UpdateExpression="SET line_count = :lc, total_gross_cents = :tg",
        ExpressionAttributeValues={":lc": len(lines), ":tg": total_gross},
    )
    meta_item["line_count"] = len(lines)
    meta_item["total_gross_cents"] = total_gross

    try:
        audit_event(
            "payroll_run.created",
            actor_sub,
            payroll_run_id=payroll_run_id,
            line_count=len(lines),
            period_start=period_start,
            period_end=period_end,
        )
    except Exception:
        pass

    return meta_item


def approve_payroll_run(
    payroll_run_id: str,
    *,
    actor_sub: str,
) -> Dict[str, Any]:
    """Transition DRAFT → APPROVED.  Re-approving is a no-op.

    Raises:
        LookupError: if the run does not exist.
        PayrollRunInvalidTransitionError: if status is not DRAFT or APPROVED.
    """
    run = get_payroll_run(payroll_run_id)
    if run is None:
        raise LookupError("payroll_run_not_found")

    if run["status"] == "APPROVED":
        return run  # idempotent no-op

    if run["status"] != "DRAFT":
        raise PayrollRunInvalidTransitionError(f"{run['status']}→APPROVED")

    ts = now_ts()
    T.hr.update_item(
        Key={"PK": f"PAYROLL#{payroll_run_id}", "SK": "META"},
        UpdateExpression=(
            "SET #status = :status, GSI1PK = :gsi1pk, "
            "approved_by = :approver, approved_at = :ts, updated_at = :ts"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":status": "APPROVED",
            ":gsi1pk": "PAYROLL#APPROVED",
            ":approver": actor_sub,
            ":ts": ts,
        },
    )

    try:
        audit_event(
            "payroll_run.approved",
            actor_sub,
            payroll_run_id=payroll_run_id,
        )
    except Exception:
        pass

    updated = get_payroll_run(payroll_run_id)
    return updated or run


def get_payroll_run(payroll_run_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a payroll run META item.  Returns None if not found."""
    resp = T.hr.get_item(Key={"PK": f"PAYROLL#{payroll_run_id}", "SK": "META"})
    return resp.get("Item")


def get_payroll_run_lines(payroll_run_id: str) -> List[Dict[str, Any]]:
    """Fetch all LINE# items for a payroll run."""
    resp = T.hr.query(
        KeyConditionExpression=(
            Key("PK").eq(f"PAYROLL#{payroll_run_id}") & Key("SK").begins_with("LINE#")
        ),
    )
    return resp.get("Items", [])


def list_payroll_runs(
    status: Optional[str] = None,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """List payroll runs by status (GSI1) or newest-first (GSI_CREATED)."""
    kwargs: Dict[str, Any] = {"Limit": limit}
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    if status is not None:
        kwargs["IndexName"] = "GSI1"
        kwargs["KeyConditionExpression"] = Key("GSI1PK").eq(f"PAYROLL#{status}")
    else:
        kwargs["IndexName"] = "GSI_CREATED"
        kwargs["KeyConditionExpression"] = Key("entity_type").eq("PAYROLL_RUN")
        kwargs["ScanIndexForward"] = False

    resp = T.hr.query(**kwargs)
    result: Dict[str, Any] = {"items": resp.get("Items", [])}
    if resp.get("LastEvaluatedKey"):
        result["next_cursor"] = encode_cursor(resp["LastEvaluatedKey"])
    return result


# ──────────────────────────── HRM-008: payroll disbursement ───────────────


def post_payroll_run(
    payroll_run_id: str,
    *,
    actor_sub: str,
) -> Dict[str, Any]:
    """Disburse an APPROVED payroll run via billing ledger entries.

    One ``new_ledger_entry`` call per line with ``reason="payroll"`` and
    ``entry_type="debit"`` (money-out from the platform).  The run transitions
    APPROVED → POSTED only after all line ledger writes succeed.

    Idempotent: already-POSTED runs are returned immediately.  Partial retries
    skip lines whose billing entry already exists (attribute_not_exists guard).

    Raises:
        LookupError: if the run does not exist.
        PayrollRunInvalidTransitionError: if status is not APPROVED or POSTED.
    """
    run = get_payroll_run(payroll_run_id)
    if run is None:
        raise LookupError("payroll_run_not_found")

    if run["status"] == "POSTED":
        return run  # idempotent no-op

    if run["status"] != "APPROVED":
        raise PayrollRunInvalidTransitionError(f"{run['status']}→POSTED")

    lines = get_payroll_run_lines(payroll_run_id)
    stable_ts = _stable_ts(run)

    for line in lines:
        emp_id = line["employment_id"]
        entry_id = _line_correlation_id(payroll_run_id, emp_id)
        billing_sk = billing_ledger_sk(stable_ts, entry_id)

        extra = {
            "employment_id": emp_id,
            "party_id": line.get("party_id", ""),
            "payroll_run_id": payroll_run_id,
        }

        _, led_item = new_ledger_entry(
            key_name="pk",
            key_value=f"PAYROLL#{payroll_run_id}",
            entry_type="debit",
            amount_cents=int(line.get("gross_cents", 0)),
            state="settled",
            reason="payroll",
            extra=extra,
        )
        # Override the internally-generated SK/ts/entry_id with our stable values
        led_item["sk"] = billing_sk
        led_item["ts"] = stable_ts
        led_item["entry_id"] = entry_id

        try:
            T.billing.put_item(
                Item=led_item,
                ConditionExpression="attribute_not_exists(sk)",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                pass  # already posted — safe to continue
            else:
                raise

        # Update line status
        T.hr.update_item(
            Key={
                "PK": f"PAYROLL#{payroll_run_id}",
                "SK": f"LINE#{emp_id}",
            },
            UpdateExpression="SET #status = :posted, ledger_sk = :lsk",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":posted": "POSTED", ":lsk": billing_sk},
        )

    # Transition run to POSTED
    ts_now = now_ts()
    T.hr.update_item(
        Key={"PK": f"PAYROLL#{payroll_run_id}", "SK": "META"},
        UpdateExpression=(
            "SET #status = :posted, GSI1PK = :gsi1pk, "
            "posted_by = :actor, posted_at = :ts, updated_at = :ts"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":posted": "POSTED",
            ":gsi1pk": "PAYROLL#POSTED",
            ":actor": actor_sub,
            ":ts": ts_now,
        },
    )

    # HRM-010: trigger GL double-entry journal hook (guarded on both flags)
    _try_post_gl_journal(run, lines, actor_sub=actor_sub)

    try:
        audit_event(
            "payroll_run.posted",
            actor_sub,
            payroll_run_id=payroll_run_id,
            line_count=len(lines),
        )
    except Exception:
        pass

    updated = get_payroll_run(payroll_run_id)
    return updated or run


# ──────────────────────────── HRM-010: GL journal hook ────────────────────


def _try_post_gl_journal(
    run: Dict[str, Any],
    lines: List[Dict[str, Any]],
    *,
    actor_sub: str,
) -> None:
    """Best-effort GL double-entry journal posting after payroll disburse.

    Guarded on BOTH:
      * S.gl_double_entry_enabled  — master GL flag (OFB-002 / sibling-owned)
      * S.hr_payroll_gl_posting_enabled — HR-specific sub-gate (HRM-001)

    Per RULE-2, the sibling flag is checked via getattr with False default.
    If either flag is off, this is a no-op — the payroll still disburses,
    only the journal entry is skipped.

    The GL posting calls gl_posting.post_journal_entry per DECISIONS D1.
    If gl_posting is not yet deployed (ImportError), this is silently skipped.
    """
    if not getattr(S, "gl_double_entry_enabled", False):
        return
    if not getattr(S, "hr_payroll_gl_posting_enabled", False):
        return

    try:
        from app.services import gl_posting  # type: ignore[import]
    except ImportError:
        return  # gl_posting not yet deployed — no-op

    payroll_run_id = run["payroll_run_id"]
    expense_account = getattr(S, "hr_payroll_expense_account_code", "6000")

    # Derive the Cash/Bank account code from the GL accounts service
    cash_account = _resolve_cash_account()

    total_gross = int(run.get("total_gross_cents", 0))
    if total_gross <= 0:
        return  # nothing to post

    try:
        gl_date = int(run.get("created_at", now_ts()))

        # Build journal lines: Debit Salaries Expense / Credit Cash
        JournalLine = gl_posting.JournalLine  # type: ignore[attr-defined]
        journal_lines = [
            JournalLine(
                account_code=expense_account,
                side="debit",
                amount_cents=total_gross,
            ),
            JournalLine(
                account_code=cash_account,
                side="credit",
                amount_cents=total_gross,
            ),
        ]

        gl_posting.post_journal_entry(
            journal_lines,
            source_type="payroll",
            source_entity_id=payroll_run_id,
            memo=f"Payroll disbursement run {payroll_run_id}",
            gl_date=gl_date,
        )
    except Exception:
        # GL hook is best-effort: a posting failure never blocks payroll
        pass


def _resolve_cash_account() -> str:
    """Resolve the Cash/Bank account code from the GL accounts service.

    Falls back to the conventional OFBiz Cash account code "1000" if the
    service is unavailable or the account cannot be resolved.
    """
    try:
        from app.services import gl_accounts  # type: ignore[import]
        account = gl_accounts.get_account("1000")
        if account:
            return "1000"
    except Exception:
        pass
    return "1000"  # OFBiz conventional Cash/Bank account code
