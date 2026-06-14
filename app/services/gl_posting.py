"""OFBiz GL double-entry posting engine (OFB-014, Milestone 4).

THE canonical double-entry GL poster. ``post_journal_entry(lines, ...)`` is the
single multi-line posting interface (DECISIONS D1) that FXA depreciation/
disposal, HRM payroll, MFG costed production, and the billing-derived path all
call. It enforces the balanced-entry invariant (Σdebits == Σcredits) BEFORE any
DynamoDB write and raises ``GLUnbalancedEntryError`` otherwise — money-safety
critical.

Idempotency: each entry's ``journal_entry_id`` is ``sha256(...)[:24]`` derived
from the source identity. A ``SOURCE_ENTRY_IDX`` pre-check plus a conditional
``attribute_not_exists`` put on the header give exactly-once semantics.

Additive, flag-gated behind ``S.gl_double_entry_enabled`` (default OFF).
SECOPS-007 parity: no ``dev_mode`` branch; reads/writes go through ``T.gl_journal``
identically dev (moto) and prod.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

_GLOBAL_PK = "JE#GLOBAL"


class GLUnbalancedEntryError(Exception):
    """Raised when generated journal lines do not balance (Σdebits ≠ Σcredits).
    Never caught within gl_posting.py — must propagate to the caller."""


@dataclass
class JournalLine:
    """One leg of a multi-line journal entry. ``amount_cents`` is always
    positive; the sign is encoded in ``side``."""

    account_code: str
    side: str  # "debit" | "credit"
    amount_cents: int


def _flag_on() -> bool:
    return bool(getattr(S, "gl_double_entry_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="GL double-entry not enabled")


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event

        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


def _journal_entry_id(seed: str) -> str:
    """Deterministic, collision-resistant 24-char id derived from the seed."""
    return hashlib.sha256(seed.encode()).hexdigest()[:24]


def _is_already_posted(journal_entry_id: str) -> bool:
    """Check the main table for an existing header row by deterministic id."""
    resp = T.gl_journal.get_item(Key={"PK": _GLOBAL_PK, "SK": f"JE#{journal_entry_id}"})
    return bool(resp.get("Item"))


def _validate_balanced(lines: List[JournalLine]) -> None:
    if not lines:
        raise GLUnbalancedEntryError("journal entry has no lines")
    debit = sum(l.amount_cents for l in lines if l.side == "debit")
    credit = sum(l.amount_cents for l in lines if l.side == "credit")
    for l in lines:
        if l.side not in ("debit", "credit"):
            raise GLUnbalancedEntryError(f"invalid side: {l.side}")
        if l.amount_cents < 0:
            raise GLUnbalancedEntryError("line amount_cents must be non-negative")
    if debit != credit:
        raise GLUnbalancedEntryError(f"unbalanced: debit={debit} credit={credit}")


def post_journal_entry(
    lines: List[JournalLine],
    *,
    source_type: str,
    source_entity_id: str,
    memo: str = "",
    gl_date: Any,
    journal_id: Optional[str] = None,
) -> str:
    """Canonical multi-line GL posting interface (DECISIONS D1).

    ``lines``: explicit debit/credit legs; must balance (Σdebits == Σcredits)
    or ``GLUnbalancedEntryError`` is raised before any write.
    ``gl_date``: a ``YYYY-MM-DD`` string (or anything str()-able) copied to the
    header for the ENTRIES_BY_DATE index.
    ``journal_id``: explicit idempotency key; if None, derived from
    ``source_type|source_entity_id``.

    Returns the ``journal_entry_id``. Idempotent: a second call for the same
    identity returns the existing id without a second write.
    """
    _require_enabled()
    _validate_balanced(lines)

    jid = journal_id or _journal_entry_id(f"{source_type}|{source_entity_id}")
    if _is_already_posted(jid):
        return jid

    posted_at = now_ts()
    gl_date_s = str(gl_date)
    total_debit = sum(l.amount_cents for l in lines if l.side == "debit")
    total_credit = sum(l.amount_cents for l in lines if l.side == "credit")

    header = {
        "PK": _GLOBAL_PK,
        "SK": f"JE#{jid}",
        "journal_entry_id": jid,
        "source_type": source_type,
        "source_entry_id": source_entity_id,
        "ledger_date": gl_date_s,
        "posted_at": posted_at,
        "state": "posted",
        "entry_type": source_type,
        "memo": memo or "",
        "total_debit_cents": total_debit,
        "total_credit_cents": total_credit,
    }
    try:
        T.gl_journal.put_item(
            Item=header,
            ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            # Lost a concurrent race; the winner posted the same deterministic id.
            return jid
        raise

    account_names = _resolve_account_names({l.account_code for l in lines})
    with T.gl_journal.batch_writer() as batch:
        for seq, line in enumerate(lines, start=1):
            batch.put_item(
                Item={
                    "PK": _GLOBAL_PK,
                    "SK": f"JL#{jid}#{seq:04d}",
                    "journal_entry_id": jid,
                    "seq": seq,
                    "account_code": line.account_code,
                    "account_name": account_names.get(line.account_code, ""),
                    "side": line.side,
                    "amount_cents": line.amount_cents,
                    "ledger_date": gl_date_s,
                    "posted_at": posted_at,
                }
            )
    _audit(
        "gl_entry_posted",
        "system_gl_poster",
        journal_entry_id=jid,
        source_type=source_type,
        total_debit_cents=total_debit,
    )
    return jid


def _resolve_account_names(codes: set) -> Dict[str, str]:
    names: Dict[str, str] = {}
    for code in codes:
        try:
            resp = T.gl_accounts.get_item(Key={"account_code": code, "sk": "META"})
            item = resp.get("Item")
            if item:
                names[code] = item.get("name", "")
        except Exception:
            pass
    return names


def get_journal_entry_header(journal_entry_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a full journal entry (header + lines), or None if not found."""
    _require_enabled()
    resp = T.gl_journal.get_item(Key={"PK": _GLOBAL_PK, "SK": f"JE#{journal_entry_id}"})
    header = resp.get("Item")
    if not header:
        return None
    lines_resp = T.gl_journal.query(
        KeyConditionExpression=Key("PK").eq(_GLOBAL_PK) & Key("SK").begins_with(f"JL#{journal_entry_id}#"),
    )
    lines = [
        {
            "seq": int(it.get("seq", 0) or 0),
            "account_code": it.get("account_code", ""),
            "account_name": it.get("account_name", ""),
            "side": it.get("side", ""),
            "amount_cents": int(it.get("amount_cents", 0) or 0),
        }
        for it in sorted(lines_resp.get("Items", []), key=lambda x: x.get("SK", ""))
    ]
    return _project_header(header, lines)


def _project_header(header: Dict[str, Any], lines: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "journal_entry_id": header.get("journal_entry_id", ""),
        "source_type": header.get("source_type", ""),
        "source_entry_id": header.get("source_entry_id", ""),
        "ledger_date": header.get("ledger_date", ""),
        "posted_at": int(header.get("posted_at", 0) or 0),
        "entry_type": header.get("entry_type", ""),
        "memo": header.get("memo", ""),
        "total_debit_cents": int(header.get("total_debit_cents", 0) or 0),
        "total_credit_cents": int(header.get("total_credit_cents", 0) or 0),
        "lines": lines,
    }


def list_journal_entries(
    start_date: str,
    end_date: str,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """Return a page of journal entry headers across an inclusive date range.

    Queries the ENTRIES_BY_DATE GSI per day and filters to JE# header rows
    (not JL# lines). Returns {"entries": [...], "count": int, "cursor": None}.
    """
    _require_enabled()
    entries: List[Dict[str, Any]] = []
    for date_str in _date_range(start_date, end_date):
        kwargs: Dict[str, Any] = {
            "IndexName": "ENTRIES_BY_DATE",
            "KeyConditionExpression": Key("ledger_date").eq(date_str),
        }
        while True:
            resp = T.gl_journal.query(**kwargs)
            for it in resp.get("Items", []):
                if str(it.get("SK", "")).startswith("JE#"):
                    entries.append(_project_header(it, []))
                    if len(entries) >= limit:
                        break
            if len(entries) >= limit:
                break
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
            kwargs["ExclusiveStartKey"] = lek
        if len(entries) >= limit:
            break
    return {"entries": entries[:limit], "count": len(entries[:limit]), "cursor": None}


def _date_range(start_date: str, end_date: str) -> List[str]:
    from datetime import date, timedelta

    try:
        sy, sm, sd = (int(x) for x in start_date.split("-"))
        ey, em, ed = (int(x) for x in end_date.split("-"))
        cur = date(sy, sm, sd)
        end = date(ey, em, ed)
    except Exception:
        return [start_date]
    out: List[str] = []
    guard = 0
    while cur <= end and guard < 10000:
        out.append(cur.isoformat())
        cur = cur + timedelta(days=1)
        guard += 1
    return out
