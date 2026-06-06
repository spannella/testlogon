"""Accounting-software column mapping for billing audit exports (GAP-0211 / FIN-016).

Finance teams import billing CSVs into accounting packages (QuickBooks, Xero).
Those wizards expect a fixed, package-specific column schema — not the generic
15-column security/compliance audit schema (``CSV_COLUMNS`` in
``audit_export_pipeline``).  This module supplies the mapped column lists and the
pure row-mapper functions that turn a :class:`UnifiedAuditEvent` (a billing
ledger row, surfaced via the ``BillingLedgerAdapter``) into a row matching the
target package's import format.

These are pure functions — no AWS calls, no environment branching — so dev (moto)
and prod (real S3) render byte-identical accounting CSVs (SECOPS-007 parity).
"""
from __future__ import annotations

from datetime import datetime, timezone

from app.services.audit_export import UnifiedAuditEvent

# Valid values for the request-level ``column_format`` parameter.  ``None`` (or a
# missing key) means "use the generic audit schema" — fully backward-compatible.
VALID_COLUMN_FORMATS = {None, "quickbooks", "xero"}

# QuickBooks Online CSV import (3-column "Bank"/Journal style uses Date/Desc, but
# the General-Journal import wizard expects Debit/Credit split columns).
QUICKBOOKS_COLUMNS = [
    "Date", "Transaction Type", "Num", "Name", "Memo",
    "Account", "Debit", "Credit",
]

# Xero bank-statement / manual-journal CSV import schema.
XERO_COLUMNS = [
    "Date", "Amount", "Payee", "Description", "Reference",
    "Cheque Number", "Account Code", "Tax Rate",
]


def _qb_transaction_type(entry_type: str, ledger_type: str) -> str:
    """Map a billing ledger entry to a QuickBooks transaction type.

    ``entry_type`` is the event's logical action (``UnifiedAuditEvent.event_action``
    or an explicit ``entry_type`` metadata value, e.g. ``tip_debit`` or
    ``debit_tip``); ``ledger_type`` is the raw ``debit``/``credit`` direction from
    the billing ledger row.  Exact ``entry_type`` matches win; otherwise the
    direction decides (debits = Sales Receipt revenue, credits = Deposit).
    """
    mapping = {
        "tip_debit": "Sales Receipt",
        "tip_credit": "Deposit",
        "unlock_debit": "Sales Receipt",
        "unlock_credit": "Deposit",
        "subscription_charge": "Invoice",
        "payout": "Check",
        "deposit": "Deposit",
        "refund": "Refund Receipt",
        "chargeback": "Journal Entry",
    }
    if entry_type in mapping:
        return mapping[entry_type]
    direction = (ledger_type or "").lower()
    if "debit" in direction or "debit" in entry_type.lower():
        return "Sales Receipt"
    if "credit" in direction or "credit" in entry_type.lower():
        return "Deposit"
    return "Journal Entry"


def _amount_cents(event: UnifiedAuditEvent) -> int:
    meta = event.metadata or {}
    raw = meta.get("amount_cents", 0)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def _entry_type(event: UnifiedAuditEvent) -> str:
    """Logical entry type: explicit ``entry_type`` metadata, else ``event_action``."""
    meta = event.metadata or {}
    return str(meta.get("entry_type") or event.event_action or "")


def _ledger_type(event: UnifiedAuditEvent) -> str:
    """Raw debit/credit direction from the billing ledger row (metadata ``type``)."""
    meta = event.metadata or {}
    return str(meta.get("type") or "")


def _description(event: UnifiedAuditEvent) -> str:
    """Human description: ``description``/``reason`` metadata, else the entry type."""
    meta = event.metadata or {}
    return str(meta.get("description") or meta.get("reason") or _entry_type(event))


def _is_debit(event: UnifiedAuditEvent) -> bool:
    entry_type = _entry_type(event)
    ledger_type = _ledger_type(event)
    return (
        "debit" in entry_type.lower()
        or "debit" in ledger_type.lower()
        or _amount_cents(event) < 0
    )


def billing_event_to_quickbooks_row(event: UnifiedAuditEvent) -> list[str]:
    """Render a billing ledger event as a QuickBooks CSV import row."""
    meta = event.metadata or {}
    entry_type = _entry_type(event)
    amount_dollars = abs(_amount_cents(event)) / 100
    amount_str = f"{amount_dollars:.2f}"
    is_debit = _is_debit(event)
    return [
        datetime.fromtimestamp(int(event.timestamp_unix), tz=timezone.utc).strftime("%m/%d/%Y"),
        _qb_transaction_type(entry_type, _ledger_type(event)),
        (event.event_id or "")[:8],
        str(meta.get("user_name") or event.actor_user_id or ""),
        _description(event),
        "Platform Revenue",
        amount_str if is_debit else "",
        amount_str if not is_debit else "",
    ]


def billing_event_to_xero_row(event: UnifiedAuditEvent) -> list[str]:
    """Render a billing ledger event as a Xero CSV import row."""
    meta = event.metadata or {}
    amount_cents = _amount_cents(event)
    return [
        datetime.fromtimestamp(int(event.timestamp_unix), tz=timezone.utc).strftime("%d %b %Y"),
        f"{abs(amount_cents) / 100:.2f}",
        str(meta.get("user_name") or event.actor_user_id or ""),
        _description(event),
        (event.event_id or "")[:16],
        "",          # Cheque Number — not applicable to platform ledger
        "200",       # default sales account code
        "Tax Exempt (0%)",
    ]


def accounting_columns(column_format: str) -> list[str]:
    """Return the column header list for the given accounting format."""
    return QUICKBOOKS_COLUMNS if column_format == "quickbooks" else XERO_COLUMNS


def accounting_row_mapper(column_format: str):
    """Return the row-mapper callable for the given accounting format."""
    return (
        billing_event_to_quickbooks_row
        if column_format == "quickbooks"
        else billing_event_to_xero_row
    )


def is_accounting_export(column_format, categories) -> bool:
    """True when an accounting column mapping should be applied.

    The mapping only applies to CSV billing exports with a recognised
    accounting ``column_format``.  All other combinations fall back to the
    generic audit schema (backward-compatible).
    """
    return (
        column_format in ("quickbooks", "xero")
        and "billing" in (categories or [])
    )
