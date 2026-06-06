"""Regression test for GAP-0211 (FIN-016): accounting-software column mapping.

The audit/financial export pipeline historically emitted a single fixed CSV
schema — 15 generic audit columns (``event_id``, ``actor_user_id``, ...). Finance
teams importing into QuickBooks or Xero need a package-specific column schema
(``Date``, ``Transaction Type``, ``Debit``, ``Credit`` ... for QuickBooks).

Fails-before: no ``column_format`` parameter exists; a CSV billing export always
emits generic columns (``event_id`` in the header) no matter what is requested.
Passes-after: ``create_export_job(..., column_format="quickbooks")`` renders a
QuickBooks header (``Date``/``Transaction Type``/``Debit``/``Credit``) with NO
generic ``event_id`` column; ``"xero"`` renders the Xero schema; an omitted
``column_format`` keeps the generic schema (backward-compatible).

Test isolation (per tests/test_gap_0192_export_receipts_zip.py): we do NOT rely
on global ``mock_aws`` interception (it leaks to real AWS once the app binds its
boto3 handles outside a mock context). The pipeline's dev path touches exactly
two module-level handles — ``T.audit_exports`` (job storage) and ``T.billing``
(the ``BillingLedgerAdapter`` source). Both are entries on the frozen singleton
``app.core.tables.T``; we swap them via ``object.__setattr__`` onto moto-backed
tables created inside the active ``mock_aws`` context and restore them on
teardown. ``S`` is frozen → ``object.__setattr__`` for ``dev_mode``. No real AWS,
no TestClient (the pipeline function is called directly).
"""
from __future__ import annotations

import boto3
import pytest

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto must be installed for this test
    mock_aws = None

pytestmark = pytest.mark.skipif(mock_aws is None, reason="moto is not installed")

_REGION = "us-east-1"
_AUDIT_TABLE = "audit_exports_test_0211"
_BILLING_TABLE = "billing_test_0211"
_USER = "alice@test.local"

# Ledger rows seeded inside this window.
_FROM = 1_700_000_000
_TO = 1_700_100_000


def _create_tables(ddb):
    ddb.create_table(
        TableName=_AUDIT_TABLE,
        KeySchema=[
            {"AttributeName": "export_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "export_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ddb.create_table(
        TableName=_BILLING_TABLE,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _seed_ledger(ddb, *, ledger_id: str, created_at: int, type_: str,
                 amount_cents: int, reason: str) -> None:
    ddb.Table(_BILLING_TABLE).put_item(
        Item={
            "pk": f"USER#{_USER}",
            "sk": f"LEDGER#{created_at}#{ledger_id}",
            "ledger_id": ledger_id,
            "type": type_,
            "amount_cents": amount_cents,
            "reason": reason,
            "currency": "usd",
            "created_at": created_at,
        }
    )


def _wire(monkeypatch, request, ddb):
    """Point the pipeline's exact handles at moto-backed tables (hermetic)."""
    from app.core import tables as tables_mod
    from app.core.tables import _FloatSafeTable
    from app.services import audit_export_pipeline as pipe

    # Force the inline dev path (no S3) — S is frozen.
    object.__setattr__(pipe.S, "dev_mode", True)

    T = tables_mod.T
    overrides = {
        "audit_exports": _FloatSafeTable(ddb.Table(_AUDIT_TABLE)),
        "billing": _FloatSafeTable(ddb.Table(_BILLING_TABLE)),
    }
    saved = {name: getattr(T, name) for name in overrides}

    def _restore():
        for name, original in saved.items():
            object.__setattr__(T, name, original)

    for name, value in overrides.items():
        object.__setattr__(T, name, value)
    request.addfinalizer(_restore)


def _run_export(column_format):
    from app.services.audit_export_pipeline import create_export_job

    job = create_export_job(
        categories=["billing"],
        format="csv",
        from_ts=_FROM,
        to_ts=_TO,
        created_by="root_user",
        column_format=column_format,
    )
    content = job.get("export_content", "")
    # Strip the UTF-8 BOM and read the header line.
    header = content.lstrip("﻿").split("\r\n")[0]
    return job, content, header


@mock_aws()
def test_quickbooks_column_mapping(monkeypatch, request):
    ddb = boto3.resource("dynamodb", region_name=_REGION)
    _create_tables(ddb)
    _wire(monkeypatch, request, ddb)

    # A debit (revenue) and a credit (payout) row.
    _seed_ledger(ddb, ledger_id="l1", created_at=_FROM + 10,
                 type_="debit", amount_cents=500, reason="tip")
    _seed_ledger(ddb, ledger_id="l2", created_at=_FROM + 20,
                 type_="credit", amount_cents=1200, reason="payout")

    job, content, header = _run_export("quickbooks")

    assert job["status"] == "completed"
    # QuickBooks header present.
    assert "Date" in header
    assert "Transaction Type" in header
    assert "Debit" in header
    assert "Credit" in header
    # The generic audit schema MUST NOT leak through.
    assert "event_id" not in header
    assert "actor_user_id" not in header
    # column_format persisted on the job item.
    assert job.get("column_format") == "quickbooks"

    # The debit row's amount lands in the Debit column ($5.00), Credit empty.
    rows = content.lstrip("﻿").split("\r\n")
    data_rows = [r for r in rows[1:] if r.strip()]
    assert len(data_rows) == 2
    debit_row = data_rows[0].split(",")
    assert debit_row[6] == "5.00"   # Debit
    assert debit_row[7] == ""       # Credit


@mock_aws()
def test_xero_column_mapping(monkeypatch, request):
    ddb = boto3.resource("dynamodb", region_name=_REGION)
    _create_tables(ddb)
    _wire(monkeypatch, request, ddb)

    _seed_ledger(ddb, ledger_id="l1", created_at=_FROM + 10,
                 type_="debit", amount_cents=750, reason="unlock")

    job, content, header = _run_export("xero")

    assert "Amount" in header
    assert "Account Code" in header
    assert "Tax Rate" in header
    assert "event_id" not in header

    data_rows = [r for r in content.lstrip("﻿").split("\r\n")[1:] if r.strip()]
    assert len(data_rows) == 1
    assert data_rows[0].split(",")[1] == "7.50"   # Amount column


@mock_aws()
def test_omitted_column_format_keeps_generic_schema(monkeypatch, request):
    """Backward-compat: no column_format -> generic audit columns."""
    ddb = boto3.resource("dynamodb", region_name=_REGION)
    _create_tables(ddb)
    _wire(monkeypatch, request, ddb)

    _seed_ledger(ddb, ledger_id="l1", created_at=_FROM + 10,
                 type_="debit", amount_cents=500, reason="tip")

    job, content, header = _run_export(None)

    # Generic schema preserved.
    assert "event_id" in header
    assert "Transaction Type" not in header


def test_pure_mapper_functions():
    """Unit-level: pure row mappers (no AWS) per the GAP-0211 writeup."""
    from app.services.audit_export import UnifiedAuditEvent
    from app.services.audit_export_accounting import (
        QUICKBOOKS_COLUMNS,
        billing_event_to_quickbooks_row,
        billing_event_to_xero_row,
    )

    assert "Date" in QUICKBOOKS_COLUMNS
    assert "Transaction Type" in QUICKBOOKS_COLUMNS
    assert "Debit" in QUICKBOOKS_COLUMNS

    event = UnifiedAuditEvent(
        event_id="evt_abc123",
        event_type="billing",
        event_action="tip_debit",
        timestamp="2026-01-15T12:00:00Z",
        timestamp_unix=1737043200,
        actor_user_id="user_alice",
        actor_role="user",
        metadata={"amount_cents": 500, "entry_type": "tip_debit"},
        source_table="billing",
    )
    qb = billing_event_to_quickbooks_row(event)
    assert qb[1] == "Sales Receipt"   # Transaction Type
    assert qb[6] == "5.00"            # Debit
    assert qb[7] == ""               # Credit empty

    xero = billing_event_to_xero_row(event)
    assert xero[1] == "5.00"          # Amount
    assert xero[3] == "tip_debit"     # Description (falls back to entry_type)
