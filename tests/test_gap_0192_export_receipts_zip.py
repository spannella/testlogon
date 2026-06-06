"""Regression test for GAP-0192 (FIN-004).

The FIN-004 spec requires ``GET /ui/tax-documents/receipts/zip`` to bundle a
user's individual receipt PDFs for a date range into a ZIP download. No such
service function or endpoint existed before this fix.

Fails-before: ``app.services.consumer_tax_documents.export_receipts_zip`` does
not exist (AttributeError / ImportError).
Passes-after: it returns a valid ZIP archive containing one ``receipt_<txn>.pdf``
per in-range transaction, scoped to the caller, with date-range filtering.

Fully offline AND hermetic: uses moto's in-process ``mock_aws`` for both
DynamoDB and S3 (no real AWS). Receipt PDFs are seeded directly into the mocked
S3 bucket and the file-manager node index so the export reads them back through
the same ``s3_client`` boto3 path used in dev (moto) and prod (real S3) —
SECOPS-007 dev/prod parity.

Test-isolation note (was GAP-0192's own bug): relying on global ``mock_aws``
interception is NOT enough. The app binds module-level handles at import time —
``app.core.tables.T`` (a frozen dataclass of boto3 ``Table`` proxies),
``app.services.filemanager.ddb`` (``from app.core.aws import ddb`` copies the
name into the module), and the module-level ``_s3`` clients in
``consumer_tax_documents`` / ``filemanager``. If ANY prior test file imports the
app first, those handles are created OUTSIDE an active ``mock_aws`` context and
moto can no longer intercept them, so DDB/S3 calls fall through to real AWS.
This test therefore monkeypatches the *exact* handles the code path uses (the
relevant ``T.*`` entries via ``object.__setattr__`` since ``T`` is frozen,
``filemanager.ddb``, and both ``_s3`` clients) onto moto-backed resources it
creates inside the active ``mock_aws`` context — never depending on global
interception.
"""
from __future__ import annotations

import io
import zipfile

import boto3
import pytest

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto must be installed for this test
    mock_aws = None

pytestmark = pytest.mark.skipif(mock_aws is None, reason="moto is not installed")

_REGION = "us-east-1"
_USER = "alice@test.local"
_BUCKET = "filemgr-test"
_FILEMGR_TABLE = "filemgr_nodes_test"
_TXN_TABLE = "purchase_transactions_test"

# Transactions seeded at these timestamps.
_T_EARLY = 1_700_000_000   # in-range "from"
_T_MID = 1_700_005_000     # in-range
_T_LATE = 1_700_100_000    # out-of-range (after date_to)


def _make_ddb():
    return boto3.resource("dynamodb", region_name=_REGION)


def _create_tables(ddb):
    ddb.create_table(
        TableName=_TXN_TABLE,
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ddb.create_table(
        TableName=_FILEMGR_TABLE,
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _seed_txn(ddb, *, txn_id: str, created_at: int) -> None:
    ddb.Table(_TXN_TABLE).put_item(
        Item={
            "user_sub": _USER,
            "sk": f"TXN#{created_at}#{txn_id}",
            "txn_id": txn_id,
            "buyer_id": _USER,
            "created_at": created_at,
            "updated_at": created_at,
            "status": "COMPLETED",
            "amount": "10.00",
            "currency": "usd",
            "version": 1,
        }
    )


def _seed_receipt(ddb, s3, fm, *, txn_id: str, pdf: bytes) -> None:
    """Upload a receipt PDF to S3 and register its file-manager node."""
    receipt_path = fm.norm_path(f"/billing/receipts/{txn_id}.pdf", is_folder=False)
    s3_key = f"{_USER}/objects/{txn_id}"
    s3.put_object(Bucket=_BUCKET, Key=s3_key, Body=pdf, ContentType="application/pdf")
    ddb.Table(_FILEMGR_TABLE).put_item(
        Item={
            "PK": fm.pk_user(_USER),
            "SK": fm.sk_node(receipt_path),
            "type": "file",
            "path": receipt_path,
            "name": f"{txn_id}.pdf",
            "content_type": "application/pdf",
            "s3_bucket": _BUCKET,
            "s3_key": s3_key,
        }
    )


def _wire(monkeypatch, request, ddb, s3):
    """Point every handle the export code path touches at the mocked AWS.

    HERMETIC: rather than relying on global ``mock_aws`` interception (which
    fails once any prior test file has imported the app and bound its handles
    outside a mock context), we monkeypatch the precise module-level names the
    code under test resolves at call time:

      - ``filemanager.ddb`` — ``filemanager`` does ``from app.core.aws import
        ddb``, copying the name into its own module namespace, so
        ``filemanager._table()`` reads ``filemanager.ddb`` (NOT
        ``app.core.aws.ddb``). This is the binding that must be swapped for
        ``fm.get_node`` to hit moto.
      - ``T.purchase_transactions`` and ``T.billing`` on the GLOBAL frozen
        ``app.core.tables.T`` — the service, ``purchase_history`` and
        ``receipts`` all import this same singleton, so the receipt-generation
        fallback (``get_or_create_receipt``) stays inside moto too. ``T`` is a
        frozen dataclass, so we assign via ``object.__setattr__`` and restore
        the originals afterwards.
      - ``consumer_tax_documents._s3`` and ``filemanager._s3`` — the
        module-level S3 clients bound at import time.
    """
    from app.core import tables as tables_mod
    from app.core.tables import _FloatSafeTable
    from app.services import consumer_tax_documents as svc
    from app.services import filemanager as fm

    object.__setattr__(svc.S, "dev_mode", True)
    object.__setattr__(fm.S, "filemgr_table_name", _FILEMGR_TABLE)
    object.__setattr__(fm.S, "filemgr_bucket", _BUCKET)

    # filemanager._table() reads the module-local ``ddb`` name (imported via
    # ``from app.core.aws import ddb``), so patch it there.
    monkeypatch.setattr(fm, "ddb", ddb, raising=False)

    # Both module-level S3 clients.
    monkeypatch.setattr(fm, "_s3", s3)
    monkeypatch.setattr(svc, "_s3", s3)

    # Swap the global frozen ``T`` entries the whole code path queries onto the
    # moto-backed tables (wrapped to preserve the float-safe write behaviour).
    # ``T`` is frozen → use object.__setattr__ and restore on teardown.
    T = tables_mod.T
    txn_table = _FloatSafeTable(ddb.Table(_TXN_TABLE))
    overrides = {"purchase_transactions": txn_table}
    saved = {name: getattr(T, name) for name in overrides}

    def _restore():
        for name, original in saved.items():
            object.__setattr__(T, name, original)

    for name, value in overrides.items():
        object.__setattr__(T, name, value)
    # Restore the frozen global T on teardown so we never leak moto tables into
    # other tests (they would be dead once mock_aws exits).
    request.addfinalizer(_restore)
    return svc


@mock_aws()
def test_export_receipts_zip_produces_valid_archive(monkeypatch, request):
    ddb = _make_ddb()
    s3 = boto3.client("s3", region_name=_REGION)
    _create_tables(ddb)
    s3.create_bucket(Bucket=_BUCKET)

    from app.services import filemanager as fm

    svc = _wire(monkeypatch, request, ddb, s3)

    # Two in-range transactions, one out-of-range (after date_to).
    for txn_id, ts in (("t1", _T_EARLY), ("t2", _T_MID), ("t3", _T_LATE)):
        _seed_txn(ddb, txn_id=txn_id, created_at=ts)
        _seed_receipt(ddb, s3, fm, txn_id=txn_id, pdf=f"%PDF-1.4 {txn_id}".encode())

    result = svc.export_receipts_zip(
        user_sub=_USER, date_from=_T_EARLY, date_to=_T_MID + 1
    )

    # Valid ZIP with exactly the in-range receipts (t3 filtered out).
    zf = zipfile.ZipFile(io.BytesIO(result))
    assert zf.testzip() is None
    names = set(zf.namelist())
    assert names == {"receipt_t1.pdf", "receipt_t2.pdf"}
    assert zf.read("receipt_t1.pdf") == b"%PDF-1.4 t1"
    assert zf.read("receipt_t2.pdf") == b"%PDF-1.4 t2"


@mock_aws()
def test_export_receipts_zip_empty_range_raises(monkeypatch, request):
    ddb = _make_ddb()
    s3 = boto3.client("s3", region_name=_REGION)
    _create_tables(ddb)
    s3.create_bucket(Bucket=_BUCKET)

    svc = _wire(monkeypatch, request, ddb, s3)

    with pytest.raises(ValueError, match="no_transactions"):
        svc.export_receipts_zip(user_sub=_USER, date_from=1, date_to=2)


@mock_aws()
def test_export_receipts_zip_too_many_raises(monkeypatch, request):
    ddb = _make_ddb()
    s3 = boto3.client("s3", region_name=_REGION)
    _create_tables(ddb)
    s3.create_bucket(Bucket=_BUCKET)

    svc = _wire(monkeypatch, request, ddb, s3)

    base = _T_EARLY
    for i in range(svc.MAX_ZIP_RECEIPTS + 1):
        _seed_txn(ddb, txn_id=f"x{i}", created_at=base + i)

    with pytest.raises(ValueError, match="too_many_transactions"):
        svc.export_receipts_zip(
            user_sub=_USER, date_from=base, date_to=base + svc.MAX_ZIP_RECEIPTS + 10
        )
