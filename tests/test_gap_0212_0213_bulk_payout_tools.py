"""Offline regression tests for GAP-0212 and GAP-0213 (FIN-017).

Both gaps live in the bulk payout/refund tooling
(``app/services/bulk_payout_tools.py`` + ``app/routers/bulk_payout_tools.py``):

GAP-0212 — No undo window. After ``execute_batch`` a batch transitioned to
``completed``/``completed_with_errors`` and could never be reversed: no
``undo_expires_at`` was stored, ``BulkBatchOut`` had no such field, and no undo
endpoint/service existed. The fix stores a 5-minute reversal window, adds
``undo_batch`` (reverses each successful item via a per-kind reversal), and a
``POST /batches/{batch_id}/undo`` route. Reversal of a *completed* payout /
*approved* refund needs an explicit terminal transition + ledger compensation
because the single-item ``reject_*`` primitives only act on pending items.

GAP-0213 — No CSV import endpoint. ``parse_payout_csv`` (pure function) +
``POST /import-csv`` (multipart) were missing; Finance teams had no bulk
ingestion path. The parser validates the header, drops injection/garbage rows
(``_REF_ID_PATTERN``), dedupes, and enforces a 500-row / 5 MB cap.

TEST ISOLATION (critical): we do NOT rely on global moto interception leaking to
real AWS. moto tables are created in an explicit ``mock_aws`` context, and the
*exact* frozen ``T`` table handles used by the service (and the
``creator_payouts`` / ``refund_requests`` / ``billing_shared`` services it reuses)
are swapped via ``object.__setattr__`` and restored afterwards. ``S`` is frozen,
so ``dev_mode`` is toggled the same way. The async router handler is invoked via a
FRESH ``asyncio.new_event_loop()`` (never ``get_event_loop()``), and the FastAPI
TestClient is not used (it is unusable in this repo).

Each test seeds enough state that the *old* code produced a wrong answer (or
raised) and the *new* code is correct.
"""
from __future__ import annotations

import asyncio
import io
import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_tables(ddb):
    """Create the four tables the bulk service + its reused services touch."""
    batches = ddb.create_table(
        TableName="BulkPayoutBatches",
        KeySchema=[{"AttributeName": "batch_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "batch_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    payouts = ddb.create_table(
        TableName="CreatorPayouts",
        KeySchema=[{"AttributeName": "payout_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "payout_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    refunds = ddb.create_table(
        TableName="RefundRequests",
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
    billing = ddb.create_table(
        TableName="Billing",
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
    return batches, payouts, refunds, billing


@unittest.skipIf(mock_aws is None, "moto is not installed")
class _BulkBase(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.batches, self.payouts, self.refunds, self.billing = _make_tables(ddb)

        from app.core.tables import T
        from app.core.settings import S

        self.T = T
        self.S = S

        # Swap the exact frozen-dataclass handles, restore on cleanup.
        self._patch_attr(T, "bulk_payout_batches", self.batches)
        self._patch_attr(T, "creator_payouts", self.payouts)
        self._patch_attr(T, "refund_requests", self.refunds)
        self._patch_attr(T, "billing", self.billing)
        # complete_payout auto-advances approved -> completed only in dev mode.
        self._patch_attr(S, "dev_mode", True)

    def _patch_attr(self, obj, name, value):
        had = name in obj.__dict__
        old = getattr(obj, name, None)
        object.__setattr__(obj, name, value)

        def _restore():
            if had:
                object.__setattr__(obj, name, old)
            else:  # pragma: no cover - all targets pre-exist on frozen instances
                object.__delattr__(obj, name)

        self.addCleanup(_restore)

    # -- seeding helpers -----------------------------------------------------

    def _seed_payout(self, payout_id, *, amount=5000, user="creator_1", status="requested"):
        self.payouts.put_item(
            Item={
                "payout_id": payout_id,
                "user_id": user,
                "amount_cents": amount,
                "status": status,
                "created_at": 1_700_000_000,
                "method": "bank_transfer",
            }
        )

    def _seed_refund(self, request_id, *, amount=5000, user="buyer_1", status="pending"):
        self.refunds.put_item(
            Item={
                "pk": f"REFUND#{request_id}",
                "sk": "META",
                "refund_request_id": request_id,
                "requester_user_id": user,
                "amount_cents": amount,
                "currency": "usd",
                "status": status,
                "created_at": 1_700_000_000,
            }
        )

    def _payments_settled(self, user):
        """approve_request credits a buyer via ``payments_settled_cents -= amount``."""
        item = self.billing.get_item(
            Key={"pk": f"USER#{user}", "sk": "BALANCE"}
        ).get("Item")
        return int(item.get("payments_settled_cents", 0)) if item else 0


class TestUndoWindowGap0212(_BulkBase):
    def test_execute_sets_undo_expires_at(self):
        """GAP-0212: execute_batch response carries undo_expires_at ~5 min out.

        FAILS BEFORE FIX: the persisted item + BulkBatchOut had no
        ``undo_expires_at`` key (KeyError / missing field).
        """
        from app.services.bulk_payout_tools import execute_batch, UNDO_WINDOW_SECONDS
        from app.core.time import now_ts

        self._seed_payout("po_undowindow01")
        out = execute_batch("admin_root", kind="payout", ref_ids=["po_undowindow01"])

        self.assertEqual(out["status"], "completed")
        self.assertIsNotNone(out["undo_expires_at"])
        self.assertLessEqual(out["undo_expires_at"], now_ts() + UNDO_WINDOW_SECONDS + 2)
        self.assertGreaterEqual(out["undo_expires_at"], now_ts() + UNDO_WINDOW_SECONDS - 5)

    def test_preview_has_no_undo_window(self):
        """A preview (dry-run) batch must not open an undo window."""
        from app.services.bulk_payout_tools import preview_batch

        self._seed_payout("po_prev01")
        out = preview_batch("admin_root", "payout", ["po_prev01"])
        self.assertEqual(out["status"], "preview")
        self.assertIsNone(out["undo_expires_at"])

    def test_undo_payout_batch_within_window(self):
        """GAP-0212: undo reverses a completed payout batch in-window.

        FAILS BEFORE FIX: ``undo_batch`` did not exist.
        """
        from app.services.bulk_payout_tools import execute_batch, undo_batch

        self._seed_payout("po_undo01")
        execute_batch("admin_root", kind="payout", ref_ids=["po_undo01"])
        # Sanity: execute drove it to completed.
        self.assertEqual(
            self.payouts.get_item(Key={"payout_id": "po_undo01"})["Item"]["status"],
            "completed",
        )
        batch_id = self.batches.scan()["Items"][0]["batch_id"]

        result = undo_batch(batch_id, "admin_root")

        self.assertEqual(result["status"], "undone")
        self.assertIsNotNone(result["undo_performed_at"])
        self.assertIsNone(result["undo_expires_at"])
        undone = [i for i in result["items"] if i["status"] == "undone"]
        self.assertEqual(len(undone), 1)
        # The underlying payout was actually reversed.
        self.assertEqual(
            self.payouts.get_item(Key={"payout_id": "po_undo01"})["Item"]["status"],
            "reversed",
        )

    def test_undo_refund_batch_reverses_credit(self):
        """GAP-0212: undo of a refund batch reverses the buyer wallet credit."""
        from app.services.bulk_payout_tools import execute_batch, undo_batch

        self._seed_refund("rr_undo01", amount=5000, user="buyer_x")
        execute_batch("admin_root", kind="refund", ref_ids=["rr_undo01"])
        # approve_request credited the buyer (payments_settled_cents -= amount).
        self.assertEqual(self._payments_settled("buyer_x"), -5000)
        batch_id = self.batches.scan()["Items"][0]["batch_id"]

        result = undo_batch(batch_id, "admin_root")

        self.assertEqual(result["status"], "undone")
        # Credit reversed back to zero.
        self.assertEqual(self._payments_settled("buyer_x"), 0)
        self.assertEqual(
            self.refunds.get_item(Key={"pk": "REFUND#rr_undo01", "sk": "META"})["Item"][
                "status"
            ],
            "reversed",
        )

    def test_undo_expired_window_rejected(self):
        """GAP-0212: undo past the window raises ValueError."""
        from app.services.bulk_payout_tools import undo_batch
        from app.core.time import now_ts

        self.batches.put_item(
            Item={
                "batch_id": "bpb_expired",
                "created_at": now_ts() - 1000,
                "created_by": "admin_root",
                "kind": "payout",
                "status": "completed",
                "item_count": 1,
                "success_count": 1,
                "failure_count": 0,
                "total_cents": 100,
                "items": [{"ref_id": "po_x", "amount_cents": 100, "status": "success"}],
                "undo_expires_at": now_ts() - 1,  # already past
            }
        )
        with self.assertRaisesRegex(ValueError, "undo window has expired"):
            undo_batch("bpb_expired", "admin_root")

    def test_double_undo_rejected(self):
        """GAP-0212: a batch already undone cannot be undone again."""
        from app.services.bulk_payout_tools import execute_batch, undo_batch

        self._seed_payout("po_double01")
        execute_batch("admin_root", kind="payout", ref_ids=["po_double01"])
        batch_id = self.batches.scan()["Items"][0]["batch_id"]
        undo_batch(batch_id, "admin_root")

        with self.assertRaisesRegex(ValueError, "already been undone"):
            undo_batch(batch_id, "admin_root")

    def test_undo_unknown_batch_rejected(self):
        from app.services.bulk_payout_tools import undo_batch

        with self.assertRaisesRegex(ValueError, "batch not found"):
            undo_batch("bpb_nope", "admin_root")

    def test_undo_preview_batch_rejected(self):
        """A preview batch is not in a completed state — cannot be undone."""
        from app.services.bulk_payout_tools import preview_batch, undo_batch

        self._seed_payout("po_prevundo")
        out = preview_batch("admin_root", "payout", ["po_prevundo"])
        with self.assertRaisesRegex(ValueError, "not in a completed state"):
            undo_batch(out["batch_id"], "admin_root")


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestParsePayoutCsvGap0213(unittest.TestCase):
    @staticmethod
    def _csv(rows, fieldnames=("ref_id", "amount_cents")):
        import csv

        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(fieldnames))
        writer.writeheader()
        writer.writerows(rows)
        return buf.getvalue().encode("utf-8")

    def test_parse_valid(self):
        """GAP-0213: parse_payout_csv exists and returns the ref_ids.

        FAILS BEFORE FIX: parse_payout_csv / CsvImportError did not exist.
        """
        from app.services.bulk_payout_tools import parse_payout_csv

        data = self._csv([{"ref_id": "po_abc123", "amount_cents": 5000}])
        self.assertEqual(parse_payout_csv(data, "payout"), ["po_abc123"])

    def test_missing_ref_id_column(self):
        from app.services.bulk_payout_tools import parse_payout_csv, CsvImportError

        with self.assertRaisesRegex(CsvImportError, "ref_id"):
            parse_payout_csv(b"amount_cents\n5000\n", "payout")

    def test_too_many_rows(self):
        from app.services.bulk_payout_tools import parse_payout_csv, CsvImportError, _CSV_MAX_ROWS

        rows = [{"ref_id": f"po_{i:06d}", "amount_cents": 100} for i in range(_CSV_MAX_ROWS + 1)]
        with self.assertRaisesRegex(CsvImportError, "exceeds maximum"):
            parse_payout_csv(self._csv(rows), "payout")

    def test_injection_rows_dropped(self):
        """CSV-injection / formula payloads never reach the execute path."""
        from app.services.bulk_payout_tools import parse_payout_csv

        data = self._csv([
            {"ref_id": "valid_id_001", "amount_cents": 100},
            {"ref_id": '=HYPERLINK("evil")', "amount_cents": 100},
            {"ref_id": "+SUM(1+1)", "amount_cents": 100},
        ])
        self.assertEqual(parse_payout_csv(data, "payout"), ["valid_id_001"])

    def test_dedup(self):
        from app.services.bulk_payout_tools import parse_payout_csv

        data = self._csv([
            {"ref_id": "dup_id_aa", "amount_cents": 100},
            {"ref_id": "dup_id_aa", "amount_cents": 200},
        ])
        self.assertEqual(parse_payout_csv(data, "payout"), ["dup_id_aa"])

    def test_bom_tolerated(self):
        """Excel UTF-8-BOM exports must parse."""
        from app.services.bulk_payout_tools import parse_payout_csv

        data = b"\xef\xbb\xbfref_id,amount_cents\r\npo_bom_001,100\r\n"
        self.assertEqual(parse_payout_csv(data, "payout"), ["po_bom_001"])

    def test_invalid_kind(self):
        from app.services.bulk_payout_tools import parse_payout_csv

        with self.assertRaises(ValueError):
            parse_payout_csv(self._csv([{"ref_id": "po_aaaaaa", "amount_cents": 1}]), "bogus")

    def test_no_valid_rows(self):
        from app.services.bulk_payout_tools import parse_payout_csv, CsvImportError

        data = self._csv([{"ref_id": "=bad", "amount_cents": 1}])
        with self.assertRaisesRegex(CsvImportError, "no valid ref_id"):
            parse_payout_csv(data, "payout")


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestImportCsvEndpointGap0213(_BulkBase):
    """Exercise the async router handler directly (no TestClient)."""

    @staticmethod
    def _upload(content: bytes, *, content_type="text/csv", filename="batch.csv"):
        from starlette.datastructures import Headers, UploadFile

        headers = Headers({"content-type": content_type})
        return UploadFile(file=io.BytesIO(content), filename=filename, headers=headers)

    def _call(self, **kwargs):
        from app.routers.bulk_payout_tools import bulk_import_csv

        class _Admin:
            sub = "admin_root"

        loop = asyncio.new_event_loop()
        try:
            with patch("app.routers.bulk_payout_tools.audit_event"):
                return loop.run_until_complete(
                    bulk_import_csv(request=object(), _admin=_Admin(), **kwargs)
                )
        finally:
            loop.close()

    def test_import_csv_dry_run_previews(self):
        """GAP-0213: POST /import-csv with dry_run previews the parsed batch.

        FAILS BEFORE FIX: no import-csv route/handler existed.
        """
        self._seed_payout("po_import01", amount=4200)
        csv_bytes = b"ref_id,amount_cents\npo_import01,4200\n"
        out = self._call(file=self._upload(csv_bytes), kind="payout", dry_run=True)

        self.assertEqual(out["status"], "preview")
        self.assertEqual(out["item_count"], 1)
        self.assertEqual(out["items"][0]["ref_id"], "po_import01")
        self.assertEqual(out["items"][0]["status"], "pending")
        # dry_run must not touch the payout.
        self.assertEqual(
            self.payouts.get_item(Key={"payout_id": "po_import01"})["Item"]["status"],
            "requested",
        )

    def test_import_csv_executes(self):
        """Non-dry-run import executes the batch via the existing path."""
        self._seed_payout("po_import02", amount=999)
        csv_bytes = b"ref_id,amount_cents\npo_import02,999\n"
        out = self._call(file=self._upload(csv_bytes), kind="payout", dry_run=False)

        self.assertEqual(out["status"], "completed")
        self.assertEqual(out["success_count"], 1)
        self.assertIsNotNone(out["undo_expires_at"])  # GAP-0212 integration
        self.assertEqual(
            self.payouts.get_item(Key={"payout_id": "po_import02"})["Item"]["status"],
            "completed",
        )

    def test_import_csv_bad_content_type_415(self):
        from fastapi import HTTPException

        with self.assertRaises(HTTPException) as ctx:
            self._call(
                file=self._upload(b"ref_id\npo_x\n", content_type="image/png"),
                kind="payout",
                dry_run=True,
            )
        self.assertEqual(ctx.exception.status_code, 415)

    def test_import_csv_missing_column_400(self):
        from fastapi import HTTPException

        with self.assertRaises(HTTPException) as ctx:
            self._call(
                file=self._upload(b"amount_cents\n100\n"),
                kind="payout",
                dry_run=True,
            )
        self.assertEqual(ctx.exception.status_code, 400)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
