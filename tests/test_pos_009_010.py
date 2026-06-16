"""
POS-009 (receipt generation) + POS-010 (X/Z session reports) — hermetic offline tests.

Pattern mirrors tests/test_pos_backend.py:
  - moto in-memory DynamoDB (pos + billing tables).
  - The frozen module-level ``T`` in each service module is patched to a
    SimpleNamespace bound to the moto tables.
  - ``S.pos_enabled`` toggled via object.__setattr__; ``S.dev_mode`` forced True.
  - No TestClient; service functions called directly.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import boto3
import pytest

try:
    from moto import mock_aws
    _MOTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    _MOTO_AVAILABLE = False
    mock_aws = None

pytestmark = pytest.mark.skipif(not _MOTO_AVAILABLE, reason="moto not installed")


# ── table builders ──────────────────────────────────────────────────────────────

def _create_pos_table(ddb):
    return ddb.create_table(
        TableName="pos",
        KeySchema=[
            {"AttributeName": "pos_pk", "KeyType": "HASH"},
            {"AttributeName": "pos_sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pos_pk", "AttributeType": "S"},
            {"AttributeName": "pos_sk", "AttributeType": "S"},
            {"AttributeName": "register_id", "AttributeType": "S"},
            {"AttributeName": "opened_at", "AttributeType": "N"},
            {"AttributeName": "session_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "cashier_sub", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_REGISTER_OPEN",
                "KeySchema": [
                    {"AttributeName": "register_id", "KeyType": "HASH"},
                    {"AttributeName": "opened_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI_SESSION_TXN",
                "KeySchema": [
                    {"AttributeName": "session_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI_CASHIER",
                "KeySchema": [
                    {"AttributeName": "cashier_sub", "KeyType": "HASH"},
                    {"AttributeName": "opened_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _create_billing_table(ddb):
    return ddb.create_table(
        TableName="billing",
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


# ── base test fixture ───────────────────────────────────────────────────────────

class _PosBase:
    pos_table: Any
    billing_table: Any
    fake_T: Any

    def setup_method(self, method):
        self._mock = mock_aws()
        self._mock.start()

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.pos_table = _create_pos_table(ddb)
        self.billing_table = _create_billing_table(ddb)
        self.fake_T = SimpleNamespace(pos=self.pos_table, billing=self.billing_table)

        import app.services.pos_register as pos_reg
        import app.services.pos_reports as pos_rep
        import app.services.pos_receipt as pos_rcpt

        self._patches = [
            patch.object(pos_reg, "T", self.fake_T),
            patch.object(pos_rep, "T", self.fake_T),
            patch.object(pos_rcpt, "T", self.fake_T),
            patch.object(pos_reg, "_audit", lambda *a, **kw: None),
        ]
        for p in self._patches:
            p.start()

        from app.core.settings import S
        self._S = S
        self._saved_enabled = S.pos_enabled
        self._saved_dev = S.dev_mode
        object.__setattr__(S, "pos_enabled", True)
        object.__setattr__(S, "dev_mode", True)

    def teardown_method(self, method):
        object.__setattr__(self._S, "pos_enabled", self._saved_enabled)
        object.__setattr__(self._S, "dev_mode", self._saved_dev)
        for p in self._patches:
            p.stop()
        self._mock.stop()

    # ── seed helpers ──
    def _seed_register(self, register_id="reg_1", label="Lane 1"):
        self.pos_table.put_item(Item={
            "pos_pk": f"REGISTER#{register_id}", "pos_sk": "META",
            "register_id": register_id, "label": label,
            "location_id": "store-1", "default_currency": "USD",
        })

    def _seed_session(self, session_id="sess_1", register_id="reg_1",
                      cashier_sub="cashier1", status="open",
                      opening_float_cents=10000, cash_in_cents=0,
                      change_out_cents=0, extra=None):
        item = {
            "pos_pk": f"SESSION#{session_id}", "pos_sk": "META",
            "session_id": session_id, "register_id": register_id,
            "cashier_sub": cashier_sub, "status": status,
            "opening_float_cents": opening_float_cents,
            "cash_in_cents": cash_in_cents, "change_out_cents": change_out_cents,
            "opened_at": 1_700_000_000,
        }
        if extra:
            item.update(extra)
        self.pos_table.put_item(Item=item)

    def _seed_txn(self, txn_id="txn_1", session_id="sess_1", cashier_sub="cashier1",
                  status="tendered", subtotal=2000, tax=0, discount=0, total=2000,
                  created_at=1_700_000_100, cart_id="cart_1"):
        self.pos_table.put_item(Item={
            "pos_pk": f"TXN#{txn_id}", "pos_sk": "META",
            "txn_id": txn_id, "session_id": session_id, "cashier_sub": cashier_sub,
            "status": status, "cart_id": cart_id,
            "subtotal_cents": subtotal, "tax_cents": tax,
            "discount_cents": discount, "total_cents": total,
            "created_at": created_at, "updated_at": created_at,
        })

    def _seed_tender(self, session_id="sess_1", txn_id="txn_1", seq=1, kind="cash",
                     amount=2000, change_due=0, created_at=1_700_000_100, extra=None):
        item = {
            "pos_pk": f"SESSION#{session_id}", "pos_sk": f"TENDER#{txn_id}#{seq:04d}",
            "session_id": session_id, "txn_id": txn_id, "kind": kind,
            "amount_cents": amount, "change_due_cents": change_due,
            "created_at": created_at,
        }
        if extra:
            item.update(extra)
        self.pos_table.put_item(Item=item)

    def _seed_refund(self, session_id="sess_1", txn_id="txn_1", seq=1,
                     kind="cash_refund", amount=2000, created_at=1_700_000_200):
        self.pos_table.put_item(Item={
            "pos_pk": f"SESSION#{session_id}", "pos_sk": f"REFUND#{txn_id}#{seq:04d}",
            "session_id": session_id, "txn_id": txn_id, "kind": kind,
            "amount_cents": amount, "created_at": created_at,
        })


# ── POS-009 receipt tests ────────────────────────────────────────────────────────

class TestPosReceipt(_PosBase):

    def _patch_cart_and_profile(self, items=None):
        items = items if items is not None else [
            {"name": "Coffee", "quantity": 2, "unit_price_cents": 500},
            {"name": "Bagel", "quantity": 1, "unit_price_cents": 300},
        ]
        import app.services.shoppingcart as sc
        import app.services.profile as pf
        return (
            patch.object(sc, "list_items", lambda *a, **kw: items),
            patch.object(pf, "get_profile", lambda sub: {"display_name": "Alice"}),
        )

    def test_generate_receipt_for_settled_cash_txn(self):
        from app.services.pos_receipt import get_or_create_pos_receipt
        self._seed_register()
        self._seed_session()
        self._seed_txn(total=1300, subtotal=1300)
        self._seed_tender(amount=1500, change_due=200)
        p_cart, p_prof = self._patch_cart_and_profile()
        with p_cart, p_prof:
            result = get_or_create_pos_receipt("txn_1")
        assert result["txn_id"] == "txn_1"
        assert result["receipt_id"]
        assert result["receipt_path"] == "/billing/receipts/txn_1.pdf"
        assert result["generated_at"] > 0
        # base64 stored on row in dev mode
        row = self.pos_table.get_item(Key={"pos_pk": "TXN#txn_1", "pos_sk": "META"})["Item"]
        assert row.get("receipt_b64")
        assert row.get("receipt_id") == result["receipt_id"]

    def test_receipt_bytes_are_valid_pdf(self):
        from app.services.pos_receipt import get_pos_receipt_bytes
        self._seed_register()
        self._seed_session()
        self._seed_txn()
        self._seed_tender()
        p_cart, p_prof = self._patch_cart_and_profile()
        with p_cart, p_prof:
            pdf = get_pos_receipt_bytes("txn_1")
        assert isinstance(pdf, (bytes, bytearray))
        assert pdf[:4] == b"%PDF"
        assert len(pdf) > 100

    def test_receipt_lines_contain_items_and_tenders(self):
        from app.services.pos_receipt import _build_payload, _render_pos_receipt_lines
        self._seed_register()
        self._seed_session()
        self._seed_txn(subtotal=1300, tax=130, total=1430)
        self._seed_tender(seq=1, kind="cash", amount=1000, change_due=70)
        self._seed_tender(seq=2, kind="card", amount=500, extra={"card_ref": "visa_4242"})
        p_cart, p_prof = self._patch_cart_and_profile()
        with p_cart, p_prof:
            txn = self.pos_table.get_item(Key={"pos_pk": "TXN#txn_1", "pos_sk": "META"})["Item"]
            lines = _render_pos_receipt_lines(_build_payload(txn))
        text = "\n".join(lines)
        assert "Coffee" in text and "Bagel" in text
        assert "Qty: 2" in text
        assert "Subtotal" in text and "Tax" in text and "TOTAL" in text
        assert "Cash" in text and "Change" in text
        assert "Card (visa ...4242)" in text
        assert "Lane 1" in text          # register label
        assert "Alice" in text           # cashier name

    def test_reprint_idempotent_no_rerender(self):
        from app.services import pos_receipt
        from app.services.pos_receipt import get_or_create_pos_receipt
        self._seed_register()
        self._seed_session()
        self._seed_txn()
        self._seed_tender()
        p_cart, p_prof = self._patch_cart_and_profile()
        with p_cart, p_prof:
            first = get_or_create_pos_receipt("txn_1")
            # Second call must NOT re-render: patch _render_bytes to blow up if called.
            with patch.object(pos_receipt, "_render_bytes",
                              side_effect=AssertionError("should not re-render")):
                second = get_or_create_pos_receipt("txn_1")
        assert first["receipt_id"] == second["receipt_id"]
        assert first["receipt_path"] == second["receipt_path"]

    def test_voided_txn_409(self):
        from app.services.pos_receipt import get_or_create_pos_receipt
        from fastapi import HTTPException
        self._seed_txn(status="voided")
        with pytest.raises(HTTPException) as ei:
            get_or_create_pos_receipt("txn_1")
        assert ei.value.status_code == 409

    def test_unsettled_txn_409(self):
        from app.services.pos_receipt import get_or_create_pos_receipt
        from fastapi import HTTPException
        self._seed_txn(status="draft")
        with pytest.raises(HTTPException) as ei:
            get_or_create_pos_receipt("txn_1")
        assert ei.value.status_code == 409

    def test_missing_txn_404(self):
        from app.services.pos_receipt import get_or_create_pos_receipt
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as ei:
            get_or_create_pos_receipt("nope")
        assert ei.value.status_code == 404

    def test_get_bytes_rerenders_when_artifact_missing(self):
        from app.services.pos_receipt import get_pos_receipt_bytes
        self._seed_register()
        self._seed_session()
        self._seed_txn()
        self._seed_tender()
        # Simulate metadata present but no inline bytes (artifact wiped).
        self.pos_table.update_item(
            Key={"pos_pk": "TXN#txn_1", "pos_sk": "META"},
            UpdateExpression="SET receipt_id = :rid, receipt_path = :rp, receipt_generated_at = :rg",
            ExpressionAttributeValues={
                ":rid": "deadbeefdeadbeef", ":rp": "/billing/receipts/txn_1.pdf",
                ":rg": 1_700_000_300,
            },
        )
        p_cart, p_prof = self._patch_cart_and_profile()
        with p_cart, p_prof:
            pdf = get_pos_receipt_bytes("txn_1")
        assert pdf[:4] == b"%PDF"

    def test_refunded_txn_still_has_receipt(self):
        from app.services.pos_receipt import get_or_create_pos_receipt
        self._seed_register()
        self._seed_session()
        self._seed_txn(status="refunded")
        self._seed_tender()
        p_cart, p_prof = self._patch_cart_and_profile()
        with p_cart, p_prof:
            result = get_or_create_pos_receipt("txn_1")
        assert result["receipt_id"]


# ── POS-010 X/Z report tests ────────────────────────────────────────────────────

class TestPosReports(_PosBase):

    def test_x_report_cash_only(self):
        from app.services.pos_reports import session_report
        self._seed_register()
        self._seed_session(cash_in_cents=1750, change_out_cents=0)
        self._seed_txn(txn_id="t1", total=1000, subtotal=1000)
        self._seed_txn(txn_id="t2", total=750, subtotal=750, created_at=1_700_000_110)
        self._seed_tender(txn_id="t1", amount=1000)
        self._seed_tender(txn_id="t2", amount=750, created_at=1_700_000_110)
        rep = session_report("sess_1", "x", cashier_sub="cashier1")
        assert rep["report_kind"] == "x"
        assert rep["gross_sales_cents"] == 1750
        assert rep["transaction_count"] == 2
        cash = next(t for t in rep["tender_breakdown"] if t["kind"] == "cash")
        assert cash["gross_cents"] == 1750
        assert rep["cash"]["expected_cash_cents"] == 10000 + 1750 - 0
        assert rep["cash"]["counted_cash_cents"] is None  # X report
        assert rep["z_report_printed_at"] is None

    def test_z_on_open_session_409(self):
        from app.services.pos_reports import session_report
        from fastapi import HTTPException
        self._seed_register()
        self._seed_session(status="open")
        with pytest.raises(HTTPException) as ei:
            session_report("sess_1", "z", cashier_sub="cashier1")
        assert ei.value.status_code == 409

    def test_x_on_closed_session_409(self):
        from app.services.pos_reports import session_report
        from fastapi import HTTPException
        self._seed_register()
        self._seed_session(status="closed")
        with pytest.raises(HTTPException) as ei:
            session_report("sess_1", "x", cashier_sub="cashier1")
        assert ei.value.status_code == 409

    def test_z_report_on_closed_sets_printed_at(self):
        from app.services.pos_reports import session_report
        self._seed_register()
        self._seed_session(
            status="closed",
            extra={
                "cash_in_cents": 2000, "change_out_cents": 0,
                "expected_cash_cents": 12000, "counted_cash_cents": 12050,
                "over_short_cents": 50, "closed_at": 1_700_000_500,
            },
        )
        self._seed_txn(total=2000, subtotal=2000)
        self._seed_tender(amount=2000)
        rep = session_report("sess_1", "z", cashier_sub="cashier1")
        assert rep["report_kind"] == "z"
        assert rep["z_report_printed_at"] is not None
        assert rep["cash"]["counted_cash_cents"] == 12050
        assert rep["cash"]["over_short_cents"] == 50
        assert rep["cash"]["expected_cash_cents"] == 12000
        # printed_at persisted
        row = self.pos_table.get_item(Key={"pos_pk": "SESSION#sess_1", "pos_sk": "META"})["Item"]
        assert row.get("z_report_printed_at") is not None

    def test_z_report_idempotent(self):
        from app.services.pos_reports import session_report
        self._seed_register()
        self._seed_session(status="closed", extra={"closed_at": 1_700_000_500})
        first = session_report("sess_1", "z", cashier_sub="cashier1")
        ts1 = first["z_report_printed_at"]
        second = session_report("sess_1", "z", cashier_sub="cashier1")
        assert second["z_report_printed_at"] == ts1  # unchanged

    def test_split_tender_no_double_count(self):
        from app.services.pos_reports import session_report
        self._seed_register()
        self._seed_session()
        self._seed_txn(total=1500, subtotal=1500)
        self._seed_tender(seq=1, kind="cash", amount=1000)
        self._seed_tender(seq=2, kind="card", amount=500,
                          extra={"card_ref": "visa_1111"}, created_at=1_700_000_101)
        rep = session_report("sess_1", "x", cashier_sub="cashier1")
        assert rep["gross_sales_cents"] == 1500  # from TXN row, not 2000
        cash = next(t for t in rep["tender_breakdown"] if t["kind"] == "cash")
        card = next(t for t in rep["tender_breakdown"] if t["kind"] == "card")
        assert cash["gross_cents"] == 1000
        assert card["gross_cents"] == 500

    def test_refund_reduces_net(self):
        from app.services.pos_reports import session_report
        self._seed_register()
        self._seed_session()
        self._seed_txn(total=2000, subtotal=2000)
        self._seed_tender(amount=2000)
        self._seed_refund(kind="cash_refund", amount=2000)
        rep = session_report("sess_1", "x", cashier_sub="cashier1")
        assert rep["gross_sales_cents"] == 2000
        assert rep["refund_total_cents"] == 2000
        cash = next(t for t in rep["tender_breakdown"] if t["kind"] == "cash")
        assert cash["refund_cents"] == 2000
        assert cash["net_cents"] == 0

    def test_voided_excluded_from_gross(self):
        from app.services.pos_reports import session_report
        self._seed_register()
        self._seed_session()
        self._seed_txn(txn_id="t1", status="voided", total=5000)
        self._seed_txn(txn_id="t2", status="tendered", total=1000, subtotal=1000,
                       created_at=1_700_000_120)
        self._seed_tender(txn_id="t2", amount=1000, created_at=1_700_000_120)
        rep = session_report("sess_1", "x", cashier_sub="cashier1")
        assert rep["gross_sales_cents"] == 1000
        assert rep["void_count"] == 1
        assert rep["transaction_count"] == 1

    def test_over_short_math(self):
        # expected = opening_float + cash_in - change_out; over_short = counted - expected
        from app.services.pos_reports import session_report
        self._seed_register()
        self._seed_session(
            status="closed",
            opening_float_cents=10000,
            extra={
                "cash_in_cents": 5000, "change_out_cents": 300,
                "expected_cash_cents": 10000 + 5000 - 300,   # 14700
                "counted_cash_cents": 14650,
                "over_short_cents": 14650 - 14700,            # -50 (short)
                "closed_at": 1_700_000_500,
            },
        )
        rep = session_report("sess_1", "z", cashier_sub="cashier1")
        assert rep["cash"]["expected_cash_cents"] == 14700
        assert rep["cash"]["over_short_cents"] == -50

    def test_flag_off_404(self):
        from app.services.pos_reports import session_report
        from fastapi import HTTPException
        object.__setattr__(self._S, "pos_enabled", False)
        with pytest.raises(HTTPException) as ei:
            session_report("sess_1", "x", cashier_sub="cashier1")
        assert ei.value.status_code == 404

    def test_invalid_kind_400(self):
        from app.services.pos_reports import session_report
        from fastapi import HTTPException
        self._seed_register()
        self._seed_session()
        with pytest.raises(HTTPException) as ei:
            session_report("sess_1", "q", cashier_sub="cashier1")
        assert ei.value.status_code == 400

    def test_ownership_enforced(self):
        from app.services.pos_reports import session_report
        from fastapi import HTTPException
        self._seed_register()
        self._seed_session(cashier_sub="cashier1")
        with pytest.raises(HTTPException) as ei:
            session_report("sess_1", "x", cashier_sub="someone_else")
        assert ei.value.status_code == 403

    def test_admin_bypass_ownership(self):
        from app.services.pos_reports import session_report
        self._seed_register()
        self._seed_session(cashier_sub="cashier1")
        rep = session_report("sess_1", "x", cashier_sub="manager", role="admin")
        assert rep["report_kind"] == "x"

    def test_empty_session_returns_zeros(self):
        from app.services.pos_reports import session_report
        self._seed_register()
        self._seed_session()
        rep = session_report("sess_1", "x", cashier_sub="cashier1")
        assert rep["gross_sales_cents"] == 0
        assert rep["transaction_count"] == 0
        assert rep["tender_breakdown"] == []

    def test_session_not_found_404(self):
        from app.services.pos_reports import session_report
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as ei:
            session_report("nope", "x", cashier_sub="cashier1")
        assert ei.value.status_code == 404
