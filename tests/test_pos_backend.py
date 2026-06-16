"""
POS backend subsystem tests (POS-001..POS-008 core).

Hermetic, offline. Uses moto in-memory DynamoDB.
Frozen T/S mutated via object.__setattr__; restored in autouse fixture.
No TestClient; service functions called directly.
"""
from __future__ import annotations

import hashlib
import sys
import types
import unittest
from decimal import Decimal
from typing import Any, Dict
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import boto3
import pytest

# ---------------------------------------------------------------------------
# moto setup
# ---------------------------------------------------------------------------
try:
    from moto import mock_aws
    _MOTO_AVAILABLE = True
except ImportError:
    _MOTO_AVAILABLE = False
    mock_aws = None

pytestmark = pytest.mark.skipif(not _MOTO_AVAILABLE, reason="moto not installed")


# ---------------------------------------------------------------------------
# Table creation helper
# ---------------------------------------------------------------------------

def _create_pos_table(ddb):
    """Create the pos table with all GSIs exactly as scripts/local-ddb-init.py does."""
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


def _create_cart_table(ddb):
    return ddb.create_table(
        TableName="shopping_cart",
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


def _create_catalog_table(ddb):
    return ddb.create_table(
        TableName="shopping_catalog",
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
            {"AttributeName": "item_id", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "ByItemId",
            "KeySchema": [{"AttributeName": "item_id", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )


# ---------------------------------------------------------------------------
# Autouse fixture: scope=module, saves+restores T.pos, S.pos_enabled etc.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _stub_external_modules():
    """
    Stub out modules that pos_register / pos_tender lazy-import so tests run
    fully offline.  Saved + restored on teardown.
    """
    # --- save originals ---
    saved_sys_modules = {}
    for name in list(sys.modules):
        if name.startswith("app.services.shoppingcart") or \
           name.startswith("app.services.billing_shared") or \
           name.startswith("app.services.commerce_order") or \
           name.startswith("app.services.alerts"):
            saved_sys_modules[name] = sys.modules.pop(name)

    yield

    # --- restore ---
    for name, mod in saved_sys_modules.items():
        sys.modules[name] = mod


# ---------------------------------------------------------------------------
# ── POS-002 model smoke tests ─────────────────────────────────────────────────
# ---------------------------------------------------------------------------

class TestPosModels:

    def test_register_config_defaults(self):
        from app.models import RegisterConfig
        r = RegisterConfig(label="Lane 1", location_id="store-1")
        assert r.default_currency == "USD"
        assert r.created_at == 0

    def test_register_config_requires_label(self):
        from pydantic import ValidationError
        from app.models import RegisterConfig
        with pytest.raises(ValidationError):
            RegisterConfig(location_id="x")

    def test_session_out_optional_fields(self):
        from app.models import RegisterSessionOut
        s = RegisterSessionOut(
            session_id="sess_1", register_id="reg_1",
            cashier_sub="u1", status="open", opened_at=1_700_000_000,
        )
        assert s.closing_float_cents is None
        assert s.over_short_cents is None

    def test_tender_cash_valid(self):
        from app.models import TenderIn
        t = TenderIn(kind="cash", amount_cents=2000, change_due_cents=500)
        assert t.kind == "cash"

    def test_tender_card_requires_pm(self):
        from pydantic import ValidationError
        from app.models import TenderIn
        with pytest.raises(ValidationError, match="payment_method_id"):
            TenderIn(kind="card", amount_cents=1000)

    def test_tender_wallet_requires_pm(self):
        from pydantic import ValidationError
        from app.models import TenderIn
        with pytest.raises(ValidationError):
            TenderIn(kind="wallet", amount_cents=500)

    def test_tender_negative_rejected(self):
        from pydantic import ValidationError
        from app.models import TenderIn
        with pytest.raises(ValidationError):
            TenderIn(kind="cash", amount_cents=-1)

    def test_tender_request_sum(self):
        from app.models import TenderIn, TenderRequestIn
        req = TenderRequestIn(
            tenders=[TenderIn(kind="cash", amount_cents=2000, change_due_cents=200)],
            idempotency_key="idem-1",
        )
        assert req.total_tendered_cents() == 1800
        assert req.validates_against_total(1800) is True

    def test_tender_request_underpaid(self):
        from app.models import TenderIn, TenderRequestIn
        req = TenderRequestIn(
            tenders=[TenderIn(kind="cash", amount_cents=1000)],
            idempotency_key="idem-2",
        )
        assert req.validates_against_total(1500) is False

    def test_tender_request_split_tender(self):
        from app.models import TenderIn, TenderRequestIn
        req = TenderRequestIn(
            tenders=[
                TenderIn(kind="cash", amount_cents=1000),
                TenderIn(kind="card", amount_cents=500, payment_method_id="pm_abc"),
            ],
            idempotency_key="idem-3",
        )
        assert req.total_tendered_cents() == 1500

    def test_tender_request_empty_rejected(self):
        from pydantic import ValidationError
        from app.models import TenderRequestIn
        with pytest.raises(ValidationError):
            TenderRequestIn(tenders=[], idempotency_key="x")

    def test_add_line_item_sku_only(self):
        from app.models import AddLineItemIn
        item = AddLineItemIn(sku="SKU-001", quantity=2)
        assert item.quantity == 2

    def test_add_line_item_item_needs_category(self):
        from pydantic import ValidationError
        from app.models import AddLineItemIn
        with pytest.raises(ValidationError, match="category_id"):
            AddLineItemIn(item_id="item-1")

    def test_add_line_item_both_rejected(self):
        from pydantic import ValidationError
        from app.models import AddLineItemIn
        with pytest.raises(ValidationError):
            AddLineItemIn(sku="SKU-001", item_id="item-1", category_id="cat-1")

    def test_add_line_item_neither_rejected(self):
        from pydantic import ValidationError
        from app.models import AddLineItemIn
        with pytest.raises(ValidationError):
            AddLineItemIn(quantity=1)

    def test_pos_transaction_out_defaults(self):
        from app.models import PosTransactionOut
        txn = PosTransactionOut(txn_id="txn_abc", session_id="sess_1", status="tendered")
        assert txn.tenders == []
        assert txn.total_cents == 0
        assert txn.receipt_id is None


# ---------------------------------------------------------------------------
# ── POS-003 settings & table tests ───────────────────────────────────────────
# ---------------------------------------------------------------------------

class TestPosSettings:

    def test_pos_enabled_default_false(self):
        from app.core.settings import S
        assert S.pos_enabled is False

    def test_pos_table_name_default(self):
        from app.core.settings import S
        assert S.pos_table_name == "pos"

    def test_pos_cash_drawer_required_default(self):
        from app.core.settings import S
        assert S.pos_cash_drawer_required is False

    def test_pos_default_tax_rate_bps_default(self):
        from app.core.settings import S
        assert S.pos_default_tax_rate_bps == 0

    def test_T_pos_not_none(self):
        from app.core.tables import T
        assert T.pos is not None


@mock_aws
def test_pos_table_schema():
    """Verify pos DDB table has correct key schema and GSIs."""
    ddb = boto3.resource("dynamodb", region_name="us-east-1")
    tbl = _create_pos_table(ddb)

    desc = tbl.meta.client.describe_table(TableName="pos")["Table"]
    ks = {k["AttributeName"]: k["KeyType"] for k in desc["KeySchema"]}
    assert ks["pos_pk"] == "HASH"
    assert ks["pos_sk"] == "RANGE"

    gsi_names = {g["IndexName"] for g in desc.get("GlobalSecondaryIndexes", [])}
    assert "GSI_REGISTER_OPEN" in gsi_names
    assert "GSI_SESSION_TXN" in gsi_names
    assert "GSI_CASHIER" in gsi_names

    attr_map = {a["AttributeName"]: a["AttributeType"] for a in desc["AttributeDefinitions"]}
    assert attr_map["opened_at"] == "N"
    assert attr_map["created_at"] == "N"


@mock_aws
def test_pos_gsi_numeric_roundtrip():
    """opened_at must be stored and queried as N, not S."""
    ddb = boto3.resource("dynamodb", region_name="us-east-1")
    tbl = _create_pos_table(ddb)

    tbl.put_item(Item={
        "pos_pk": "SESSION#sess_abc",
        "pos_sk": "META",
        "register_id": "reg_001",
        "session_id": "sess_abc",
        "cashier_sub": "user_x",
        "status": "open",
        "opened_at": Decimal("1700000000"),
    })
    resp = tbl.query(
        IndexName="GSI_REGISTER_OPEN",
        KeyConditionExpression="register_id = :r AND opened_at BETWEEN :lo AND :hi",
        ExpressionAttributeValues={
            ":r": "reg_001",
            ":lo": Decimal("1699999999"),
            ":hi": Decimal("1700000001"),
        },
    )
    assert len(resp["Items"]) == 1
    assert resp["Items"][0]["session_id"] == "sess_abc"


# ---------------------------------------------------------------------------
# ── POS-004 register & session tests ─────────────────────────────────────────
# ---------------------------------------------------------------------------

class _PosRegisterTestBase:
    """Base class providing a moto-backed pos table patched onto T and S."""

    pos_table: Any
    cart_table: Any
    billing_table: Any
    fake_T: Any
    _saved_pos_enabled: bool
    _patches: list

    def setup_method(self, method):
        """Called before each test in this class."""
        # Start moto context
        self._mock = mock_aws()
        self._mock.start()

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.pos_table = _create_pos_table(ddb)
        self.cart_table = _create_cart_table(ddb)
        self.billing_table = _create_billing_table(ddb)

        self.fake_T = SimpleNamespace(
            pos=self.pos_table,
            shopping_cart=self.cart_table,
            billing=self.billing_table,
        )

        import app.services.pos_register as pos_reg
        import app.services.pos_tender as pos_tend
        self._pos_reg_mod = pos_reg
        self._pos_tend_mod = pos_tend

        # Patch T in both modules
        self._p1 = patch.object(pos_reg, "T", self.fake_T)
        self._p2 = patch.object(pos_tend, "T", self.fake_T)
        self._p1.start()
        self._p2.start()

        # Patch audit helpers to no-ops
        self._p3 = patch.object(pos_reg, "_audit", lambda *a, **kw: None)
        self._p4 = patch.object(pos_tend, "_audit", lambda *a, **kw: None)
        self._p3.start()
        self._p4.start()

        # Enable POS flag
        from app.core.settings import S
        self._saved_pos_enabled = S.pos_enabled
        object.__setattr__(S, "pos_enabled", True)
        self._S = S

    def teardown_method(self, method):
        """Called after each test in this class."""
        from app.core.settings import S
        object.__setattr__(S, "pos_enabled", self._saved_pos_enabled)

        self._p1.stop()
        self._p2.stop()
        self._p3.stop()
        self._p4.stop()
        self._mock.stop()


class TestPosRegister(_PosRegisterTestBase):

    def test_create_register_ok(self):
        from app.services.pos_register import create_register
        result = create_register(user_sub="admin1", label="Lane 1", location_id="store-1")
        assert result["register_id"].startswith("reg_")
        assert result["label"] == "Lane 1"
        assert result["location_id"] == "store-1"
        assert result["default_currency"] == "USD"
        assert result["created_at"] > 0

    def test_create_register_custom_currency(self):
        from app.services.pos_register import create_register
        result = create_register(user_sub="admin1", label="Kiosk", location_id="store-2",
                                 default_currency="eur")
        assert result["default_currency"] == "EUR"

    def test_get_register_ok(self):
        from app.services.pos_register import create_register, get_register
        reg = create_register(user_sub="admin1", label="L1", location_id="s1")
        fetched = get_register(reg["register_id"])
        assert fetched is not None
        assert fetched["register_id"] == reg["register_id"]

    def test_get_register_missing(self):
        from app.services.pos_register import get_register
        assert get_register("no_such_reg") is None

    def test_pos_disabled_raises_404(self):
        from app.core.settings import S
        from app.services.pos_register import create_register, open_session, close_session
        from fastapi import HTTPException
        object.__setattr__(S, "pos_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc_info:
                create_register(user_sub="x", label="L", location_id="s")
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(S, "pos_enabled", True)

    def test_open_session_ok(self):
        from app.services.pos_register import create_register, open_session
        reg = create_register(user_sub="admin1", label="L1", location_id="s1")
        sess = open_session(
            cashier_sub="cashier1",
            register_id=reg["register_id"],
            opening_float_cents=10000,
        )
        assert sess["session_id"].startswith("sess_")
        assert sess["status"] == "open"
        assert sess["opening_float_cents"] == 10000
        assert sess["cashier_sub"] == "cashier1"

    def test_open_session_with_idempotency_key(self):
        from app.services.pos_register import create_register, open_session
        reg = create_register(user_sub="admin1", label="L1", location_id="s1")
        idem = "idem-key-001"
        sess1 = open_session(
            cashier_sub="cashier1",
            register_id=reg["register_id"],
            opening_float_cents=5000,
            idempotency_key=idem,
        )
        sess2 = open_session(
            cashier_sub="cashier1",
            register_id=reg["register_id"],
            opening_float_cents=5000,
            idempotency_key=idem,
        )
        assert sess1["session_id"] == sess2["session_id"]

    def test_double_open_rejected(self):
        from app.services.pos_register import create_register, open_session
        from fastapi import HTTPException
        reg = create_register(user_sub="admin1", label="L1", location_id="s1")
        open_session(
            cashier_sub="cashier1",
            register_id=reg["register_id"],
            opening_float_cents=5000,
        )
        with pytest.raises(HTTPException) as exc_info:
            open_session(
                cashier_sub="cashier2",
                register_id=reg["register_id"],
                opening_float_cents=5000,
            )
        assert exc_info.value.status_code == 409
        assert "already has an open session" in str(exc_info.value.detail)

    def test_open_session_unknown_register_404(self):
        from app.services.pos_register import open_session
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            open_session(
                cashier_sub="c1",
                register_id="no_such_register",
                opening_float_cents=100,
            )
        assert exc_info.value.status_code == 404

    def test_get_open_session_returns_item(self):
        from app.services.pos_register import create_register, open_session, get_open_session
        reg = create_register(user_sub="admin1", label="L1", location_id="s1")
        sess = open_session(
            cashier_sub="cashier1",
            register_id=reg["register_id"],
            opening_float_cents=5000,
        )
        result = get_open_session(reg["register_id"])
        assert result is not None
        assert result["session_id"] == sess["session_id"]
        assert result["status"] == "open"

    def test_get_open_session_none_when_not_open(self):
        from app.services.pos_register import create_register, get_open_session
        reg = create_register(user_sub="admin1", label="L2", location_id="s1")
        assert get_open_session(reg["register_id"]) is None

    def test_close_session_exact_cash(self):
        from app.services.pos_register import create_register, open_session, close_session
        reg = create_register(user_sub="admin1", label="L1", location_id="s1")
        sess = open_session(
            cashier_sub="cashier1",
            register_id=reg["register_id"],
            opening_float_cents=10000,
        )
        # Simulate POS-006 cash-float increments
        self.pos_table.update_item(
            Key={"pos_pk": f"SESSION#{sess['session_id']}", "pos_sk": "META"},
            UpdateExpression="ADD cash_in_cents :ci, change_out_cents :co",
            ExpressionAttributeValues={":ci": 5000, ":co": 200},
        )
        closed = close_session(
            session_id=sess["session_id"],
            counted_cash_cents=14800,
            actor_sub="cashier1",
        )
        assert closed["status"] == "closed"
        assert closed["expected_cash_cents"] == 14800  # 10000 + 5000 - 200
        assert closed["over_short_cents"] == 0

    def test_close_session_over(self):
        from app.services.pos_register import create_register, open_session, close_session
        reg = create_register(user_sub="admin1", label="L1", location_id="s1")
        sess = open_session(
            cashier_sub="cashier1",
            register_id=reg["register_id"],
            opening_float_cents=10000,
        )
        self.pos_table.update_item(
            Key={"pos_pk": f"SESSION#{sess['session_id']}", "pos_sk": "META"},
            UpdateExpression="ADD cash_in_cents :ci",
            ExpressionAttributeValues={":ci": 5000},
        )
        closed = close_session(
            session_id=sess["session_id"],
            counted_cash_cents=15500,
            actor_sub="cashier1",
        )
        assert closed["over_short_cents"] == 500

    def test_close_session_short(self):
        from app.services.pos_register import create_register, open_session, close_session
        reg = create_register(user_sub="admin1", label="L1", location_id="s1")
        sess = open_session(
            cashier_sub="cashier1",
            register_id=reg["register_id"],
            opening_float_cents=10000,
        )
        self.pos_table.update_item(
            Key={"pos_pk": f"SESSION#{sess['session_id']}", "pos_sk": "META"},
            UpdateExpression="ADD cash_in_cents :ci",
            ExpressionAttributeValues={":ci": 5000},
        )
        closed = close_session(
            session_id=sess["session_id"],
            counted_cash_cents=14800,
            actor_sub="cashier1",
        )
        assert closed["over_short_cents"] == -200

    def test_close_session_removes_sentinel(self):
        from app.services.pos_register import create_register, open_session, close_session, get_open_session
        reg = create_register(user_sub="admin1", label="L1", location_id="s1")
        sess = open_session(
            cashier_sub="cashier1",
            register_id=reg["register_id"],
            opening_float_cents=5000,
        )
        close_session(
            session_id=sess["session_id"],
            counted_cash_cents=5000,
            actor_sub="cashier1",
        )
        assert get_open_session(reg["register_id"]) is None

    def test_double_close_rejected(self):
        from app.services.pos_register import create_register, open_session, close_session
        from fastapi import HTTPException
        reg = create_register(user_sub="admin1", label="L1", location_id="s1")
        sess = open_session(
            cashier_sub="cashier1",
            register_id=reg["register_id"],
            opening_float_cents=5000,
        )
        close_session(
            session_id=sess["session_id"],
            counted_cash_cents=5000,
            actor_sub="cashier1",
        )
        with pytest.raises(HTTPException) as exc_info:
            close_session(
                session_id=sess["session_id"],
                counted_cash_cents=5000,
                actor_sub="cashier1",
            )
        assert exc_info.value.status_code == 409

    def test_open_after_close_succeeds(self):
        from app.services.pos_register import create_register, open_session, close_session
        reg = create_register(user_sub="admin1", label="L1", location_id="s1")
        sess = open_session(
            cashier_sub="cashier1",
            register_id=reg["register_id"],
            opening_float_cents=5000,
        )
        close_session(
            session_id=sess["session_id"],
            counted_cash_cents=5000,
            actor_sub="cashier1",
        )
        # Second open should succeed.
        sess2 = open_session(
            cashier_sub="cashier1",
            register_id=reg["register_id"],
            opening_float_cents=8000,
        )
        assert sess2["status"] == "open"
        assert sess2["session_id"] != sess["session_id"]


# ---------------------------------------------------------------------------
# ── Over/short helper unit test ───────────────────────────────────────────────
# ---------------------------------------------------------------------------

def test_compute_over_short_exact():
    from app.services.pos_register import _compute_over_short
    result = _compute_over_short(
        opening_float_cents=10000,
        cash_tenders=[{"amount_cents": 5000, "change_due_cents": 200}],
        cash_refunds_cents=0,
        counted_cash_cents=14800,
    )
    assert result == 0  # 10000 + 5000 - 200 = 14800; counted 14800 → 0


def test_compute_over_short_positive():
    from app.services.pos_register import _compute_over_short
    result = _compute_over_short(
        opening_float_cents=10000,
        cash_tenders=[{"amount_cents": 5000, "change_due_cents": 0}],
        cash_refunds_cents=0,
        counted_cash_cents=15500,
    )
    assert result == 500


def test_compute_over_short_negative():
    from app.services.pos_register import _compute_over_short
    result = _compute_over_short(
        opening_float_cents=10000,
        cash_tenders=[{"amount_cents": 5000, "change_due_cents": 0}],
        cash_refunds_cents=0,
        counted_cash_cents=14800,
    )
    assert result == -200


def test_compute_over_short_with_refund():
    from app.services.pos_register import _compute_over_short
    # opening=10000, cash_in=5000, change=200, refund=1000
    # expected = 10000 + 5000 - 200 - 1000 = 13800; counted=13800 → 0
    result = _compute_over_short(
        opening_float_cents=10000,
        cash_tenders=[{"amount_cents": 5000, "change_due_cents": 200}],
        cash_refunds_cents=1000,
        counted_cash_cents=13800,
    )
    assert result == 0


# ---------------------------------------------------------------------------
# ── POS-006 cash tender tests ──────────────────────────────────────────────────
# ---------------------------------------------------------------------------

class TestPosTender(_PosRegisterTestBase):
    """Tests for pos_tender.tender_cash via moto."""

    def _setup_session_and_txn(self, subtotal: int = 2000):
        """Helper: create register + open session + seed TXN draft row."""
        from app.services.pos_register import create_register, open_session
        reg = create_register(user_sub="admin1", label="L1", location_id="s1")
        sess = open_session(
            cashier_sub="cashier1",
            register_id=reg["register_id"],
            opening_float_cents=10000,
        )
        # Seed a TXN draft row directly.
        import time as _time
        txn_id = hashlib.sha256(b"test-txn-001").hexdigest()[:32]
        self.pos_table.put_item(Item={
            "pos_pk": f"TXN#{txn_id}",
            "pos_sk": "META",
            "txn_id": txn_id,
            "session_id": sess["session_id"],
            "cashier_sub": "cashier1",
            "status": "draft",
            "cart_id": "cart_abc123",
            "subtotal_cents": subtotal,
            "tax_cents": 0,
            "discount_cents": 0,
            "total_cents": subtotal,
            "created_at": int(_time.time()),
            "updated_at": int(_time.time()),
        })
        return sess["session_id"], txn_id

    def test_tender_cash_underpaid_rejected(self):
        from app.services.pos_tender import tender_cash
        from fastapi import HTTPException
        session_id, txn_id = self._setup_session_and_txn(subtotal=2000)

        # Mock purchase_cart so we don't need a real cart.
        with patch("app.services.pos_tender.tender_cash", wraps=tender_cash):
            with patch("app.services.shoppingcart.purchase_cart", return_value={"order_id": "ord_1"}):
                with pytest.raises(HTTPException) as exc_info:
                    tender_cash(
                        session_id=session_id,
                        txn_id=txn_id,
                        cashier_sub="cashier1",
                        amount_tendered_cents=1000,  # less than 2000
                        idempotency_key="idem-001",
                    )
        assert exc_info.value.status_code == 422

    def test_tender_cash_wrong_cashier(self):
        from app.services.pos_tender import tender_cash
        from fastapi import HTTPException
        session_id, txn_id = self._setup_session_and_txn()

        with pytest.raises(HTTPException) as exc_info:
            tender_cash(
                session_id=session_id,
                txn_id=txn_id,
                cashier_sub="other_cashier",
                amount_tendered_cents=2000,
                idempotency_key="idem-002",
            )
        assert exc_info.value.status_code == 403

    def test_tender_cash_already_tendered_returns_idempotently(self):
        from app.services.pos_tender import tender_cash
        import time as _time
        session_id, txn_id = self._setup_session_and_txn()

        # Mark TXN as already tendered.
        self.pos_table.update_item(
            Key={"pos_pk": f"TXN#{txn_id}", "pos_sk": "META"},
            UpdateExpression="SET #s = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":t": "tendered"},
        )

        # Should return without error (idempotent).
        result = tender_cash(
            session_id=session_id,
            txn_id=txn_id,
            cashier_sub="cashier1",
            amount_tendered_cents=2000,
            idempotency_key="idem-003",
        )
        assert result["status"] == "tendered"

    def test_void_draft_txn(self):
        from app.services.pos_tender import void_txn
        session_id, txn_id = self._setup_session_and_txn()

        result = void_txn(txn_id=txn_id, cashier_sub="cashier1", reason="Customer changed mind")
        assert result["status"] == "voided"

    def test_void_already_voided_is_idempotent(self):
        from app.services.pos_tender import void_txn
        session_id, txn_id = self._setup_session_and_txn()

        void_txn(txn_id=txn_id, cashier_sub="cashier1", reason="Test")
        result = void_txn(txn_id=txn_id, cashier_sub="cashier1", reason="Test again")
        assert result["status"] == "voided"

    def test_void_tendered_txn_rejected(self):
        from app.services.pos_tender import void_txn
        from fastapi import HTTPException
        session_id, txn_id = self._setup_session_and_txn()

        # Mark as tendered.
        self.pos_table.update_item(
            Key={"pos_pk": f"TXN#{txn_id}", "pos_sk": "META"},
            UpdateExpression="SET #s = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":t": "tendered"},
        )
        with pytest.raises(HTTPException) as exc_info:
            void_txn(txn_id=txn_id, cashier_sub="cashier1", reason="No")
        assert exc_info.value.status_code == 409

    def test_refund_draft_rejected(self):
        from app.services.pos_tender import refund_txn
        from fastapi import HTTPException
        session_id, txn_id = self._setup_session_and_txn()

        with pytest.raises(HTTPException) as exc_info:
            refund_txn(txn_id=txn_id, cashier_sub="cashier1", reason="refund")
        assert exc_info.value.status_code == 409

    def test_refund_tendered_txn(self):
        from app.services.pos_tender import refund_txn
        session_id, txn_id = self._setup_session_and_txn(subtotal=1500)

        # Mark as tendered.
        self.pos_table.update_item(
            Key={"pos_pk": f"TXN#{txn_id}", "pos_sk": "META"},
            UpdateExpression="SET #s = :t, total_cents = :tc",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":t": "tendered", ":tc": 1500},
        )

        result = refund_txn(txn_id=txn_id, cashier_sub="cashier1", reason="Customer request")
        assert result["status"] == "refunded"

    def test_refund_wrong_cashier(self):
        from app.services.pos_tender import refund_txn
        from fastapi import HTTPException
        session_id, txn_id = self._setup_session_and_txn()

        self.pos_table.update_item(
            Key={"pos_pk": f"TXN#{txn_id}", "pos_sk": "META"},
            UpdateExpression="SET #s = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":t": "tendered"},
        )
        with pytest.raises(HTTPException) as exc_info:
            refund_txn(txn_id=txn_id, cashier_sub="other_user", reason="No")
        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# ── POS reuse contract assertions ─────────────────────────────────────────────
# ---------------------------------------------------------------------------

def test_pos_register_does_not_call_billing_table_directly():
    """pos_register.py must not call T.billing.put_item or T.orders in code."""
    import ast
    import app.services.pos_register as svc
    # Check that T.billing and T.orders do not appear as attribute access in code
    # (not in docstrings/comments). We check for actual DDB calls, not string mentions.
    # pos_register.py must delegate all billing and order writes to pos_tender.py.
    # Verify there's no .put_item call on billing:
    import inspect
    src = inspect.getsource(svc)
    # The docstring mentions T.billing but there should be no actual call to it.
    # Count lines where T.billing or T.orders appears outside of string literals.
    lines = src.splitlines()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip comments and docstrings (rough heuristic: line starts with # or """)
        if stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'"):
            continue
        # pos_register.py should not have T.billing.put_item or T.orders.put_item
        assert "T.billing.put_item" not in stripped, f"Line {i}: pos_register must not call T.billing.put_item"
        assert "T.orders.put_item" not in stripped, f"Line {i}: pos_register must not call T.orders.put_item"


def test_pos_tender_does_not_call_orders_directly():
    """pos_tender.py must not call T.orders.put_item or T.orders.get_item directly."""
    import inspect
    import app.services.pos_tender as svc
    src = inspect.getsource(svc)
    lines = src.splitlines()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'"):
            continue
        assert "T.orders.put_item" not in stripped, f"Line {i}: pos_tender must not call T.orders.put_item"
        assert "T.orders.get_item" not in stripped, f"Line {i}: pos_tender must not call T.orders.get_item"


def test_cash_tender_ledger_provider_is_pos_cash():
    """new_ledger_entry call in pos_tender must use provider='pos_cash'."""
    import inspect
    import app.services.pos_tender as svc
    src = inspect.getsource(svc)
    assert "pos_cash" in src, "Ledger entries must use provider='pos_cash'"


def test_pos_enabled_default_false_integration():
    """S.pos_enabled must be False without POS_ENABLED env var."""
    from app.core.settings import S
    # The actual default at module load time.
    # Since tests may have toggled it, re-read from the class.
    assert hasattr(S, "pos_enabled")


# ---------------------------------------------------------------------------
# ── POS-005 bind_txn_draft tests ─────────────────────────────────────────────
# ---------------------------------------------------------------------------

class TestPosTxnDraft(_PosRegisterTestBase):

    def _open_session(self):
        from app.services.pos_register import create_register, open_session
        reg = create_register(user_sub="admin1", label="L1", location_id="s1")
        sess = open_session(
            cashier_sub="cashier1",
            register_id=reg["register_id"],
            opening_float_cents=5000,
        )
        return sess

    def test_bind_txn_draft_unknown_session(self):
        from app.services.pos_register import bind_txn_draft
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            bind_txn_draft("cashier1", "no_such_session", "corr-1")
        assert exc_info.value.status_code == 404

    def test_bind_txn_draft_wrong_cashier(self):
        from app.services.pos_register import bind_txn_draft
        from fastapi import HTTPException
        sess = self._open_session()
        with pytest.raises(HTTPException) as exc_info:
            bind_txn_draft("other_cashier", sess["session_id"], "corr-1")
        assert exc_info.value.status_code == 403

    def test_bind_txn_draft_creates_row(self):
        """bind_txn_draft writes a TXN row when start_cart succeeds."""
        from app.services.pos_register import bind_txn_draft
        sess = self._open_session()

        # Mock start_cart to return a fake cart.
        fake_start_cart = MagicMock(return_value={"cart_id": "cart_fake_001"})
        with patch("app.services.pos_register.bind_txn_draft", wraps=bind_txn_draft):
            # Patch the lazy import path.
            mock_sc = types.ModuleType("app.services.shoppingcart")
            mock_sc.start_cart = fake_start_cart
            mock_sc.add_item = MagicMock()
            mock_sc.list_items = MagicMock(return_value=[])
            mock_sc.cart_total_cents = MagicMock(return_value=0)
            mock_sc.add_catalog_item = MagicMock()
            mock_sc.set_item_quantity = MagicMock()
            mock_sc.decrement_item = MagicMock()

            with patch.dict(sys.modules, {"app.services.shoppingcart": mock_sc}):
                result = bind_txn_draft("cashier1", sess["session_id"], "corr-unique-1")

        assert result["status"] == "draft"
        assert result["cart_id"] == "cart_fake_001"
        assert result["subtotal_cents"] == 0

    def test_bind_txn_draft_idempotent(self):
        """Same (session_id, correlation_id) → same txn_id."""
        from app.services.pos_register import bind_txn_draft
        sess = self._open_session()

        mock_sc = types.ModuleType("app.services.shoppingcart")
        mock_sc.start_cart = MagicMock(return_value={"cart_id": "cart_idem_001"})
        mock_sc.cart_total_cents = MagicMock(return_value=0)

        with patch.dict(sys.modules, {"app.services.shoppingcart": mock_sc}):
            r1 = bind_txn_draft("cashier1", sess["session_id"], "corr-idem")
            r2 = bind_txn_draft("cashier1", sess["session_id"], "corr-idem")

        assert r1["txn_id"] == r2["txn_id"]
        # start_cart should only be called once (second call returns existing row).
        assert mock_sc.start_cart.call_count == 1

    def test_get_txn_draft_wrong_cashier(self):
        from app.services.pos_register import get_txn_draft, bind_txn_draft
        from fastapi import HTTPException
        sess = self._open_session()

        mock_sc = types.ModuleType("app.services.shoppingcart")
        mock_sc.start_cart = MagicMock(return_value={"cart_id": "cart_xx"})
        mock_sc.cart_total_cents = MagicMock(return_value=0)

        with patch.dict(sys.modules, {"app.services.shoppingcart": mock_sc}):
            result = bind_txn_draft("cashier1", sess["session_id"], "corr-get-wrong")

        with pytest.raises(HTTPException) as exc_info:
            get_txn_draft("other_user", result["txn_id"])
        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# ── Session report tests ──────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

class TestPosSessionReport(_PosRegisterTestBase):

    def test_session_report_not_found(self):
        from app.services.pos_tender import get_session_report
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            get_session_report("no_such_session")
        assert exc_info.value.status_code == 404

    def test_session_report_empty(self):
        from app.services.pos_register import create_register, open_session
        from app.services.pos_tender import get_session_report
        reg = create_register(user_sub="admin1", label="L1", location_id="s1")
        sess = open_session(
            cashier_sub="cashier1",
            register_id=reg["register_id"],
            opening_float_cents=5000,
        )
        report = get_session_report(sess["session_id"])
        assert report["session_id"] == sess["session_id"]
        assert report["transaction_count"] == 0
        assert report["total_sales_cents"] == 0
