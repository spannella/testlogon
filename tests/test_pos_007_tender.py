"""
POS-007 — card & wallet tender (hermetic offline).

Pattern mirrors tests/test_pos_backend.py / test_pos_009_010.py:
  - moto in-memory DynamoDB (pos + billing tables) bound onto the frozen
    module-level ``T`` via patch.object (SimpleNamespace).
  - ``S.pos_enabled`` toggled via object.__setattr__ and restored.
  - billing.charge_once + shoppingcart.purchase_cart + pos_receipt patched so no
    real Stripe / cart / S3 is touched. NO TestClient.
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


class _Base:
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

        import app.services.pos_tender as pos_tend
        self._patches = [
            patch.object(pos_tend, "T", self.fake_T),
            patch.object(pos_tend, "_audit", lambda *a, **kw: None),
        ]
        for p in self._patches:
            p.start()

        from app.core.settings import S
        self._S = S
        self._saved_enabled = S.pos_enabled
        object.__setattr__(S, "pos_enabled", True)

    def teardown_method(self, method):
        object.__setattr__(self._S, "pos_enabled", self._saved_enabled)
        for p in self._patches:
            p.stop()
        self._mock.stop()

    # ── seed helpers ──
    def _seed_txn(self, txn_id="txn_1", session_id="sess_1", cashier="cashier1",
                  status="draft", subtotal=1500, cart_id="cart_1"):
        self.pos_table.put_item(Item={
            "pos_pk": f"TXN#{txn_id}", "pos_sk": "META",
            "txn_id": txn_id, "session_id": session_id, "cashier_sub": cashier,
            "status": status, "cart_id": cart_id,
            "subtotal_cents": subtotal, "tax_cents": 0, "discount_cents": 0,
            "total_cents": subtotal, "created_at": 1_700_000_000, "updated_at": 1_700_000_000,
        })

    def _seed_wallet(self, cashier="cashier1", balance=2000):
        self.billing_table.put_item(Item={
            "pk": f"USER#{cashier}", "sk": "WALLET",
            "wallet_balance_cents": balance, "currency": "usd",
            "updated_at": 1_700_000_000,
        })

    def _ledger_rows(self, cashier="cashier1"):
        resp = self.billing_table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
            ExpressionAttributeValues={":pk": f"USER#{cashier}", ":p": "LEDGER#"},
        )
        return resp.get("Items", [])

    def _tender_row(self, session_id="sess_1", txn_id="txn_1"):
        return self.pos_table.get_item(
            Key={"pos_pk": f"SESSION#{session_id}", "pos_sk": f"TENDER#{txn_id}"}
        ).get("Item")


# ── card tender ────────────────────────────────────────────────────────────────

def _fake_billing(charge_return=None, charge_side_effect=None):
    """A stand-in ``app.routers.billing`` module providing only ``charge_once``.

    Injected via patch.dict(sys.modules, ...) so the lazy
    ``from app.routers.billing import charge_once`` in pos_tender resolves to
    this fake WITHOUT importing the heavy real billing router (which perturbs
    sys.modules and collides with other test modules' fixtures).
    """
    from unittest.mock import MagicMock
    mock_charge = MagicMock(name="charge_once")
    if charge_side_effect is not None:
        mock_charge.side_effect = charge_side_effect
    else:
        mock_charge.return_value = charge_return
    return SimpleNamespace(charge_once=mock_charge), mock_charge


def _collab_patches(order_id="ord_1"):
    """patch.dict-based stand-ins for the lazily-imported collaborator modules
    (shoppingcart.purchase_cart, pos_receipt.get_or_create_pos_receipt) so this
    test module never leaves real (re-imported) copies cached in sys.modules —
    which would otherwise collide with sibling test modules' module-scoped
    sys.modules snapshot fixtures (test_pos_backend / test_pos_009_010).

    Returns (patch_dict_ctx, purchase_cart_mock).
    """
    import sys
    from unittest.mock import MagicMock
    pc = MagicMock(name="purchase_cart", return_value={"order_id": order_id})
    fake_sc = SimpleNamespace(purchase_cart=pc)
    fake_rcpt = SimpleNamespace(get_or_create_pos_receipt=lambda *a, **k: {})
    ctx = patch.dict(sys.modules, {
        "app.services.shoppingcart": fake_sc,
        "app.services.pos_receipt": fake_rcpt,
    })
    return ctx, pc


class TestCardTender(_Base):

    def test_card_tender_happy_path(self):
        import sys
        from app.services.pos_tender import tender_card
        self._seed_txn()
        fake_mod, mock_charge = _fake_billing(
            charge_return={"status": "succeeded", "payment_intent_id": "pi_001"})
        charge = patch.dict(sys.modules, {"app.routers.billing": fake_mod})
        collab, _pc = _collab_patches()
        with charge, collab:
            out = tender_card(
                session_id="sess_1", txn_id="txn_1", cashier_sub="cashier1",
                amount_tendered_cents=1500, payment_method_id="pm_x",
                idempotency_key="ik_1", card_kind="visa", last4="4242",
            )
        assert out["status"] == "tendered"
        assert out["order_id"] == "ord_1"
        assert mock_charge.call_count == 1
        rows = self._ledger_rows()
        assert len(rows) == 1
        assert rows[0]["provider"] == "pos_card"
        assert rows[0]["reason"] == "pos_card_sale"
        assert int(rows[0]["signed_amount_cents"]) == -1500
        tr = self._tender_row()
        assert tr["kind"] == "card"
        assert tr["card_kind"] == "visa"
        assert tr["last4"] == "4242"
        assert tr["pi_id"] == "pi_001"

    def test_card_decline_no_side_effects(self):
        import sys
        from app.services.pos_tender import tender_card
        from fastapi import HTTPException
        self._seed_txn()
        fake_mod, _ = _fake_billing(
            charge_return={"status": "failed", "reason": "card_declined"})
        charge = patch.dict(sys.modules, {"app.routers.billing": fake_mod})
        collab, _pc = _collab_patches()
        with charge, collab:
            with pytest.raises(HTTPException) as ei:
                tender_card(
                    session_id="sess_1", txn_id="txn_1", cashier_sub="cashier1",
                    amount_tendered_cents=1500, payment_method_id="pm_x",
                    idempotency_key="ik_d",
                )
        assert ei.value.status_code == 402
        assert self._tender_row() is None
        assert self._ledger_rows() == []
        txn = self.pos_table.get_item(Key={"pos_pk": "TXN#txn_1", "pos_sk": "META"})["Item"]
        assert txn["status"] == "draft"

    def test_card_provider_disabled_503_no_side_effects(self):
        import sys
        from app.services.pos_tender import tender_card
        from fastapi import HTTPException
        self._seed_txn()

        def _raise(*a, **k):
            raise HTTPException(status_code=503, detail="provider_disabled")

        fake_mod, _ = _fake_billing(charge_side_effect=_raise)
        charge = patch.dict(sys.modules, {"app.routers.billing": fake_mod})
        collab, _pc = _collab_patches()
        with charge, collab:
            with pytest.raises(HTTPException) as ei:
                tender_card(
                    session_id="sess_1", txn_id="txn_1", cashier_sub="cashier1",
                    amount_tendered_cents=1500, payment_method_id="pm_x",
                    idempotency_key="ik_503",
                )
        assert ei.value.status_code == 503
        assert self._tender_row() is None
        assert self._ledger_rows() == []

    def test_card_tender_idempotent_re_tender(self):
        import sys
        from app.services.pos_tender import tender_card
        self._seed_txn()
        fake_mod, mock_charge = _fake_billing(
            charge_return={"status": "succeeded", "payment_intent_id": "pi_idem"})
        charge = patch.dict(sys.modules, {"app.routers.billing": fake_mod})
        collab, _pc = _collab_patches()
        with charge, collab:
            tender_card(
                session_id="sess_1", txn_id="txn_1", cashier_sub="cashier1",
                amount_tendered_cents=1500, payment_method_id="pm_x", idempotency_key="ik_1",
            )
            out2 = tender_card(
                session_id="sess_1", txn_id="txn_1", cashier_sub="cashier1",
                amount_tendered_cents=1500, payment_method_id="pm_x", idempotency_key="ik_1",
            )
        assert mock_charge.call_count == 1
        assert out2["status"] == "tendered"
        assert len(self._ledger_rows()) == 1

    def test_card_flag_off_404(self):
        from app.services.pos_tender import tender_card
        from fastapi import HTTPException
        object.__setattr__(self._S, "pos_enabled", False)
        with pytest.raises(HTTPException) as ei:
            tender_card(
                session_id="sess_1", txn_id="txn_1", cashier_sub="cashier1",
                amount_tendered_cents=1500, payment_method_id="pm_x", idempotency_key="ik",
            )
        assert ei.value.status_code == 404


# ── wallet tender ────────────────────────────────────────────────────────────

class TestWalletTender(_Base):

    def test_wallet_tender_debits_balance(self):
        from app.services.pos_tender import tender_wallet
        self._seed_txn()
        self._seed_wallet(balance=2000)
        collab, _pc = _collab_patches(order_id="ord_w")
        with collab:
            out = tender_wallet(
                session_id="sess_1", txn_id="txn_1", cashier_sub="cashier1",
                amount_tendered_cents=1500, idempotency_key="wk_1",
            )
        assert out["status"] == "tendered"
        w = self.billing_table.get_item(Key={"pk": "USER#cashier1", "sk": "WALLET"})["Item"]
        assert int(w["wallet_balance_cents"]) == 500
        rows = self._ledger_rows()
        assert len(rows) == 1
        assert rows[0]["provider"] == "pos_wallet"
        assert rows[0]["reason"] == "pos_wallet_sale"
        tr = self._tender_row()
        assert tr["kind"] == "wallet"

    def test_wallet_insufficient_rejected(self):
        from app.services.pos_tender import tender_wallet
        from fastapi import HTTPException
        self._seed_txn()
        self._seed_wallet(balance=500)  # < 1500
        collab, _pc = _collab_patches()
        with collab:
            with pytest.raises(HTTPException) as ei:
                tender_wallet(
                    session_id="sess_1", txn_id="txn_1", cashier_sub="cashier1",
                    amount_tendered_cents=1500, idempotency_key="wk_bad",
                )
        assert ei.value.status_code == 402
        w = self.billing_table.get_item(Key={"pk": "USER#cashier1", "sk": "WALLET"})["Item"]
        assert int(w["wallet_balance_cents"]) == 500
        assert self._tender_row() is None
        assert self._ledger_rows() == []
        txn = self.pos_table.get_item(Key={"pos_pk": "TXN#txn_1", "pos_sk": "META"})["Item"]
        assert txn["status"] == "draft"

    def test_wallet_flag_off_404(self):
        from app.services.pos_tender import tender_wallet
        from fastapi import HTTPException
        object.__setattr__(self._S, "pos_enabled", False)
        with pytest.raises(HTTPException) as ei:
            tender_wallet(
                session_id="sess_1", txn_id="txn_1", cashier_sub="cashier1",
                amount_tendered_cents=1500, idempotency_key="wk",
            )
        assert ei.value.status_code == 404
