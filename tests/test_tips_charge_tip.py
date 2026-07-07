"""TIP-013 — behavior-preserving contract tests for the centralized tip seam.

Every tipping surface (messaging attached/post-hoc, newsfeed post/comment,
broadcast, video) funnels through ``app.services.tips.charge_tip`` after the
TIP-005..012 migration. These tests lock the money-path contract at that seam so
a future refactor cannot silently change what a surface credits:

  * each content_type writes a paired settled DEBIT(gross) + CREDIT(net, type
    "credit") to the right users with the 20% ``fee_tips_bps`` split (ecom Bug#3),
  * an idempotent replay (same idempotency_key) is a no-op — no double ledger,
  * self-tip / bad amount / bad content_type are rejected 400,
  * PM ownership is validated once (unknown PM -> 400; blank allowed in dev),
  * the delegate ``can_tip`` guard is default-DENY (403 without the grant).

Uses a FakeTable that mimics the DynamoDB surface charge_tip + write_tip_ledger
touch (get_item / put_item / query), same pattern as test_tip_ledger.py.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

sys.modules.setdefault("prometheus_client", MagicMock())

from botocore.exceptions import ClientError

from app.core.tables import T
from app.services import tips as tips_mod
from app.services.tips import TIP_CONTENT_TYPES, TipResult, charge_tip
from fastapi import HTTPException


# ---------------------------------------------------------------------------
# FakeTable — supports the calls charge_tip + write_tip_ledger make.
# ---------------------------------------------------------------------------
class FakeTable:
    def __init__(self) -> None:
        self.items: List[Dict[str, Any]] = []

    def _find(self, pk: str, sk: str):
        for it in self.items:
            if it.get("pk") == pk and it.get("sk") == sk:
                return it
        return None

    def get_item(self, *, Key: Dict[str, Any], **_: Any) -> Dict[str, Any]:
        it = self._find(Key.get("pk"), Key.get("sk"))
        return {"Item": it} if it is not None else {}

    def put_item(self, *, Item: Dict[str, Any], ConditionExpression: str = None, **_: Any) -> None:
        if ConditionExpression == "attribute_not_exists(sk)":
            if self._find(Item.get("pk"), Item.get("sk")) is not None:
                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "exists"}},
                    "PutItem",
                )
        self.items.append(Item)

    def query(self, *, ExpressionAttributeValues: Dict[str, str] = None, **_: Any):
        if ExpressionAttributeValues:
            pk = ExpressionAttributeValues.get(":pk", "")
            return {"Items": [i for i in self.items if i.get("pk") == pk]}
        return {"Items": list(self.items)}


@pytest.fixture(autouse=True)
def _fake_billing():
    fake = FakeTable()
    original = T.billing
    object.__setattr__(T, "billing", fake)
    yield fake
    object.__setattr__(T, "billing", original)


def _ledger(fake: FakeTable, user_id: str) -> List[Dict[str, Any]]:
    return [i for i in fake.items
            if i.get("pk") == f"USER#{user_id}" and str(i.get("sk", "")).startswith("LEDGER#")]


def _seed_pm(fake: FakeTable, user_id: str, pm_id: str) -> None:
    fake.items.append({"pk": f"USER#{user_id}", "sk": f"PM#{pm_id}", "payment_method_id": pm_id})


# ---------------------------------------------------------------------------
# Money-path: each surface credits net-of-20% to the right recipient.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("content_type", list(TIP_CONTENT_TYPES))
def test_each_surface_writes_paired_debit_and_net_credit(_fake_billing, content_type):
    fake = _fake_billing
    res = charge_tip(
        tipper_id="alice", recipient_id="bob", amount_cents=500,
        payment_method_id=None, content_type=content_type,
        content_id=f"{content_type}_1", meta={}, idempotency_key=f"k_{content_type}",
    )
    debits = [r for r in _ledger(fake, "alice") if r["type"] == "debit"]
    credits = [r for r in _ledger(fake, "bob") if r["type"] == "credit"]
    assert len(debits) == 1 and len(credits) == 1
    # DEBIT = gross, CREDIT = net (Bug#3: credit uses type "credit")
    assert debits[0]["amount_cents"] == 500 and debits[0]["type"] == "debit"
    assert credits[0]["amount_cents"] == 400 and credits[0]["type"] == "credit"
    assert debits[0].get("state") == "settled" and credits[0].get("state") == "settled"
    # Receipt reflects the 20% split.
    assert res.charged_cents == 500 and res.net_cents == 400 and res.fee_cents == 100
    assert res.recipient == "bob" and res.idempotent_replay is False
    assert res.payment_intent_id is None  # B0: mock charge, no real PaymentIntent


def test_receipt_is_tipresult_with_ledger_ids(_fake_billing):
    res = charge_tip(
        tipper_id="alice", recipient_id="bob", amount_cents=1000,
        payment_method_id=None, content_type="post", content_id="p1",
        meta={}, idempotency_key="rk1",
    )
    assert isinstance(res, TipResult)
    assert res.tip_payment_id.startswith("tip_")
    assert res.charged_cents == 1000 and res.net_cents == 800 and res.fee_cents == 200


# ---------------------------------------------------------------------------
# Idempotency: replay with the same key is a no-op (no double debit/credit).
# ---------------------------------------------------------------------------
def test_idempotent_replay_writes_no_second_ledger(_fake_billing):
    fake = _fake_billing
    r1 = charge_tip(tipper_id="alice", recipient_id="bob", amount_cents=500,
                    payment_method_id=None, content_type="message", content_id="m1",
                    meta={}, idempotency_key="dupe")
    n_debit = len([r for r in _ledger(fake, "alice") if r["type"] == "debit"])
    n_credit = len([r for r in _ledger(fake, "bob") if r["type"] == "credit"])
    r2 = charge_tip(tipper_id="alice", recipient_id="bob", amount_cents=500,
                    payment_method_id=None, content_type="message", content_id="m1",
                    meta={}, idempotency_key="dupe")
    assert r2.idempotent_replay is True
    assert r2.tip_payment_id == r1.tip_payment_id
    # No new ledger rows on replay.
    assert len([r for r in _ledger(fake, "alice") if r["type"] == "debit"]) == n_debit
    assert len([r for r in _ledger(fake, "bob") if r["type"] == "credit"]) == n_credit


# ---------------------------------------------------------------------------
# Validation guards.
# ---------------------------------------------------------------------------
def test_self_tip_rejected(_fake_billing):
    with pytest.raises(HTTPException) as e:
        charge_tip(tipper_id="alice", recipient_id="alice", amount_cents=500,
                   payment_method_id=None, content_type="post", content_id="p",
                   meta={}, idempotency_key="s1")
    assert e.value.status_code == 400


def test_invalid_content_type_rejected(_fake_billing):
    with pytest.raises(HTTPException) as e:
        charge_tip(tipper_id="alice", recipient_id="bob", amount_cents=500,
                   payment_method_id=None, content_type="not_a_type", content_id="x",
                   meta={}, idempotency_key="c1")
    assert e.value.status_code == 400


@pytest.mark.parametrize("amount", [0, -5])
def test_invalid_amount_rejected(_fake_billing, amount):
    with pytest.raises(HTTPException) as e:
        charge_tip(tipper_id="alice", recipient_id="bob", amount_cents=amount,
                   payment_method_id=None, content_type="post", content_id="p",
                   meta={}, idempotency_key=f"a_{amount}")
    assert e.value.status_code == 400


def test_unknown_payment_method_rejected(_fake_billing):
    # An explicit PM the tipper does not own -> 400 (ownership validated once).
    with pytest.raises(HTTPException) as e:
        charge_tip(tipper_id="alice", recipient_id="bob", amount_cents=500,
                   payment_method_id="pm_not_mine", content_type="post", content_id="p",
                   meta={}, idempotency_key="pm1")
    assert e.value.status_code == 400


def test_owned_payment_method_accepted(_fake_billing):
    fake = _fake_billing
    _seed_pm(fake, "alice", "pm_mine")
    res = charge_tip(tipper_id="alice", recipient_id="bob", amount_cents=500,
                     payment_method_id="pm_mine", content_type="post", content_id="p",
                     meta={}, idempotency_key="pm2")
    assert res.net_cents == 400
    debit = [r for r in _ledger(fake, "alice") if r["type"] == "debit"][0]
    assert debit["meta"].get("payment_method_id") == "pm_mine"


def test_blank_pm_allowed_in_dev(_fake_billing):
    # dev_mode preserves today's behavior: the mock charge does not require a PM.
    assert tips_mod.S.dev_mode is True
    res = charge_tip(tipper_id="alice", recipient_id="bob", amount_cents=500,
                     payment_method_id=None, content_type="post", content_id="p",
                     meta={}, idempotency_key="blank1")
    assert res.net_cents == 400


# ---------------------------------------------------------------------------
# Delegate can_tip guard — default DENY (folds prod _delegate_guard_tip).
# ---------------------------------------------------------------------------
def test_delegate_without_can_tip_forbidden(_fake_billing, monkeypatch):
    import app.services.delegates as deleg
    monkeypatch.setattr(deleg, "get_delegate", lambda c, d: {"permissions": ["can_post"]})
    with pytest.raises(HTTPException) as e:
        charge_tip(tipper_id="creator", recipient_id="bob", amount_cents=500,
                   payment_method_id=None, content_type="post", content_id="p",
                   meta={}, idempotency_key="d1", acting_delegate_id="delegateX")
    assert e.value.status_code == 403
    assert "delegate_tip_forbidden" in str(e.value.detail)


def test_delegate_missing_row_forbidden(_fake_billing, monkeypatch):
    import app.services.delegates as deleg
    monkeypatch.setattr(deleg, "get_delegate", lambda c, d: None)  # default DENY
    with pytest.raises(HTTPException) as e:
        charge_tip(tipper_id="creator", recipient_id="bob", amount_cents=500,
                   payment_method_id=None, content_type="post", content_id="p",
                   meta={}, idempotency_key="d2", acting_delegate_id="delegateY")
    assert e.value.status_code == 403


def test_delegate_with_can_tip_allowed(_fake_billing, monkeypatch):
    import app.services.delegates as deleg
    monkeypatch.setattr(deleg, "get_delegate", lambda c, d: {"permissions": ["can_tip"]})
    res = charge_tip(tipper_id="creator", recipient_id="bob", amount_cents=500,
                     payment_method_id=None, content_type="post", content_id="p",
                     meta={}, idempotency_key="d3", acting_delegate_id="delegateZ")
    assert res.net_cents == 400
