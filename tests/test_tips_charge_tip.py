"""TIP-013 / TIP-506 — money-path contract tests for the centralized tip seam.

Every tipping surface (messaging attached/post-hoc, newsfeed post/comment,
broadcast, video, reactions, video-comment, pay-to-message) funnels through
``app.services.tips.charge_tip``. These tests lock the money-path contract:

  * each content_type writes ONE paired settled DEBIT(gross) + CREDIT(net, type
    "credit") to the right users with the 20% ``fee_tips_bps`` split (ecom Bug#3),
  * the debit + credit + idempotency receipt are written ATOMICALLY (TIP-501):
    a replay is a no-op (no double), and a transaction failure orphans NOTHING,
  * a FAILED charge writes no ledger rows at all,
  * ``reverse_tip`` (TIP-502) returns the money idempotently WITHOUT inflating
    earnings (reversal entries are type != "credit"),
  * self-tip / bad amount / bad content_type are rejected 400,
  * PM ownership is validated once; the delegate ``can_tip`` guard is default-DENY.

Uses a FakeTable that mimics the DynamoDB surface charge_tip + write_tip_ledger +
reverse_tip touch (get_item / put_item / query / update_item + a low-level client
``transact_write_items``), same pattern as test_tip_ledger.py.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

sys.modules.setdefault("prometheus_client", MagicMock())

from boto3.dynamodb.types import TypeDeserializer
from botocore.exceptions import ClientError

from app.core.tables import T
from app.services import tips as tips_mod
from app.services.tips import TIP_CONTENT_TYPES, TipResult, charge_tip, reverse_tip
from fastapi import HTTPException

_DESER = TypeDeserializer()


def _deser_item(av: Dict[str, Any]) -> Dict[str, Any]:
    return {k: _DESER.deserialize(v) for k, v in av.items()}


# ---------------------------------------------------------------------------
# FakeTable — supports the calls charge_tip / write_tip_ledger / reverse_tip make,
# including a low-level client with transact_write_items (TIP-501).
# ---------------------------------------------------------------------------
class _FakeDDBClient:
    """Minimal low-level client: transact_write_items with Put + conditions."""

    def __init__(self, table: "FakeTable") -> None:
        self._t = table

    def transact_write_items(self, *, TransactItems: List[Dict[str, Any]]) -> None:
        pending: List[Dict[str, Any]] = []
        # Phase 1: check every condition BEFORE applying (all-or-nothing).
        for ti in TransactItems:
            put = ti.get("Put")
            if not put:
                continue
            item = _deser_item(put["Item"])
            cond = put.get("ConditionExpression")
            if cond == "attribute_not_exists(sk)":
                if self._t._find(item.get("pk"), item.get("sk")) is not None:
                    raise ClientError(
                        {"Error": {"Code": "TransactionCanceledException",
                                   "Message": "ConditionalCheckFailed"}},
                        "TransactWriteItems",
                    )
            pending.append(item)
        # Phase 2: apply.
        for item in pending:
            self._t.items.append(item)


class FakeTable:
    def __init__(self) -> None:
        self.items: List[Dict[str, Any]] = []
        self.fail_transact = False  # test hook: simulate a non-cancellation txn error

    def _find(self, pk: str, sk: str):
        for it in self.items:
            if it.get("pk") == pk and it.get("sk") == sk:
                return it
        return None

    @property
    def meta(self) -> Any:
        client = _FakeDDBClient(self)
        if self.fail_transact:
            def _boom(**_: Any) -> None:
                raise ClientError(
                    {"Error": {"Code": "InternalServerError", "Message": "boom"}},
                    "TransactWriteItems",
                )
            client.transact_write_items = _boom  # type: ignore[assignment]
        return SimpleNamespace(client=client)

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

    def update_item(self, *, Key: Dict[str, Any], UpdateExpression: str = "",
                    ConditionExpression: str = None,
                    ExpressionAttributeNames: Dict[str, str] = None,
                    ExpressionAttributeValues: Dict[str, Any] = None, **_: Any) -> None:
        it = self._find(Key.get("pk"), Key.get("sk"))
        if ConditionExpression == "attribute_exists(sk)" and it is None:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "missing"}},
                "UpdateItem",
            )
        if it is None:
            return
        names = ExpressionAttributeNames or {}
        values = ExpressionAttributeValues or {}
        expr = UpdateExpression.strip()
        if expr.upper().startswith("SET"):
            for assign in expr[3:].split(","):
                lhs, rhs = assign.split("=")
                key = names.get(lhs.strip(), lhs.strip())
                it[key] = values.get(rhs.strip())

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
# Money-path: each surface credits net-of-20% to the right recipient (ONE pair).
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
    assert int(debits[0]["amount_cents"]) == 500 and debits[0]["type"] == "debit"
    assert int(credits[0]["amount_cents"]) == 400 and credits[0]["type"] == "credit"
    assert debits[0].get("state") == "settled" and credits[0].get("state") == "settled"
    # Receipt reflects the 20% split.
    assert res.charged_cents == 500 and res.net_cents == 400 and res.fee_cents == 100
    assert res.recipient == "bob" and res.idempotent_replay is False
    assert res.payment_intent_id is None  # dev stub: no real PaymentIntent


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
# TIP-501: idempotency + atomicity.
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
    assert n_debit == 1 and n_credit == 1


def test_atomic_race_second_writer_is_noop(_fake_billing, monkeypatch):
    """TIP-501: two identical calls both slip past the pre-charge replay read (the
    race window). The receipt-marker conditional put inside the transaction makes
    exactly ONE win the ledger write; the loser's transaction cancels on the marker
    and writes NOTHING -- no double debit/credit."""
    fake = _fake_billing
    # Force BOTH calls past the pre-charge replay read to exercise the marker race.
    monkeypatch.setattr(tips_mod, "_load_idempotent_receipt", lambda tid, key: None)
    charge_tip(tipper_id="alice", recipient_id="bob", amount_cents=500,
               payment_method_id=None, content_type="post", content_id="p",
               meta={}, idempotency_key="race")
    r2 = charge_tip(tipper_id="alice", recipient_id="bob", amount_cents=500,
                    payment_method_id=None, content_type="post", content_id="p",
                    meta={}, idempotency_key="race")
    # The loser's transaction cancelled on the marker -> it is a no-op replay.
    assert r2.idempotent_replay is True
    assert len([r for r in _ledger(fake, "alice") if r["type"] == "debit"]) == 1
    assert len([r for r in _ledger(fake, "bob") if r["type"] == "credit"]) == 1


def test_transaction_failure_orphans_nothing(_fake_billing):
    """TIP-501: a non-cancellation transaction error writes NEITHER row (no orphan
    credit without its debit). The failure surfaces to the caller."""
    fake = _fake_billing
    fake.fail_transact = True
    with pytest.raises(ClientError):
        charge_tip(tipper_id="alice", recipient_id="bob", amount_cents=500,
                   payment_method_id=None, content_type="post", content_id="p",
                   meta={}, idempotency_key="fail1")
    assert _ledger(fake, "alice") == []
    assert _ledger(fake, "bob") == []


def test_failed_charge_writes_nothing(_fake_billing, monkeypatch):
    """A declined/failed processor charge (402) must write NO ledger rows and NO
    idempotency receipt -- the money-path never reaches the ledger."""
    fake = _fake_billing

    def _decline(**_: Any):
        raise HTTPException(402, {"code": "payment_failed", "message": "declined"})

    monkeypatch.setattr(tips_mod, "_charge_tip_payment_intent", _decline)
    with pytest.raises(HTTPException) as e:
        charge_tip(tipper_id="alice", recipient_id="bob", amount_cents=500,
                   payment_method_id=None, content_type="post", content_id="p",
                   meta={}, idempotency_key="declined")
    assert e.value.status_code == 402
    assert _ledger(fake, "alice") == [] and _ledger(fake, "bob") == []
    assert not any(i.get("sk") == "TIPIDEMP#declined" for i in fake.items)


# ---------------------------------------------------------------------------
# TIP-502: reversal returns money, idempotent, does NOT inflate earnings.
# ---------------------------------------------------------------------------
def _credit_of(fake: FakeTable, user_id: str) -> Dict[str, Any]:
    return [r for r in _ledger(fake, user_id) if r["type"] == "credit"][0]


def test_reverse_tip_returns_money_without_inflating_earnings(_fake_billing):
    fake = _fake_billing
    res = charge_tip(tipper_id="alice", recipient_id="bob", amount_cents=500,
                     payment_method_id=None, content_type="post", content_id="p1",
                     meta={}, idempotency_key="rv1")
    credit = _credit_of(fake, "bob")
    n_credits_before = len([r for r in _ledger(fake, "bob") if r["type"] == "credit"])

    rev = reverse_tip(
        tipper_id="alice", recipient_id="bob", gross_cents=500, net_cents=400,
        tip_payment_id=res.tip_payment_id, content_type="post", content_id="p1",
        credit_entry_id=res.credit_entry_id, credit_ts=int(credit["ts"]),
        reason="admin_reversal",
    )
    assert rev.refunded_cents == 500 and rev.clawback_cents == 400
    assert rev.idempotent_replay is False

    # Money returned: tipper has a REFUND entry (gross), recipient a REVERSAL entry (net).
    refunds = [r for r in _ledger(fake, "alice") if r["type"] == "refund"]
    reversals = [r for r in _ledger(fake, "bob") if r["type"] == "reversal"]
    assert len(refunds) == 1 and int(refunds[0]["amount_cents"]) == 500
    assert len(reversals) == 1 and int(reversals[0]["amount_cents"]) == 400

    # Earnings NOT inflated: no NEW type=="credit" entries anywhere.
    assert len([r for r in _ledger(fake, "bob") if r["type"] == "credit"]) == n_credits_before
    assert [r for r in _ledger(fake, "alice") if r["type"] == "credit"] == []

    # Balance clawed back: the original credit is flipped to state=="reversed"
    # (get_available_balance excludes state=="reversed" credits).
    assert _credit_of(fake, "bob")["state"] == "reversed"


def test_reverse_tip_is_idempotent(_fake_billing):
    fake = _fake_billing
    res = charge_tip(tipper_id="alice", recipient_id="bob", amount_cents=500,
                     payment_method_id=None, content_type="post", content_id="p1",
                     meta={}, idempotency_key="rv2")
    kw = dict(tipper_id="alice", recipient_id="bob", gross_cents=500, net_cents=400,
              tip_payment_id=res.tip_payment_id, content_type="post", content_id="p1")
    r1 = reverse_tip(**kw)
    r2 = reverse_tip(**kw)
    assert r1.idempotent_replay is False and r2.idempotent_replay is True
    # Exactly ONE reversal + ONE refund entry (no double-reversal).
    assert len([r for r in _ledger(fake, "bob") if r["type"] == "reversal"]) == 1
    assert len([r for r in _ledger(fake, "alice") if r["type"] == "refund"]) == 1


def test_reversal_entries_are_never_type_credit(_fake_billing):
    fake = _fake_billing
    res = charge_tip(tipper_id="alice", recipient_id="bob", amount_cents=1000,
                     payment_method_id=None, content_type="video", content_id="v1",
                     meta={}, idempotency_key="rv3")
    reverse_tip(tipper_id="alice", recipient_id="bob", gross_cents=1000, net_cents=800,
                tip_payment_id=res.tip_payment_id, content_type="video", content_id="v1")
    for uid in ("alice", "bob"):
        for r in _ledger(fake, uid):
            if r["type"] == "credit":
                # the only credit is the ORIGINAL tip credit to bob, not a reversal artifact
                assert r["meta"].get("reversal_of") is None


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
