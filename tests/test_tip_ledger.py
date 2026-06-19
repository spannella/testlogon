"""Unit tests for app/services/tip_ledger.py.

Tests the TipLedgerEntry class, _reason_for_content_type, _build_meta,
and write_tip_ledger function using a FakeTable that mimics DynamoDB.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

sys.modules.setdefault("prometheus_client", MagicMock())

from app.services.tip_ledger import (
    TipLedgerEntry,
    _build_meta,
    _reason_for_content_type,
    write_tip_ledger,
)
from app.core.tables import T


# ---------------------------------------------------------------------------
# FakeTable — minimal DynamoDB table mock supporting put_item and query
# ---------------------------------------------------------------------------

class FakeTable:
    def __init__(self) -> None:
        self.items: List[Dict[str, Any]] = []

    def put_item(self, *, Item: Dict[str, Any], **_: Any) -> None:
        self.items.append(Item)

    def query(self, *, KeyConditionExpression: Any = None,
              ExpressionAttributeValues: Dict[str, str] | None = None,
              **_: Any) -> Dict[str, List[Dict[str, Any]]]:
        # Simple filter: match on pk prefix from ExpressionAttributeValues
        if ExpressionAttributeValues:
            pk = ExpressionAttributeValues.get(":pk", "")
            matched = [i for i in self.items if i.get("pk") == pk]
        else:
            matched = list(self.items)
        # Further filter by sk begins_with if KeyConditionExpression is present
        # (simplistic — only handles the pattern used in tests)
        return {"Items": matched}


@pytest.fixture(autouse=True)
def _patch_billing_table(monkeypatch):
    """Replace T.billing with a FakeTable for every test.

    Also stub out services added after this test was written that access DynamoDB
    tables not set up here:
    - collaboration_revenue.maybe_split_content_revenue → return None (no split)
    - billing_config.split_fee → return (0, amount, 0) so tip_ledger math still runs
    """
    fake = FakeTable()
    original = T.billing
    object.__setattr__(T, "billing", fake)

    # Patch split_fee to avoid billing_config DDB access
    import app.services.tip_ledger as _tl_mod
    monkeypatch.setattr(
        _tl_mod,
        "split_fee",
        lambda entry_type, amount_cents: (0, amount_cents, 0),
    )

    # Patch the lazy-imported collaboration module
    import sys, types
    _fake_collab = types.ModuleType("app.services.collaboration_revenue")
    _fake_collab.maybe_split_content_revenue = lambda **kw: None
    monkeypatch.setitem(sys.modules, "app.services.collaboration_revenue", _fake_collab)
    yield fake
    object.__setattr__(T, "billing", original)


@pytest.fixture
def billing_table(_patch_billing_table) -> FakeTable:
    return _patch_billing_table


# ---------------------------------------------------------------------------
# Helper to query items for a specific user
# ---------------------------------------------------------------------------

def _items_for_user(billing_table: FakeTable, user_id: str) -> List[Dict[str, Any]]:
    return [i for i in billing_table.items if i["pk"] == f"USER#{user_id}"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_debit_entry_written_for_tipper(billing_table: FakeTable):
    """write_tip_ledger creates debit for tipper."""
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=500, content_type="message", content_id="msg_123",
    )
    result = write_tip_ledger(entry)

    items = _items_for_user(billing_table, "alice")
    assert len(items) == 1
    assert items[0]["type"] == "debit"
    assert items[0]["amount_cents"] == 500
    assert items[0]["reason"] == "Tip: message"
    assert items[0]["entry_id"] == result["debit_entry_id"]


def test_credit_entry_written_for_recipient(billing_table: FakeTable):
    """write_tip_ledger creates credit for recipient."""
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=500, content_type="message", content_id="msg_123",
    )
    write_tip_ledger(entry)

    items = _items_for_user(billing_table, "bob")
    assert len(items) == 1
    assert items[0]["type"] == "credit"
    assert items[0]["amount_cents"] == 500


def test_debit_and_credit_have_same_amount_currency_ts(billing_table: FakeTable):
    """Debit and credit have same amount, currency, and timestamp."""
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=500, content_type="post", content_id="post_456",
    )
    write_tip_ledger(entry)

    debit = _items_for_user(billing_table, "alice")[0]
    credit = _items_for_user(billing_table, "bob")[0]

    assert debit["amount_cents"] == credit["amount_cents"]
    assert debit["currency"] == credit["currency"]
    assert debit["ts"] == credit["ts"]


def test_meta_contains_all_required_fields(billing_table: FakeTable):
    """Meta contains all required fields."""
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=500, content_type="comment", content_id="cmt_789",
        payment_method_id="pm_123",
    )
    write_tip_ledger(entry)

    debit = _items_for_user(billing_table, "alice")[0]
    meta = debit["meta"]
    assert meta["content_type"] == "comment"
    assert meta["content_id"] == "cmt_789"
    assert meta["tipper_user_id"] == "alice"
    assert meta["recipient_user_id"] == "bob"
    assert "tip_payment_id" in meta
    assert meta["payment_method_id"] == "pm_123"


def test_extra_meta_is_merged(billing_table: FakeTable):
    """Extra meta is merged into the ledger entry meta."""
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=500, content_type="message", content_id="msg_123",
        extra_meta={"conversation_id": "conv_abc"},
    )
    write_tip_ledger(entry)

    debit = _items_for_user(billing_table, "alice")[0]
    assert debit["meta"]["conversation_id"] == "conv_abc"


def test_payment_method_id_is_optional(billing_table: FakeTable):
    """Call without PM -- meta does not contain payment_method_id key."""
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=500, content_type="message", content_id="msg_123",
    )
    write_tip_ledger(entry)

    debit = _items_for_user(billing_table, "alice")[0]
    assert "payment_method_id" not in debit["meta"]


def test_reason_strings_are_correct():
    """Reason strings map correctly for all content types."""
    assert _reason_for_content_type("message") == "Tip: message"
    assert _reason_for_content_type("post") == "Tip: post"
    assert _reason_for_content_type("comment") == "Tip: comment"
    assert _reason_for_content_type("unknown") == "Tip: unknown"


def test_ddb_debit_failure_does_not_prevent_credit(billing_table: FakeTable, monkeypatch):
    """DDB failure on debit does not prevent credit write."""
    original_put = billing_table.put_item
    call_count = 0

    def failing_put(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:  # First call = debit
            raise Exception("DDB write error")
        return original_put(**kwargs)

    monkeypatch.setattr(billing_table, "put_item", failing_put)

    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=500, content_type="message", content_id="msg_123",
    )
    write_tip_ledger(entry)  # Should not raise

    # Credit should still be written
    credit_items = _items_for_user(billing_table, "bob")
    assert len(credit_items) == 1


def test_ddb_credit_failure_does_not_raise(billing_table: FakeTable, monkeypatch):
    """DDB failure on credit does not raise."""
    original_put = billing_table.put_item
    call_count = 0

    def failing_put(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 2:  # Second call = credit
            raise Exception("DDB write error")
        return original_put(**kwargs)

    monkeypatch.setattr(billing_table, "put_item", failing_put)

    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=500, content_type="message", content_id="msg_123",
    )
    result = write_tip_ledger(entry)  # Should not raise
    assert "debit_entry_id" in result
    assert "credit_entry_id" in result


def test_return_value_contains_both_entry_ids(billing_table: FakeTable):
    """Return value contains both entry IDs."""
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=500, content_type="message", content_id="msg_123",
    )
    result = write_tip_ledger(entry)
    assert isinstance(result["debit_entry_id"], str)
    assert isinstance(result["credit_entry_id"], str)
    assert len(result["debit_entry_id"]) == 32  # UUID hex
    assert result["debit_entry_id"] != result["credit_entry_id"]


def test_tip_ledger_entry_rejects_zero_amount():
    """TipLedgerEntry rejects amount_cents <= 0."""
    with pytest.raises(ValueError, match="amount_cents must be > 0"):
        TipLedgerEntry(tipper_user_id="a", recipient_user_id="b",
                       amount_cents=0, content_type="message", content_id="x")


def test_tip_ledger_entry_rejects_negative_amount():
    """TipLedgerEntry rejects negative amount_cents."""
    with pytest.raises(ValueError, match="amount_cents must be > 0"):
        TipLedgerEntry(tipper_user_id="a", recipient_user_id="b",
                       amount_cents=-100, content_type="message", content_id="x")


def test_tip_ledger_entry_rejects_invalid_content_type():
    """TipLedgerEntry rejects invalid content_type."""
    with pytest.raises(ValueError, match="Invalid content_type"):
        TipLedgerEntry(tipper_user_id="a", recipient_user_id="b",
                       amount_cents=100, content_type="video", content_id="x")


def test_build_meta_includes_all_fields():
    """_build_meta builds correct metadata dict."""
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=200, content_type="post", content_id="p_1",
        payment_method_id="pm_42", tip_payment_id="tip_abc",
        extra_meta={"post_id": "p_1"},
    )
    meta = _build_meta(entry)
    assert meta["content_type"] == "post"
    assert meta["content_id"] == "p_1"
    assert meta["tipper_user_id"] == "alice"
    assert meta["recipient_user_id"] == "bob"
    assert meta["tip_payment_id"] == "tip_abc"
    assert meta["payment_method_id"] == "pm_42"
    assert meta["post_id"] == "p_1"


def test_tip_payment_id_auto_generated():
    """tip_payment_id is auto-generated when not provided."""
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=100, content_type="message", content_id="m_1",
    )
    assert entry.tip_payment_id.startswith("tip_")
    assert len(entry.tip_payment_id) == 4 + 32  # "tip_" + uuid hex


def test_state_is_settled(billing_table: FakeTable):
    """Both entries have state='settled'."""
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=100, content_type="message", content_id="m_1",
    )
    write_tip_ledger(entry)

    for item in billing_table.items:
        assert item["state"] == "settled"


def test_sk_format(billing_table: FakeTable):
    """Sort keys follow the LEDGER#{ts}#{entry_id} pattern."""
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=100, content_type="message", content_id="m_1",
    )
    result = write_tip_ledger(entry)

    debit = _items_for_user(billing_table, "alice")[0]
    credit = _items_for_user(billing_table, "bob")[0]

    assert debit["sk"].startswith("LEDGER#")
    assert result["debit_entry_id"] in debit["sk"]
    assert credit["sk"].startswith("LEDGER#")
    assert result["credit_entry_id"] in credit["sk"]
