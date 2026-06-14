"""OBP PAY-002 — Standing orders: due-tick idempotency, conditional advance, lifecycle.

Offline/hermetic: moto in-memory ``counterparties`` + ``standing_orders`` tables bound
to the frozen ``T.*`` handles via ``object.__setattr__``. The TXR money-out collaborator
is patched at ``app.services.pay_txr_bridge.emit_counterparty_request`` (PAY's single
lazy boundary to TXR) so NO real TXR/wallet/AWS is touched and we can assert the exact
number of money emissions per occurrence.
"""
from __future__ import annotations

from unittest.mock import patch

import boto3
import pytest

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

pytestmark = pytest.mark.skipif(mock_aws is None, reason="moto not installed")


def _make_counterparties(ddb):
    return ddb.create_table(
        TableName="counterparties",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "counterparty_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "counterparty_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {"IndexName": "ByUserCreatedAt",
             "KeySchema": [{"AttributeName": "user_sub", "KeyType": "HASH"},
                           {"AttributeName": "created_at", "KeyType": "RANGE"}],
             "Projection": {"ProjectionType": "ALL"}},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_standing_orders(ddb):
    return ddb.create_table(
        TableName="standing_orders",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "standing_order_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "standing_order_id", "AttributeType": "S"},
            {"AttributeName": "GSI_DUE_PK", "AttributeType": "S"},
            {"AttributeName": "next_run_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {"IndexName": "ByDue",
             "KeySchema": [{"AttributeName": "GSI_DUE_PK", "KeyType": "HASH"},
                           {"AttributeName": "next_run_at", "KeyType": "RANGE"}],
             "Projection": {"ProjectionType": "ALL"}},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@pytest.fixture(scope="module", autouse=True)
def _bind_tables():
    if mock_aws is None:
        yield
        return
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        cp = _make_counterparties(ddb)
        so = _make_standing_orders(ddb)
        from app.core.tables import T

        orig_cp = getattr(T, "counterparties", None)
        orig_so = getattr(T, "standing_orders", None)
        object.__setattr__(T, "counterparties", cp)
        object.__setattr__(T, "standing_orders", so)
        try:
            yield
        finally:
            object.__setattr__(T, "counterparties", orig_cp)
            object.__setattr__(T, "standing_orders", orig_so)


def _mk_cp(user="alice", currency="usd"):
    from app.services import counterparties as cps

    out = cps.create_counterparty(user, {
        "name": "Payee", "is_beneficiary": True,
        "routing": {"scheme": "ACCOUNT_NUMBER", "account_number": "12345678", "currency": currency},
    })
    return out["counterparty_id"]


def test_create_computes_next_run_and_validates_counterparty():
    from app.services import standing_orders as so

    cp_id = _mk_cp()
    out = so.create_standing_order("alice", {
        "counterparty_id": cp_id, "amount_cents": 5000, "cadence": "weekly", "start_at": 1000,
    })
    assert out["status"] == "active"
    assert out["next_run_at"] is not None
    # foreign / unknown counterparty rejected
    with pytest.raises(so.StandingOrderError):
        so.create_standing_order("alice", {"counterparty_id": "cp_nope", "amount_cents": 1, "cadence": "weekly", "start_at": 1})


def test_due_tick_emits_exactly_one_request_with_idem_key():
    from app.services import standing_orders as so

    cp_id = _mk_cp()
    out = so.create_standing_order("alice", {
        "counterparty_id": cp_id, "amount_cents": 7000, "cadence": "weekly", "start_at": 1,
    })
    so_id = out["standing_order_id"]
    prev_next = so.get_standing_order("alice", so_id)["next_run_at"]

    with patch("app.services.pay_txr_bridge.emit_counterparty_request",
               return_value={"request_id": "txr_1"}) as emit:
        so.execute_due_standing_order("alice", so_id)

    assert emit.call_count == 1
    _, kwargs = emit.call_args
    assert kwargs["idempotency_key"] == f"{so_id}#{int(prev_next)}"
    assert kwargs["reason"] == "standing_order"
    # next_run_at advanced by one cadence, runs_count incremented
    after = so.get_standing_order("alice", so_id)
    assert int(after["next_run_at"]) == int(prev_next) + 7 * 86400
    assert int(after["runs_count"]) == 1


def test_retry_same_occurrence_reuses_deterministic_idem_key():
    """A scheduler retry of the SAME occurrence (same next_run_at) reuses the SAME
    deterministic idempotency_key → TXR collapses to at most ONE request/debit
    (money-safety #2). And after the first tick advances, the occurrence is gone so
    no further emit happens for it without a rewind."""
    from app.services import standing_orders as so
    from app.core.tables import T

    cp_id = _mk_cp()
    out = so.create_standing_order("alice", {
        "counterparty_id": cp_id, "amount_cents": 3000, "cadence": "weekly", "start_at": 1,
    })
    so_id = out["standing_order_id"]
    prev_next = int(so.get_standing_order("alice", so_id)["next_run_at"])

    keys = []

    def _emit(*a, **k):
        keys.append(k["idempotency_key"])
        return {"request_id": f"txr_{len(keys)}"}

    with patch("app.services.pay_txr_bridge.emit_counterparty_request", side_effect=_emit):
        so.execute_due_standing_order("alice", so_id)  # tick 1 — advances next_run_at
        # Simulate a retry of the SAME occurrence by rewinding next_run_at.
        T.standing_orders.update_item(
            Key={"user_sub": "alice", "standing_order_id": so_id},
            UpdateExpression="SET next_run_at = :p",
            ExpressionAttributeValues={":p": prev_next},
        )
        so.execute_due_standing_order("alice", so_id)  # retry of same occurrence

    # Both emits used the IDENTICAL deterministic key for the occurrence → TXR dedupes.
    assert keys == [f"{so_id}#{prev_next}", f"{so_id}#{prev_next}"]
    assert len(set(keys)) == 1  # one unique key ⇒ at most one debit at TXR


def test_concurrent_advance_only_one_wins():
    """Two ticks reading the same next_run_at: exactly one conditional advance succeeds."""
    from app.services import standing_orders as so
    from app.core.tables import T

    cp_id = _mk_cp()
    out = so.create_standing_order("alice", {
        "counterparty_id": cp_id, "amount_cents": 1000, "cadence": "weekly", "start_at": 1,
    })
    so_id = out["standing_order_id"]
    prev_next = int(so.get_standing_order("alice", so_id)["next_run_at"])
    new_next = prev_next + 7 * 86400

    # Manually perform the conditional advance twice with the SAME expected prev → 2nd fails.
    ok1 = True
    try:
        T.standing_orders.update_item(
            Key={"user_sub": "alice", "standing_order_id": so_id},
            UpdateExpression="SET next_run_at = :n",
            ConditionExpression="next_run_at = :p",
            ExpressionAttributeValues={":n": new_next, ":p": prev_next},
        )
    except Exception:
        ok1 = False
    ok2 = True
    try:
        T.standing_orders.update_item(
            Key={"user_sub": "alice", "standing_order_id": so_id},
            UpdateExpression="SET next_run_at = :n",
            ConditionExpression="next_run_at = :p",
            ExpressionAttributeValues={":n": new_next, ":p": prev_next},
        )
    except Exception:
        ok2 = False
    assert ok1 is True and ok2 is False  # exactly one wins


def test_end_at_completes_and_removes_from_due():
    from app.services import standing_orders as so

    cp_id = _mk_cp()
    out = so.create_standing_order("alice", {
        "counterparty_id": cp_id, "amount_cents": 2000, "cadence": "weekly",
        "start_at": 1, "end_at": 100,  # next occurrence (start+7d) > end_at
    })
    so_id = out["standing_order_id"]
    with patch("app.services.pay_txr_bridge.emit_counterparty_request", return_value={"request_id": "x"}):
        so.execute_due_standing_order("alice", so_id)
    after = so.get_standing_order("alice", so_id)
    assert after["status"] == "completed"
    assert "GSI_DUE_PK" not in after  # removed from ByDue index


def test_pause_resume_toggles_due_keys():
    from app.services import standing_orders as so

    cp_id = _mk_cp()
    out = so.create_standing_order("alice", {
        "counterparty_id": cp_id, "amount_cents": 2000, "cadence": "monthly", "start_at": 1,
    })
    so_id = out["standing_order_id"]
    so.pause("alice", so_id)
    paused = so.get_standing_order("alice", so_id)
    assert paused["status"] == "paused"
    assert "GSI_DUE_PK" not in paused
    so.resume("alice", so_id)
    resumed = so.get_standing_order("alice", so_id)
    assert resumed["status"] == "active"
    assert resumed.get("GSI_DUE_PK") == "DUE"


def test_query_due_only_returns_past_due():
    from app.services import standing_orders as so

    cp_id = _mk_cp("frank")
    so.create_standing_order("frank", {
        "counterparty_id": cp_id, "amount_cents": 100, "cadence": "weekly", "start_at": 1,
    })
    due = so.query_due(now=10**12)  # far future → due
    assert any(d["user_sub"] == "frank" for d in due)
    none_due = so.query_due(now=0)  # nothing due at epoch
    assert all(int(d["next_run_at"]) <= 0 for d in none_due)
