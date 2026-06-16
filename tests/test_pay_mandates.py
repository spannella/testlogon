"""OBP PAY-003 — Direct-debit mandates: cap enforcement, idempotency, revoke, window.

Offline/hermetic: moto ``counterparties`` + ``direct_debit_mandates`` tables bound to the
frozen ``T.*`` handles. TXR is patched at ``pay_txr_bridge.emit_counterparty_request`` so
NO real money moves and we can assert exactly when a request is (not) emitted.
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
        KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"},
                   {"AttributeName": "counterparty_id", "KeyType": "RANGE"}],
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


def _make_mandates(ddb):
    return ddb.create_table(
        TableName="direct_debit_mandates",
        KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"},
                   {"AttributeName": "mandate_id", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "mandate_id", "AttributeType": "S"},
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
        dd = _make_mandates(ddb)
        from app.core.tables import T

        orig_cp = getattr(T, "counterparties", None)
        orig_dd = getattr(T, "direct_debit_mandates", None)
        object.__setattr__(T, "counterparties", cp)
        object.__setattr__(T, "direct_debit_mandates", dd)
        try:
            yield
        finally:
            object.__setattr__(T, "counterparties", orig_cp)
            object.__setattr__(T, "direct_debit_mandates", orig_dd)


def _mk_cp(user="alice"):
    from app.services import counterparties as cps

    out = cps.create_counterparty(user, {
        "name": "Utility", "is_beneficiary": True,
        "routing": {"scheme": "ACCOUNT_NUMBER", "account_number": "55556666", "currency": "usd"},
    })
    return out["counterparty_id"]


def test_create_validates_counterparty():
    from app.services import direct_debit_mandates as dd

    cp_id = _mk_cp()
    out = dd.create_mandate("alice", {
        "counterparty_id": cp_id, "max_amount_cents": 10000, "cadence": "monthly", "start_at": 1,
    })
    assert out["status"] == "active"
    assert out["next_run_at"] is not None
    with pytest.raises(dd.MandateError):
        dd.create_mandate("alice", {"counterparty_id": "cp_x", "max_amount_cents": 1, "cadence": "monthly", "start_at": 1})


def test_within_cap_pull_emits_one_and_increments_window():
    from app.services import direct_debit_mandates as dd

    cp_id = _mk_cp()
    out = dd.create_mandate("alice", {
        "counterparty_id": cp_id, "max_amount_cents": 10000, "cadence": "monthly", "start_at": 1,
    })
    mid = out["mandate_id"]
    prev_next = int(dd.get_mandate("alice", mid)["next_run_at"])

    with patch("app.services.pay_txr_bridge.emit_counterparty_request",
               return_value={"request_id": "txr_1"}) as emit:
        res = dd.execute_mandate_pull("alice", mid, 4000)

    assert res["action"] == "debited"
    assert emit.call_count == 1
    assert emit.call_args.kwargs["idempotency_key"] == f"{mid}#{prev_next}"
    after = dd.get_mandate("alice", mid)
    assert int(after["pulled_this_window_cents"]) == 4000
    assert int(after["next_run_at"]) == prev_next + 30 * 86400


def test_over_cap_pull_emits_nothing_and_debits_nothing():
    """money-safety #4 — over-cap pull creates NO request, debits NOTHING, marked skipped."""
    from app.services import direct_debit_mandates as dd

    cp_id = _mk_cp()
    out = dd.create_mandate("alice", {
        "counterparty_id": cp_id, "max_amount_cents": 5000, "cadence": "monthly", "start_at": 1,
    })
    mid = out["mandate_id"]
    with patch("app.services.pay_txr_bridge.emit_counterparty_request") as emit:
        res = dd.execute_mandate_pull("alice", mid, 9999)  # > cap
    assert res["action"] == "skipped"
    assert res["reason"] == "cap_exceeded"
    assert emit.call_count == 0
    after = dd.get_mandate("alice", mid)
    assert int(after["pulled_this_window_cents"]) == 0  # nothing pulled


def test_cumulative_window_cap_blocks_second_pull():
    from app.services import direct_debit_mandates as dd

    cp_id = _mk_cp()
    out = dd.create_mandate("alice", {
        "counterparty_id": cp_id, "max_amount_cents": 10000, "cadence": "monthly", "start_at": 1,
    })
    mid = out["mandate_id"]
    with patch("app.services.pay_txr_bridge.emit_counterparty_request", return_value={"request_id": "x"}) as emit:
        dd.execute_mandate_pull("alice", mid, 7000)  # ok, window=7000
        res = dd.execute_mandate_pull("alice", mid, 4000)  # 7000+4000 > 10000 → blocked
    assert res["action"] == "skipped"
    assert emit.call_count == 1  # only the first pull emitted


def test_revoke_stops_further_pulls():
    from app.services import direct_debit_mandates as dd

    cp_id = _mk_cp()
    out = dd.create_mandate("alice", {
        "counterparty_id": cp_id, "max_amount_cents": 10000, "cadence": "monthly", "start_at": 1,
    })
    mid = out["mandate_id"]
    revoked = dd.revoke("alice", mid)
    assert revoked["status"] == "revoked"
    item = dd.get_mandate("alice", mid)
    assert "GSI_DUE_PK" not in item
    with patch("app.services.pay_txr_bridge.emit_counterparty_request") as emit:
        res = dd.execute_mandate_pull("alice", mid, 1000)
    assert res["action"] == "noop"
    assert emit.call_count == 0


def test_window_rollover_resets_counter(monkeypatch):
    from app.services import direct_debit_mandates as dd

    cp_id = _mk_cp()
    clock = {"t": 1000}
    monkeypatch.setattr(dd, "now_ts", lambda: clock["t"])
    out = dd.create_mandate("alice", {
        "counterparty_id": cp_id, "max_amount_cents": 6000, "cadence": "weekly", "start_at": 1000,
    })
    mid = out["mandate_id"]
    with patch("app.services.pay_txr_bridge.emit_counterparty_request", return_value={"request_id": "x"}):
        dd.execute_mandate_pull("alice", mid, 5000)  # window pulled=5000
        assert int(dd.get_mandate("alice", mid)["pulled_this_window_cents"]) == 5000
        # advance clock past one weekly window → counter resets on next pull
        clock["t"] += 7 * 86400 + 10
        dd.execute_mandate_pull("alice", mid, 5000)  # would exceed if not reset; ok after rollover
    after = dd.get_mandate("alice", mid)
    assert int(after["pulled_this_window_cents"]) == 5000  # fresh window, only the 2nd pull counted


def test_idempotency_key_deterministic_per_occurrence():
    from app.services import direct_debit_mandates as dd
    from app.core.tables import T

    cp_id = _mk_cp()
    out = dd.create_mandate("alice", {
        "counterparty_id": cp_id, "max_amount_cents": 10000, "cadence": "monthly", "start_at": 1,
    })
    mid = out["mandate_id"]
    prev_next = int(dd.get_mandate("alice", mid)["next_run_at"])
    keys = []

    def _emit(*a, **k):
        keys.append(k["idempotency_key"])
        return {"request_id": f"t{len(keys)}"}

    with patch("app.services.pay_txr_bridge.emit_counterparty_request", side_effect=_emit):
        dd.execute_mandate_pull("alice", mid, 1000)
        T.direct_debit_mandates.update_item(  # rewind occurrence
            Key={"user_sub": "alice", "mandate_id": mid},
            UpdateExpression="SET next_run_at = :p",
            ExpressionAttributeValues={":p": prev_next},
        )
        dd.execute_mandate_pull("alice", mid, 1000)
    assert keys == [f"{mid}#{prev_next}", f"{mid}#{prev_next}"]
    assert len(set(keys)) == 1
