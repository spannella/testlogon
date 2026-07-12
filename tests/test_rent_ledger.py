"""Hermetic offline tests for the RENT-LEDGER (RNT-001..RNT-005) subsystem.

Test isolation (per repo rules):
  * moto in-memory DynamoDB tables bound to the frozen ``T.billing`` and
    ``T.rent_period_markers`` handles via ``object.__setattr__`` in a
    module-scoped autouse fixture that SAVES the prior value and RESTORES it on
    teardown.
  * frozen ``S.rent_ledger_enabled`` toggled via ``object.__setattr__`` and
    restored in the same fixture.
  * lease lookups patched at ``app.services.rent_ledger._get_lease`` /
    ``_list_active_leases_for_owner`` (LSE is a stale-base sibling — its IDs are
    opaque strings here).
  * route coroutines run on a fresh ``asyncio.new_event_loop()``. No TestClient.
  * NO real AWS / network.
"""
from __future__ import annotations

import asyncio
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

import app.services.rent_ledger as rl
from app.core.settings import S
from app.core.tables import T

FIXED_TS = 1_750_000_000  # deterministic now_ts
ALICE = "alice_sub"
BOB = "bob_sub"


def _mk_table(ddb, name):
    return ddb.create_table(
        TableName=name,
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


@pytest.fixture(scope="module", autouse=True)
def _env():
    _moto = mock_aws()
    _moto.start()
    ddb = boto3.resource("dynamodb", region_name="us-east-1")
    billing = _mk_table(ddb, "billing")
    markers = _mk_table(ddb, "rent_period_markers")

    saved_billing = T.billing
    saved_markers = T.rent_period_markers
    saved_flag = S.rent_ledger_enabled
    object.__setattr__(T, "billing", billing)
    object.__setattr__(T, "rent_period_markers", markers)
    object.__setattr__(S, "rent_ledger_enabled", True)
    try:
        yield
    finally:
        object.__setattr__(T, "billing", saved_billing)
        object.__setattr__(T, "rent_period_markers", saved_markers)
        object.__setattr__(S, "rent_ledger_enabled", saved_flag)
        _moto.stop()


@pytest.fixture(autouse=True)
def _clean_tables():
    # Wipe rows between tests for isolation (module-scoped moto tables).
    for tbl in (T.billing, T.rent_period_markers):
        items = tbl.scan().get("Items", [])
        for it in items:
            tbl.delete_item(Key={"pk": it["pk"], "sk": it["sk"]})
    yield


def _lease(lease_id="L1", user_sub=ALICE, rent=100_000, status="active",
           due_day=5, grace=0, currency="usd"):
    return {
        "lease_id": lease_id,
        "user_sub": user_sub,
        "lease_number": f"LN-{lease_id}",
        "monthly_rent_cents": rent,
        "rent_due_day": due_day,
        "late_fee_grace_days": grace,
        "currency": currency,
        "property_id": "P1",
        "unit_id": "U1",
        "tenant_id": "TEN1",
        "status": status,
    }


def _billing_rows(user_sub=ALICE):
    return [
        it for it in T.billing.scan().get("Items", [])
        if it["pk"] == rl.user_pk(user_sub)
    ]


def _ledger_rows(user_sub=ALICE):
    return [r for r in _billing_rows(user_sub) if str(r["sk"]).startswith("LEDGER#")]


def _balance(user_sub=ALICE):
    return rl.ddb_get(T.billing, rl.user_pk(user_sub), "BALANCE") or {}


# ---------------------------------------------------------------------------
# RNT-001
# ---------------------------------------------------------------------------
def test_post_rent_charge_writes_ledger_row():
    with patch.object(rl, "now_ts", return_value=FIXED_TS):
        item = rl.post_rent_charge(ALICE, _lease(), period="2026-06")
    assert item["type"] == "rent_charge"
    assert item["state"] == "settled"
    assert int(item["amount_cents"]) == 100_000
    assert item["period"] == "2026-06"
    assert item["lease_id"] == "L1"
    assert item["signed_amount_cents"] == 100_000  # D1: positive for charge
    rows = _ledger_rows()
    assert len(rows) == 1
    markers = T.rent_period_markers.scan().get("Items", [])
    assert len(markers) == 1
    assert markers[0]["ledger_sk"] == item["sk"]


def test_post_rent_charge_idempotent():
    rl.post_rent_charge(ALICE, _lease(), period="2026-06")
    second = rl.post_rent_charge(ALICE, _lease(), period="2026-06")
    assert second == {"skipped": True, "reason": "already_charged", "period": "2026-06"}
    assert len(_ledger_rows()) == 1


def test_post_rent_charge_bumps_owed_settled_cents():
    rl.post_rent_charge(ALICE, _lease(lease_id="L1"), period="2026-06")
    assert int(_balance()["owed_settled_cents"]) == 100_000
    rl.post_rent_charge(ALICE, _lease(lease_id="L2", rent=50_000), period="2026-06")
    assert int(_balance()["owed_settled_cents"]) == 150_000


def test_post_rent_charge_flag_off_returns_none():
    saved = S.rent_ledger_enabled
    object.__setattr__(S, "rent_ledger_enabled", False)
    try:
        assert rl.post_rent_charge(ALICE, _lease()) is None
        assert _ledger_rows() == []
    finally:
        object.__setattr__(S, "rent_ledger_enabled", saved)


def test_zero_rent_writes_zero_row():
    item = rl.post_rent_charge(ALICE, _lease(rent=0), period="2026-06")
    assert int(item["amount_cents"]) == 0
    assert len(_ledger_rows()) == 1


def test_run_rent_charges_all_active(monkeypatch):
    leases = [_lease(lease_id="L1", user_sub=ALICE), _lease(lease_id="L2", user_sub=BOB)]
    monkeypatch.setattr(rl, "_scan_active_leases", lambda: leases)
    result = rl.run_rent_charges(period="2026-06")
    assert result["charged"] == 2
    assert result["lease_count"] == 2
    assert len(_ledger_rows(ALICE)) == 1
    assert len(_ledger_rows(BOB)) == 1


def test_run_rent_charges_skips_no_user_sub(monkeypatch):
    leases = [_lease(lease_id="L1", user_sub="")]
    monkeypatch.setattr(rl, "_scan_active_leases", lambda: leases)
    result = rl.run_rent_charges(period="2026-06")
    assert result["charged"] == 0


def test_run_rent_charges_exception_isolation(monkeypatch):
    leases = [_lease(lease_id="A", user_sub=ALICE), _lease(lease_id="B", user_sub=ALICE)]
    monkeypatch.setattr(rl, "_scan_active_leases", lambda: leases)
    real = rl.post_rent_charge

    def flaky(user_sub, lease, *, period=None):
        if lease["lease_id"] == "A":
            raise RuntimeError("boom")
        return real(user_sub, lease, period=period)

    monkeypatch.setattr(rl, "post_rent_charge", flaky)
    result = rl.run_rent_charges(period="2026-06")
    assert result["charged"] == 1


def test_start_rent_run_task_both_flags():
    saved_run = S.rent_run_enabled
    object.__setattr__(S, "rent_run_enabled", True)
    try:
        with patch.object(rl.asyncio, "ensure_future") as ef:
            rl.start_rent_run_task()
        assert ef.call_count == 1
    finally:
        object.__setattr__(S, "rent_run_enabled", saved_run)


def test_start_rent_run_task_noop_run_flag_off():
    saved_run = S.rent_run_enabled
    object.__setattr__(S, "rent_run_enabled", False)
    try:
        with patch.object(rl.asyncio, "ensure_future") as ef:
            rl.start_rent_run_task()
        assert ef.call_count == 0
    finally:
        object.__setattr__(S, "rent_run_enabled", saved_run)


def test_audit_event_on_charge():
    with patch.object(rl, "audit_event") as ae:
        rl.post_rent_charge(ALICE, _lease(), period="2026-06")
    events = [c.args[0] for c in ae.call_args_list]
    assert "rent.charge_posted" in events


def test_startup_handler_registered():
    from app.main import create_app
    app = create_app()
    names = [getattr(h, "__name__", repr(h)) for h in app.router.on_startup]
    assert "start_rent_run_task" in names


# ---------------------------------------------------------------------------
# RNT-002
# ---------------------------------------------------------------------------
def test_record_payment_writes_row():
    with patch.object(rl, "_get_lease", return_value=_lease()):
        item = rl.record_payment(ALICE, lease_id="L1", amount_cents=40_000,
                                 method="cash", period="2026-06")
    assert item["type"] == "rent_payment"
    assert item["rent_kind"] == "payment"
    assert item["signed_amount_cents"] == -40_000  # D1: negative for payment
    assert int(_balance()["payments_settled_cents"]) == 40_000


def test_record_payment_unknown_lease_404():
    from fastapi import HTTPException
    with patch.object(rl, "_get_lease", return_value=None):
        with pytest.raises(HTTPException) as ei:
            rl.record_payment(ALICE, lease_id="X", amount_cents=10, method="cash")
    assert ei.value.status_code == 404


def test_record_payment_flag_off():
    saved = S.rent_ledger_enabled
    object.__setattr__(S, "rent_ledger_enabled", False)
    try:
        assert rl.record_payment(ALICE, lease_id="L1", amount_cents=10, method="cash") is None
    finally:
        object.__setattr__(S, "rent_ledger_enabled", saved)


def _seed_charge_and_payments(charge_amt=100_000, pay_amts=(), period="2026-06"):
    with patch.object(rl, "now_ts", return_value=FIXED_TS):
        rl.post_rent_charge(ALICE, _lease(rent=charge_amt), period=period)
    with patch.object(rl, "_get_lease", return_value=_lease(rent=charge_amt)):
        for a in pay_amts:
            rl.record_payment(ALICE, lease_id="L1", amount_cents=a, method="cash", period=period)
    rows = rl.list_rent_ledger_for_lease(ALICE, "L1")
    charge = next(r for r in rows if r["rent_kind"] == "charge")
    return charge, rows


def test_derive_status_paid():
    charge, rows = _seed_charge_and_payments(100_000, (100_000,))
    assert rl.derive_charge_status(charge, payments=rows, lease=_lease()) == "paid"


def test_derive_status_partial():
    charge, rows = _seed_charge_and_payments(100_000, (40_000,))
    assert rl.derive_charge_status(charge, payments=rows, lease=_lease()) == "partial"


def test_derive_status_open_vs_overdue():
    charge, rows = _seed_charge_and_payments(100_000, ())
    lease = _lease(due_day=5, grace=0)
    # due = 2026-06-05 00:00 UTC
    due_ts = 1780617600  # 2026-06-05 00:00 UTC
    assert rl.derive_charge_status(charge, payments=rows, lease=lease, as_of_ts=due_ts - 1) == "open"
    assert rl.derive_charge_status(charge, payments=rows, lease=lease, as_of_ts=due_ts + 1) == "overdue"


def test_derive_status_voided():
    charge, rows = _seed_charge_and_payments(100_000, ())
    charge = dict(charge, state="reversed")
    assert rl.derive_charge_status(charge, payments=rows, lease=_lease()) == "voided"


def test_derive_status_reversed_payment_excluded():
    charge, rows = _seed_charge_and_payments(100_000, (100_000,))
    for r in rows:
        if r["rent_kind"] == "payment":
            r["state"] = "reversed"
    # With the only payment reversed, no payment counts -> not "paid".
    status = rl.derive_charge_status(charge, payments=rows, lease=_lease(), as_of_ts=FIXED_TS)
    assert status in {"open", "overdue"}


def test_list_rent_ledger_scopes_to_lease():
    with patch.object(rl, "now_ts", return_value=FIXED_TS):
        rl.post_rent_charge(ALICE, _lease(lease_id="L1"), period="2026-06")
        rl.post_rent_charge(ALICE, _lease(lease_id="L2"), period="2026-06")
    rows = rl.list_rent_ledger_for_lease(ALICE, "L1")
    assert all(r["lease_id"] == "L1" for r in rows)
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# RNT-003
# ---------------------------------------------------------------------------
def test_void_charge_flips_state_and_releases_marker():
    rl.post_rent_charge(ALICE, _lease(), period="2026-06")
    charge = _ledger_rows()[0]
    with patch.object(rl, "_get_lease", return_value=_lease()):
        res = rl.void_rent_row(ALICE, "L1", charge["sk"], reason="oops")
    assert res["state"] == "reversed"
    refetched = rl.ddb_get(T.billing, rl.user_pk(ALICE), charge["sk"])
    assert refetched["state"] == "reversed"  # not deleted
    assert int(_balance()["owed_settled_cents"]) == 0
    assert T.rent_period_markers.scan().get("Items", []) == []
    # marker released -> re-charge works
    again = rl.post_rent_charge(ALICE, _lease(), period="2026-06")
    assert again.get("skipped") is not True


def test_void_payment_flips_state():
    with patch.object(rl, "_get_lease", return_value=_lease()):
        pay = rl.record_payment(ALICE, lease_id="L1", amount_cents=30_000, method="cash", period="2026-06")
        res = rl.void_rent_row(ALICE, "L1", pay["sk"])
    assert res["state"] == "reversed"
    assert int(_balance()["payments_settled_cents"]) == 0


def test_void_already_voided_409():
    from fastapi import HTTPException
    rl.post_rent_charge(ALICE, _lease(), period="2026-06")
    charge = _ledger_rows()[0]
    with patch.object(rl, "_get_lease", return_value=_lease()):
        rl.void_rent_row(ALICE, "L1", charge["sk"])
        with pytest.raises(HTTPException) as ei:
            rl.void_rent_row(ALICE, "L1", charge["sk"])
    assert ei.value.status_code == 409
    assert int(_balance()["owed_settled_cents"]) == 0  # decremented exactly once


def test_void_wrong_lease_404():
    from fastapi import HTTPException
    rl.post_rent_charge(ALICE, _lease(lease_id="L1"), period="2026-06")
    charge = _ledger_rows()[0]
    with patch.object(rl, "_get_lease", return_value=_lease(lease_id="L2")):
        with pytest.raises(HTTPException) as ei:
            rl.void_rent_row(ALICE, "L2", charge["sk"])
    assert ei.value.status_code == 404


def test_list_rent_history_pagination_and_status():
    with patch.object(rl, "now_ts", return_value=FIXED_TS):
        rl.post_rent_charge(ALICE, _lease(), period="2026-06")
    with patch.object(rl, "_get_lease", return_value=_lease()):
        for p in ("2026-05", "2026-04"):
            with patch.object(rl, "now_ts", return_value=FIXED_TS):
                rl.post_rent_charge(ALICE, _lease(), period=p)
        result = rl.list_rent_history(ALICE, "L1", limit=2)
    assert result["count"] == 3
    assert len(result["rows"]) == 2
    assert result["next_cursor"] is not None
    with patch.object(rl, "_get_lease", return_value=_lease()):
        page2 = rl.list_rent_history(ALICE, "L1", limit=2, cursor=result["next_cursor"])
    assert len(page2["rows"]) == 1
    assert page2["next_cursor"] is None
    # charge rows carry status
    assert all("status" in r for r in result["rows"] if r["rent_kind"] == "charge")


def test_list_rent_history_flag_off():
    saved = S.rent_ledger_enabled
    object.__setattr__(S, "rent_ledger_enabled", False)
    try:
        assert rl.list_rent_history(ALICE, "L1") is None
    finally:
        object.__setattr__(S, "rent_ledger_enabled", saved)


# ---------------------------------------------------------------------------
# RNT-004
# ---------------------------------------------------------------------------
def test_period_summary_totals():
    rl.post_rent_charge(ALICE, _lease(rent=100_000), period="2026-06")
    with patch.object(rl, "_get_lease", return_value=_lease()):
        rl.record_payment(ALICE, lease_id="L1", amount_cents=40_000, method="cash", period="2026-06")
        with patch.object(rl, "_list_active_leases_for_owner", return_value=[_lease()]):
            s = rl.period_summary(ALICE, period="2026-06")
    assert s["charged_cents"] == 100_000
    assert s["collected_cents"] == 40_000
    assert s["outstanding_cents"] == 60_000
    assert s["due_settled_cents_all_time"] == 60_000
    assert s["aging"] is None


def test_period_summary_void_excluded():
    rl.post_rent_charge(ALICE, _lease(), period="2026-06")
    charge = _ledger_rows()[0]
    with patch.object(rl, "_get_lease", return_value=_lease()):
        rl.void_rent_row(ALICE, "L1", charge["sk"])
        with patch.object(rl, "_list_active_leases_for_owner", return_value=[]):
            s = rl.period_summary(ALICE, period="2026-06")
    assert s["charged_cents"] == 0
    assert s["outstanding_cents"] == 0


def test_period_summary_invalid_period():
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as ei:
        rl.period_summary(ALICE, period="bad")
    assert ei.value.status_code == 422


def test_period_summary_flag_off():
    saved = S.rent_ledger_enabled
    object.__setattr__(S, "rent_ledger_enabled", False)
    try:
        assert rl.period_summary(ALICE, period="2026-06") is None
    finally:
        object.__setattr__(S, "rent_ledger_enabled", saved)


def test_list_periods_default():
    ps = rl.list_periods(ALICE, count=12)
    assert len(ps) == 12
    import re as _re
    assert all(_re.match(r"^\d{4}-(0[1-9]|1[0-2])$", p) for p in ps)
    # ascending
    assert ps == sorted(ps)


def test_list_periods_clamp():
    assert len(rl.list_periods(ALICE, count=0)) == 1
    assert len(rl.list_periods(ALICE, count=100)) == 60


# ---------------------------------------------------------------------------
# RNT-005
# ---------------------------------------------------------------------------
def test_charge_lease_now_creates():
    with patch.object(rl, "_get_lease", return_value=_lease()):
        item = rl.charge_lease_now(ALICE, "L1", period="2026-06")
    assert item["type"] == "rent_charge"
    assert "skipped" not in item


def test_charge_lease_now_idempotent():
    with patch.object(rl, "_get_lease", return_value=_lease()):
        rl.charge_lease_now(ALICE, "L1", period="2026-06")
        second = rl.charge_lease_now(ALICE, "L1", period="2026-06")
    assert second["skipped"] is True


def test_charge_lease_now_409_upcoming():
    from fastapi import HTTPException
    with patch.object(rl, "_get_lease", return_value=_lease(status="upcoming")):
        with pytest.raises(HTTPException) as ei:
            rl.charge_lease_now(ALICE, "L1")
    assert ei.value.status_code == 409


def test_charge_lease_now_404_unknown():
    from fastapi import HTTPException
    with patch.object(rl, "_get_lease", return_value=None):
        with pytest.raises(HTTPException) as ei:
            rl.charge_lease_now(ALICE, "X")
    assert ei.value.status_code == 404


def test_run_rent_charges_for_owner():
    leases = [_lease(lease_id="L1"), _lease(lease_id="L2"), _lease(lease_id="L3")]
    with patch.object(rl, "_list_active_leases_for_owner", return_value=leases):
        result = rl.run_rent_charges_for_owner(ALICE, period="2026-06")
    assert result["charged"] == 3
    assert result["lease_count"] == 3
    # second run all skipped
    with patch.object(rl, "_list_active_leases_for_owner", return_value=leases):
        result2 = rl.run_rent_charges_for_owner(ALICE, period="2026-06")
    assert result2["charged"] == 0
    assert result2["skipped"] == 3


def test_run_rent_charges_for_owner_flag_off():
    saved = S.rent_ledger_enabled
    object.__setattr__(S, "rent_ledger_enabled", False)
    try:
        assert rl.run_rent_charges_for_owner(ALICE) is None
    finally:
        object.__setattr__(S, "rent_ledger_enabled", saved)


# ---------------------------------------------------------------------------
# Router (coroutines on a fresh event loop)
# ---------------------------------------------------------------------------
def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_router_charge_endpoint():
    import app.routers.rent_ledger as rr
    with patch.object(rl, "_get_lease", return_value=_lease()):
        out = _run(rr.charge_lease_now_endpoint(
            "L1", rr.RentRunTriggerIn(period="2026-06"), ctx={"user_sub": ALICE}))
    assert out["type"] == "rent_charge"


def test_router_summary_endpoint():
    import app.routers.rent_ledger as rr
    rl.post_rent_charge(ALICE, _lease(), period="2026-06")
    with patch.object(rl, "_list_active_leases_for_owner", return_value=[_lease()]):
        out = _run(rr.get_rent_summary(period="2026-06", lease_id=None, ctx={"user_sub": ALICE}))
    assert out.charged_cents == 100_000


def test_router_flag_off_404():
    from fastapi import HTTPException
    import app.routers.rent_ledger as rr
    saved = S.rent_ledger_enabled
    object.__setattr__(S, "rent_ledger_enabled", False)
    try:
        with pytest.raises(HTTPException) as ei:
            _run(rr.get_rent_periods(lease_id=None, count=12, ctx={"user_sub": ALICE}))
        assert ei.value.status_code == 404
    finally:
        object.__setattr__(S, "rent_ledger_enabled", saved)


def test_router_admin_run_root():
    import app.routers.rent_ledger as rr
    leases = [_lease(lease_id="L1", user_sub=ALICE)]
    with patch.object(rl, "_scan_active_leases", return_value=leases):
        out = _run(rr.admin_run_rent_endpoint(rr.RentRunTriggerIn(period="2026-06"), user=object()))
    assert out.charged == 1
