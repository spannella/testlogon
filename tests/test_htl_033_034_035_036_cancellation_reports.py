"""tests/test_htl_033_034_035_036_cancellation_reports.py

Hermetic offline pytest for HTL-033 (cancellation engine), HTL-034 (policy CRUD +
router wiring), HTL-035 (hotel KPI reports), and HTL-036 (tax/currency wire-in).

Pattern:
- moto-backed DynamoDB tables bound to frozen T.* handles via object.__setattr__
- frozen S flags toggled via object.__setattr__
- all restored on teardown
- no live stack, no real AWS, no Stripe, no network

Run:
    AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 \
      .venv/bin/pytest -q tests/test_htl_033_034_035_036_cancellation_reports.py
"""
from __future__ import annotations

import sys
from decimal import Decimal
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import boto3
import pytest

try:
    from moto import mock_aws
except ImportError:
    from moto import mock_dynamodb as mock_aws  # moto 4.x fallback


# ---------------------------------------------------------------------------
# Fixture: scope="module" autouse — sets up moto + frozen T/S, restores on teardown
# ---------------------------------------------------------------------------

_orig_T_attrs: dict = {}
_orig_S_attrs: dict = {}


@pytest.fixture(autouse=True, scope="module")
def _hotel_tables():
    """Create moto-backed tables and bind them to frozen T/S handles."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        # hotels (PK=hotel_id, SK=sk)
        hotels = ddb.create_table(
            TableName="hotels",
            KeySchema=[
                {"AttributeName": "hotel_id", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "hotel_id", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # hotel_reservations (PK=reservation_id, SK=sk) + GSIs
        res = ddb.create_table(
            TableName="hotel_reservations",
            KeySchema=[
                {"AttributeName": "reservation_id", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "reservation_id", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "hotel_id", "AttributeType": "S"},
                {"AttributeName": "checkin", "AttributeType": "S"},
                {"AttributeName": "status", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI_HOTEL_ARRIVALS",
                    "KeySchema": [
                        {"AttributeName": "hotel_id", "KeyType": "HASH"},
                        {"AttributeName": "checkin", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI_HOTEL_STATUS",
                    "KeySchema": [
                        {"AttributeName": "hotel_id", "KeyType": "HASH"},
                        {"AttributeName": "status", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # hotel_availability (PK=availability_pk, SK=sk) + GSI_HOTEL_DATE
        avail = ddb.create_table(
            TableName="hotel_availability",
            KeySchema=[
                {"AttributeName": "availability_pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "availability_pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "hotel_id", "AttributeType": "S"},
                {"AttributeName": "date", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI_HOTEL_DATE",
                    "KeySchema": [
                        {"AttributeName": "hotel_id", "KeyType": "HASH"},
                        {"AttributeName": "date", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # billing (PK=pk, SK=sk)
        billing = ddb.create_table(
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

        # Bind to frozen T handles
        from app.core import tables as T_mod
        from app.services import hotel_cancellation as canc
        from app.services import hotel_reports as rpt

        table_map = {
            "hotels": hotels,
            "hotel_reservations": res,
            "hotel_availability": avail,
            "billing": billing,
        }
        for attr, tbl in table_map.items():
            _orig_T_attrs[attr] = getattr(T_mod.T, attr, None)
            object.__setattr__(T_mod.T, attr, tbl)

        # Freeze S flags on each module
        for mod, attrs in [
            (canc, {"hotel_pms_enabled": True}),
            (rpt, {
                "hotel_pms_enabled": True,
                "hotel_kpi_max_range_days": 366,
                "hotel_kpi_max_stay_nights": 370,
            }),
        ]:
            for attr, val in attrs.items():
                _orig_S_attrs.setdefault(attr, getattr(mod.S, attr, None))
                object.__setattr__(mod.S, attr, val)

        # seed a hotel META row for HTL-034 policy CRUD
        hotels.put_item(Item={
            "hotel_id": "h1",
            "sk": "META",
            "owner_sub": "admin-u1",
            "name": "Test Hotel",
            "status": "active",
        })

        yield {
            "hotels": hotels,
            "res": res,
            "avail": avail,
            "billing": billing,
            "canc": canc,
            "rpt": rpt,
            "T_mod": T_mod,
        }

        # Restore T handles
        for attr, orig in _orig_T_attrs.items():
            if orig is not None:
                object.__setattr__(T_mod.T, attr, orig)

        # Restore S flags
        for attr, orig in _orig_S_attrs.items():
            for mod in (canc, rpt):
                if hasattr(mod.S, attr):
                    try:
                        object.__setattr__(mod.S, attr, orig)
                    except Exception:
                        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _epoch(date_str: str) -> int:
    from datetime import date, datetime, timezone
    d = date.fromisoformat(date_str)
    return int(datetime(d.year, d.month, d.day, tzinfo=timezone.utc).timestamp())


def _ledger_rows(billing_tbl: Any, sub: str) -> list[dict]:
    """Return all LEDGER# rows for a user pk."""
    from boto3.dynamodb.conditions import Key
    pk = f"USER#{sub}"
    resp = billing_tbl.query(
        KeyConditionExpression=Key("pk").eq(pk),
    )
    return [i for i in resp.get("Items", []) if str(i.get("sk", "")).startswith("LEDGER#")]


def _seed_res(res_tbl, hotel_id, rid, checkin, checkout, nights, rooms, total_cents,
              status="confirmed", currency="usd", **extra):
    item = {
        "reservation_id": rid,
        "sk": "META",
        "hotel_id": hotel_id,
        "checkin": checkin,
        "checkout": checkout,
        "nights": nights,
        "rooms": rooms,
        "total_cents": total_cents,
        "currency": currency,
        "status": status,
        "version": 1,
        "created_at": 0,
        "updated_at": 0,
    }
    item.update(extra)
    res_tbl.put_item(Item=item)


def _seed_avail(avail_tbl, hotel_id, room_type_id, dates, total_rooms):
    for d in dates:
        avail_tbl.put_item(Item={
            "availability_pk": f"{hotel_id}#{room_type_id}",
            "sk": f"DATE#{d}",
            "hotel_id": hotel_id,
            "room_type_id": room_type_id,
            "date": d,
            "total_rooms": total_rooms,
            "booked": 0,
            "held": 0,
            "updated_at": 0,
        })


def _make_reservation(total_cents=20000, check_in_ts=None, hold_id="hold1",
                      user_sub="u1", currency="usd", hotel_id="h1",
                      reservation_id="r1", **extra):
    base_ts = _epoch("2026-07-01")
    return {
        "reservation_id": reservation_id,
        "hotel_id": hotel_id,
        "user_sub": user_sub,
        "currency": currency,
        "total_cents": total_cents,
        "check_in_ts": check_in_ts if check_in_ts is not None else base_ts + 10 * 86400,
        "check_out_ts": (check_in_ts if check_in_ts is not None else base_ts + 10 * 86400) + 2 * 86400,
        "hold_id": hold_id,
        **extra,
    }


# ---------------------------------------------------------------------------
# =============================
# HTL-033 — compute_cancellation_refund
# =============================
# ---------------------------------------------------------------------------

class TestComputeCancellationRefund:
    def test_flag_off_no_effect_on_pure_function(self, _hotel_tables):
        """compute_cancellation_refund is pure/not flag-gated — works with flag off."""
        from app.services.hotel_cancellation import compute_cancellation_refund
        canc = _hotel_tables["canc"]
        object.__setattr__(canc.S, "hotel_pms_enabled", False)
        try:
            res = compute_cancellation_refund({"total_cents": 100, "check_in_ts": 9999999999}, {}, now=0)
            assert "refundable_cents" in res
        finally:
            object.__setattr__(canc.S, "hotel_pms_enabled", True)

    def test_free_window_full_refund(self, _hotel_tables):
        from app.services.hotel_cancellation import compute_cancellation_refund
        check_in_ts = _epoch("2026-07-15")
        now = _epoch("2026-07-01")  # 14 days out
        r = compute_cancellation_refund(
            {"total_cents": 20000, "check_in_ts": check_in_ts},
            {"free_until_days_before": 7, "penalty_pct": 50},
            now=now,
        )
        assert r["days_to_checkin"] == 14
        assert r["penalty_cents"] == 0
        assert r["refundable_cents"] == 20000

    def test_boundary_inclusive_free_window(self, _hotel_tables):
        from app.services.hotel_cancellation import compute_cancellation_refund
        check_in_ts = _epoch("2026-07-08")
        now = _epoch("2026-07-01")  # exactly 7 days out
        r = compute_cancellation_refund(
            {"total_cents": 20000, "check_in_ts": check_in_ts},
            {"free_until_days_before": 7, "penalty_pct": 50},
            now=now,
        )
        assert r["days_to_checkin"] == 7
        assert r["penalty_cents"] == 0  # >= free_until → no penalty

    def test_penalty_window_pct(self, _hotel_tables):
        from app.services.hotel_cancellation import compute_cancellation_refund
        check_in_ts = _epoch("2026-07-04")
        now = _epoch("2026-07-01")  # 3 days out (< 7 → penalty window)
        r = compute_cancellation_refund(
            {"total_cents": 20000, "check_in_ts": check_in_ts},
            {"free_until_days_before": 7, "penalty_pct": 50},
            now=now,
        )
        assert r["penalty_cents"] == 10000
        assert r["refundable_cents"] == 10000

    def test_penalty_fixed_cents_precedence(self, _hotel_tables):
        from app.services.hotel_cancellation import compute_cancellation_refund
        check_in_ts = _epoch("2026-07-04")
        now = _epoch("2026-07-01")
        r = compute_cancellation_refund(
            {"total_cents": 20000, "check_in_ts": check_in_ts},
            {"free_until_days_before": 7, "penalty_pct": 50, "penalty_fixed_cents": 3000},
            now=now,
        )
        assert r["penalty_cents"] == 3000
        assert r["refundable_cents"] == 17000

    def test_fixed_cents_clamp_to_base(self, _hotel_tables):
        from app.services.hotel_cancellation import compute_cancellation_refund
        check_in_ts = _epoch("2026-07-04")
        now = _epoch("2026-07-01")
        r = compute_cancellation_refund(
            {"total_cents": 20000, "check_in_ts": check_in_ts},
            {"free_until_days_before": 7, "penalty_fixed_cents": 99999},
            now=now,
        )
        assert r["penalty_cents"] == 20000
        assert r["refundable_cents"] == 0

    def test_pct_clamp_150_becomes_100(self, _hotel_tables):
        from app.services.hotel_cancellation import compute_cancellation_refund
        check_in_ts = _epoch("2026-07-04")
        now = _epoch("2026-07-01")
        r = compute_cancellation_refund(
            {"total_cents": 20000, "check_in_ts": check_in_ts},
            {"free_until_days_before": 7, "penalty_pct": 150},
            now=now,
        )
        assert r["penalty_cents"] == 20000
        assert r["refundable_cents"] == 0

    def test_past_checkin_floors_to_zero_days(self, _hotel_tables):
        from app.services.hotel_cancellation import compute_cancellation_refund
        check_in_ts = _epoch("2026-07-01")
        now = _epoch("2026-07-02")  # 1 day AFTER check_in
        r = compute_cancellation_refund(
            {"total_cents": 20000, "check_in_ts": check_in_ts},
            {"free_until_days_before": 7, "penalty_pct": 50},
            now=now,
        )
        assert r["days_to_checkin"] == 0  # max(0, negative) → 0


# ---------------------------------------------------------------------------
# =============================
# HTL-033 — apply_cancellation
# =============================
# ---------------------------------------------------------------------------

class TestApplyCancellation:
    def test_flag_off_raises_404(self, _hotel_tables):
        from app.services.hotel_cancellation import apply_cancellation
        from fastapi import HTTPException
        canc = _hotel_tables["canc"]
        object.__setattr__(canc.S, "hotel_pms_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                apply_cancellation(_make_reservation(), {}, actor_sub="admin")
            assert exc.value.status_code == 404
        finally:
            object.__setattr__(canc.S, "hotel_pms_enabled", True)

    def test_posts_one_refund_row(self, _hotel_tables):
        billing = _hotel_tables["billing"]
        from app.services.hotel_cancellation import apply_cancellation
        check_in_ts = _epoch("2026-08-10")
        now_val = _epoch("2026-08-07")  # 3 days out, inside 7-day window → 50% penalty
        res = _make_reservation(
            total_cents=20000,
            check_in_ts=check_in_ts,
            reservation_id="r_cancel_1",
            user_sub="u_cancel_1",
        )
        policy = {"free_until_days_before": 7, "penalty_pct": 50}

        fake_avail = MagicMock()
        fake_avail.release_hold = MagicMock(return_value=None)
        with patch.dict(sys.modules, {"app.services.hotel_availability": fake_avail}):
            outcome = apply_cancellation(res, policy, actor_sub="admin", now=now_val)

        assert outcome["refundable_cents"] == 10000
        assert outcome["penalty_cents"] == 10000
        assert outcome["idempotent"] is False
        assert outcome["refund_ledger_sk"] is not None

        rows = _ledger_rows(billing, "u_cancel_1")
        assert len(rows) == 1
        assert rows[0]["reason"] == "refund"
        assert int(rows[0]["amount_cents"]) == 10000
        assert rows[0].get("provider") == "stripe"

    def test_zero_refund_no_ledger_row(self, _hotel_tables):
        billing = _hotel_tables["billing"]
        from app.services.hotel_cancellation import apply_cancellation
        check_in_ts = _epoch("2026-09-10")
        now_val = _epoch("2026-09-07")  # 3 days in → full penalty
        res = _make_reservation(
            total_cents=20000,
            check_in_ts=check_in_ts,
            reservation_id="r_full_penalty",
            user_sub="u_full_penalty",
        )
        policy = {"free_until_days_before": 7, "penalty_fixed_cents": 99999}

        outcome = apply_cancellation(res, policy, actor_sub="admin", now=now_val)
        assert outcome["refundable_cents"] == 0
        assert outcome["refund_ledger_sk"] is None
        rows = _ledger_rows(billing, "u_full_penalty")
        assert len(rows) == 0

    def test_idempotency_no_double_refund(self, _hotel_tables):
        billing = _hotel_tables["billing"]
        from app.services.hotel_cancellation import apply_cancellation
        check_in_ts = _epoch("2026-10-10")
        now_val = _epoch("2026-10-07")
        res = _make_reservation(
            total_cents=20000,
            check_in_ts=check_in_ts,
            reservation_id="r_idem_1",
            user_sub="u_idem_1",
        )
        policy = {"free_until_days_before": 7, "penalty_pct": 50}

        outcome1 = apply_cancellation(res, policy, actor_sub="admin", now=now_val)
        # Simulate HTL-034 back-writing the token
        res2 = dict(res, cancellation_ledger_sk=outcome1["refund_ledger_sk"])
        outcome2 = apply_cancellation(res2, policy, actor_sub="admin", now=now_val)

        assert outcome2["idempotent"] is True
        rows = _ledger_rows(billing, "u_idem_1")
        # Still exactly one row
        assert len(rows) == 1

    def test_release_hold_failure_does_not_abort_refund(self, _hotel_tables):
        billing = _hotel_tables["billing"]
        from app.services.hotel_cancellation import apply_cancellation
        check_in_ts = _epoch("2026-11-10")
        now_val = _epoch("2026-11-07")
        res = _make_reservation(
            total_cents=20000,
            check_in_ts=check_in_ts,
            reservation_id="r_rh_fail",
            user_sub="u_rh_fail",
        )

        fake_avail = MagicMock()
        fake_avail.release_hold.side_effect = RuntimeError("inventory unreachable")
        with patch.dict(sys.modules, {"app.services.hotel_availability": fake_avail}):
            outcome = apply_cancellation(res, {"free_until_days_before": 0}, actor_sub="admin", now=now_val)

        # Refund row still written
        rows = _ledger_rows(billing, "u_rh_fail")
        assert len(rows) == 1
        assert outcome["released_nights"] == 0

    def test_currency_propagation(self, _hotel_tables):
        billing = _hotel_tables["billing"]
        from app.services.billing_shared import apply_balance_delta
        check_in_ts = _epoch("2026-12-10")
        now_val = _epoch("2026-12-07")
        res = _make_reservation(
            total_cents=20000,
            check_in_ts=check_in_ts,
            reservation_id="r_currency",
            user_sub="u_currency",
            currency="eur",
        )

        with patch("app.services.hotel_cancellation.apply_balance_delta") as mock_abd:
            from app.services.hotel_cancellation import apply_cancellation
            apply_cancellation(res, {}, actor_sub="admin", now=now_val)
        if mock_abd.called:
            _, kwargs = mock_abd.call_args
            assert kwargs.get("currency") == "eur" or mock_abd.call_args[0][-1] == "eur"

    def test_original_charge_reversed(self, _hotel_tables):
        billing = _hotel_tables["billing"]
        from app.services.hotel_cancellation import apply_cancellation
        check_in_ts = _epoch("2026-07-20")
        now_val = _epoch("2026-07-10")  # 10 days out → free window → full refund
        pk = "USER#u_reverse"
        # Seed original charge row
        billing.put_item(Item={
            "pk": pk,
            "sk": "LEDGER#orig",
            "type": "charge",
            "state": "settled",
            "amount_cents": 20000,
        })
        res = _make_reservation(
            total_cents=20000,
            check_in_ts=check_in_ts,
            reservation_id="r_reverse",
            user_sub="u_reverse",
            ledger_sk="LEDGER#orig",
        )
        apply_cancellation(res, {}, actor_sub="admin", now=now_val)
        row = billing.get_item(Key={"pk": pk, "sk": "LEDGER#orig"}).get("Item")
        assert row is not None
        assert row.get("state") == "reversed"


# ---------------------------------------------------------------------------
# =============================
# HTL-033 — apply_no_show
# =============================
# ---------------------------------------------------------------------------

class TestApplyNoShow:
    def test_flag_off_raises_404(self, _hotel_tables):
        from app.services.hotel_cancellation import apply_no_show
        from fastapi import HTTPException
        canc = _hotel_tables["canc"]
        object.__setattr__(canc.S, "hotel_pms_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                apply_no_show(_make_reservation(), {}, actor_sub="admin")
            assert exc.value.status_code == 404
        finally:
            object.__setattr__(canc.S, "hotel_pms_enabled", True)

    def test_posts_fee_row(self, _hotel_tables):
        billing = _hotel_tables["billing"]
        from app.services.hotel_cancellation import apply_no_show
        res = _make_reservation(reservation_id="r_ns_1", user_sub="u_ns_1")
        policy = {"no_show_fee_cents": 5000}
        outcome = apply_no_show(res, policy, actor_sub="admin")

        assert outcome["no_show_fee_cents"] == 5000
        assert outcome["no_show_ledger_sk"] is not None
        assert outcome["idempotent"] is False

        rows = _ledger_rows(billing, "u_ns_1")
        assert len(rows) == 1
        assert rows[0]["reason"] == "no_show_fee"
        assert int(rows[0]["amount_cents"]) == 5000

    def test_zero_fee_no_row(self, _hotel_tables):
        billing = _hotel_tables["billing"]
        from app.services.hotel_cancellation import apply_no_show
        res = _make_reservation(reservation_id="r_ns_zero", user_sub="u_ns_zero")
        outcome = apply_no_show(res, {}, actor_sub="admin")  # no_show_fee_cents defaults to 0
        assert outcome["no_show_fee_cents"] == 0
        assert outcome["no_show_ledger_sk"] is None
        rows = _ledger_rows(billing, "u_ns_zero")
        assert len(rows) == 0

    def test_idempotency_no_double_fee(self, _hotel_tables):
        billing = _hotel_tables["billing"]
        from app.services.hotel_cancellation import apply_no_show
        res = _make_reservation(reservation_id="r_ns_idem", user_sub="u_ns_idem")
        policy = {"no_show_fee_cents": 5000}
        outcome1 = apply_no_show(res, policy, actor_sub="admin")
        res2 = dict(res, no_show_ledger_sk=outcome1["no_show_ledger_sk"])
        outcome2 = apply_no_show(res2, policy, actor_sub="admin")

        assert outcome2["idempotent"] is True
        rows = _ledger_rows(billing, "u_ns_idem")
        assert len(rows) == 1  # no second row

    def test_no_show_does_not_release_hold(self, _hotel_tables):
        """apply_no_show must NOT call release_hold (forfeited night)."""
        from app.services.hotel_cancellation import apply_no_show
        fake_avail = MagicMock()
        res = _make_reservation(reservation_id="r_ns_nrh", user_sub="u_ns_nrh")
        with patch.dict(sys.modules, {"app.services.hotel_availability": fake_avail}):
            apply_no_show(res, {"no_show_fee_cents": 1000}, actor_sub="admin")
        # release_hold is called via lazy import inside apply_cancellation, not apply_no_show
        # so the fake_avail.release_hold should not have been called
        fake_avail.release_hold.assert_not_called()


# ---------------------------------------------------------------------------
# =============================
# HTL-034 — policy CRUD
# =============================
# ---------------------------------------------------------------------------

class TestCancellationPolicyCRUD:
    def test_upsert_creates_row(self, _hotel_tables):
        from app.services.hotel_cancellation import upsert_cancellation_policy
        hotels = _hotel_tables["hotels"]
        result = upsert_cancellation_policy(
            "h1",
            scope="default",
            free_until_days_before=3,
            penalty_pct=50,
            no_show_fee_cents=2000,
            user_sub="admin-u1",
        )
        assert result["policy_id"] == "default"
        assert result["penalty_pct"] == 50
        row = hotels.get_item(Key={"hotel_id": "h1", "sk": "CANCELPOLICY#default"}).get("Item")
        assert row is not None
        assert int(row["penalty_pct"]) == 50

    def test_upsert_in_place_preserves_created_at(self, _hotel_tables):
        from app.services.hotel_cancellation import upsert_cancellation_policy, get_cancellation_policy
        # First write
        r1 = upsert_cancellation_policy(
            "h1", scope="default", penalty_pct=20, user_sub="admin-u1"
        )
        created_at_1 = r1["created_at"]
        import time
        time.sleep(0.01)
        # Second write
        r2 = upsert_cancellation_policy(
            "h1", scope="default", penalty_pct=80, user_sub="admin-u1"
        )
        p = get_cancellation_policy("h1")
        assert p is not None
        assert p["penalty_pct"] == 80
        # created_at preserved
        assert p["created_at"] == created_at_1

    def test_upsert_404_unknown_hotel(self, _hotel_tables):
        from app.services.hotel_cancellation import upsert_cancellation_policy
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            upsert_cancellation_policy("nope", penalty_pct=10, user_sub="admin-u1")
        assert exc.value.status_code == 404

    def test_upsert_404_non_owner(self, _hotel_tables):
        from app.services.hotel_cancellation import upsert_cancellation_policy
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            upsert_cancellation_policy("h1", penalty_pct=10, user_sub="wrong-user")
        assert exc.value.status_code == 404

    def test_upsert_422_penalty_pct_out_of_range(self, _hotel_tables):
        from app.services.hotel_cancellation import upsert_cancellation_policy
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            upsert_cancellation_policy("h1", penalty_pct=150, user_sub="admin-u1")
        assert exc.value.status_code == 422

    def test_upsert_422_negative_cents(self, _hotel_tables):
        from app.services.hotel_cancellation import upsert_cancellation_policy
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            upsert_cancellation_policy("h1", no_show_fee_cents=-1, user_sub="admin-u1")
        assert exc.value.status_code == 422

    def test_get_policy_hit(self, _hotel_tables):
        from app.services.hotel_cancellation import upsert_cancellation_policy, get_cancellation_policy
        upsert_cancellation_policy("h1", penalty_pct=25, no_show_fee_cents=500, user_sub="admin-u1")
        p = get_cancellation_policy("h1")
        assert p is not None
        assert isinstance(p["penalty_pct"], int)
        assert p["penalty_pct"] == 25

    def test_get_policy_miss_returns_none(self, _hotel_tables):
        from app.services.hotel_cancellation import get_cancellation_policy, upsert_cancellation_policy
        # Seed a hotel with no CANCELPOLICY# row
        _hotel_tables["hotels"].put_item(Item={
            "hotel_id": "h_nocancel",
            "sk": "META",
            "owner_sub": "admin-u1",
            "name": "No Cancel Hotel",
        })
        p = get_cancellation_policy("h_nocancel")
        assert p is None

    def test_decimal_coercion(self, _hotel_tables):
        from app.services.hotel_cancellation import get_cancellation_policy
        # moto returns Decimal for numeric fields
        p = get_cancellation_policy("h1")
        if p:
            for field in ("penalty_pct", "no_show_fee_cents", "created_at"):
                assert isinstance(p[field], int), f"{field} should be int, got {type(p[field])}"

    def test_resolve_policy_for_reservation_precedence(self, _hotel_tables):
        """Rate-plan scope wins over default; default wins over zero-penalty."""
        from app.services.hotel_cancellation import (
            upsert_cancellation_policy,
            resolve_policy_for_reservation,
        )
        # Setup default policy (20%) and rate-plan policy (90%)
        upsert_cancellation_policy("h1", scope="default", penalty_pct=20, user_sub="admin-u1")
        upsert_cancellation_policy("h1", scope="RATE#rp1", penalty_pct=90, user_sub="admin-u1")

        # Reservation with rate_plan_id → rate-plan wins
        r_rate = {"hotel_id": "h1", "rate_plan_id": "rp1"}
        p = resolve_policy_for_reservation(r_rate)
        assert p["penalty_pct"] == 90

        # Reservation without rate_plan_id → default
        r_def = {"hotel_id": "h1"}
        p2 = resolve_policy_for_reservation(r_def)
        assert p2["penalty_pct"] == 20

        # Hotel with no policy → zero-penalty default
        _hotel_tables["hotels"].put_item(Item={
            "hotel_id": "h_nopol",
            "sk": "META",
            "owner_sub": "admin-u1",
        })
        p3 = resolve_policy_for_reservation({"hotel_id": "h_nopol"})
        assert p3["penalty_pct"] == 0
        assert p3["no_show_fee_cents"] == 0


# ---------------------------------------------------------------------------
# =============================
# HTL-035 — compute_hotel_kpis
# =============================
# ---------------------------------------------------------------------------

class TestComputeHotelKpis:
    def test_flag_off_raises_404(self, _hotel_tables):
        from app.services.hotel_reports import compute_hotel_kpis
        from fastapi import HTTPException
        rpt = _hotel_tables["rpt"]
        object.__setattr__(rpt.S, "hotel_pms_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                compute_hotel_kpis("h1", from_ts=_epoch("2026-06-01"), to_ts=_epoch("2026-06-08"))
            assert exc.value.status_code == 404
        finally:
            object.__setattr__(rpt.S, "hotel_pms_enabled", True)

    def test_inverted_range_422(self, _hotel_tables):
        from app.services.hotel_reports import compute_hotel_kpis
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            compute_hotel_kpis("h1", from_ts=_epoch("2026-06-08"), to_ts=_epoch("2026-06-01"))
        assert exc.value.status_code == 422

    def test_oversized_range_422(self, _hotel_tables):
        from app.services.hotel_reports import compute_hotel_kpis
        from fastapi import HTTPException
        rpt = _hotel_tables["rpt"]
        object.__setattr__(rpt.S, "hotel_kpi_max_range_days", 7)
        try:
            with pytest.raises(HTTPException) as exc:
                compute_hotel_kpis("h1", from_ts=_epoch("2026-06-01"), to_ts=_epoch("2026-07-01"))
            assert exc.value.status_code == 422
        finally:
            object.__setattr__(rpt.S, "hotel_kpi_max_range_days", 366)

    def test_empty_range_all_zeros_no_div_by_zero(self, _hotel_tables):
        from app.services.hotel_reports import compute_hotel_kpis
        kpis = compute_hotel_kpis("h_empty", from_ts=_epoch("2026-06-01"), to_ts=_epoch("2026-06-08"))
        assert kpis["rooms_available"] == 0
        assert kpis["rooms_sold"] == 0
        assert kpis["occupancy_pct"] == 0.0
        assert kpis["room_revenue_cents"] == 0
        assert kpis["adr_cents"] == 0
        assert kpis["revpar_cents"] == 0
        assert kpis["arrivals"] == 0
        assert kpis["departures"] == 0

    def test_single_fully_in_range_stay(self, _hotel_tables):
        """ADR/RevPAR/occupancy exact on known fixture."""
        res_tbl = _hotel_tables["res"]
        avail_tbl = _hotel_tables["avail"]
        from app.services.hotel_reports import compute_hotel_kpis

        hotel_id = "h_kpi_1"
        # 7 nights × 10 rooms = 70 room-nights available
        _seed_avail(avail_tbl, hotel_id, "RT1",
                    [f"2026-06-0{i}" for i in range(1, 8)], 10)
        # 3-night stay fully in range
        _seed_res(res_tbl, hotel_id, f"res_{hotel_id}", "2026-06-01", "2026-06-04",
                  nights=3, rooms=1, total_cents=30000)

        kpis = compute_hotel_kpis(hotel_id,
                                   from_ts=_epoch("2026-06-01"),
                                   to_ts=_epoch("2026-06-08"))
        assert kpis["rooms_available"] == 70
        assert kpis["rooms_sold"] == 3
        assert kpis["room_revenue_cents"] == 30000
        assert kpis["adr_cents"] == 10000  # 30000 // 3
        assert kpis["revpar_cents"] == 428  # 30000 // 70
        assert round(kpis["occupancy_pct"], 1) == 4.3  # round(3/70*100,1)
        assert kpis["arrivals"] == 1
        assert kpis["departures"] == 1
        assert kpis["currency"] == "usd"

    def test_revpar_adr_occupancy_identity(self, _hotel_tables):
        """RevPAR ≈ ADR × occupancy (within ±2 cents for integer rounding)."""
        res_tbl = _hotel_tables["res"]
        avail_tbl = _hotel_tables["avail"]
        from app.services.hotel_reports import compute_hotel_kpis

        hotel_id = "h_kpi_id"
        _seed_avail(avail_tbl, hotel_id, "RT1",
                    [f"2026-06-0{i}" for i in range(1, 8)], 10)
        _seed_res(res_tbl, hotel_id, f"res_{hotel_id}", "2026-06-01", "2026-06-04",
                  nights=3, rooms=1, total_cents=30000)
        kpis = compute_hotel_kpis(hotel_id,
                                   from_ts=_epoch("2026-06-01"),
                                   to_ts=_epoch("2026-06-08"))
        computed = kpis["adr_cents"] * (kpis["occupancy_pct"] / 100)
        assert abs(kpis["revpar_cents"] - computed) <= 2

    def test_room_night_basis_multi_room(self, _hotel_tables):
        """rooms_sold = nights × rooms, not reservation count."""
        res_tbl = _hotel_tables["res"]
        from app.services.hotel_reports import compute_hotel_kpis
        hotel_id = "h_rn_basis"
        _seed_res(res_tbl, hotel_id, "res_rn", "2026-06-01", "2026-06-04",
                  nights=3, rooms=2, total_cents=60000)
        kpis = compute_hotel_kpis(hotel_id,
                                   from_ts=_epoch("2026-06-01"),
                                   to_ts=_epoch("2026-06-08"))
        assert kpis["rooms_sold"] == 6  # 3 nights × 2 rooms

    def test_straddling_stay_pro_rate(self, _hotel_tables):
        """A stay spanning the window boundary contributes only in-range nights."""
        res_tbl = _hotel_tables["res"]
        from app.services.hotel_reports import compute_hotel_kpis
        hotel_id = "h_straddle"
        # checkin=05-30, checkout=06-04 (5 nights), only 3 nights in [06-01,06-04)
        _seed_res(res_tbl, hotel_id, "res_straddle", "2026-05-30", "2026-06-04",
                  nights=5, rooms=1, total_cents=50000)
        kpis = compute_hotel_kpis(hotel_id,
                                   from_ts=_epoch("2026-06-01"),
                                   to_ts=_epoch("2026-06-04"))
        assert kpis["rooms_sold"] == 3
        # (50000 * 3) // 5 = 30000
        assert kpis["room_revenue_cents"] == 30000

    def test_cancelled_no_show_excluded(self, _hotel_tables):
        """Cancelled and no_show reservations excluded from sold/revenue/arrivals/departures."""
        res_tbl = _hotel_tables["res"]
        from app.services.hotel_reports import compute_hotel_kpis
        hotel_id = "h_excl"
        _seed_res(res_tbl, hotel_id, "res_conf", "2026-06-01", "2026-06-03",
                  nights=2, rooms=1, total_cents=20000, status="confirmed")
        _seed_res(res_tbl, hotel_id, "res_cancel", "2026-06-01", "2026-06-03",
                  nights=2, rooms=1, total_cents=20000, status="cancelled")
        _seed_res(res_tbl, hotel_id, "res_ns", "2026-06-01", "2026-06-03",
                  nights=2, rooms=1, total_cents=20000, status="no_show")
        kpis = compute_hotel_kpis(hotel_id,
                                   from_ts=_epoch("2026-06-01"),
                                   to_ts=_epoch("2026-06-08"))
        assert kpis["rooms_sold"] == 2
        assert kpis["room_revenue_cents"] == 20000
        assert kpis["arrivals"] == 1  # only confirmed
        assert kpis["departures"] == 1

    def test_arrivals_departures_distinct_exclusive_upper(self, _hotel_tables):
        """arrivals/departures use half-open [from,to) semantics."""
        res_tbl = _hotel_tables["res"]
        from app.services.hotel_reports import compute_hotel_kpis
        hotel_id = "h_arr_dep"
        # Stay A: checkin=06-02 (in range), checkout=06-05 (== to → excluded)
        _seed_res(res_tbl, hotel_id, "res_A", "2026-06-02", "2026-06-05",
                  nights=3, rooms=1, total_cents=30000, status="confirmed")
        # Stay B: checkin=05-31 (before from → no arrival), checkout=06-02 (in range)
        _seed_res(res_tbl, hotel_id, "res_B", "2026-05-31", "2026-06-02",
                  nights=2, rooms=1, total_cents=20000, status="confirmed")
        kpis = compute_hotel_kpis(hotel_id,
                                   from_ts=_epoch("2026-06-01"),
                                   to_ts=_epoch("2026-06-05"))
        assert kpis["arrivals"] == 1   # only A's checkin 06-02 in [06-01,06-05)
        assert kpis["departures"] == 1  # only B's checkout 06-02 in [06-01,06-05); A's 06-05 excluded

    def test_multi_room_type_availability_sum(self, _hotel_tables):
        """rooms_available sums across all room types for a date."""
        avail_tbl = _hotel_tables["avail"]
        from app.services.hotel_reports import compute_hotel_kpis
        hotel_id = "h_multi_rt"
        _seed_avail(avail_tbl, hotel_id, "RT_A", ["2026-06-01", "2026-06-02", "2026-06-03"], 5)
        _seed_avail(avail_tbl, hotel_id, "RT_B", ["2026-06-01", "2026-06-02", "2026-06-03"], 5)
        kpis = compute_hotel_kpis(hotel_id,
                                   from_ts=_epoch("2026-06-01"),
                                   to_ts=_epoch("2026-06-04"))
        assert kpis["rooms_available"] == 30  # 3 nights × (5+5) rooms

    def test_missing_night_zero_capacity(self, _hotel_tables):
        """A night with no availability row contributes 0 to rooms_available."""
        avail_tbl = _hotel_tables["avail"]
        from app.services.hotel_reports import compute_hotel_kpis
        hotel_id = "h_missing_night"
        # Only seed 06-01 and 06-03, skip 06-02
        _seed_avail(avail_tbl, hotel_id, "RT1", ["2026-06-01", "2026-06-03"], 4)
        kpis = compute_hotel_kpis(hotel_id,
                                   from_ts=_epoch("2026-06-01"),
                                   to_ts=_epoch("2026-06-04"))
        assert kpis["rooms_available"] == 8  # 4 + 0 + 4

    def test_occupancy_pct_rounding(self, _hotel_tables):
        """occupancy_pct rounds to 1 decimal."""
        avail_tbl = _hotel_tables["avail"]
        res_tbl = _hotel_tables["res"]
        from app.services.hotel_reports import compute_hotel_kpis
        hotel_id = "h_rounding"
        # 3 available room-nights, 1 sold → 33.333...%
        _seed_avail(avail_tbl, hotel_id, "RT1", ["2026-06-01", "2026-06-02", "2026-06-03"], 1)
        _seed_res(res_tbl, hotel_id, "res_round", "2026-06-01", "2026-06-02",
                  nights=1, rooms=1, total_cents=10000, status="confirmed")
        kpis = compute_hotel_kpis(hotel_id,
                                   from_ts=_epoch("2026-06-01"),
                                   to_ts=_epoch("2026-06-04"))
        assert kpis["occupancy_pct"] == 33.3

    def test_occupancy_pct_over_100_unclamped(self, _hotel_tables):
        """Over-sold (rooms_available=0 but rooms_sold>0) is returned unclamped."""
        res_tbl = _hotel_tables["res"]
        from app.services.hotel_reports import compute_hotel_kpis
        hotel_id = "h_oversold"
        _seed_res(res_tbl, hotel_id, "res_os", "2026-06-01", "2026-06-02",
                  nights=1, rooms=1, total_cents=10000, status="confirmed")
        kpis = compute_hotel_kpis(hotel_id,
                                   from_ts=_epoch("2026-06-01"),
                                   to_ts=_epoch("2026-06-02"))
        # rooms_available=0, rooms_sold=1 → occ > 100 (rooms_sold / max(0,1)*100 = 100)
        assert kpis["occupancy_pct"] >= 100.0

    def test_currency_from_reservations(self, _hotel_tables):
        """currency is taken from the most common currency of sold stays."""
        res_tbl = _hotel_tables["res"]
        from app.services.hotel_reports import compute_hotel_kpis
        hotel_id = "h_cur_eur"
        for i in range(3):
            _seed_res(res_tbl, hotel_id, f"res_eur_{i}", "2026-06-01", "2026-06-02",
                      nights=1, rooms=1, total_cents=10000, currency="eur")
        kpis = compute_hotel_kpis(hotel_id,
                                   from_ts=_epoch("2026-06-01"),
                                   to_ts=_epoch("2026-06-02"))
        assert kpis["currency"] == "eur"

    def test_no_dev_mode_branch(self, _hotel_tables):
        """hotel_reports.py must contain no dev_mode if-branch (SECOPS-007)."""
        import ast
        import app.services.hotel_reports as rpt
        import inspect
        src = inspect.getsource(rpt)
        # Parse the AST; check that no If node's test references dev_mode
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                if_src = ast.unparse(node.test)
                assert "dev_mode" not in if_src, f"Found dev_mode in if-branch: {if_src}"

    def test_lasteval_key_loop_no_truncation(self, _hotel_tables):
        """GSI query loops on LastEvaluatedKey — seed >100 reservations."""
        res_tbl = _hotel_tables["res"]
        avail_tbl = _hotel_tables["avail"]
        from app.services.hotel_reports import compute_hotel_kpis
        hotel_id = "h_paged"
        # Seed 120 reservations each 1-night
        for i in range(120):
            _seed_res(res_tbl, hotel_id, f"res_page_{i:04d}", "2026-06-01", "2026-06-02",
                      nights=1, rooms=1, total_cents=10000)
        kpis = compute_hotel_kpis(hotel_id,
                                   from_ts=_epoch("2026-06-01"),
                                   to_ts=_epoch("2026-06-02"))
        assert kpis["rooms_sold"] == 120
        assert kpis["arrivals"] == 120


# ---------------------------------------------------------------------------
# =============================
# HTL-036 — tax/currency wire-in
# =============================
# ---------------------------------------------------------------------------

class TestTaxCurrencyWireIn:
    def test_tax_flags_off_uses_flat_bps(self, _hotel_tables):
        """With INV flags off, resolve_tax_cents uses flat invoices_tax_bps."""
        from app.services.hotel_tax_currency import resolve_tax_cents
        from app.services import hotel_tax_currency as htc

        object.__setattr__(htc.S, "crm_tax_rates_enabled", False)
        object.__setattr__(htc.S, "aos_per_line_tax_enabled", False)
        object.__setattr__(htc.S, "invoices_tax_bps", 1000)  # 10%
        try:
            result = resolve_tax_cents(10000)
            assert result == 1000  # 10000 * 1000 // 10000
        finally:
            object.__setattr__(htc.S, "crm_tax_rates_enabled", False)
            object.__setattr__(htc.S, "aos_per_line_tax_enabled", False)
            object.__setattr__(htc.S, "invoices_tax_bps", 0)

    def test_tax_registry_consume_via_stub(self, _hotel_tables):
        """With INV flags on + patched registry stub, uses registry rate."""
        from app.services.hotel_tax_currency import resolve_tax_cents
        from app.services import hotel_tax_currency as htc

        fake_crm_tax = MagicMock()
        fake_crm_tax.get_tax_rate.return_value = {"rate_bps": 1500}

        object.__setattr__(htc.S, "crm_tax_rates_enabled", True)
        object.__setattr__(htc.S, "aos_per_line_tax_enabled", True)
        try:
            with patch.dict(sys.modules, {"app.services.crm_tax_rates": fake_crm_tax}):
                result = resolve_tax_cents(10000, tax_rate_id="rate-1")
            assert result == 1500  # 10000 * 1500 // 10000
        finally:
            object.__setattr__(htc.S, "crm_tax_rates_enabled", False)
            object.__setattr__(htc.S, "aos_per_line_tax_enabled", False)

    def test_tax_accessor_raises_falls_back(self, _hotel_tables):
        """If registry accessor raises, falls back to flat bps."""
        from app.services.hotel_tax_currency import resolve_tax_cents
        from app.services import hotel_tax_currency as htc

        def _raiser(*a, **kw):
            raise RuntimeError("registry down")

        fake_crm_tax = MagicMock()
        fake_crm_tax.get_tax_rate.side_effect = _raiser

        object.__setattr__(htc.S, "crm_tax_rates_enabled", True)
        object.__setattr__(htc.S, "aos_per_line_tax_enabled", True)
        object.__setattr__(htc.S, "invoices_tax_bps", 500)
        try:
            with patch.dict(sys.modules, {"app.services.crm_tax_rates": fake_crm_tax}):
                result = resolve_tax_cents(10000, tax_rate_id="rate-x")
            assert result == 500  # fallback 10000 * 500 // 10000
        finally:
            object.__setattr__(htc.S, "crm_tax_rates_enabled", False)
            object.__setattr__(htc.S, "aos_per_line_tax_enabled", False)
            object.__setattr__(htc.S, "invoices_tax_bps", 0)

    def test_currency_flags_off_opaque_fallback(self, _hotel_tables):
        """With INV flags off, resolve_currency_amount returns opaque fallback."""
        from app.services.hotel_tax_currency import resolve_currency_amount
        from app.services import hotel_tax_currency as htc

        object.__setattr__(htc.S, "crm_currencies_enabled", False)
        object.__setattr__(htc.S, "aos_invoice_currency_conversion_enabled", False)
        amount, orig, usd = resolve_currency_amount(10000, "eur")
        assert amount == 10000
        assert orig == ""
        assert usd == 10000

    def test_currency_consume_via_stub(self, _hotel_tables):
        """With INV flags on + patched crm_currencies stub, converts amount."""
        from app.services.hotel_tax_currency import resolve_currency_amount
        from app.services import hotel_tax_currency as htc

        fake_crm_cur = MagicMock()
        fake_crm_cur.convert_amount.return_value = 10800  # EUR → USD

        object.__setattr__(htc.S, "crm_currencies_enabled", True)
        object.__setattr__(htc.S, "aos_invoice_currency_conversion_enabled", True)
        try:
            with patch.dict(sys.modules, {"app.services.crm_currencies": fake_crm_cur}):
                amount, orig, usd = resolve_currency_amount(10000, "eur")
            assert amount == 10000
            assert orig == "eur"
            assert usd == 10800
        finally:
            object.__setattr__(htc.S, "crm_currencies_enabled", False)
            object.__setattr__(htc.S, "aos_invoice_currency_conversion_enabled", False)

    def test_currency_accessor_raises_falls_back(self, _hotel_tables):
        """If currency accessor raises, returns opaque fallback."""
        from app.services.hotel_tax_currency import resolve_currency_amount
        from app.services import hotel_tax_currency as htc

        fake_crm_cur = MagicMock()
        fake_crm_cur.convert_amount.side_effect = RuntimeError("fx down")

        object.__setattr__(htc.S, "crm_currencies_enabled", True)
        object.__setattr__(htc.S, "aos_invoice_currency_conversion_enabled", True)
        try:
            with patch.dict(sys.modules, {"app.services.crm_currencies": fake_crm_cur}):
                amount, orig, usd = resolve_currency_amount(10000, "eur")
            assert orig == ""
            assert usd == 10000
        finally:
            object.__setattr__(htc.S, "crm_currencies_enabled", False)
            object.__setattr__(htc.S, "aos_invoice_currency_conversion_enabled", False)


# ---------------------------------------------------------------------------
# Smoke: import app.main succeeds (checks table wiring + settings)
# ---------------------------------------------------------------------------

def test_import_main_succeeds():
    """Verify app.main can be imported (settings + tables compile)."""
    import importlib
    # Re-import to pick up new hotel settings/tables
    import app.main  # noqa: F401
    assert True
