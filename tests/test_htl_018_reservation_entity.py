"""HTL-018 — Hermetic offline tests for the reservation entity.

Moto-backed hotel_reservations table bound to frozen T via object.__setattr__.
Forward-dep collaborators patched on the hotel_reservations module namespace.
"""
from __future__ import annotations

import re
import sys
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import boto3
import pytest
from fastapi import HTTPException
from moto import mock_aws

# ---------------------------------------------------------------------------
# Module-scoped stubs for sibling modules that may not exist in this worktree.
# Saves + restores sys.modules entries on teardown.
# ---------------------------------------------------------------------------

_STUB_NAMES = [
    "app.services.hotel_availability",
    "app.services.hotel_pms",
    "app.services.hotel_rate_plans",
]


@pytest.fixture(scope="session", autouse=True)
def _install_module_stubs():
    saved = {}
    for name in _STUB_NAMES:
        saved[name] = sys.modules.get(name)

    ha_stub = SimpleNamespace(
        check_availability=MagicMock(
            return_value={"available": True, "min_remaining": 5, "rooms_needed": 1, "per_night": []}
        ),
        hold_rooms=MagicMock(return_value={"hold_id": "hold_abc"}),
        release_hold=MagicMock(return_value={"status": "released"}),
    )
    pms_stub = SimpleNamespace(
        list_hotels=MagicMock(),
        list_room_types=MagicMock(return_value={"room_types": [], "count": 0, "cursor": None}),
        set_room_status=MagicMock(),
    )
    rp_stub = SimpleNamespace(
        compute_stay_price=MagicMock(
            return_value=SimpleNamespace(total_cents=30000, currency="USD")
        )
    )

    sys.modules["app.services.hotel_availability"] = ha_stub  # type: ignore[assignment]
    sys.modules["app.services.hotel_pms"] = pms_stub  # type: ignore[assignment]
    sys.modules["app.services.hotel_rate_plans"] = rp_stub  # type: ignore[assignment]

    yield

    for name in _STUB_NAMES:
        orig = saved[name]
        if orig is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = orig


# ---------------------------------------------------------------------------
# Fixture: moto table + frozen T + frozen S
# ---------------------------------------------------------------------------

@pytest.fixture()
def setup_table(monkeypatch):
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = ddb.create_table(
            TableName="hotel_reservations",
            KeySchema=[
                {"AttributeName": "reservation_id", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "reservation_id", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "hotel_id", "AttributeType": "S"},
                {"AttributeName": "guest_party_id", "AttributeType": "S"},
                {"AttributeName": "checkin", "AttributeType": "S"},
                {"AttributeName": "status", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
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
                    "IndexName": "GSI_GUEST",
                    "KeySchema": [
                        {"AttributeName": "guest_party_id", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
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
        from app.core import tables as T_mod
        from app.services import hotel_reservations as hr

        object.__setattr__(T_mod.T, "hotel_reservations", table)
        object.__setattr__(hr.S, "hotel_pms_enabled", True)
        object.__setattr__(hr.S, "hotel_reservations_table_name", "hotel_reservations")

        yield SimpleNamespace(table=table, hr=hr, T_mod=T_mod)

        object.__setattr__(hr.S, "hotel_pms_enabled", False)


# ---------------------------------------------------------------------------
# Collaborator stub helpers
# ---------------------------------------------------------------------------

def _stub_ok(hr, monkeypatch, *, total_cents=30000, currency="USD", hold_id="hold_abc"):
    monkeypatch.setattr(
        hr, "ha",
        SimpleNamespace(
            check_availability=MagicMock(
                return_value={"available": True, "rooms_needed": 1, "per_night": [], "min_remaining": 5}
            ),
            hold_rooms=MagicMock(return_value={"hold_id": hold_id}),
            release_hold=MagicMock(return_value={"status": "released"}),
        )
    )
    monkeypatch.setattr(
        hr, "hotel_rate_plans",
        SimpleNamespace(
            compute_stay_price=MagicMock(
                return_value=SimpleNamespace(total_cents=total_cents, currency=currency)
            )
        )
    )
    monkeypatch.setattr(hr, "hotel_pms", SimpleNamespace(
        list_hotels=MagicMock(),
        list_room_types=MagicMock(),
        set_room_status=MagicMock(),
    ))


def _default_args():
    return {
        "hotel_id": "h1",
        "guest_party_id": "g1",
        "room_type_id": "rt1",
        "checkin": "2026-06-01",
        "checkout": "2026-06-04",
        "adults": 2,
        "rooms": 1,
        "user_sub": "admin1",
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_flag_off_raises_404(setup_table, monkeypatch):
    ns = setup_table
    hr = ns.hr
    object.__setattr__(hr.S, "hotel_pms_enabled", False)
    _stub_ok(hr, monkeypatch)
    with pytest.raises(HTTPException) as exc:
        hr.create_reservation(**_default_args())
    assert exc.value.status_code == 404
    with pytest.raises(HTTPException) as exc2:
        hr.get_reservation("res_xxx")
    assert exc2.value.status_code == 404
    # Restore flag for other tests
    object.__setattr__(hr.S, "hotel_pms_enabled", True)


def test_create_reservation_success(setup_table, monkeypatch):
    ns = setup_table
    hr, table = ns.hr, ns.table
    _stub_ok(hr, monkeypatch)

    result = hr.create_reservation(**_default_args())

    assert result["status"] == "confirmed"
    assert result["version"] == 1
    assert result["assigned_room_ids"] == []
    assert result["nights"] == 3
    assert result["total_cents"] == 30000
    assert result["currency"] == "usd"
    assert result["hold_id"] == "hold_abc"
    assert result["sk"] == "META"
    assert isinstance(result["created_at"], int)
    assert isinstance(result["updated_at"], int)
    assert isinstance(result["version"], int)


def test_header_persisted_under_sk_meta(setup_table, monkeypatch):
    ns = setup_table
    hr, table = ns.hr, ns.table
    _stub_ok(hr, monkeypatch)

    result = hr.create_reservation(**_default_args())
    rid = result["reservation_id"]

    raw = table.get_item(Key={"reservation_id": rid, "sk": "META"})
    assert "Item" in raw
    item = raw["Item"]
    # Raw DDB item has Decimal for numerics
    assert isinstance(item["version"], Decimal)
    # get_reservation coerces to int
    got = hr.get_reservation(rid)
    assert isinstance(got["version"], int)
    assert got["version"] == 1


def test_hold_before_write_ordering(setup_table, monkeypatch):
    ns = setup_table
    hr, table = ns.hr, ns.table

    call_order = []

    mock_ha = SimpleNamespace(
        check_availability=MagicMock(
            return_value={"available": True, "min_remaining": 5, "rooms_needed": 1, "per_night": []}
        ),
        hold_rooms=MagicMock(side_effect=lambda *a, **k: (call_order.append("hold"), {"hold_id": "hx"})[1]),
        release_hold=MagicMock(),
    )
    monkeypatch.setattr(hr, "ha", mock_ha)
    monkeypatch.setattr(hr, "hotel_rate_plans", SimpleNamespace(
        compute_stay_price=MagicMock(return_value=SimpleNamespace(total_cents=5000, currency="usd"))
    ))

    orig_put = table.put_item

    def _spy_put(**kwargs):
        call_order.append("put_item")
        return orig_put(**kwargs)

    table.put_item = _spy_put

    try:
        result = hr.create_reservation(**_default_args())
        hold_pos = call_order.index("hold")
        put_pos = call_order.index("put_item")
        assert hold_pos < put_pos, f"Expected hold before put_item, got {call_order}"
        assert result["hold_id"] == "hx"
    finally:
        table.put_item = orig_put


def test_hold_rooms_409_leaves_no_header(setup_table, monkeypatch):
    ns = setup_table
    hr, table = ns.hr, ns.table

    monkeypatch.setattr(hr, "ha", SimpleNamespace(
        check_availability=MagicMock(
            return_value={"available": True, "min_remaining": 5, "rooms_needed": 1, "per_night": []}
        ),
        hold_rooms=MagicMock(side_effect=HTTPException(status_code=409, detail="sold out")),
        release_hold=MagicMock(),
    ))
    monkeypatch.setattr(hr, "hotel_rate_plans", SimpleNamespace(
        compute_stay_price=MagicMock(return_value=SimpleNamespace(total_cents=5000, currency="usd"))
    ))

    with pytest.raises(HTTPException) as exc:
        hr.create_reservation(**_default_args())
    assert exc.value.status_code == 409

    scan = table.scan()
    assert scan["Count"] == 0


def test_check_availability_sold_out_raises_409(setup_table, monkeypatch):
    ns = setup_table
    hr, table = ns.hr, ns.table
    hold_mock = MagicMock()
    monkeypatch.setattr(hr, "ha", SimpleNamespace(
        check_availability=MagicMock(
            return_value={"available": False, "min_remaining": 0, "rooms_needed": 1, "per_night": []}
        ),
        hold_rooms=hold_mock,
        release_hold=MagicMock(),
    ))
    monkeypatch.setattr(hr, "hotel_rate_plans", SimpleNamespace(
        compute_stay_price=MagicMock()
    ))

    with pytest.raises(HTTPException) as exc:
        hr.create_reservation(**_default_args())
    assert exc.value.status_code == 409
    assert exc.value.detail == {"code": "no_availability"}
    hold_mock.assert_not_called()
    assert table.scan()["Count"] == 0


def test_price_422_propagates_no_hold(setup_table, monkeypatch):
    ns = setup_table
    hr, table = ns.hr, ns.table
    hold_mock = MagicMock()
    monkeypatch.setattr(hr, "ha", SimpleNamespace(
        check_availability=MagicMock(
            return_value={"available": True, "min_remaining": 5, "rooms_needed": 1, "per_night": []}
        ),
        hold_rooms=hold_mock,
        release_hold=MagicMock(),
    ))
    monkeypatch.setattr(hr, "hotel_rate_plans", SimpleNamespace(
        compute_stay_price=MagicMock(side_effect=HTTPException(422, "stay too short"))
    ))

    with pytest.raises(HTTPException) as exc:
        hr.create_reservation(**_default_args())
    assert exc.value.status_code == 422
    hold_mock.assert_not_called()
    assert table.scan()["Count"] == 0


def test_span_validation_422(setup_table, monkeypatch):
    ns = setup_table
    hr, table = ns.hr, ns.table
    _stub_ok(hr, monkeypatch)

    with pytest.raises(HTTPException) as exc:
        hr.create_reservation(
            hotel_id="h1", guest_party_id="g1", room_type_id="rt1",
            checkin="2026-06-04", checkout="2026-06-01",
            adults=2, user_sub="admin1",
        )
    assert exc.value.status_code == 422
    assert table.scan()["Count"] == 0


def test_write_failure_compensation(setup_table, monkeypatch):
    ns = setup_table
    hr, table = ns.hr, ns.table

    release_mock = MagicMock()
    monkeypatch.setattr(hr, "ha", SimpleNamespace(
        check_availability=MagicMock(
            return_value={"available": True, "min_remaining": 5, "rooms_needed": 1, "per_night": []}
        ),
        hold_rooms=MagicMock(return_value={"hold_id": "hold_to_release"}),
        release_hold=release_mock,
    ))
    monkeypatch.setattr(hr, "hotel_rate_plans", SimpleNamespace(
        compute_stay_price=MagicMock(return_value=SimpleNamespace(total_cents=5000, currency="usd"))
    ))

    orig_put = table.put_item
    table.put_item = MagicMock(side_effect=RuntimeError("write failed"))
    try:
        with pytest.raises(RuntimeError, match="write failed"):
            hr.create_reservation(**_default_args())
        release_mock.assert_called_once()
        call_kwargs = release_mock.call_args
        assert call_kwargs.kwargs.get("terminal_status") == "released" or \
               (call_kwargs.args and "released" in call_kwargs.args)
    finally:
        table.put_item = orig_put


def test_non_idempotency(setup_table, monkeypatch):
    ns = setup_table
    hr, table = ns.hr, ns.table
    _stub_ok(hr, monkeypatch)

    r1 = hr.create_reservation(**_default_args())
    r2 = hr.create_reservation(**_default_args())
    assert r1["reservation_id"] != r2["reservation_id"]
    assert table.scan()["Count"] >= 2   # (+ possible HIST rows)


def test_get_reservation_hit_and_miss(setup_table, monkeypatch):
    ns = setup_table
    hr = ns.hr
    _stub_ok(hr, monkeypatch)

    result = hr.create_reservation(**_default_args())
    rid = result["reservation_id"]

    got = hr.get_reservation(rid)
    assert got is not None
    assert got["reservation_id"] == rid
    assert isinstance(got["version"], int)

    missing = hr.get_reservation("res_nope_does_not_exist")
    assert missing is None


def test_reservation_id_format(setup_table, monkeypatch):
    ns = setup_table
    hr = ns.hr
    _stub_ok(hr, monkeypatch)
    result = hr.create_reservation(**_default_args())
    assert re.match(r"^res_[0-9a-f]{16}$", result["reservation_id"])


def test_decimal_coercion(setup_table, monkeypatch):
    ns = setup_table
    hr = ns.hr
    _stub_ok(hr, monkeypatch)
    result = hr.create_reservation(**_default_args())
    for f in ("nights", "adults", "rooms", "total_cents", "deposit_cents",
              "version", "created_at", "updated_at"):
        assert isinstance(result[f], int), f"Expected int for {f}, got {type(result[f])}"
    assert isinstance(result["assigned_room_ids"], list)


def test_gsi_smoke_queries(setup_table, monkeypatch):
    ns = setup_table
    hr, table = ns.hr, ns.table

    hold_counter = {"n": 0}

    def _hold(*a, **k):
        hold_counter["n"] += 1
        return {"hold_id": f"hold_{hold_counter['n']}"}

    monkeypatch.setattr(hr, "ha", SimpleNamespace(
        check_availability=MagicMock(
            return_value={"available": True, "min_remaining": 5, "rooms_needed": 1, "per_night": []}
        ),
        hold_rooms=_hold,
        release_hold=MagicMock(),
    ))
    monkeypatch.setattr(hr, "hotel_rate_plans", SimpleNamespace(
        compute_stay_price=MagicMock(return_value=SimpleNamespace(total_cents=5000, currency="usd"))
    ))

    from boto3.dynamodb.conditions import Key

    r1 = hr.create_reservation(
        hotel_id="h1", guest_party_id="guest_a",
        room_type_id="rt1", checkin="2026-07-01", checkout="2026-07-03",
        adults=2, user_sub="admin1",
    )
    r2 = hr.create_reservation(
        hotel_id="h1", guest_party_id="guest_b",
        room_type_id="rt1", checkin="2026-08-01", checkout="2026-08-03",
        adults=1, user_sub="admin1",
    )

    # GSI_GUEST: query for guest_a only
    guest_a_resp = table.query(
        IndexName="GSI_GUEST",
        KeyConditionExpression=Key("guest_party_id").eq("guest_a"),
    )
    assert guest_a_resp["Count"] == 1
    assert guest_a_resp["Items"][0]["reservation_id"] == r1["reservation_id"]

    # GSI_HOTEL_ARRIVALS: query hotel h1 — no ValidationException (attr_types={"created_at":"N"})
    arrivals_resp = table.query(
        IndexName="GSI_HOTEL_ARRIVALS",
        KeyConditionExpression=Key("hotel_id").eq("h1"),
    )
    assert arrivals_resp["Count"] == 2
