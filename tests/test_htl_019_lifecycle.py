"""HTL-019 — Hermetic offline tests for the reservation lifecycle state machine.

Moto-backed hotel_reservations table bound to frozen T.  Forward-dep
collaborators patched on the hotel_reservations namespace.  No TestClient.
"""
from __future__ import annotations

import inspect
import sys
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from fastapi import HTTPException
from moto import mock_aws

# ---------------------------------------------------------------------------
# Module-scoped stubs
# ---------------------------------------------------------------------------

_STUB_NAMES = [
    "app.services.hotel_availability",
    "app.services.hotel_pms",
    "app.services.hotel_rate_plans",
]


@pytest.fixture(scope="module", autouse=True)
def _install_module_stubs():
    saved = {}
    for name in _STUB_NAMES:
        saved[name] = sys.modules.get(name)

    ha_stub = SimpleNamespace(
        check_availability=MagicMock(
            return_value={"available": True, "min_remaining": 5, "rooms_needed": 1, "per_night": []}
        ),
        hold_rooms=MagicMock(return_value={"hold_id": "hold_new"}),
        release_hold=MagicMock(return_value={"status": "released"}),
    )
    pms_stub = SimpleNamespace(
        list_hotels=MagicMock(),
        list_room_types=MagicMock(return_value={"room_types": [], "count": 0, "cursor": None}),
        set_room_status=MagicMock(),
    )
    rp_stub = SimpleNamespace(
        compute_stay_price=MagicMock(
            return_value=SimpleNamespace(total_cents=20000, currency="usd", per_night=[], applied_rule_ids=[])
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
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def setup(monkeypatch):
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
                {"AttributeName": "status", "AttributeType": "S"},
                {"AttributeName": "checkin", "AttributeType": "S"},
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

        # Patch collaborators
        monkeypatch.setattr(hr, "ha", SimpleNamespace(
            check_availability=MagicMock(
                return_value={"available": True, "min_remaining": 5, "rooms_needed": 1, "per_night": []}
            ),
            hold_rooms=MagicMock(return_value={"hold_id": "hold_new"}),
            release_hold=MagicMock(return_value={"status": "released"}),
        ))
        monkeypatch.setattr(hr, "rate_plans", SimpleNamespace(
            compute_stay_price=MagicMock(
                return_value=SimpleNamespace(
                    total_cents=20000, currency="usd", per_night=[], applied_rule_ids=[]
                )
            )
        ), raising=False)
        monkeypatch.setattr(hr, "hotel_pms", SimpleNamespace(set_room_status=MagicMock()))
        monkeypatch.setattr(hr, "hotel_rate_plans", SimpleNamespace(
            compute_stay_price=MagicMock(
                return_value=SimpleNamespace(
                    total_cents=20000, currency="usd", per_night=[], applied_rule_ids=[]
                )
            )
        ))

        yield hr, table

        object.__setattr__(hr.S, "hotel_pms_enabled", False)


def _seed(table, *, status="confirmed", version=1, rooms=1,
          hold_id="hold_old", assigned=None, checkin="2026-07-01",
          checkout="2026-07-03"):
    rid = "res_test01"
    table.put_item(Item={
        "reservation_id": rid,
        "sk": "META",
        "hotel_id": "h1",
        "guest_party_id": "g1",
        "room_type_id": "rt1",
        "checkin": checkin,
        "checkout": checkout,
        "nights": 2,
        "adults": 2,
        "children": 0,
        "rooms": rooms,
        "total_cents": 20000,
        "currency": "usd",
        "status": status,
        "hold_id": hold_id,
        "version": version,
        "assigned_room_ids": assigned or [],
        "deposit_cents": 0,
        "created_at": 1_700_000_000,
        "updated_at": 1_700_000_000,
    })
    return rid


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_flag_off_raises_404(setup, monkeypatch):
    hr, table = setup
    object.__setattr__(hr.S, "hotel_pms_enabled", False)
    with pytest.raises(HTTPException) as exc:
        hr.transition_reservation("rid", "checked_in", actor="a1")
    assert exc.value.status_code == 404
    object.__setattr__(hr.S, "hotel_pms_enabled", True)


def test_confirmed_to_checked_in(setup):
    hr, table = setup
    rid = _seed(table, status="confirmed", rooms=2)
    result = hr.transition_reservation(
        rid, "checked_in", actor="a1", assigned_room_ids=["r101", "r102"]
    )
    assert result["status"] == "checked_in"
    assert result["version"] == 2
    assert result["assigned_room_ids"] == ["r101", "r102"]

    # Verify HIST row
    from boto3.dynamodb.conditions import Key
    hist = table.query(
        KeyConditionExpression=Key("reservation_id").eq(rid) & Key("sk").begins_with("HIST#"),
    )
    # Should have at least one HIST row
    assert hist["Count"] >= 1
    hist_item = hist["Items"][0]
    assert hist_item["to_status"] == "checked_in"


def test_checked_in_missing_assigned_room_ids_raises_422(setup):
    hr, table = setup
    rid = _seed(table, status="confirmed", rooms=2)
    with pytest.raises(HTTPException) as exc:
        hr.transition_reservation(rid, "checked_in", actor="a1")
    assert exc.value.status_code == 422

    # Header unchanged
    item = hr.get_reservation(rid)
    assert item["status"] == "confirmed"
    assert item["version"] == 1


def test_checked_in_length_mismatch_raises_422(setup):
    hr, table = setup
    rid = _seed(table, status="confirmed", rooms=2)
    with pytest.raises(HTTPException) as exc:
        hr.transition_reservation(rid, "checked_in", actor="a1", assigned_room_ids=["r101"])
    assert exc.value.status_code == 422

    item = hr.get_reservation(rid)
    assert item["status"] == "confirmed"
    assert item["version"] == 1


def test_checked_in_to_checked_out(setup, monkeypatch):
    hr, table = setup
    rid = _seed(table, status="checked_in", version=2, rooms=1, assigned=["r101"])

    release_mock = MagicMock()
    set_room_mock = MagicMock()
    monkeypatch.setattr(hr, "ha", SimpleNamespace(
        check_availability=MagicMock(),
        hold_rooms=MagicMock(),
        release_hold=release_mock,
    ))
    monkeypatch.setattr(hr, "hotel_pms", SimpleNamespace(set_room_status=set_room_mock))

    result = hr.transition_reservation(rid, "checked_out", actor="a1")
    assert result["status"] == "checked_out"
    assert result["version"] == 3

    # set_room_status called with "dirty"
    set_room_mock.assert_called_once_with("r101", "dirty")
    # release_hold NOT called on check-out
    release_mock.assert_not_called()


def test_confirmed_to_cancelled_releases_inventory(setup, monkeypatch):
    hr, table = setup
    rid = _seed(table, status="confirmed", hold_id="hold_x")

    release_mock = MagicMock(return_value={"status": "released"})
    monkeypatch.setattr(hr, "ha", SimpleNamespace(
        check_availability=MagicMock(),
        hold_rooms=MagicMock(),
        release_hold=release_mock,
    ))

    result = hr.transition_reservation(rid, "cancelled", actor="a1")
    assert result["status"] == "cancelled"
    assert result["version"] == 2

    release_mock.assert_called_once()
    call_kwargs = release_mock.call_args
    assert call_kwargs.args[0] == "hold_x" or call_kwargs.kwargs.get("hold_id") == "hold_x"
    first_pos_arg = release_mock.call_args.args[0] if release_mock.call_args.args else None
    assert first_pos_arg == "hold_x"


def test_confirmed_to_no_show_releases_inventory(setup, monkeypatch):
    hr, table = setup
    rid = _seed(table, status="confirmed", hold_id="hold_y")
    release_mock = MagicMock(return_value={"status": "released"})
    monkeypatch.setattr(hr, "ha", SimpleNamespace(
        check_availability=MagicMock(),
        hold_rooms=MagicMock(),
        release_hold=release_mock,
    ))

    result = hr.transition_reservation(rid, "no_show", actor="a1")
    assert result["status"] == "no_show"
    release_mock.assert_called_once()


def test_illegal_transition_from_terminal_raises_409(setup):
    hr, table = setup
    rid = _seed(table, status="checked_out", version=3)
    with pytest.raises(HTTPException) as exc:
        hr.transition_reservation(rid, "confirmed", actor="a1")
    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "invalid_status_transition"

    # Header unchanged
    item = hr.get_reservation(rid)
    assert item["status"] == "checked_out"
    assert item["version"] == 3


def test_illegal_non_terminal_edge_raises_409(setup):
    hr, table = setup
    rid = _seed(table, status="confirmed")
    with pytest.raises(HTTPException) as exc:
        hr.transition_reservation(rid, "checked_out", actor="a1")
    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "invalid_status_transition"


def test_version_conflict_raises_409_concurrent_update(setup, monkeypatch):
    hr, table = setup
    rid = _seed(table, status="confirmed", version=1)

    # Simulate version conflict via ClientError
    orig_update = table.update_item
    conflict_raised = {"done": False}

    def _conflict_update(**kwargs):
        if not conflict_raised["done"]:
            conflict_raised["done"] = True
            error_response = {"Error": {"Code": "ConditionalCheckFailedException", "Message": "conflict"}}
            raise ClientError(error_response, "UpdateItem")
        return orig_update(**kwargs)

    table.update_item = _conflict_update

    try:
        with pytest.raises(HTTPException) as exc:
            hr.transition_reservation(rid, "checked_in", actor="a1", assigned_room_ids=["r101"])
        assert exc.value.status_code == 409
        assert exc.value.detail["code"] == "concurrent_update"
    finally:
        table.update_item = orig_update


def test_missing_reservation_raises_404(setup):
    hr, table = setup
    with pytest.raises(HTTPException) as exc:
        hr.transition_reservation("res_missing_x", "checked_in", actor="a1", assigned_room_ids=["r1"])
    assert exc.value.status_code == 404


def test_modify_reservation_re_checks_and_re_prices(setup, monkeypatch):
    hr, table = setup
    rid = _seed(table, status="confirmed", hold_id="hold_old", checkin="2026-07-01", checkout="2026-07-03")

    check_mock = MagicMock(
        return_value={"available": True, "min_remaining": 5, "rooms_needed": 1, "per_night": []}
    )
    hold_mock = MagicMock(return_value={"hold_id": "hold_new"})
    release_mock = MagicMock()
    monkeypatch.setattr(hr, "ha", SimpleNamespace(
        check_availability=check_mock,
        hold_rooms=hold_mock,
        release_hold=release_mock,
    ))
    monkeypatch.setattr(hr, "hotel_rate_plans", SimpleNamespace(
        compute_stay_price=MagicMock(
            return_value=SimpleNamespace(total_cents=30000, currency="usd", per_night=[], applied_rule_ids=[])
        )
    ))

    result = hr.modify_reservation(
        rid,
        checkin="2026-07-01",
        checkout="2026-07-04",
        actor="a1",
    )

    check_mock.assert_called_once()
    hold_mock.assert_called_once()
    release_mock.assert_called_once()   # old hold released
    assert result["total_cents"] == 30000
    assert result["nights"] == 3
    assert result["hold_id"] == "hold_new"
    assert result["version"] == 2


def test_modify_reservation_new_span_sold_out_keeps_old_hold(setup, monkeypatch):
    hr, table = setup
    rid = _seed(table, status="confirmed", hold_id="hold_old")

    monkeypatch.setattr(hr, "ha", SimpleNamespace(
        check_availability=MagicMock(
            return_value={"available": False, "min_remaining": 0, "rooms_needed": 1, "per_night": []}
        ),
        hold_rooms=MagicMock(),
        release_hold=MagicMock(),
    ))

    with pytest.raises(HTTPException) as exc:
        hr.modify_reservation(rid, checkout="2026-07-10", actor="a1")
    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "no_availability"

    # Old hold still present
    item = hr.get_reservation(rid)
    assert item["hold_id"] == "hold_old"
    assert item["version"] == 1


def test_modify_reservation_rejects_non_confirmed(setup, monkeypatch):
    hr, table = setup
    rid = _seed(table, status="checked_in", version=2)

    with pytest.raises(HTTPException) as exc:
        hr.modify_reservation(rid, checkout="2026-07-10", actor="a1")
    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "not_modifiable"


def test_modify_reservation_new_before_old(setup, monkeypatch):
    hr, table = setup
    rid = _seed(table, status="confirmed", hold_id="hold_old")

    call_log = []

    def _hold(*a, **k):
        call_log.append("hold_rooms")
        return {"hold_id": "hold_new"}

    def _release(*a, **k):
        call_log.append("release_hold")

    monkeypatch.setattr(hr, "ha", SimpleNamespace(
        check_availability=MagicMock(
            return_value={"available": True, "min_remaining": 5, "rooms_needed": 1, "per_night": []}
        ),
        hold_rooms=_hold,
        release_hold=_release,
    ))
    monkeypatch.setattr(hr, "hotel_rate_plans", SimpleNamespace(
        compute_stay_price=MagicMock(
            return_value=SimpleNamespace(total_cents=25000, currency="usd", per_night=[], applied_rule_ids=[])
        )
    ))

    hr.modify_reservation(rid, checkout="2026-07-04", actor="a1")

    hold_idx = call_log.index("hold_rooms")
    release_idx = call_log.index("release_hold")
    assert hold_idx < release_idx, f"Expected hold_rooms before release_hold, got {call_log}"


def test_list_reservation_history_newest_first(setup):
    hr, table = setup
    rid = _seed(table, status="confirmed")

    # Drive confirmed → checked_in → checked_out
    hr.transition_reservation(rid, "checked_in", actor="a1", assigned_room_ids=["r1"])
    hr.transition_reservation(rid, "checked_out", actor="a1")

    hist = hr.list_reservation_history(rid)
    assert hist["count"] >= 2
    # Newest first: last event at top
    events = hist["history"]
    assert events[0]["to_status"] == "checked_out"
    assert events[1]["to_status"] == "checked_in"


def test_hist_idempotency(setup):
    hr, table = setup
    rid = _seed(table, status="confirmed")

    # Write same HIST row twice
    hr._record_history(rid, "confirmed", "checked_in", actor="a1", ts=100)
    hr._record_history(rid, "confirmed", "checked_in", actor="a1", ts=100)

    from boto3.dynamodb.conditions import Key
    hist = table.query(
        KeyConditionExpression=Key("reservation_id").eq(rid) & Key("sk").begins_with("HIST#"),
    )
    assert hist["Count"] == 1


def test_decimal_coercion_after_transition(setup):
    hr, table = setup
    rid = _seed(table, status="confirmed")
    result = hr.transition_reservation(rid, "cancelled", actor="a1")
    for f in ("version", "total_cents", "nights"):
        assert isinstance(result[f], int), f"Expected int for {f}"


def test_no_dev_mode_in_transition_source(setup):
    hr, table = setup
    source = inspect.getsource(hr.transition_reservation)
    assert "dev_mode" not in source
    source_modify = inspect.getsource(hr.modify_reservation)
    assert "dev_mode" not in source_modify


def test_cancel_best_effort_release_does_not_block_transition(setup, monkeypatch):
    hr, table = setup
    rid = _seed(table, status="confirmed", hold_id="hold_fail")
    monkeypatch.setattr(hr, "ha", SimpleNamespace(
        check_availability=MagicMock(),
        hold_rooms=MagicMock(),
        release_hold=MagicMock(side_effect=RuntimeError("release failed")),
    ))
    # Should still succeed despite release failure
    result = hr.transition_reservation(rid, "cancelled", actor="a1")
    assert result["status"] == "cancelled"
    assert result["version"] == 2
