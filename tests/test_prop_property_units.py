"""
Hermetic offline pytest for the open-property vertical (PROP-001..PROP-004).

Pattern:
  - moto-backed ``properties`` table bound to frozen ``T.properties`` via
    ``object.__setattr__``
  - frozen ``S`` flag toggled via ``object.__setattr__``
  - ``audit_event`` patched to a no-op
  - route-handler coroutines called directly on fresh ``asyncio.new_event_loop()``
    (no TestClient — broken per CLAUDE.md)

No real AWS, no live stack, no network calls.
"""
from __future__ import annotations

import asyncio
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import boto3
import pytest
from fastapi import HTTPException
from moto import mock_aws

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

OWNER_SUB = "alice-owner"
OTHER_SUB = "bob-other"

ADDRESS = {
    "line1": "123 Main St",
    "city": "Springfield",
    "region": "IL",
    "postal_code": "62701",
    "country": "US",
}


def _make_table(ddb):
    return ddb.create_table(
        TableName="properties",
        KeySchema=[
            {"AttributeName": "property_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "property_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "owner_sub", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "occupancy_status", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_OWNER",
                "KeySchema": [
                    {"AttributeName": "owner_sub", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI_STATUS",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI_UNIT_OCCUPANCY",
                "KeySchema": [
                    {"AttributeName": "property_id", "KeyType": "HASH"},
                    {"AttributeName": "occupancy_status", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.fixture(autouse=True)
def setup(monkeypatch):
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = _make_table(ddb)

        from app.core import tables as T_mod
        from app.services import property_mgmt as svc

        object.__setattr__(T_mod.T, "properties", table)
        object.__setattr__(svc.S, "property_mgmt_enabled", True)
        object.__setattr__(svc.S, "properties_table_name", "properties")

        with patch("app.services.alerts.audit_event", return_value=None):
            yield table, svc


# ===========================================================================
# PROP-001: Property entity
# ===========================================================================

class TestProp001PropertyEntity:

    def test_flag_off_raises_404_on_create(self, setup):
        _table, svc = setup
        object.__setattr__(svc.S, "property_mgmt_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                svc.create_property(OWNER_SUB, "Test", "apartment", ADDRESS)
            assert exc.value.status_code == 404
        finally:
            object.__setattr__(svc.S, "property_mgmt_enabled", True)

    def test_create_property_success(self, setup):
        _table, svc = setup
        result = svc.create_property(OWNER_SUB, "Maple House", "apartment", ADDRESS, color_tags=["blue"])
        assert result["property_id"]
        assert result["sk"] == "META"
        assert result["status"] == "active"
        assert result["occupancy_status"] == "vacant"
        assert result["unit_count"] == 0
        assert isinstance(result["created_at"], int)
        assert isinstance(result["updated_at"], int)
        assert result["owner_sub"] == OWNER_SUB
        assert result["name"] == "Maple House"
        assert result["color_tags"] == ["blue"]

    def test_create_property_idempotent(self, setup):
        _table, svc = setup
        r1 = svc.create_property(OWNER_SUB, "Maple House", "apartment", ADDRESS)
        r2 = svc.create_property(OWNER_SUB, "Maple House", "apartment", ADDRESS)
        assert r1["property_id"] == r2["property_id"]

    def test_get_property_hit(self, setup):
        _table, svc = setup
        created = svc.create_property(OWNER_SUB, "Elm Flat", "single_family", ADDRESS)
        fetched = svc.get_property(created["property_id"])
        assert fetched is not None
        assert fetched["property_id"] == created["property_id"]

    def test_get_property_miss(self, setup):
        _table, svc = setup
        result = svc.get_property("nonexistent-id-0000000000000000")
        assert result is None

    def test_update_property_changes_fields(self, setup):
        _table, svc = setup
        created = svc.create_property(OWNER_SUB, "Cedar Flat", "apartment", ADDRESS)
        pid = created["property_id"]
        original_ts = created["updated_at"]

        updated = svc.update_property(pid, user_sub=OWNER_SUB, name="Cedar Grove")
        assert updated["name"] == "Cedar Grove"
        assert updated["updated_at"] >= original_ts

    def test_update_property_missing_raises_404(self, setup):
        _table, svc = setup
        with pytest.raises(HTTPException) as exc:
            svc.update_property("bad-id-00000000000000000000000000", user_sub=OWNER_SUB, name="X")
        assert exc.value.status_code == 404

    def test_archive_property(self, setup):
        _table, svc = setup
        created = svc.create_property(OWNER_SUB, "Oak Tower", "commercial", ADDRESS)
        archived = svc.archive_property(created["property_id"], user_sub=OWNER_SUB)
        assert archived["status"] == "archived"

    def test_property_id_derivation_determinism(self, setup):
        _table, svc = setup
        assert svc._property_id("alice", "Maple House") == svc._property_id("alice", "Maple House")
        assert svc._property_id("alice", "Maple House") != svc._property_id("bob", "Maple House")

    def test_address_round_trip(self, setup):
        _table, svc = setup
        addr = {**ADDRESS, "line2": "Apt 3B"}
        created = svc.create_property(OWNER_SUB, "Full Address Place", "apartment", addr)
        fetched = svc.get_property(created["property_id"])
        assert fetched is not None
        assert fetched["address"]["line1"] == ADDRESS["line1"]
        assert fetched["address"]["line2"] == "Apt 3B"
        assert fetched["address"]["city"] == ADDRESS["city"]

    def test_color_tags_round_trip(self, setup):
        _table, svc = setup
        created = svc.create_property(OWNER_SUB, "Tagged Prop", "multi_family", ADDRESS, color_tags=["urgent", "blue"])
        fetched = svc.get_property(created["property_id"])
        assert fetched is not None
        assert "urgent" in fetched["color_tags"]
        assert "blue" in fetched["color_tags"]

    def test_empty_color_tags(self, setup):
        _table, svc = setup
        created = svc.create_property(OWNER_SUB, "No Tags Prop", "apartment", ADDRESS, color_tags=[])
        fetched = svc.get_property(created["property_id"])
        assert fetched is not None
        assert fetched["color_tags"] == []

    def test_decimal_coercion_on_numeric_fields(self, setup):
        table, svc = setup
        created = svc.create_property(OWNER_SUB, "Decimal Prop", "apartment", ADDRESS)
        pid = created["property_id"]

        # Raw DDB item has Decimal types
        raw = table.get_item(Key={"property_id": pid, "sk": "META"}).get("Item", {})
        assert isinstance(raw["created_at"], Decimal)
        assert isinstance(raw["unit_count"], Decimal)

        # Service layer coerces to int
        fetched = svc.get_property(pid)
        assert isinstance(fetched["created_at"], int)
        assert isinstance(fetched["updated_at"], int)
        assert isinstance(fetched["unit_count"], int)


# ===========================================================================
# PROP-002: Unit entity
# ===========================================================================

class TestProp002UnitEntity:

    def _create_prop(self, svc):
        return svc.create_property(OWNER_SUB, "Unit Test Building", "apartment", ADDRESS)

    def test_flag_off_raises_404_on_unit_functions(self, setup):
        _table, svc = setup
        object.__setattr__(svc.S, "property_mgmt_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                svc.create_unit("pid", label="A1", bedrooms=1, bathrooms=1.0,
                                square_footage=500, market_rent_cents=100000, user_sub=OWNER_SUB)
            assert exc.value.status_code == 404

            with pytest.raises(HTTPException):
                svc.get_unit("pid", "uid")

            with pytest.raises(HTTPException):
                svc.list_units("pid")

            with pytest.raises(HTTPException):
                svc.update_unit("pid", "uid", user_sub=OWNER_SUB, label="X")

            with pytest.raises(HTTPException):
                svc.delete_unit("pid", "uid", user_sub=OWNER_SUB)
        finally:
            object.__setattr__(svc.S, "property_mgmt_enabled", True)

    def test_create_unit_success_full_fields(self, setup):
        _table, svc = setup
        prop = self._create_prop(svc)
        unit = svc.create_unit(
            prop["property_id"],
            label="Apt 2B",
            bedrooms=2,
            bathrooms=1.5,
            square_footage=900,
            market_rent_cents=150000,
            user_sub=OWNER_SUB,
        )
        assert unit["unit_id"]
        assert len(unit["unit_id"]) == 32  # uuid4().hex
        assert unit["sk"] == f"UNIT#{unit['unit_id']}"
        assert unit["occupancy_status"] == "vacant"
        assert unit["market_rent_cents"] == 150000
        assert unit["bathrooms"] == 1.5
        assert isinstance(unit["bathrooms"], float)
        assert unit["bedrooms"] == 2
        assert isinstance(unit["bedrooms"], int)

    def test_create_unit_increments_unit_count(self, setup):
        table, svc = setup
        prop = self._create_prop(svc)
        pid = prop["property_id"]

        meta_before = table.get_item(Key={"property_id": pid, "sk": "META"})["Item"]
        assert int(meta_before["unit_count"]) == 0

        svc.create_unit(pid, label="U1", bedrooms=1, bathrooms=1.0,
                        square_footage=400, market_rent_cents=80000, user_sub=OWNER_SUB)
        meta_after = table.get_item(Key={"property_id": pid, "sk": "META"})["Item"]
        assert int(meta_after["unit_count"]) == 1

    def test_create_unit_nonexistent_property_raises_404(self, setup):
        _table, svc = setup
        with pytest.raises(HTTPException) as exc:
            svc.create_unit("nonexistent00000000000000000000", label="U", bedrooms=1,
                            bathrooms=1.0, square_footage=400, market_rent_cents=50000,
                            user_sub=OWNER_SUB)
        assert exc.value.status_code == 404

    def test_create_unit_wrong_owner_raises_403(self, setup):
        _table, svc = setup
        prop = self._create_prop(svc)
        with pytest.raises(HTTPException) as exc:
            svc.create_unit(prop["property_id"], label="U", bedrooms=1,
                            bathrooms=1.0, square_footage=400, market_rent_cents=50000,
                            user_sub=OTHER_SUB)
        assert exc.value.status_code == 403

    def test_get_unit_hit_and_miss(self, setup):
        _table, svc = setup
        prop = self._create_prop(svc)
        unit = svc.create_unit(prop["property_id"], label="B1", bedrooms=3,
                               bathrooms=2.0, square_footage=1200, market_rent_cents=200000,
                               user_sub=OWNER_SUB)
        fetched = svc.get_unit(prop["property_id"], unit["unit_id"])
        assert fetched is not None
        assert fetched["unit_id"] == unit["unit_id"]

        miss = svc.get_unit(prop["property_id"], "nonexistent")
        assert miss is None

    def test_list_units_returns_only_unit_rows(self, setup):
        _table, svc = setup
        prop = self._create_prop(svc)
        svc.create_unit(prop["property_id"], label="A1", bedrooms=1, bathrooms=1.0,
                        square_footage=400, market_rent_cents=50000, user_sub=OWNER_SUB)
        svc.create_unit(prop["property_id"], label="B2", bedrooms=2, bathrooms=2.0,
                        square_footage=800, market_rent_cents=90000, user_sub=OWNER_SUB)

        units = svc.list_units(prop["property_id"])
        assert len(units) == 2
        for u in units:
            assert u["sk"].startswith("UNIT#")

    def test_list_units_sorted_by_label(self, setup):
        _table, svc = setup
        prop = self._create_prop(svc)
        for label in ["Unit C", "Unit A", "Unit B"]:
            svc.create_unit(prop["property_id"], label=label, bedrooms=1, bathrooms=1.0,
                            square_footage=400, market_rent_cents=50000, user_sub=OWNER_SUB)
        units = svc.list_units(prop["property_id"])
        labels = [u["label"] for u in units]
        assert labels == ["Unit A", "Unit B", "Unit C"]

    def test_list_units_empty(self, setup):
        _table, svc = setup
        prop = self._create_prop(svc)
        units = svc.list_units(prop["property_id"])
        assert units == []

    def test_update_unit_partial_update(self, setup):
        _table, svc = setup
        prop = self._create_prop(svc)
        unit = svc.create_unit(prop["property_id"], label="X1", bedrooms=1, bathrooms=1.0,
                               square_footage=400, market_rent_cents=50000, user_sub=OWNER_SUB)
        original_ts = unit["updated_at"]

        updated = svc.update_unit(prop["property_id"], unit["unit_id"],
                                  user_sub=OWNER_SUB, market_rent_cents=200000)
        assert updated["market_rent_cents"] == 200000
        assert updated["label"] == "X1"  # unchanged
        assert updated["updated_at"] >= original_ts

    def test_update_unit_not_found_raises_404(self, setup):
        _table, svc = setup
        prop = self._create_prop(svc)
        with pytest.raises(HTTPException) as exc:
            svc.update_unit(prop["property_id"], "nonexistent", user_sub=OWNER_SUB, label="Y")
        assert exc.value.status_code == 404

    def test_update_unit_occupancy_change_no_exception(self, setup):
        """compute_property_occupancy may not exist yet; except Exception guard absorbs it."""
        _table, svc = setup
        prop = self._create_prop(svc)
        unit = svc.create_unit(prop["property_id"], label="Z1", bedrooms=1, bathrooms=1.0,
                               square_footage=400, market_rent_cents=50000, user_sub=OWNER_SUB)
        # Should not raise even though compute_property_occupancy is called
        updated = svc.update_unit(prop["property_id"], unit["unit_id"],
                                  user_sub=OWNER_SUB, occupancy_status="occupied")
        assert updated["occupancy_status"] == "occupied"

    def test_delete_unit_success_returns_true(self, setup):
        table, svc = setup
        prop = self._create_prop(svc)
        unit = svc.create_unit(prop["property_id"], label="D1", bedrooms=1, bathrooms=1.0,
                               square_footage=400, market_rent_cents=50000, user_sub=OWNER_SUB)

        result = svc.delete_unit(prop["property_id"], unit["unit_id"], user_sub=OWNER_SUB)
        assert result is True

        # unit_count back to 0
        meta = table.get_item(Key={"property_id": prop["property_id"], "sk": "META"})["Item"]
        assert int(meta["unit_count"]) == 0

        # unit is gone
        assert svc.get_unit(prop["property_id"], unit["unit_id"]) is None

    def test_delete_unit_unknown_returns_false(self, setup):
        _table, svc = setup
        prop = self._create_prop(svc)
        result = svc.delete_unit(prop["property_id"], "nonexistent", user_sub=OWNER_SUB)
        assert result is False

    def test_delete_unit_idempotent(self, setup):
        _table, svc = setup
        prop = self._create_prop(svc)
        unit = svc.create_unit(prop["property_id"], label="I1", bedrooms=1, bathrooms=1.0,
                               square_footage=400, market_rent_cents=50000, user_sub=OWNER_SUB)
        assert svc.delete_unit(prop["property_id"], unit["unit_id"], user_sub=OWNER_SUB) is True
        assert svc.delete_unit(prop["property_id"], unit["unit_id"], user_sub=OWNER_SUB) is False

    def test_unit_count_floor_guard(self, setup):
        table, svc = setup
        prop = self._create_prop(svc)
        unit = svc.create_unit(prop["property_id"], label="F1", bedrooms=1, bathrooms=1.0,
                               square_footage=400, market_rent_cents=50000, user_sub=OWNER_SUB)
        svc.delete_unit(prop["property_id"], unit["unit_id"], user_sub=OWNER_SUB)
        # Second delete — unit_count must not go negative
        svc.delete_unit(prop["property_id"], unit["unit_id"], user_sub=OWNER_SUB)
        meta = table.get_item(Key={"property_id": prop["property_id"], "sk": "META"})["Item"]
        assert int(meta["unit_count"]) == 0

    def test_unit_decimal_coercion(self, setup):
        table, svc = setup
        prop = self._create_prop(svc)
        unit = svc.create_unit(prop["property_id"], label="DC1", bedrooms=2, bathrooms=1.5,
                               square_footage=700, market_rent_cents=120000, user_sub=OWNER_SUB)
        # Raw DDB item uses Decimal
        raw = table.get_item(
            Key={"property_id": prop["property_id"], "sk": f"UNIT#{unit['unit_id']}"}
        )["Item"]
        assert isinstance(raw["market_rent_cents"], Decimal)
        assert isinstance(raw["bedrooms"], Decimal)

        # Service returns proper types
        fetched = svc.get_unit(prop["property_id"], unit["unit_id"])
        assert isinstance(fetched["market_rent_cents"], int)
        assert isinstance(fetched["bedrooms"], int)
        assert isinstance(fetched["bathrooms"], float)

    def test_gsi_unit_occupancy_query(self, setup):
        table, svc = setup
        prop = self._create_prop(svc)
        from boto3.dynamodb.conditions import Key, Attr

        for _ in range(2):
            svc.create_unit(prop["property_id"], label=f"V{_}", bedrooms=1, bathrooms=1.0,
                            square_footage=400, market_rent_cents=50000,
                            occupancy_status="vacant", user_sub=OWNER_SUB)
        svc.create_unit(prop["property_id"], label="O1", bedrooms=1, bathrooms=1.0,
                        square_footage=400, market_rent_cents=50000,
                        occupancy_status="occupied", user_sub=OWNER_SUB)

        vacant_resp = table.query(
            IndexName="GSI_UNIT_OCCUPANCY",
            KeyConditionExpression=Key("property_id").eq(prop["property_id"])
                & Key("occupancy_status").eq("vacant"),
            FilterExpression=Attr("sk").begins_with("UNIT#"),
        )
        assert len(vacant_resp["Items"]) == 2

        occupied_resp = table.query(
            IndexName="GSI_UNIT_OCCUPANCY",
            KeyConditionExpression=Key("property_id").eq(prop["property_id"])
                & Key("occupancy_status").eq("occupied"),
            FilterExpression=Attr("sk").begins_with("UNIT#"),
        )
        assert len(occupied_resp["Items"]) == 1

    def test_list_units_does_not_return_meta_row(self, setup):
        _table, svc = setup
        prop = self._create_prop(svc)
        svc.create_unit(prop["property_id"], label="L1", bedrooms=1, bathrooms=1.0,
                        square_footage=400, market_rent_cents=50000, user_sub=OWNER_SUB)
        units = svc.list_units(prop["property_id"])
        for u in units:
            assert u["sk"].startswith("UNIT#")

    def test_audit_events_emitted(self, setup):
        _table, svc = setup
        prop = self._create_prop(svc)

        with patch("app.services.property_mgmt._audit") as mock_audit:
            unit = svc.create_unit(prop["property_id"], label="AU1", bedrooms=1, bathrooms=1.0,
                                   square_footage=400, market_rent_cents=50000, user_sub=OWNER_SUB)
            svc.update_unit(prop["property_id"], unit["unit_id"], user_sub=OWNER_SUB, label="AU2")
            svc.delete_unit(prop["property_id"], unit["unit_id"], user_sub=OWNER_SUB)

        calls = [c[0][0] for c in mock_audit.call_args_list]
        assert "property.unit.created" in calls
        assert "property.unit.updated" in calls
        assert "property.unit.deleted" in calls


# ===========================================================================
# PROP-003: List/filter + occupancy roll-up
# ===========================================================================

class TestProp003ListFilterOccupancy:

    def _insert_property(self, table, pid, owner, status="active", property_type="apartment",
                         created_at=1000):
        table.put_item(Item={
            "property_id": pid,
            "sk": "META",
            "owner_sub": owner,
            "name": f"Prop {pid[:4]}",
            "property_type": property_type,
            "address": ADDRESS,
            "color_tags": [],
            "occupancy_status": "vacant",
            "unit_count": 0,
            "status": status,
            "created_at": created_at,
            "updated_at": created_at,
        })

    def _insert_unit(self, table, pid, uid, occupancy_status="vacant"):
        table.put_item(Item={
            "property_id": pid,
            "sk": f"UNIT#{uid}",
            "unit_id": uid,
            "label": f"Unit {uid[:4]}",
            "bedrooms": 1,
            "bathrooms": Decimal("1.0"),
            "square_footage": 400,
            "market_rent_cents": 50000,
            "occupancy_status": occupancy_status,
            "created_at": 1000,
            "updated_at": 1000,
        })

    def test_flag_off_list_properties(self, setup):
        _table, svc = setup
        object.__setattr__(svc.S, "property_mgmt_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                svc.list_properties("alice")
            assert exc.value.status_code == 404
        finally:
            object.__setattr__(svc.S, "property_mgmt_enabled", True)

    def test_flag_off_compute_occupancy(self, setup):
        _table, svc = setup
        object.__setattr__(svc.S, "property_mgmt_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                svc.compute_property_occupancy("pid")
            assert exc.value.status_code == 404
        finally:
            object.__setattr__(svc.S, "property_mgmt_enabled", True)

    def test_flag_off_portfolio_rollup(self, setup):
        _table, svc = setup
        object.__setattr__(svc.S, "property_mgmt_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                svc.portfolio_occupancy_rollup("alice")
            assert exc.value.status_code == 404
        finally:
            object.__setattr__(svc.S, "property_mgmt_enabled", True)

    def test_list_properties_empty_portfolio(self, setup):
        _table, svc = setup
        result = svc.list_properties("nobody")
        assert result == {"properties": [], "count": 0, "cursor": None}

    def test_list_properties_basic(self, setup):
        table, svc = setup
        self._insert_property(table, "p1" + "a" * 30, OWNER_SUB, created_at=1000)
        self._insert_property(table, "p2" + "b" * 30, OWNER_SUB, created_at=2000)
        self._insert_property(table, "p3" + "c" * 30, OWNER_SUB, created_at=3000)
        result = svc.list_properties(OWNER_SUB)
        assert result["count"] == 3
        assert result["cursor"] is None
        # Newest-first by created_at
        returned_ids = [p["property_id"] for p in result["properties"]]
        assert returned_ids[0] == "p3" + "c" * 30

    def test_list_properties_status_filter_active(self, setup):
        table, svc = setup
        self._insert_property(table, "pa" + "a" * 30, OWNER_SUB, status="active", created_at=1000)
        self._insert_property(table, "pa" + "b" * 30, OWNER_SUB, status="active", created_at=2000)
        self._insert_property(table, "px" + "c" * 30, OWNER_SUB, status="archived", created_at=3000)
        result = svc.list_properties(OWNER_SUB, status="active")
        assert result["count"] == 2

    def test_list_properties_status_filter_archived(self, setup):
        table, svc = setup
        self._insert_property(table, "pa" + "a" * 30, OWNER_SUB, status="active", created_at=1000)
        self._insert_property(table, "px" + "c" * 30, OWNER_SUB, status="archived", created_at=3000)
        result = svc.list_properties(OWNER_SUB, status="archived")
        assert result["count"] == 1

    def test_list_properties_status_all(self, setup):
        table, svc = setup
        self._insert_property(table, "pa" + "a" * 30, OWNER_SUB, status="active", created_at=1000)
        self._insert_property(table, "px" + "c" * 30, OWNER_SUB, status="archived", created_at=3000)
        result = svc.list_properties(OWNER_SUB, status="all")
        assert result["count"] == 2

    def test_list_properties_property_type_filter(self, setup):
        table, svc = setup
        self._insert_property(table, "pt" + "a" * 30, OWNER_SUB, property_type="apartment", created_at=1000)
        self._insert_property(table, "pt" + "b" * 30, OWNER_SUB, property_type="apartment", created_at=2000)
        self._insert_property(table, "pt" + "c" * 30, OWNER_SUB, property_type="commercial", created_at=3000)
        result = svc.list_properties(OWNER_SUB, property_type="apartment")
        assert result["count"] == 2

    def test_list_properties_combined_filters(self, setup):
        table, svc = setup
        self._insert_property(table, "cf" + "a" * 30, OWNER_SUB, status="active", property_type="apartment", created_at=1000)
        self._insert_property(table, "cf" + "b" * 30, OWNER_SUB, status="archived", property_type="apartment", created_at=2000)
        self._insert_property(table, "cf" + "c" * 30, OWNER_SUB, status="active", property_type="commercial", created_at=3000)
        result = svc.list_properties(OWNER_SUB, status="active", property_type="apartment")
        assert result["count"] == 1

    def test_list_properties_invalid_status_raises_422(self, setup):
        _table, svc = setup
        with pytest.raises(HTTPException) as exc:
            svc.list_properties(OWNER_SUB, status="unknown")
        assert exc.value.status_code == 422

    def test_list_properties_invalid_property_type_raises_422(self, setup):
        _table, svc = setup
        with pytest.raises(HTTPException) as exc:
            svc.list_properties(OWNER_SUB, property_type="castle")
        assert exc.value.status_code == 422

    def test_list_properties_pagination(self, setup):
        table, svc = setup
        for i in range(5):
            self._insert_property(table, f"pg{i}" + "x" * 30, OWNER_SUB, created_at=1000 + i)

        page1 = svc.list_properties(OWNER_SUB, limit=2)
        assert page1["count"] == 2
        assert page1["cursor"] is not None

        page2 = svc.list_properties(OWNER_SUB, limit=2, cursor=page1["cursor"])
        assert page2["count"] == 2
        assert page2["cursor"] is not None

        page3 = svc.list_properties(OWNER_SUB, limit=2, cursor=page2["cursor"])
        assert page3["count"] == 1
        assert page3["cursor"] is None

    def test_compute_occupancy_zero_units(self, setup):
        _table, svc = setup
        result = svc.compute_property_occupancy("nonexistent-pid-00000000000000")
        assert result["total"] == 0
        assert result["occupied"] == 0
        assert result["vacant"] == 0
        assert result["occupancy_status"] == "vacant"
        assert result["occupancy_rate"] == 0.0

    def test_compute_occupancy_all_occupied(self, setup):
        table, svc = setup
        pid = "occ-all-occupied" + "x" * 16
        self._insert_property(table, pid, OWNER_SUB)
        for i in range(3):
            self._insert_unit(table, pid, f"uid{i}xx" * 5, occupancy_status="occupied")
        result = svc.compute_property_occupancy(pid)
        assert result["total"] == 3
        assert result["occupied"] == 3
        assert result["occupancy_status"] == "occupied"
        assert result["occupancy_rate"] == 1.0

    def test_compute_occupancy_all_vacant(self, setup):
        table, svc = setup
        pid = "occ-all-vacant000" + "x" * 15
        self._insert_property(table, pid, OWNER_SUB)
        for i in range(3):
            self._insert_unit(table, pid, f"uid{i}vv" * 5, occupancy_status="vacant")
        result = svc.compute_property_occupancy(pid)
        assert result["total"] == 3
        assert result["occupied"] == 0
        assert result["occupancy_status"] == "vacant"
        assert result["occupancy_rate"] == 0.0

    def test_compute_occupancy_partial(self, setup):
        table, svc = setup
        pid = "occ-partial000000" + "x" * 15
        self._insert_property(table, pid, OWNER_SUB)
        self._insert_unit(table, pid, "uid0-occ" * 4, occupancy_status="occupied")
        self._insert_unit(table, pid, "uid0-occ" * 3 + "x" * 4, occupancy_status="occupied")
        self._insert_unit(table, pid, "uid0-vac" * 4, occupancy_status="vacant")
        result = svc.compute_property_occupancy(pid)
        assert result["total"] == 3
        assert result["occupied"] == 2
        assert result["occupancy_status"] == "partial"
        assert abs(result["occupancy_rate"] - 2/3) < 0.01

    def test_compute_occupancy_mixed_four_states(self, setup):
        table, svc = setup
        pid = "occ-mixed4stat00" + "x" * 16
        self._insert_property(table, pid, OWNER_SUB)
        self._insert_unit(table, pid, "uid-occ" * 4 + "aa", occupancy_status="occupied")
        self._insert_unit(table, pid, "uid-vac" * 4 + "bb", occupancy_status="vacant")
        self._insert_unit(table, pid, "uid-tur" * 4 + "cc", occupancy_status="turnover")
        self._insert_unit(table, pid, "uid-una" * 4 + "dd", occupancy_status="unavailable")
        result = svc.compute_property_occupancy(pid)
        assert result["total"] == 4
        assert result["occupied"] == 1
        assert result["vacant"] == 1
        assert result["turnover"] == 1
        assert result["unavailable"] == 1
        assert result["occupancy_status"] == "partial"

    def test_compute_occupancy_write_back(self, setup):
        table, svc = setup
        pid = "occ-writeback0000" + "x" * 15
        self._insert_property(table, pid, OWNER_SUB)
        self._insert_unit(table, pid, "uid-wb1" * 4 + "xx", occupancy_status="occupied")
        svc.compute_property_occupancy(pid)
        meta = table.get_item(Key={"property_id": pid, "sk": "META"})["Item"]
        assert meta["occupancy_status"] == "occupied"

    def test_compute_occupancy_no_exception_on_unknown_property(self, setup):
        _table, svc = setup
        # Should not raise even for missing META row
        result = svc.compute_property_occupancy("totally-unknown-id000000000000000")
        assert result["total"] == 0

    def test_portfolio_rollup_empty(self, setup):
        _table, svc = setup
        result = svc.portfolio_occupancy_rollup("nobody-sub")
        assert result == {
            "property_count": 0,
            "unit_count": 0,
            "occupied": 0,
            "vacant": 0,
            "turnover": 0,
            "unavailable": 0,
            "occupancy_rate": 0.0,
        }

    def test_portfolio_rollup_single_property(self, setup):
        table, svc = setup
        pid = "port-single-prop" + "x" * 16
        self._insert_property(table, pid, OWNER_SUB)
        self._insert_unit(table, pid, "uid-port1" * 3 + "aaa", occupancy_status="occupied")
        self._insert_unit(table, pid, "uid-port2" * 3 + "bbb", occupancy_status="occupied")
        self._insert_unit(table, pid, "uid-port3" * 3 + "ccc", occupancy_status="vacant")
        result = svc.portfolio_occupancy_rollup(OWNER_SUB)
        assert result["property_count"] == 1
        assert result["unit_count"] == 3
        assert result["occupied"] == 2
        assert abs(result["occupancy_rate"] - 2/3) < 0.01

    def test_portfolio_rollup_multiple_properties(self, setup):
        table, svc = setup
        pid1 = "port-multi-prop1" + "x" * 16
        pid2 = "port-multi-prop2" + "y" * 16
        self._insert_property(table, pid1, OWNER_SUB, created_at=1000)
        self._insert_property(table, pid2, OWNER_SUB, created_at=2000)
        self._insert_unit(table, pid1, "uid-m1-oc" * 3 + "aa", occupancy_status="occupied")
        self._insert_unit(table, pid2, "uid-m2-va" * 3 + "bb", occupancy_status="vacant")
        result = svc.portfolio_occupancy_rollup(OWNER_SUB)
        assert result["property_count"] == 2
        assert result["unit_count"] == 2
        assert result["occupied"] == 1
        assert abs(result["occupancy_rate"] - 0.5) < 0.01

    def test_portfolio_rollup_no_division_by_zero(self, setup):
        table, svc = setup
        pid = "port-no-div0" + "x" * 20
        self._insert_property(table, pid, OWNER_SUB)
        result = svc.portfolio_occupancy_rollup(OWNER_SUB)
        assert result["occupancy_rate"] == 0.0

    def test_decimal_coercion_in_list_properties(self, setup):
        table, svc = setup
        pid = "deccoerce0000000" + "x" * 16
        # Insert with integer created_at (moto converts to Decimal)
        self._insert_property(table, pid, OWNER_SUB, created_at=1234567890)
        result = svc.list_properties(OWNER_SUB)
        assert result["count"] == 1
        prop = result["properties"][0]
        assert isinstance(prop["created_at"], int)
        assert isinstance(prop["updated_at"], int)
        assert isinstance(prop["unit_count"], int)


# ===========================================================================
# PROP-004: Router
# ===========================================================================

class TestProp004Router:

    def _make_session(self, sub=OWNER_SUB):
        return {"user_sub": sub, "role": "ADMIN"}

    def _make_auth_user(self, sub=OWNER_SUB):
        from app.auth.deps import AuthenticatedUser
        from app.auth.roles import Role
        return AuthenticatedUser(sub=sub, role=Role.ADMIN)

    def _create_prop_via_svc(self, svc, name="Router Test Prop"):
        return svc.create_property(OWNER_SUB, name, "apartment", ADDRESS)

    def test_flag_off_all_handlers_return_404(self, setup):
        _table, svc = setup
        from app.routers.properties import (
            create_property,
            get_property,
            update_property,
            archive_property,
            list_properties,
            get_portfolio_occupancy,
            get_property_occupancy,
            list_units,
            create_unit,
            get_unit,
            update_unit,
            delete_unit,
        )
        from app.models import PropertyIn, PropertyAddress, UnitIn, PropertyUpdateIn, UnitUpdateIn

        object.__setattr__(svc.S, "property_mgmt_enabled", False)
        try:
            session = self._make_session()
            user = self._make_auth_user()

            body = PropertyIn(
                name="X",
                property_type="apartment",
                address=PropertyAddress(line1="1 Main", city="C", region="R", postal_code="1", country="US"),
            )

            with pytest.raises(HTTPException) as exc:
                _run(create_property(body=body, user=user))
            assert exc.value.status_code == 404

            with pytest.raises(HTTPException):
                _run(get_property(property_id="x", session=session))

            with pytest.raises(HTTPException):
                _run(list_properties(session=session))

            with pytest.raises(HTTPException):
                _run(get_portfolio_occupancy(session=session))

            with pytest.raises(HTTPException):
                _run(get_property_occupancy(property_id="x", session=session))

        finally:
            object.__setattr__(svc.S, "property_mgmt_enabled", True)

    def test_create_property_handler(self, setup):
        _table, svc = setup
        from app.routers.properties import create_property as handler
        from app.models import PropertyIn, PropertyAddress

        body = PropertyIn(
            name="Handler Test",
            property_type="apartment",
            address=PropertyAddress(**ADDRESS),
        )
        user = self._make_auth_user()
        result = _run(handler(body=body, user=user))
        assert result.status == "active"  # PropertyOut
        assert result.occupancy_status == "vacant"
        assert result.unit_count == 0

    def test_create_property_idempotency(self, setup):
        _table, svc = setup
        from app.routers.properties import create_property as handler
        from app.models import PropertyIn, PropertyAddress

        body = PropertyIn(
            name="Idempotent Property",
            property_type="apartment",
            address=PropertyAddress(**ADDRESS),
        )
        user = self._make_auth_user()
        r1 = _run(handler(body=body, user=user))
        r2 = _run(handler(body=body, user=user))
        assert r1.property_id == r2.property_id

    def test_list_properties_handler(self, setup):
        _table, svc = setup
        from app.routers.properties import list_properties as handler

        self._create_prop_via_svc(svc, "List Handler 1")
        self._create_prop_via_svc(svc, "List Handler 2")

        session = self._make_session()
        result = _run(handler(status="active", property_type=None, cursor=None, limit=50, session=session))
        assert len(result.properties) == 2

    def test_list_properties_status_filter(self, setup):
        _table, svc = setup
        from app.routers.properties import list_properties as handler, archive_property as archive_handler

        p1 = self._create_prop_via_svc(svc, "Filter Active")
        p2 = self._create_prop_via_svc(svc, "Filter Archived")
        svc.archive_property(p2["property_id"], user_sub=OWNER_SUB)

        session = self._make_session()
        result = _run(handler(status="active", property_type=None, cursor=None, limit=50, session=session))
        assert result.count == 1

    def test_list_properties_invalid_status_422(self, setup):
        _table, svc = setup
        from app.routers.properties import list_properties as handler

        session = self._make_session()
        with pytest.raises(HTTPException) as exc:
            _run(handler(status="garbage", property_type=None, cursor=None, limit=50, session=session))
        assert exc.value.status_code == 422

    def test_get_property_handler_hit(self, setup):
        _table, svc = setup
        from app.routers.properties import get_property as handler

        prop = self._create_prop_via_svc(svc)
        session = self._make_session()
        result = _run(handler(property_id=prop["property_id"], session=session))
        assert result.property_id == prop["property_id"]

    def test_get_property_handler_miss_404(self, setup):
        _table, svc = setup
        from app.routers.properties import get_property as handler

        session = self._make_session()
        with pytest.raises(HTTPException) as exc:
            _run(handler(property_id="bad-id-0000000000000000000000", session=session))
        assert exc.value.status_code == 404

    def test_update_property_handler(self, setup):
        _table, svc = setup
        from app.routers.properties import update_property as handler
        from app.models import PropertyUpdateIn

        prop = self._create_prop_via_svc(svc, "Before Update")
        user = self._make_auth_user()
        body = PropertyUpdateIn(name="After Update")
        result = _run(handler(property_id=prop["property_id"], body=body, user=user))
        assert result.name == "After Update"

    def test_archive_property_handler(self, setup):
        _table, svc = setup
        from app.routers.properties import archive_property as handler, get_property as get_handler

        prop = self._create_prop_via_svc(svc, "To Archive")
        user = self._make_auth_user()
        result = _run(handler(property_id=prop["property_id"], user=user))
        assert result.status == "archived"

        session = self._make_session()
        still_there = _run(get_handler(property_id=prop["property_id"], session=session))
        assert still_there.status == "archived"

    def test_get_property_occupancy_zero_units(self, setup):
        _table, svc = setup
        from app.routers.properties import get_property_occupancy as handler

        prop = self._create_prop_via_svc(svc, "Occ Zero")
        session = self._make_session()
        result = _run(handler(property_id=prop["property_id"], session=session))
        assert result.total == 0
        assert result.occupied == 0
        assert result.occupancy_status == "vacant"
        assert result.occupancy_rate == 0.0

    def test_get_property_occupancy_unknown_no_404(self, setup):
        _table, svc = setup
        from app.routers.properties import get_property_occupancy as handler

        session = self._make_session()
        result = _run(handler(property_id="unknown-property-id000000000000000", session=session))
        assert result.total == 0  # no exception

    def test_portfolio_occupancy_route_not_captured_by_property_id(self, setup):
        """Verify /portfolio/occupancy handler is distinct from /{property_id}."""
        _table, svc = setup
        from app.routers import properties as props_mod
        from app.routers.properties import properties_router

        # Check route ordering: portfolio route appears before /{property_id}
        paths = [r.path for r in properties_router.routes]
        portfolio_idx = next((i for i, p in enumerate(paths) if "portfolio" in p), None)
        dynamic_idx = next((i for i, p in enumerate(paths) if "{property_id}" in p and "/units" not in p and "/occupancy" not in p), None)
        assert portfolio_idx is not None, "Portfolio occupancy route not found"
        assert dynamic_idx is not None, "Dynamic /{property_id} route not found"
        assert portfolio_idx < dynamic_idx, (
            f"/portfolio/occupancy (idx={portfolio_idx}) must be declared before "
            f"/{{property_id}} (idx={dynamic_idx})"
        )

    def test_create_unit_handler(self, setup):
        _table, svc = setup
        from app.routers.properties import create_unit as handler
        from app.models import UnitIn

        prop = self._create_prop_via_svc(svc, "Unit Create Prop")
        user = self._make_auth_user()
        body = UnitIn(label="Router Unit 1", bedrooms=2, bathrooms=1.5, square_footage=800,
                      market_rent_cents=120000)
        result = _run(handler(property_id=prop["property_id"], body=body, user=user))
        assert result.unit_id
        assert result.label == "Router Unit 1"
        assert result.property_id == prop["property_id"]

    def test_create_unit_handler_unknown_property_404(self, setup):
        _table, svc = setup
        from app.routers.properties import create_unit as handler
        from app.models import UnitIn

        user = self._make_auth_user()
        body = UnitIn(label="X", bedrooms=1, bathrooms=1.0, square_footage=400, market_rent_cents=50000)
        with pytest.raises(HTTPException) as exc:
            _run(handler(property_id="nonexistent00000000000000000000", body=body, user=user))
        assert exc.value.status_code == 404

    def test_list_units_handler(self, setup):
        _table, svc = setup
        from app.routers.properties import list_units as handler

        prop = self._create_prop_via_svc(svc, "List Units Prop")
        svc.create_unit(prop["property_id"], label="LU1", bedrooms=1, bathrooms=1.0,
                        square_footage=400, market_rent_cents=50000, user_sub=OWNER_SUB)
        svc.create_unit(prop["property_id"], label="LU2", bedrooms=2, bathrooms=2.0,
                        square_footage=800, market_rent_cents=90000, user_sub=OWNER_SUB)

        session = self._make_session()
        result = _run(handler(property_id=prop["property_id"], session=session))
        assert len(result) == 2
        labels = [u.label for u in result]
        assert "LU1" in labels
        assert "LU2" in labels

    def test_get_unit_handler_miss_404(self, setup):
        _table, svc = setup
        from app.routers.properties import get_unit as handler

        prop = self._create_prop_via_svc(svc, "GetUnit Prop")
        session = self._make_session()
        with pytest.raises(HTTPException) as exc:
            _run(handler(property_id=prop["property_id"], unit_id="nope", session=session))
        assert exc.value.status_code == 404

    def test_update_unit_handler_triggers_rollup(self, setup):
        table, svc = setup
        from app.routers.properties import update_unit as handler
        from app.models import UnitUpdateIn

        prop = self._create_prop_via_svc(svc, "Rollup Test Prop")
        unit = svc.create_unit(prop["property_id"], label="RU1", bedrooms=1, bathrooms=1.0,
                               square_footage=400, market_rent_cents=50000, user_sub=OWNER_SUB)

        user = self._make_auth_user()
        body = UnitUpdateIn(occupancy_status="occupied")
        result = _run(handler(
            property_id=prop["property_id"],
            unit_id=unit["unit_id"],
            body=body,
            user=user,
        ))
        assert result.occupancy_status == "occupied"

        meta = table.get_item(Key={"property_id": prop["property_id"], "sk": "META"})["Item"]
        assert meta["occupancy_status"] == "occupied"

    def test_delete_unit_handler_success(self, setup):
        table, svc = setup
        from app.routers.properties import delete_unit as handler

        prop = self._create_prop_via_svc(svc, "Delete Unit Prop")
        unit = svc.create_unit(prop["property_id"], label="DU1", bedrooms=1, bathrooms=1.0,
                               square_footage=400, market_rent_cents=50000, user_sub=OWNER_SUB)

        user = self._make_auth_user()
        result = _run(handler(property_id=prop["property_id"], unit_id=unit["unit_id"], user=user))
        assert result == {"ok": True}

        meta = table.get_item(Key={"property_id": prop["property_id"], "sk": "META"})["Item"]
        assert int(meta["unit_count"]) == 0

    def test_delete_unit_handler_unknown_ok_false(self, setup):
        _table, svc = setup
        from app.routers.properties import delete_unit as handler

        prop = self._create_prop_via_svc(svc, "Delete Miss Prop")
        user = self._make_auth_user()
        result = _run(handler(property_id=prop["property_id"], unit_id="nope", user=user))
        assert result == {"ok": False}

    def test_list_units_handler_empty(self, setup):
        _table, svc = setup
        from app.routers.properties import list_units as handler

        prop = self._create_prop_via_svc(svc, "Empty Units Prop")
        session = self._make_session()
        result = _run(handler(property_id=prop["property_id"], session=session))
        assert result == []

    def test_portfolio_occupancy_handler_empty(self, setup):
        _table, svc = setup
        from app.routers.properties import get_portfolio_occupancy as handler

        session = self._make_session(sub="empty-user-no-props")
        result = _run(handler(session=session))
        assert result.property_count == 0
        assert result.unit_count == 0
        assert result.occupancy_rate == 0.0

    def test_main_py_registration(self, setup):
        """properties_router must be registered in app.main."""
        from app.main import create_app
        app = create_app()
        all_paths = []
        for route in app.routes:
            if hasattr(route, "path"):
                all_paths.append(route.path)
        assert any("/ui/properties" in p for p in all_paths), (
            "Expected /ui/properties routes to be registered in app"
        )
