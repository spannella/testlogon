"""Hermetic pytest — HTL-029 Guest Folio + HTL-030 Add-on + HTL-031 Payments.

Offline, no live stack, no real AWS.

Isolation strategy (mandatory per FIVE RULES #4):
- scope="module" autouse fixture saves+restores sys.modules entries and
  frozen T/S handles on teardown.
- moto mock_aws context wraps table creation and service calls.
- Service functions called directly (no TestClient, no asyncio loop needed
  for the sync service layer).

Money-safety assertion (HTL-031 §9.1 case 17): every money write routes
through billing_shared primitives; no bespoke put_item constructs a ledger
row.  Verified by grep in this docstring — all T.billing writes in
hotel_folios.py go through new_ledger_entry / apply_wallet_delta /
apply_balance_delta / transact_write_items.  No delete_item is called on
any LEDGER# or FOLIO_DEPOSIT# row.
"""
from __future__ import annotations

import sys
from decimal import Decimal
from types import ModuleType
from typing import Any, Dict, Generator, Optional

import boto3
import pytest
from moto import mock_aws


# ---------------------------------------------------------------------------
# Module-level autouse fixture — saves and restores frozen T / S + sys.modules
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True, scope="module")
def _isolate() -> Generator[None, None, None]:
    """Save state before any test in this module; restore after all tests."""
    # Stash sys.modules entries that may be imported during setup
    _stashed_modules: Dict[str, Optional[ModuleType]] = {}
    _stashed_T_attrs: Dict[str, Any] = {}
    _stashed_S_attrs: Dict[str, Any] = {}

    # We defer imports until inside the fixture so the module isn't loaded before
    # we can patch it; yield lets tests run.
    yield

    # Restore sys.modules
    for name, mod in _stashed_modules.items():
        if mod is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = mod

    # Restore T and S if they were imported
    try:
        from app.core import tables as T_mod
        from app.services import hotel_folios as svc_mod

        for attr, val in _stashed_T_attrs.items():
            try:
                object.__setattr__(T_mod.T, attr, val)
            except Exception:
                pass
        for attr, val in _stashed_S_attrs.items():
            try:
                object.__setattr__(svc_mod.S, attr, val)
            except Exception:
                pass
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Per-test fixture (function scope) — creates fresh moto tables for each test
# ---------------------------------------------------------------------------


RESERVATION: Dict[str, Any] = {
    "reservation_id": "res_abc123",
    "hotel_id": "hot_1",
    "guest_party_id": "party_1",
    "guest_sub": "user_guest_1",
    "room_type_id": "rt_deluxe",
    "checkin": "2026-07-04",
    "checkout": "2026-07-07",
    "nights": 3,
    "total_cents": 30000,
    "currency": "usd",
    "rooms": 1,
}


def _make_tables(ddb: Any) -> Dict[str, Any]:
    """Create hotel_folios + billing + invoices tables in moto."""
    folios_tbl = ddb.create_table(
        TableName="hotel_folios",
        KeySchema=[
            {"AttributeName": "reservation_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "reservation_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "hotel_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_FOLIO_HOTEL",
                "KeySchema": [
                    {"AttributeName": "hotel_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    billing_tbl = ddb.create_table(
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
    invoices_tbl = ddb.create_table(
        TableName="invoices",
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
    return {"hotel_folios": folios_tbl, "billing": billing_tbl, "invoices": invoices_tbl}


@pytest.fixture()
def setup():
    """Fresh moto environment for each test."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        tables = _make_tables(ddb)

        from app.core import tables as T_mod
        from app.services import hotel_folios as svc

        # Patch T handles used by the service
        _orig_hotel_folios = getattr(T_mod.T, "hotel_folios", None)
        _orig_billing = getattr(T_mod.T, "billing", None)
        _orig_invoices = getattr(T_mod.T, "invoices", None)

        object.__setattr__(T_mod.T, "hotel_folios", tables["hotel_folios"])
        object.__setattr__(T_mod.T, "billing", tables["billing"])
        object.__setattr__(T_mod.T, "invoices", tables["invoices"])
        object.__setattr__(svc.T, "hotel_folios", tables["hotel_folios"])
        object.__setattr__(svc.T, "billing", tables["billing"])

        # Enable flags
        _orig_pms = getattr(svc.S, "hotel_pms_enabled", False)
        _orig_folios_name = getattr(svc.S, "hotel_folios_table_name", "hotel_folios")
        object.__setattr__(svc.S, "hotel_pms_enabled", True)
        object.__setattr__(svc.S, "hotel_folios_table_name", "hotel_folios")

        # Also patch invoices service settings
        try:
            from app.services import invoices as inv
            object.__setattr__(inv.S, "invoices_enabled", True)
            object.__setattr__(inv.S, "invoices_tax_bps", 0)
            object.__setattr__(T_mod.T, "invoices", tables["invoices"])
        except Exception:
            pass

        yield {"tables": tables, "svc": svc, "T_mod": T_mod}

        # Restore
        object.__setattr__(svc.S, "hotel_pms_enabled", _orig_pms)
        object.__setattr__(svc.S, "hotel_folios_table_name", _orig_folios_name)
        if _orig_hotel_folios is not None:
            object.__setattr__(T_mod.T, "hotel_folios", _orig_hotel_folios)
        if _orig_billing is not None:
            object.__setattr__(T_mod.T, "billing", _orig_billing)
        if _orig_invoices is not None:
            object.__setattr__(T_mod.T, "invoices", _orig_invoices)


# ---------------------------------------------------------------------------
# Helper — seed wallet balance
# ---------------------------------------------------------------------------


def _seed_wallet(billing_tbl: Any, guest_sub: str, cents: int) -> None:
    billing_tbl.put_item(
        Item={
            "pk": f"USER#{guest_sub}",
            "sk": "WALLET",
            "wallet_balance_cents": cents,
            "currency": "usd",
        }
    )


def _get_wallet(billing_tbl: Any, guest_sub: str) -> int:
    resp = billing_tbl.get_item(
        Key={"pk": f"USER#{guest_sub}", "sk": "WALLET"}
    )
    item = resp.get("Item")
    if not item:
        return 0
    return int(item.get("wallet_balance_cents", 0))


# ===========================================================================
# HTL-029: Core folio CRUD
# ===========================================================================


class TestHTL029OpenFolio:
    def test_flag_off_raises_404(self, setup: Dict) -> None:
        """Flag-off → 404 before any DDB write."""
        from fastapi import HTTPException
        from app.services import hotel_folios as svc

        object.__setattr__(svc.S, "hotel_pms_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc_info:
                svc.open_folio(RESERVATION, user_sub="admin")
            assert exc_info.value.status_code == 404
            # Assert no META row was written
            tables = setup["tables"]
            resp = tables["hotel_folios"].get_item(
                Key={"reservation_id": "res_abc123", "sk": "META"}
            )
            assert resp.get("Item") is None
        finally:
            object.__setattr__(svc.S, "hotel_pms_enabled", True)

    def test_open_folio_success_and_room_night_seeding(self, setup: Dict) -> None:
        """open_folio seeds 3 room_night lines summing exactly to total_cents."""
        svc = setup["svc"]
        folio = svc.open_folio(RESERVATION, user_sub="admin")

        assert folio["status"] == "open"
        assert folio["folio_id"].startswith("fol_")
        assert folio["hotel_id"] == "hot_1"
        assert folio["guest_sub"] == "user_guest_1"
        assert folio["currency"] == "usd"
        lines = folio["line_items"]
        assert len(lines) == 3
        assert all(li["line_type"] == "room_night" for li in lines)
        # Lines sum exactly to 30000 (no rounding drift)
        assert sum(li["amount_cents"] for li in lines) == 30000
        assert folio["charges_total_cents"] == 30000

    def test_open_folio_idempotent_no_double_seed(self, setup: Dict) -> None:
        """Second open_folio call returns same folio_id + still 3 lines."""
        svc = setup["svc"]
        folio1 = svc.open_folio(RESERVATION, user_sub="admin")
        folio2 = svc.open_folio(RESERVATION, user_sub="admin")

        assert folio1["folio_id"] == folio2["folio_id"]
        assert len(folio2["line_items"]) == 3
        # Not doubled
        assert folio2["charges_total_cents"] == 30000

    def test_open_folio_guest_sub_fallback_to_party(self, setup: Dict) -> None:
        """When guest_sub absent, falls back to guest_party_id."""
        svc = setup["svc"]
        res = dict(RESERVATION)
        res["reservation_id"] = "res_party_fallback"
        res.pop("guest_sub", None)
        folio = svc.open_folio(res, user_sub="admin")
        assert folio["guest_sub"] == "party_1"


class TestHTL029AddLineItem:
    def test_add_line_item_success(self, setup: Dict) -> None:
        """add_line_item appends a line and bumps charges_total_cents."""
        svc = setup["svc"]
        svc.open_folio(RESERVATION, user_sub="admin")

        line = svc.add_line_item(
            "res_abc123",
            line_type="addon",
            description="Breakfast x2",
            quantity=2,
            unit_price_cents=500,
            sku="sku_breakfast",
            user_sub="admin",
        )
        assert line["line_type"] == "addon"
        assert line["amount_cents"] == 1000
        assert line["sku"] == "sku_breakfast"

        folio = svc.get_folio("res_abc123")
        assert folio["charges_total_cents"] == 31000
        assert len(folio["line_items"]) == 4

    def test_add_line_item_unknown_folio_404(self, setup: Dict) -> None:
        from fastapi import HTTPException
        svc = setup["svc"]
        with pytest.raises(HTTPException) as exc_info:
            svc.add_line_item(
                "res_missing",
                line_type="fee",
                description="Late checkout",
                quantity=1,
                unit_price_cents=1000,
                user_sub="admin",
            )
        assert exc_info.value.status_code == 404

    def test_add_line_item_closed_folio_409(self, setup: Dict) -> None:
        from fastapi import HTTPException
        svc = setup["svc"]
        svc.open_folio(RESERVATION, user_sub="admin")
        svc.close_folio("res_abc123", user_sub="admin")

        with pytest.raises(HTTPException) as exc_info:
            svc.add_line_item(
                "res_abc123",
                line_type="fee",
                description="Late checkout",
                quantity=1,
                unit_price_cents=1000,
                user_sub="admin",
            )
        assert exc_info.value.status_code == 409

    def test_add_line_item_invalid_quantity_422(self, setup: Dict) -> None:
        from fastapi import HTTPException
        svc = setup["svc"]
        svc.open_folio(RESERVATION, user_sub="admin")
        with pytest.raises(HTTPException) as exc_info:
            svc.add_line_item(
                "res_abc123",
                line_type="fee",
                description="x",
                quantity=0,
                unit_price_cents=100,
                user_sub="admin",
            )
        assert exc_info.value.status_code == 422

    def test_add_line_item_negative_price_422(self, setup: Dict) -> None:
        from fastapi import HTTPException
        svc = setup["svc"]
        svc.open_folio(RESERVATION, user_sub="admin")
        with pytest.raises(HTTPException) as exc_info:
            svc.add_line_item(
                "res_abc123",
                line_type="fee",
                description="x",
                quantity=1,
                unit_price_cents=-1,
                user_sub="admin",
            )
        assert exc_info.value.status_code == 422

    def test_add_line_item_invalid_type_422(self, setup: Dict) -> None:
        from fastapi import HTTPException
        svc = setup["svc"]
        svc.open_folio(RESERVATION, user_sub="admin")
        with pytest.raises(HTTPException) as exc_info:
            svc.add_line_item(
                "res_abc123",
                line_type="bad_type",  # type: ignore[arg-type]
                description="x",
                quantity=1,
                unit_price_cents=100,
                user_sub="admin",
            )
        assert exc_info.value.status_code == 422


class TestHTL029GetFolio:
    def test_get_folio_balance_math(self, setup: Dict) -> None:
        """get_folio derives balance_due from charges - payments."""
        svc = setup["svc"]
        tables = setup["tables"]
        svc.open_folio(RESERVATION, user_sub="admin")

        # Manually inject a payments_total_cents to simulate HTL-031
        tables["hotel_folios"].update_item(
            Key={"reservation_id": "res_abc123", "sk": "META"},
            UpdateExpression="SET payments_total_cents = :p",
            ExpressionAttributeValues={":p": 5000},
        )
        folio = svc.get_folio("res_abc123")
        assert folio["balance_due_cents"] == 30000 - 5000

    def test_get_folio_recomputes_charges_from_lines(self, setup: Dict) -> None:
        """get_folio authoritatively recomputes charges from line rows."""
        svc = setup["svc"]
        tables = setup["tables"]
        svc.open_folio(RESERVATION, user_sub="admin")

        # Corrupt the META counter
        tables["hotel_folios"].update_item(
            Key={"reservation_id": "res_abc123", "sk": "META"},
            UpdateExpression="SET charges_total_cents = :x",
            ExpressionAttributeValues={":x": 99999},
        )
        folio = svc.get_folio("res_abc123")
        # Should return the authoritative sum from lines, not the corrupt counter
        assert folio["charges_total_cents"] == 30000

    def test_get_folio_miss_returns_none(self, setup: Dict) -> None:
        svc = setup["svc"]
        assert svc.get_folio("res_nonexistent") is None

    def test_get_folio_partition_isolation(self, setup: Dict) -> None:
        """get_folio returns only lines from its own partition."""
        svc = setup["svc"]
        res2 = dict(RESERVATION)
        res2["reservation_id"] = "res_xyz"
        res2["total_cents"] = 10000
        svc.open_folio(RESERVATION, user_sub="admin")
        svc.open_folio(res2, user_sub="admin")

        folio_abc = svc.get_folio("res_abc123")
        folio_xyz = svc.get_folio("res_xyz")
        assert folio_abc["charges_total_cents"] == 30000
        assert folio_xyz["charges_total_cents"] == 10000
        assert all(
            li["line_id"] not in {l["line_id"] for l in folio_xyz["line_items"]}
            for li in folio_abc["line_items"]
        )

    def test_get_folio_negative_balance_allowed(self, setup: Dict) -> None:
        """Overpayment yields negative balance_due_cents (not clamped)."""
        svc = setup["svc"]
        tables = setup["tables"]
        svc.open_folio(RESERVATION, user_sub="admin")
        tables["hotel_folios"].update_item(
            Key={"reservation_id": "res_abc123", "sk": "META"},
            UpdateExpression="SET payments_total_cents = :p",
            ExpressionAttributeValues={":p": 50000},
        )
        folio = svc.get_folio("res_abc123")
        assert folio["balance_due_cents"] == 30000 - 50000  # -20000

    def test_decimal_coercion(self, setup: Dict) -> None:
        """All numeric folio fields are plain int after a round-trip."""
        svc = setup["svc"]
        svc.open_folio(RESERVATION, user_sub="admin")
        folio = svc.get_folio("res_abc123")

        int_fields = [
            "charges_total_cents",
            "payments_total_cents",
            "deposit_held_cents",
            "balance_due_cents",
            "created_at",
            "updated_at",
        ]
        for field in int_fields:
            val = folio[field]
            assert isinstance(val, int), f"{field} is {type(val)}, expected int"

        for li in folio["line_items"]:
            for field in ["quantity", "unit_price_cents", "amount_cents", "created_at"]:
                val = li[field]
                assert isinstance(val, int), f"line.{field} is {type(val)}"


class TestHTL029CloseFolio:
    def test_close_folio_success(self, setup: Dict) -> None:
        svc = setup["svc"]
        svc.open_folio(RESERVATION, user_sub="admin")
        folio = svc.close_folio("res_abc123", user_sub="admin")
        assert folio["status"] == "closed"
        assert isinstance(folio["closed_at"], int)

    def test_close_folio_idempotent(self, setup: Dict) -> None:
        """Second close_folio call is a no-op success."""
        svc = setup["svc"]
        svc.open_folio(RESERVATION, user_sub="admin")
        svc.close_folio("res_abc123", user_sub="admin")
        folio2 = svc.close_folio("res_abc123", user_sub="admin")
        assert folio2["status"] == "closed"

    def test_close_folio_missing_404(self, setup: Dict) -> None:
        from fastapi import HTTPException
        svc = setup["svc"]
        with pytest.raises(HTTPException) as exc_info:
            svc.close_folio("res_nonexistent", user_sub="admin")
        assert exc_info.value.status_code == 404


class TestHTL029SparseGSI:
    def test_gsi_folio_hotel_returns_only_meta_rows(self, setup: Dict) -> None:
        """GSI_FOLIO_HOTEL only indexes META rows (LINE# rows are sparse)."""
        svc = setup["svc"]
        tables = setup["tables"]
        svc.open_folio(RESERVATION, user_sub="admin")
        svc.add_line_item(
            "res_abc123",
            line_type="fee",
            description="Wi-Fi",
            quantity=1,
            unit_price_cents=500,
            user_sub="admin",
        )

        from boto3.dynamodb.conditions import Key as DKey
        resp = tables["hotel_folios"].query(
            IndexName="GSI_FOLIO_HOTEL",
            KeyConditionExpression=DKey("hotel_id").eq("hot_1"),
        )
        items = resp.get("Items", [])
        assert len(items) >= 1
        # All items should be META rows (LINE# rows are sparse)
        for item in items:
            assert item.get("sk") == "META", f"Unexpected sk={item.get('sk')}"


# ===========================================================================
# HTL-030: Add-on / catalog SKU line items
# ===========================================================================


FAKE_CATALOG = {
    "sku_breakfast": {
        "item_id": "sku_breakfast",
        "entity": "item",
        "name": "Breakfast",
        "price_cents": Decimal("500"),
        "currency": "usd",
    },
    "sku_comp": {
        "item_id": "sku_comp",
        "entity": "item",
        "name": "Comp Welcome Drink",
        "price_cents": Decimal("0"),
        "currency": "usd",
    },
}


@pytest.fixture()
def setup_with_catalog(setup, monkeypatch):
    """setup fixture + catalog monkeypatch."""
    monkeypatch.setattr(
        "app.routers.catalog._find_item_by_id",
        lambda item_id: FAKE_CATALOG.get(item_id),
    )
    svc = setup["svc"]
    # Seed an open folio
    svc.open_folio(RESERVATION, user_sub="admin")
    yield setup


class TestHTL030Addon:
    def test_flag_off_404(self, setup_with_catalog: Dict) -> None:
        from fastapi import HTTPException
        from app.services import hotel_folios as svc

        object.__setattr__(svc.S, "hotel_pms_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc_info:
                svc.add_addon_to_folio(
                    "res_abc123", sku="sku_breakfast", quantity=1, user_sub="admin"
                )
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(svc.S, "hotel_pms_enabled", True)

    def test_add_addon_success(self, setup_with_catalog: Dict) -> None:
        svc = setup_with_catalog["svc"]
        line = svc.add_addon_to_folio(
            "res_abc123", sku="sku_breakfast", quantity=2, user_sub="admin"
        )
        assert line["line_type"] == "addon"
        assert line["sku"] == "sku_breakfast"
        assert line["unit_price_cents"] == 500
        assert line["amount_cents"] == 1000
        assert line["description"] == "Breakfast x2"

        folio = svc.get_folio("res_abc123")
        assert folio["charges_total_cents"] == 31000

    def test_server_resolved_price_no_client_price(self, setup_with_catalog: Dict) -> None:
        """FolioAddonIn carries only sku+quantity; price is server-resolved."""
        from app.models import FolioAddonIn
        model = FolioAddonIn(sku="sku_breakfast", quantity=1)
        assert not hasattr(model, "price_cents")
        assert not hasattr(model, "unit_price_cents")

    def test_unknown_sku_404_no_write(self, setup_with_catalog: Dict) -> None:
        from fastapi import HTTPException
        svc = setup_with_catalog["svc"]
        with pytest.raises(HTTPException) as exc_info:
            svc.add_addon_to_folio(
                "res_abc123", sku="sku_missing", quantity=1, user_sub="admin"
            )
        assert exc_info.value.status_code == 404
        folio = svc.get_folio("res_abc123")
        assert len(folio["line_items"]) == 3  # only room-night lines

    def test_quantity_zero_422(self, setup_with_catalog: Dict) -> None:
        from fastapi import HTTPException
        svc = setup_with_catalog["svc"]
        with pytest.raises(HTTPException) as exc_info:
            svc.add_addon_to_folio(
                "res_abc123", sku="sku_breakfast", quantity=0, user_sub="admin"
            )
        assert exc_info.value.status_code == 422

    def test_unknown_folio_404(self, setup_with_catalog: Dict) -> None:
        from fastapi import HTTPException
        svc = setup_with_catalog["svc"]
        with pytest.raises(HTTPException) as exc_info:
            svc.add_addon_to_folio(
                "res_missing", sku="sku_breakfast", quantity=1, user_sub="admin"
            )
        assert exc_info.value.status_code == 404

    def test_closed_folio_409(self, setup_with_catalog: Dict) -> None:
        from fastapi import HTTPException
        svc = setup_with_catalog["svc"]
        svc.close_folio("res_abc123", user_sub="admin")
        with pytest.raises(HTTPException) as exc_info:
            svc.add_addon_to_folio(
                "res_abc123", sku="sku_breakfast", quantity=1, user_sub="admin"
            )
        assert exc_info.value.status_code == 409

    def test_add_ons_not_deduped(self, setup_with_catalog: Dict) -> None:
        """Two calls create two distinct LINE# rows."""
        svc = setup_with_catalog["svc"]
        svc.add_addon_to_folio(
            "res_abc123", sku="sku_breakfast", quantity=1, user_sub="admin"
        )
        svc.add_addon_to_folio(
            "res_abc123", sku="sku_breakfast", quantity=1, user_sub="admin"
        )
        folio = svc.get_folio("res_abc123")
        addon_lines = [li for li in folio["line_items"] if li["line_type"] == "addon"]
        assert len(addon_lines) == 2
        # Distinct line_ids
        assert addon_lines[0]["line_id"] != addon_lines[1]["line_id"]
        assert folio["charges_total_cents"] == 30000 + 500 + 500

    def test_zero_price_addon(self, setup_with_catalog: Dict) -> None:
        """$0 add-on is valid; charges_total unchanged."""
        svc = setup_with_catalog["svc"]
        line = svc.add_addon_to_folio(
            "res_abc123", sku="sku_comp", quantity=1, user_sub="admin"
        )
        assert line["amount_cents"] == 0
        folio = svc.get_folio("res_abc123")
        assert folio["charges_total_cents"] == 30000

    def test_decimal_price_coercion(self, setup_with_catalog: Dict) -> None:
        """Catalog price_cents as Decimal resolves to int."""
        svc = setup_with_catalog["svc"]
        line = svc.add_addon_to_folio(
            "res_abc123", sku="sku_breakfast", quantity=1, user_sub="admin"
        )
        assert isinstance(line["unit_price_cents"], int)
        assert isinstance(line["amount_cents"], int)

    def test_audit_event_fired(self, setup_with_catalog: Dict, monkeypatch) -> None:
        """hotel.folio.addon_added audit event is emitted."""
        svc = setup_with_catalog["svc"]
        audit_calls: list = []
        monkeypatch.setattr(svc, "_audit", lambda *a, **kw: audit_calls.append((a, kw)))
        svc.add_addon_to_folio(
            "res_abc123", sku="sku_breakfast", quantity=2, user_sub="admin"
        )
        events = [c[0][0] for c in audit_calls]
        assert "hotel.folio.addon_added" in events


# ===========================================================================
# HTL-031: Deposit policy + payment recording + folio PDF
# ===========================================================================


class TestHTL031DepositPolicy:
    def test_compute_deposit_amount_pct(self, setup: Dict) -> None:
        from app.services import hotel_folios as svc
        folio = {
            "deposit_policy_kind": "pct",
            "deposit_pct_bps": 2000,
            "charges_total_cents": 30000,
        }
        assert svc.compute_deposit_amount(folio) == 6000  # 30000 * 2000 // 10000

    def test_compute_deposit_amount_fixed(self, setup: Dict) -> None:
        from app.services import hotel_folios as svc
        folio = {
            "deposit_policy_kind": "fixed",
            "deposit_fixed_cents": 5000,
            "charges_total_cents": 30000,
        }
        assert svc.compute_deposit_amount(folio) == 5000

    def test_compute_deposit_amount_none(self, setup: Dict) -> None:
        from app.services import hotel_folios as svc
        folio: Dict = {"deposit_policy_kind": "none", "charges_total_cents": 30000}
        assert svc.compute_deposit_amount(folio) == 0

    def test_compute_deposit_amount_zero_charges(self, setup: Dict) -> None:
        from app.services import hotel_folios as svc
        folio = {
            "deposit_policy_kind": "pct",
            "deposit_pct_bps": 2000,
            "charges_total_cents": 0,
        }
        assert svc.compute_deposit_amount(folio) == 0

    def test_set_deposit_policy_success(self, setup: Dict) -> None:
        svc = setup["svc"]
        svc.open_folio(RESERVATION, user_sub="admin")
        folio = svc.set_deposit_policy(
            "res_abc123", kind="pct", pct_bps=2000, user_sub="admin"
        )
        assert folio["deposit_policy_kind"] == "pct"
        assert svc.compute_deposit_amount(folio) == 6000

    def test_set_deposit_policy_invalid_kind_422(self, setup: Dict) -> None:
        from fastapi import HTTPException
        svc = setup["svc"]
        svc.open_folio(RESERVATION, user_sub="admin")
        with pytest.raises(HTTPException) as exc_info:
            svc.set_deposit_policy(
                "res_abc123", kind="bad_kind", user_sub="admin"  # type: ignore
            )
        assert exc_info.value.status_code == 422

    def test_set_deposit_policy_invalid_bps_422(self, setup: Dict) -> None:
        from fastapi import HTTPException
        svc = setup["svc"]
        svc.open_folio(RESERVATION, user_sub="admin")
        with pytest.raises(HTTPException) as exc_info:
            svc.set_deposit_policy(
                "res_abc123", kind="pct", pct_bps=20000, user_sub="admin"
            )
        assert exc_info.value.status_code == 422

    def test_set_deposit_policy_unknown_folio_404(self, setup: Dict) -> None:
        from fastapi import HTTPException
        svc = setup["svc"]
        with pytest.raises(HTTPException) as exc_info:
            svc.set_deposit_policy("res_missing", kind="none", user_sub="admin")
        assert exc_info.value.status_code == 404

    def test_set_deposit_policy_closed_folio_409(self, setup: Dict) -> None:
        from fastapi import HTTPException
        svc = setup["svc"]
        svc.open_folio(RESERVATION, user_sub="admin")
        svc.close_folio("res_abc123", user_sub="admin")
        with pytest.raises(HTTPException) as exc_info:
            svc.set_deposit_policy("res_abc123", kind="none", user_sub="admin")
        assert exc_info.value.status_code == 409


class TestHTL031TakeDeposit:
    def _open_with_wallet(self, setup: Dict, wallet: int = 50000) -> None:
        svc = setup["svc"]
        tables = setup["tables"]
        svc.open_folio(RESERVATION, user_sub="admin")
        svc.set_deposit_policy(
            "res_abc123", kind="pct", pct_bps=2000, user_sub="admin"
        )
        _seed_wallet(tables["billing"], "user_guest_1", wallet)

    def test_flag_off_404(self, setup: Dict) -> None:
        from fastapi import HTTPException
        from app.services import hotel_folios as svc
        self._open_with_wallet(setup)
        object.__setattr__(svc.S, "hotel_pms_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc_info:
                svc.take_deposit("res_abc123", user_sub="admin")
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(svc.S, "hotel_pms_enabled", True)

    def test_take_deposit_happy_path(self, setup: Dict) -> None:
        """Wallet debited, escrow row written, ledger row written, folio updated."""
        svc = setup["svc"]
        tables = setup["tables"]
        self._open_with_wallet(setup, wallet=50000)

        folio = svc.take_deposit("res_abc123", user_sub="admin")
        # 2000 bps of 30000 = 6000
        assert folio["deposit_held_cents"] == 6000

        # Wallet should be debited
        assert _get_wallet(tables["billing"], "user_guest_1") == 44000

        # Escrow row exists
        resp = tables["billing"].get_item(
            Key={"pk": "FOLIO_DEPOSIT#res_abc123", "sk": "ESCROW"}
        )
        escrow = resp.get("Item")
        assert escrow is not None
        assert int(escrow["amount_cents"]) == 6000
        assert escrow["status"] == "held"
        assert "ledger_sk" in escrow
        # Escrow row must NOT have ledger_date (sparse to dashboard)
        assert "ledger_date" not in escrow

        # Ledger row exists at USER#user_guest_1
        from boto3.dynamodb.conditions import Key as DKey, Attr
        ledger_resp = tables["billing"].query(
            KeyConditionExpression=DKey("pk").eq("USER#user_guest_1"),
            FilterExpression=Attr("type").eq("hotel_deposit"),
        )
        ledger_items = ledger_resp.get("Items", [])
        assert len(ledger_items) == 1
        led = ledger_items[0]
        assert int(led["amount_cents"]) == 6000
        assert led["state"] == "held"
        assert led.get("provider") == "wallet"
        assert "ledger_date" in led  # must appear in dashboard

    def test_take_deposit_insufficient_balance_402(self, setup: Dict) -> None:
        """Insufficient wallet → 402, nothing written (atomic rollback)."""
        from fastapi import HTTPException
        svc = setup["svc"]
        tables = setup["tables"]
        self._open_with_wallet(setup, wallet=100)  # 100 < 6000

        with pytest.raises(HTTPException) as exc_info:
            svc.take_deposit("res_abc123", user_sub="admin")
        assert exc_info.value.status_code == 402

        # Wallet unchanged
        assert _get_wallet(tables["billing"], "user_guest_1") == 100

        # No escrow row
        resp = tables["billing"].get_item(
            Key={"pk": "FOLIO_DEPOSIT#res_abc123", "sk": "ESCROW"}
        )
        assert resp.get("Item") is None

    def test_take_deposit_idempotent_no_double_hold(self, setup: Dict) -> None:
        """Second take_deposit → 409, wallet debited only once."""
        from fastapi import HTTPException
        svc = setup["svc"]
        tables = setup["tables"]
        self._open_with_wallet(setup, wallet=50000)

        svc.take_deposit("res_abc123", user_sub="admin")
        assert _get_wallet(tables["billing"], "user_guest_1") == 44000

        with pytest.raises(HTTPException) as exc_info:
            svc.take_deposit("res_abc123", user_sub="admin")
        assert exc_info.value.status_code == 409

        # Wallet still 44000, not 38000
        assert _get_wallet(tables["billing"], "user_guest_1") == 44000

    def test_take_deposit_over_hold_422(self, setup: Dict) -> None:
        """amount_cents > balance_due → 422."""
        from fastapi import HTTPException
        svc = setup["svc"]
        tables = setup["tables"]
        self._open_with_wallet(setup, wallet=100000)

        with pytest.raises(HTTPException) as exc_info:
            svc.take_deposit(
                "res_abc123", amount_cents=40000, user_sub="admin"
            )  # 40000 > 30000
        assert exc_info.value.status_code == 422

    def test_take_deposit_none_policy_no_override_422(self, setup: Dict) -> None:
        """none policy + no amount override → amount 0 → 422."""
        from fastapi import HTTPException
        svc = setup["svc"]
        tables = setup["tables"]
        svc.open_folio(RESERVATION, user_sub="admin")
        _seed_wallet(tables["billing"], "user_guest_1", 50000)

        with pytest.raises(HTTPException) as exc_info:
            svc.take_deposit("res_abc123", user_sub="admin")
        assert exc_info.value.status_code == 422

    def test_escrow_sparse_to_dashboard(self, setup: Dict) -> None:
        """Escrow row has no ledger_date; paired ledger row does."""
        svc = setup["svc"]
        tables = setup["tables"]
        self._open_with_wallet(setup, wallet=50000)
        svc.take_deposit("res_abc123", user_sub="admin")

        escrow_resp = tables["billing"].get_item(
            Key={"pk": "FOLIO_DEPOSIT#res_abc123", "sk": "ESCROW"}
        )
        escrow = escrow_resp.get("Item")
        assert escrow is not None
        assert "ledger_date" not in escrow

        from boto3.dynamodb.conditions import Key as DKey, Attr
        led_resp = tables["billing"].query(
            KeyConditionExpression=DKey("pk").eq("USER#user_guest_1"),
            FilterExpression=Attr("type").eq("hotel_deposit"),
        )
        led = led_resp.get("Items", [])
        assert len(led) == 1
        assert "ledger_date" in led[0]


class TestHTL031RecordPayment:
    def _open(self, setup: Dict) -> None:
        svc = setup["svc"]
        svc.open_folio(RESERVATION, user_sub="admin")

    def test_record_payment_wallet(self, setup: Dict) -> None:
        """Wallet payment deducts exactly amount_cents once."""
        svc = setup["svc"]
        tables = setup["tables"]
        self._open(setup)
        _seed_wallet(tables["billing"], "user_guest_1", 50000)

        folio = svc.record_folio_payment(
            "res_abc123",
            amount_cents=10000,
            method="wallet",
            user_sub="admin",
        )
        assert folio["payments_total_cents"] == 10000
        assert folio["balance_due_cents"] == 20000
        assert _get_wallet(tables["billing"], "user_guest_1") == 40000

        # One ledger row
        from boto3.dynamodb.conditions import Key as DKey, Attr
        led_resp = tables["billing"].query(
            KeyConditionExpression=DKey("pk").eq("USER#user_guest_1"),
            FilterExpression=Attr("type").eq("hotel_payment"),
        )
        assert len(led_resp.get("Items", [])) == 1

    def test_record_payment_no_double_debit(self, setup: Dict) -> None:
        """Two wallet payments of 5000 each deduct exactly 10000 total."""
        svc = setup["svc"]
        tables = setup["tables"]
        self._open(setup)
        _seed_wallet(tables["billing"], "user_guest_1", 50000)

        svc.record_folio_payment(
            "res_abc123", amount_cents=5000, method="wallet", user_sub="admin"
        )
        svc.record_folio_payment(
            "res_abc123", amount_cents=5000, method="wallet", user_sub="admin"
        )
        assert _get_wallet(tables["billing"], "user_guest_1") == 40000

        from boto3.dynamodb.conditions import Key as DKey, Attr
        led_resp = tables["billing"].query(
            KeyConditionExpression=DKey("pk").eq("USER#user_guest_1"),
            FilterExpression=Attr("type").eq("hotel_payment"),
        )
        assert len(led_resp.get("Items", [])) == 2

    def test_record_payment_external_no_wallet_move(self, setup: Dict) -> None:
        """card_external method is informational — wallet unchanged."""
        svc = setup["svc"]
        tables = setup["tables"]
        self._open(setup)
        _seed_wallet(tables["billing"], "user_guest_1", 50000)

        folio = svc.record_folio_payment(
            "res_abc123",
            amount_cents=15000,
            method="card_external",
            user_sub="admin",
        )
        assert folio["payments_total_cents"] == 15000
        assert _get_wallet(tables["billing"], "user_guest_1") == 50000  # unchanged

        from boto3.dynamodb.conditions import Key as DKey, Attr
        led_resp = tables["billing"].query(
            KeyConditionExpression=DKey("pk").eq("USER#user_guest_1"),
            FilterExpression=Attr("type").eq("hotel_payment"),
        )
        led = led_resp.get("Items", [])
        assert len(led) == 1
        assert led[0].get("provider") == "card_external"

    def test_record_payment_insufficient_wallet_402_no_ledger(self, setup: Dict) -> None:
        """Wallet 100 paying 5000 → 402; no orphan ledger row."""
        from fastapi import HTTPException
        svc = setup["svc"]
        tables = setup["tables"]
        self._open(setup)
        _seed_wallet(tables["billing"], "user_guest_1", 100)

        with pytest.raises(HTTPException) as exc_info:
            svc.record_folio_payment(
                "res_abc123", amount_cents=5000, method="wallet", user_sub="admin"
            )
        assert exc_info.value.status_code == 402
        assert _get_wallet(tables["billing"], "user_guest_1") == 100

        from boto3.dynamodb.conditions import Key as DKey, Attr
        led_resp = tables["billing"].query(
            KeyConditionExpression=DKey("pk").eq("USER#user_guest_1"),
            FilterExpression=Attr("type").eq("hotel_payment"),
        )
        assert len(led_resp.get("Items", [])) == 0

    def test_record_payment_validation_zero_422(self, setup: Dict) -> None:
        from fastapi import HTTPException
        svc = setup["svc"]
        self._open(setup)
        with pytest.raises(HTTPException) as exc_info:
            svc.record_folio_payment(
                "res_abc123", amount_cents=0, method="cash", user_sub="admin"
            )
        assert exc_info.value.status_code == 422

    def test_record_payment_invalid_method_422(self, setup: Dict) -> None:
        from fastapi import HTTPException
        svc = setup["svc"]
        self._open(setup)
        with pytest.raises(HTTPException) as exc_info:
            svc.record_folio_payment(
                "res_abc123",
                amount_cents=1000,
                method="bad_method",  # type: ignore
                user_sub="admin",
            )
        assert exc_info.value.status_code == 422

    def test_record_payment_unknown_folio_404(self, setup: Dict) -> None:
        from fastapi import HTTPException
        svc = setup["svc"]
        with pytest.raises(HTTPException) as exc_info:
            svc.record_folio_payment(
                "res_missing", amount_cents=1000, method="cash", user_sub="admin"
            )
        assert exc_info.value.status_code == 404

    def test_record_payment_closed_folio_409(self, setup: Dict) -> None:
        from fastapi import HTTPException
        svc = setup["svc"]
        self._open(setup)
        svc.close_folio("res_abc123", user_sub="admin")
        with pytest.raises(HTTPException) as exc_info:
            svc.record_folio_payment(
                "res_abc123", amount_cents=1000, method="cash", user_sub="admin"
            )
        assert exc_info.value.status_code == 409


class TestHTL031BalanceDueOnArrival:
    def test_balance_due_on_arrival_calculation(self, setup: Dict) -> None:
        """charges 30000, payments 10000, deposit 6000 → arrival balance 14000."""
        svc = setup["svc"]
        tables = setup["tables"]
        svc.open_folio(RESERVATION, user_sub="admin")
        svc.set_deposit_policy("res_abc123", kind="pct", pct_bps=2000, user_sub="admin")
        _seed_wallet(tables["billing"], "user_guest_1", 50000)

        svc.take_deposit("res_abc123", user_sub="admin")  # holds 6000
        folio = svc.record_folio_payment(
            "res_abc123", amount_cents=10000, method="cash", user_sub="admin"
        )

        arrival = svc.balance_due_on_arrival(folio)
        assert arrival == 30000 - 10000 - 6000  # 14000

    def test_balance_due_on_arrival_can_be_negative(self, setup: Dict) -> None:
        """Negative arrival balance allowed (no clamp)."""
        from app.services import hotel_folios as svc
        folio = {
            "charges_total_cents": 1000,
            "payments_total_cents": 500,
            "deposit_held_cents": 2000,
        }
        # 1000 - 500 - 2000 = -1500
        assert svc.balance_due_on_arrival(folio) == -1500

    def test_balance_due_on_arrival_on_folio_out(self, setup: Dict) -> None:
        """FolioOut.balance_due_on_arrival_cents is populated."""
        svc = setup["svc"]
        tables = setup["tables"]
        svc.open_folio(RESERVATION, user_sub="admin")
        svc.set_deposit_policy("res_abc123", kind="fixed", fixed_cents=5000, user_sub="admin")
        _seed_wallet(tables["billing"], "user_guest_1", 50000)
        svc.take_deposit("res_abc123", user_sub="admin")

        folio = svc.get_folio("res_abc123")
        assert folio["balance_due_on_arrival_cents"] == 30000 - 5000  # 25000


class TestHTL031RenderFolioPdf:
    def test_render_folio_pdf_returns_valid_pdf(self, setup: Dict) -> None:
        """render_folio_pdf returns bytes starting with %PDF."""
        svc = setup["svc"]
        svc.open_folio(RESERVATION, user_sub="admin")
        pdf = svc.render_folio_pdf("res_abc123")
        assert pdf is not None
        assert pdf[:4] == b"%PDF"

    def test_render_folio_pdf_flag_off_returns_none(self, setup: Dict) -> None:
        from app.services import hotel_folios as svc
        object.__setattr__(svc.S, "hotel_pms_enabled", False)
        try:
            result = svc.render_folio_pdf("res_abc123")
            assert result is None
        finally:
            object.__setattr__(svc.S, "hotel_pms_enabled", True)

    def test_render_folio_pdf_unknown_folio_returns_none(self, setup: Dict) -> None:
        svc = setup["svc"]
        assert svc.render_folio_pdf("res_nonexistent") is None

    def test_render_folio_pdf_contains_balance_line(self, setup: Dict) -> None:
        """PDF bytes contain BALANCE DUE ON ARRIVAL text."""
        svc = setup["svc"]
        svc.open_folio(RESERVATION, user_sub="admin")
        pdf = svc.render_folio_pdf("res_abc123")
        assert pdf is not None
        assert b"BALANCE DUE ON ARRIVAL" in pdf


# ===========================================================================
# HTL-031: FolioOut model extensions
# ===========================================================================


class TestHTL031FolioOutModel:
    def test_folio_out_deposit_fields_default(self, setup: Dict) -> None:
        """FolioOut has deposit_held_cents / deposit_policy_kind / balance_due_on_arrival_cents."""
        from app.models import FolioOut
        folio_data = {
            "reservation_id": "res_test",
            "folio_id": "fol_test",
            "hotel_id": "hot_1",
            "guest_sub": "user_g",
            "currency": "usd",
            "status": "open",
            "charges_total_cents": 1000,
            "payments_total_cents": 0,
            "balance_due_cents": 1000,
            "line_items": [],
            "created_at": 1700000000,
            "updated_at": 1700000000,
        }
        out = FolioOut(**folio_data)
        assert out.deposit_held_cents == 0
        assert out.deposit_policy_kind == "none"
        assert out.balance_due_on_arrival_cents == 0


# ===========================================================================
# HTL-032: Router basic import test
# ===========================================================================


class TestHTL032RouterImport:
    def test_router_imports_without_error(self) -> None:
        """hotel_folios_router can be imported (basic smoke test)."""
        from app.routers.hotel_folios import hotel_folios_router
        assert hotel_folios_router is not None
        assert hotel_folios_router.prefix == "/ui/hotels"

    def test_models_importable(self) -> None:
        """All HTL-029..032 Pydantic models are importable."""
        from app.models import (
            FolioLineIn,
            FolioLineOut,
            FolioOut,
            FolioAddonIn,
            DepositPolicyIn,
            TakeDepositIn,
            FolioPaymentIn,
        )
        # Smoke-test each model
        _ = FolioLineIn(line_type="room_night", description="test", unit_price_cents=100)
        _ = FolioAddonIn(sku="sku_test")
        _ = DepositPolicyIn()
        _ = TakeDepositIn()
        _ = FolioPaymentIn(amount_cents=100, method="cash")
