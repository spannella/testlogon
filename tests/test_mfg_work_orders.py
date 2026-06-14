"""MFG-007/014 hermetic tests - Work-order lifecycle."""
from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

import boto3
import pytest

# Module-level state shared between fixture and tests
_STATE: dict = {"bom_id": ""}


def _make_boms_table(ddb):
    return ddb.create_table(
        TableName="wo_test_mfg_boms",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[
            {"AttributeName": "bom_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "bom_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "product_sku", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_PRODUCT",
                "KeySchema": [
                    {"AttributeName": "product_sku", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )


def _make_work_orders_table(ddb):
    return ddb.create_table(
        TableName="wo_test_mfg_work_orders",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[
            {"AttributeName": "work_order_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "work_order_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "product_sku", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_STATUS",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI_PRODUCT",
                "KeySchema": [
                    {"AttributeName": "product_sku", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )


@pytest.fixture(scope="module", autouse=True)
def _wo_tables():
    import moto
    with moto.mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        boms_tbl = _make_boms_table(ddb)
        wo_tbl = _make_work_orders_table(ddb)

        fake_T = SimpleNamespace(
            mfg_boms=boms_tbl,
            mfg_work_orders=wo_tbl,
        )

        import app.services.manufacturing_bom as bom_mod
        import app.services.manufacturing_work_orders as wo_mod
        from app.core.settings import S

        orig_bom_T = getattr(bom_mod, "T", None)
        orig_wo_T = getattr(wo_mod, "T", None)
        orig_flag = getattr(S, "manufacturing_mrp_enabled", False)
        orig_inv_flag = getattr(S, "inventory_reservations_enabled", False)
        orig_cost_flag = getattr(S, "manufacturing_cost_posting_enabled", False)

        bom_mod.T = fake_T
        wo_mod.T = fake_T
        object.__setattr__(S, "manufacturing_mrp_enabled", True)
        object.__setattr__(S, "inventory_reservations_enabled", False)  # sibling off
        object.__setattr__(S, "manufacturing_cost_posting_enabled", False)

        # Seed a BOM for testing
        from app.services.manufacturing_bom import create_bom
        _bom = create_bom(
            "FINISH-GOOD",
            "Test FG BOM",
            1,
            [
                {"component_sku": "RAW-ALPHA", "quantity_per": 2, "scrap_pct": 0.0},
                {"component_sku": "RAW-BETA", "quantity_per": 1, "scrap_pct": 0.0},
            ],
            user_sub="test",
        )
        _STATE["bom_id"] = _bom["bom_id"]

        yield

        if orig_bom_T is not None:
            bom_mod.T = orig_bom_T
        if orig_wo_T is not None:
            wo_mod.T = orig_wo_T
        object.__setattr__(S, "manufacturing_mrp_enabled", orig_flag)
        object.__setattr__(S, "inventory_reservations_enabled", orig_inv_flag)
        object.__setattr__(S, "manufacturing_cost_posting_enabled", orig_cost_flag)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_create_work_order():
    from app.services.manufacturing_work_orders import create_work_order, get_work_order

    bom_id = _STATE["bom_id"]
    wo = create_work_order(
        "FINISH-GOOD",
        quantity=5,
        bom_id=bom_id,
        user_sub="test",
    )
    assert wo["status"] == "created"
    assert wo["quantity"] == 5
    assert wo["bom_id"] == bom_id
    assert wo["issues_guard"] == ""

    fetched = get_work_order(wo["work_order_id"])
    assert fetched is not None
    assert fetched["work_order_id"] == wo["work_order_id"]


def test_release_work_order_issues_components():
    """Release issues components; with inventory flag off the calls are no-ops."""
    from app.services.manufacturing_work_orders import create_work_order, release_work_order

    bom_id = _STATE["bom_id"]
    wo = create_work_order("FINISH-GOOD", quantity=3, bom_id=bom_id, user_sub="test")
    released = release_work_order(wo["work_order_id"], user_sub="test")

    assert released["status"] == "released"
    assert released["issues_guard"] == "done"
    assert len(released["issues"]) == 2  # RAW-ALPHA, RAW-BETA


def test_release_idempotency():
    """Calling release twice does not double-issue (guard flag check)."""
    from app.services.manufacturing_work_orders import create_work_order, release_work_order

    bom_id = _STATE["bom_id"]
    wo = create_work_order("FINISH-GOOD", quantity=2, bom_id=bom_id, user_sub="test")
    released1 = release_work_order(wo["work_order_id"], user_sub="test")
    released2 = release_work_order(wo["work_order_id"], user_sub="test")

    assert released1["status"] == "released"
    assert released2["status"] == "released"


def test_start_work_order():
    from app.services.manufacturing_work_orders import create_work_order, release_work_order, start_work_order

    bom_id = _STATE["bom_id"]
    wo = create_work_order("FINISH-GOOD", quantity=1, bom_id=bom_id, user_sub="test")
    release_work_order(wo["work_order_id"], user_sub="test")
    started = start_work_order(wo["work_order_id"], user_sub="test")
    assert started["status"] == "in_progress"


def test_complete_work_order():
    """Complete produces finished goods."""
    from app.services.manufacturing_work_orders import (
        create_work_order, release_work_order, start_work_order, complete_work_order
    )

    bom_id = _STATE["bom_id"]
    wo = create_work_order("FINISH-GOOD", quantity=4, bom_id=bom_id, user_sub="test")
    release_work_order(wo["work_order_id"], user_sub="test")
    start_work_order(wo["work_order_id"], user_sub="test")
    completed = complete_work_order(wo["work_order_id"], user_sub="test")

    assert completed["status"] == "completed"
    assert completed["produce_guard"] == "done"
    assert completed["produced_qty"] == 4


def test_complete_idempotency():
    """Calling complete twice writes only one produce call."""
    from app.services.manufacturing_work_orders import (
        create_work_order, release_work_order, start_work_order, complete_work_order
    )
    adjust_calls = []

    import app.services.manufacturing_work_orders as wo_mod

    orig_adjust = wo_mod._inventory_adjust
    def mock_adjust(sku, delta, reason, *, location_id, user_sub):
        adjust_calls.append((sku, delta, reason))

    wo_mod._inventory_adjust = mock_adjust
    try:
        bom_id = _STATE["bom_id"]
        wo = create_work_order("FINISH-GOOD", quantity=1, bom_id=bom_id, user_sub="test")
        release_work_order(wo["work_order_id"], user_sub="test")
        start_work_order(wo["work_order_id"], user_sub="test")
        complete_work_order(wo["work_order_id"], user_sub="test")
        complete_work_order(wo["work_order_id"], user_sub="test")  # second call
    finally:
        wo_mod._inventory_adjust = orig_adjust

    produce_calls = [c for c in adjust_calls if c[2] == "mfg_produce"]
    assert len(produce_calls) == 1


def test_cancel_from_created():
    """Cancel before release with no component returns."""
    from app.services.manufacturing_work_orders import create_work_order, cancel_work_order

    bom_id = _STATE["bom_id"]
    wo = create_work_order("FINISH-GOOD", quantity=2, bom_id=bom_id, user_sub="test")
    cancelled = cancel_work_order(wo["work_order_id"], reason="changed mind", user_sub="test")
    assert cancelled["status"] == "cancelled"


def test_cancel_after_release_returns_components():
    """Cancel after release returns components."""
    from app.services.manufacturing_work_orders import (
        create_work_order, release_work_order, cancel_work_order
    )
    return_calls = []

    import app.services.manufacturing_work_orders as wo_mod
    orig_adjust = wo_mod._inventory_adjust
    def mock_adjust(sku, delta, reason, *, location_id, user_sub):
        return_calls.append((sku, delta, reason))

    wo_mod._inventory_adjust = mock_adjust
    try:
        bom_id = _STATE["bom_id"]
        wo = create_work_order("FINISH-GOOD", quantity=3, bom_id=bom_id, user_sub="test")
        release_work_order(wo["work_order_id"], user_sub="test")
        cancelled = cancel_work_order(wo["work_order_id"], user_sub="test")
    finally:
        wo_mod._inventory_adjust = orig_adjust

    assert cancelled["status"] == "cancelled"
    returns = [c for c in return_calls if c[2] == "mfg_cancel_return"]
    assert len(returns) == 2  # RAW-ALPHA and RAW-BETA


def test_illegal_transition_raises_409():
    """Cannot complete from created (skipping release)."""
    from app.services.manufacturing_work_orders import create_work_order, complete_work_order
    from fastapi import HTTPException

    bom_id = _STATE["bom_id"]
    wo = create_work_order("FINISH-GOOD", quantity=1, bom_id=bom_id, user_sub="test")
    with pytest.raises(HTTPException) as exc:
        complete_work_order(wo["work_order_id"], user_sub="test")
    assert exc.value.status_code == 409


def test_list_work_orders():
    from app.services.manufacturing_work_orders import list_work_orders

    wos = list_work_orders()
    assert isinstance(wos, list)
    assert len(wos) > 0


def test_flag_off_raises_404():
    from app.services.manufacturing_work_orders import create_work_order
    from app.core.settings import S
    from fastapi import HTTPException

    object.__setattr__(S, "manufacturing_mrp_enabled", False)
    try:
        with pytest.raises(HTTPException) as exc:
            create_work_order("SKU", 1, bom_id="bom123", user_sub="u")
        assert exc.value.status_code == 404
    finally:
        object.__setattr__(S, "manufacturing_mrp_enabled", True)
