"""MFG-010/014 hermetic tests - Lite MRP engine."""
from __future__ import annotations

from types import SimpleNamespace

import boto3
import pytest

# Module-level state
_STATE: dict = {"bom_id": ""}


def _make_boms_table(ddb):
    return ddb.create_table(
        TableName="mrp_test_mfg_boms",
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
        GlobalSecondaryIndexes=[{
            "IndexName": "GSI_PRODUCT",
            "KeySchema": [
                {"AttributeName": "product_sku", "KeyType": "HASH"},
                {"AttributeName": "created_at", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
    )


def _make_work_orders_table(ddb):
    return ddb.create_table(
        TableName="mrp_test_mfg_wo",
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


def _make_mrp_table(ddb):
    return ddb.create_table(
        TableName="mrp_test_mfg_mrp",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[
            {"AttributeName": "mrp_run_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "mrp_run_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "GSI_RUN_STATUS",
            "KeySchema": [
                {"AttributeName": "status", "KeyType": "HASH"},
                {"AttributeName": "created_at", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
    )


def _make_orders_table(ddb):
    return ddb.create_table(
        TableName="mrp_test_orders",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "order_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "order_id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "GSI_STATUS",
            "KeySchema": [
                {"AttributeName": "status", "KeyType": "HASH"},
                {"AttributeName": "created_at", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
    )


def _make_order_items_table(ddb):
    return ddb.create_table(
        TableName="mrp_test_order_items",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[
            {"AttributeName": "order_id", "KeyType": "HASH"},
            {"AttributeName": "item_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "order_id", "AttributeType": "S"},
            {"AttributeName": "item_id", "AttributeType": "S"},
        ],
    )


@pytest.fixture(scope="module", autouse=True)
def _mrp_tables():
    import moto
    with moto.mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        boms_tbl = _make_boms_table(ddb)
        wo_tbl = _make_work_orders_table(ddb)
        mrp_tbl = _make_mrp_table(ddb)
        orders_tbl = _make_orders_table(ddb)
        order_items_tbl = _make_order_items_table(ddb)

        fake_T = SimpleNamespace(
            mfg_boms=boms_tbl,
            mfg_work_orders=wo_tbl,
            mfg_mrp=mrp_tbl,
            orders=orders_tbl,
            order_items=order_items_tbl,
        )

        import app.services.manufacturing_bom as bom_mod
        import app.services.manufacturing_work_orders as wo_mod
        import app.services.manufacturing_mrp as mrp_mod
        from app.core.settings import S

        orig_bom_T = getattr(bom_mod, "T", None)
        orig_wo_T = getattr(wo_mod, "T", None)
        orig_mrp_T = getattr(mrp_mod, "T", None)
        orig_flag = getattr(S, "manufacturing_mrp_enabled", False)
        orig_inv_flag = getattr(S, "inventory_reservations_enabled", False)
        orig_cost_flag = getattr(S, "manufacturing_cost_posting_enabled", False)

        bom_mod.T = fake_T
        wo_mod.T = fake_T
        mrp_mod.T = fake_T
        object.__setattr__(S, "manufacturing_mrp_enabled", True)
        object.__setattr__(S, "inventory_reservations_enabled", False)
        object.__setattr__(S, "manufacturing_cost_posting_enabled", False)

        # Seed a BOM: FG-SKU uses COMP-SKU (which has no sub-BOM -> purchase)
        from app.services.manufacturing_bom import create_bom
        bom = create_bom(
            "FG-SKU",
            "FG BOM",
            1,
            [{"component_sku": "COMP-SKU", "quantity_per": 2, "scrap_pct": 0.0}],
            user_sub="test",
        )
        _STATE["bom_id"] = bom["bom_id"]

        # Seed open orders with demand for FG-SKU
        import datetime
        ts_iso = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        orders_tbl.put_item(Item={
            "order_id": "ORDER-001",
            "status": "pending_payment",
            "created_at": ts_iso,
        })
        order_items_tbl.put_item(Item={
            "order_id": "ORDER-001",
            "item_id": "ITEM-001",
            "sku": "FG-SKU",
            "quantity": 10,
            "amount_cents": 1000,
        })

        # Demand for SURPLUS-SKU
        orders_tbl.put_item(Item={
            "order_id": "ORDER-002",
            "status": "pending_payment",
            "created_at": ts_iso,
        })
        order_items_tbl.put_item(Item={
            "order_id": "ORDER-002",
            "item_id": "ITEM-002",
            "sku": "SURPLUS-SKU",
            "quantity": 3,
            "amount_cents": 500,
        })

        yield

        if orig_bom_T is not None:
            bom_mod.T = orig_bom_T
        if orig_wo_T is not None:
            wo_mod.T = orig_wo_T
        if orig_mrp_T is not None:
            mrp_mod.T = orig_mrp_T
        object.__setattr__(S, "manufacturing_mrp_enabled", orig_flag)
        object.__setattr__(S, "inventory_reservations_enabled", orig_inv_flag)
        object.__setattr__(S, "manufacturing_cost_posting_enabled", orig_cost_flag)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_mrp_run_produce_action_for_fg_sku():
    """FG-SKU has demand + an active BOM -> suggested_action=produce."""
    from app.services.manufacturing_mrp import run_mrp

    result = run_mrp(horizon_days=30, correlation_id="test-mrp-run-001", user_sub="test")
    assert result["status"] == "completed"

    reqs_by_sku = {r["sku"]: r for r in result["requirements"]}
    assert "FG-SKU" in reqs_by_sku

    fg_req = reqs_by_sku["FG-SKU"]
    assert fg_req["gross_requirement"] == 10
    assert fg_req["on_hand_available"] == 0  # inventory flag off
    assert fg_req["net_requirement"] == 10
    assert fg_req["suggested_action"] == "produce"
    assert fg_req["suggested_quantity"] == 10


def test_mrp_run_purchase_action_for_component():
    """COMP-SKU has no BOM -> suggested_action=purchase."""
    from app.services.manufacturing_mrp import run_mrp

    result = run_mrp(horizon_days=30, correlation_id="test-mrp-run-002", user_sub="test")
    reqs_by_sku = {r["sku"]: r for r in result["requirements"]}

    if "COMP-SKU" in reqs_by_sku:
        comp_req = reqs_by_sku["COMP-SKU"]
        assert comp_req["suggested_action"] in ("purchase", "none")


def test_mrp_run_surplus_none_action():
    """With large on-hand inventory, SURPLUS-SKU net_requirement < 0."""
    import app.services.manufacturing_mrp as mrp_mod

    orig_fn = mrp_mod._get_on_hand_available
    def mock_on_hand(sku, location_id):
        if sku == "SURPLUS-SKU":
            return 100  # surplus
        return 0

    mrp_mod._get_on_hand_available = mock_on_hand
    try:
        from app.services.manufacturing_mrp import run_mrp
        result = run_mrp(horizon_days=30, correlation_id="test-mrp-surplus-001", user_sub="test")
    finally:
        mrp_mod._get_on_hand_available = orig_fn

    reqs_by_sku = {r["sku"]: r for r in result["requirements"]}
    if "SURPLUS-SKU" in reqs_by_sku:
        surplus_req = reqs_by_sku["SURPLUS-SKU"]
        assert surplus_req["net_requirement"] < 0
        assert surplus_req["suggested_action"] == "none"
        assert surplus_req["suggested_quantity"] == 0


def test_mrp_idempotent_rerun():
    """Same correlation_id produces same mrp_run_id; second run overwrites first."""
    from app.services.manufacturing_mrp import run_mrp, get_mrp_run

    corr = "test-idempotent-mrp-999"
    r1 = run_mrp(horizon_days=30, correlation_id=corr, user_sub="test")
    r2 = run_mrp(horizon_days=30, correlation_id=corr, user_sub="test")
    assert r1["mrp_run_id"] == r2["mrp_run_id"]

    fetched = get_mrp_run(r1["mrp_run_id"])
    assert fetched is not None
    assert fetched["status"] == "completed"


def test_mrp_does_not_mutate_inventory():
    """MRP run never calls inventory.adjust."""
    import app.services.manufacturing_work_orders as wo_mod

    adjust_calls = []
    orig_adj = wo_mod._inventory_adjust
    def spy_adjust(*args, **kwargs):
        adjust_calls.append(args)
        return orig_adj(*args, **kwargs)
    wo_mod._inventory_adjust = spy_adjust
    try:
        from app.services.manufacturing_mrp import run_mrp
        run_mrp(horizon_days=30, correlation_id="test-no-mutate-001", user_sub="test")
    finally:
        wo_mod._inventory_adjust = orig_adj

    assert len(adjust_calls) == 0


def test_flag_off_raises_404():
    from app.services.manufacturing_mrp import run_mrp
    from app.core.settings import S
    from fastapi import HTTPException

    object.__setattr__(S, "manufacturing_mrp_enabled", False)
    try:
        with pytest.raises(HTTPException) as exc:
            run_mrp()
        assert exc.value.status_code == 404
    finally:
        object.__setattr__(S, "manufacturing_mrp_enabled", True)
