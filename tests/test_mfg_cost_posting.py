"""MFG-008/014 hermetic tests - Optional costed-production GL hook."""
from __future__ import annotations

from types import SimpleNamespace

import boto3
import pytest

# Module-level state
_STATE: dict = {"bom_id": "", "billing_tbl": None}


def _make_boms_table(ddb):
    return ddb.create_table(
        TableName="cost_test_mfg_boms",
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
        TableName="cost_test_mfg_wo",
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


def _make_billing_table(ddb):
    # The billing_shared.new_ledger_entry uses key_name as the PK field.
    # For work orders it uses key_name="work_order_id". We need sk as range key.
    return ddb.create_table(
        TableName="cost_test_billing",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[
            {"AttributeName": "work_order_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "work_order_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
    )


@pytest.fixture(scope="module", autouse=True)
def _cost_tables():
    import moto
    with moto.mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        boms_tbl = _make_boms_table(ddb)
        wo_tbl = _make_work_orders_table(ddb)
        billing_tbl = _make_billing_table(ddb)

        fake_T = SimpleNamespace(
            mfg_boms=boms_tbl,
            mfg_work_orders=wo_tbl,
            billing=billing_tbl,
        )

        import app.services.manufacturing_bom as bom_mod
        import app.services.manufacturing_work_orders as wo_mod
        import app.core.tables as tables_mod
        from app.core.settings import S

        orig_bom_T = getattr(bom_mod, "T", None)
        orig_wo_T = getattr(wo_mod, "T", None)
        orig_tables_T = getattr(tables_mod, "T", None)
        orig_flag = getattr(S, "manufacturing_mrp_enabled", False)
        orig_inv_flag = getattr(S, "inventory_reservations_enabled", False)
        orig_cost_flag = getattr(S, "manufacturing_cost_posting_enabled", False)

        bom_mod.T = fake_T
        wo_mod.T = fake_T
        tables_mod.T = fake_T  # so _post_cost_entry's T.billing points to fake
        object.__setattr__(S, "manufacturing_mrp_enabled", True)
        object.__setattr__(S, "inventory_reservations_enabled", False)
        object.__setattr__(S, "manufacturing_cost_posting_enabled", False)

        # Seed BOM
        from app.services.manufacturing_bom import create_bom
        bom = create_bom(
            "COST-FG",
            "Cost FG BOM",
            1,
            [{"component_sku": "COST-COMP", "quantity_per": 1, "scrap_pct": 0.0}],
            user_sub="test",
        )
        _STATE["bom_id"] = bom["bom_id"]
        _STATE["billing_tbl"] = billing_tbl

        yield

        if orig_bom_T is not None:
            bom_mod.T = orig_bom_T
        if orig_wo_T is not None:
            wo_mod.T = orig_wo_T
        if orig_tables_T is not None:
            tables_mod.T = orig_tables_T
        object.__setattr__(S, "manufacturing_mrp_enabled", orig_flag)
        object.__setattr__(S, "inventory_reservations_enabled", orig_inv_flag)
        object.__setattr__(S, "manufacturing_cost_posting_enabled", orig_cost_flag)


def _scan_billing_for_wo(work_order_id: str):
    from boto3.dynamodb.conditions import Attr
    billing_tbl = _STATE["billing_tbl"]
    resp = billing_tbl.scan(
        FilterExpression=Attr("work_order_id").eq(work_order_id)
        & Attr("type").eq("production_cost")
    )
    return resp.get("Items", [])


def test_cost_flag_off_no_ledger_entry():
    """With cost flag off, complete writes no ledger entry."""
    from app.services.manufacturing_work_orders import (
        create_work_order, release_work_order, start_work_order, complete_work_order
    )
    from app.core.settings import S

    object.__setattr__(S, "manufacturing_cost_posting_enabled", False)
    bom_id = _STATE["bom_id"]
    wo = create_work_order("COST-FG", quantity=5, bom_id=bom_id, user_sub="test")
    release_work_order(wo["work_order_id"], user_sub="test")
    start_work_order(wo["work_order_id"], user_sub="test")
    complete_work_order(wo["work_order_id"], user_sub="test")

    entries = _scan_billing_for_wo(wo["work_order_id"])
    assert len(entries) == 0


def test_cost_flag_on_writes_ledger_entry():
    """With cost flag on, complete writes exactly one ledger entry."""
    from app.services.manufacturing_work_orders import (
        create_work_order, release_work_order, start_work_order, complete_work_order
    )
    from app.core.settings import S

    object.__setattr__(S, "manufacturing_cost_posting_enabled", True)
    try:
        bom_id = _STATE["bom_id"]
        wo = create_work_order("COST-FG", quantity=3, bom_id=bom_id, user_sub="test")
        release_work_order(wo["work_order_id"], user_sub="test")
        start_work_order(wo["work_order_id"], user_sub="test")
        complete_work_order(wo["work_order_id"], user_sub="test")
    finally:
        object.__setattr__(S, "manufacturing_cost_posting_enabled", False)

    entries = _scan_billing_for_wo(wo["work_order_id"])
    assert len(entries) == 1
    entry = entries[0]
    assert entry.get("type") == "production_cost"
    assert entry.get("reason") == "mfg_production_completed"
    assert "ledger_date" in entry
    assert entry.get("work_order_id") == wo["work_order_id"]


def test_cost_flag_on_idempotency():
    """Completing same work order twice writes only one ledger entry."""
    from app.services.manufacturing_work_orders import (
        create_work_order, release_work_order, start_work_order, complete_work_order
    )
    from app.core.settings import S

    object.__setattr__(S, "manufacturing_cost_posting_enabled", True)
    try:
        bom_id = _STATE["bom_id"]
        wo = create_work_order("COST-FG", quantity=2, bom_id=bom_id, user_sub="test")
        release_work_order(wo["work_order_id"], user_sub="test")
        start_work_order(wo["work_order_id"], user_sub="test")
        complete_work_order(wo["work_order_id"], user_sub="test")
        complete_work_order(wo["work_order_id"], user_sub="test")  # idempotent
    finally:
        object.__setattr__(S, "manufacturing_cost_posting_enabled", False)

    entries = _scan_billing_for_wo(wo["work_order_id"])
    # produce_guard prevents double-produce -> only one ledger entry
    assert len(entries) == 1
