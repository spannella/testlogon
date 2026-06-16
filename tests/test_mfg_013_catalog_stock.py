"""MFG-013 hermetic tests — finished-goods → catalog stock mirror.

Offline: moto-backed inventory + shopping_catalog + mfg_boms + mfg_work_orders
tables bound to the frozen T via object.__setattr__ (restored on teardown);
frozen S flags toggled. Service functions called inline; no TestClient.
"""
from __future__ import annotations

import boto3
import pytest


def _make_inventory_table(ddb):
    return ddb.create_table(
        TableName="mfg013_inventory",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[
            {"AttributeName": "sku", "KeyType": "HASH"},
            {"AttributeName": "location_sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "sku", "AttributeType": "S"},
            {"AttributeName": "location_sk", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "available", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "GSI_AVAILABLE",
            "KeySchema": [
                {"AttributeName": "status", "KeyType": "HASH"},
                {"AttributeName": "available", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
    )


def _make_catalog_table(ddb):
    return ddb.create_table(
        TableName="mfg013_shopping_catalog",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
        ],
    )


def _make_boms_table(ddb):
    return ddb.create_table(
        TableName="mfg013_mfg_boms",
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


def _make_wo_table(ddb):
    return ddb.create_table(
        TableName="mfg013_mfg_work_orders",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[
            {"AttributeName": "work_order_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "work_order_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
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


CAT = "cat-fg"
ITEM = "item-fg"
SKU = "WIDGET-FG"


@pytest.fixture(scope="module", autouse=True)
def _tables():
    import moto
    with moto.mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        inv_tbl = _make_inventory_table(ddb)
        cat_tbl = _make_catalog_table(ddb)
        boms_tbl = _make_boms_table(ddb)
        wo_tbl = _make_wo_table(ddb)

        from app.core import tables as tables_mod
        from app.core.settings import S

        orig = {
            "inventory": getattr(tables_mod.T, "inventory", None),
            "catalog": getattr(tables_mod.T, "catalog", None),
            "mfg_boms": getattr(tables_mod.T, "mfg_boms", None),
            "mfg_work_orders": getattr(tables_mod.T, "mfg_work_orders", None),
        }
        orig_mfg = getattr(S, "manufacturing_mrp_enabled", False)
        orig_inv = getattr(S, "inventory_reservations_enabled", False)

        object.__setattr__(tables_mod.T, "inventory", inv_tbl)
        object.__setattr__(tables_mod.T, "catalog", cat_tbl)
        object.__setattr__(tables_mod.T, "mfg_boms", boms_tbl)
        object.__setattr__(tables_mod.T, "mfg_work_orders", wo_tbl)
        object.__setattr__(S, "manufacturing_mrp_enabled", True)
        object.__setattr__(S, "inventory_reservations_enabled", True)

        # Seed a BOM (1 component) for the finished good
        from app.services.manufacturing_bom import create_bom
        bom = create_bom(SKU, "FG BOM", 1,
                         [{"component_sku": "RAW", "quantity_per": 1, "scrap_pct": 0.0}],
                         user_sub="test")
        globals()["_BOM_ID"] = bom["bom_id"]

        # Seed plenty of RAW component stock so releases succeed (inventory flag on)
        from app.services.inventory import set_on_hand
        set_on_hand("RAW", 1_000_000, user_sub="test")

        yield

        object.__setattr__(S, "manufacturing_mrp_enabled", orig_mfg)
        object.__setattr__(S, "inventory_reservations_enabled", orig_inv)
        for k, v in orig.items():
            if v is not None:
                object.__setattr__(tables_mod.T, k, v)


def _seed_catalog_item(stock_count=0):
    from app.core.tables import T
    from app.routers.catalog import cat_pk, item_sk
    T.catalog.put_item(Item={
        "PK": cat_pk(CAT), "SK": item_sk(ITEM),
        "item_id": ITEM, "stock_count": stock_count, "name": "Widget",
    })


def _get_catalog_sc():
    from app.core.tables import T
    from app.routers.catalog import cat_pk, item_sk
    it = T.catalog.get_item(Key={"PK": cat_pk(CAT), "SK": item_sk(ITEM)}).get("Item")
    if it is None:
        return None
    sc = it.get("stock_count")
    return int(sc) if sc is not None else None


def _complete_wo(qty, *, cat=CAT, item=ITEM, sku=SKU, corr=None):
    from app.services.manufacturing_work_orders import (
        create_work_order, release_work_order, start_work_order, complete_work_order,
    )
    wo = create_work_order(sku, quantity=qty, bom_id=_BOM_ID, user_sub="test",
                           catalog_category_id=cat, catalog_item_id=item,
                           correlation_id=corr)
    release_work_order(wo["work_order_id"], user_sub="test")
    start_work_order(wo["work_order_id"], user_sub="test")
    return complete_work_order(wo["work_order_id"], user_sub="test")


# ---------------------------------------------------------------------------

def test_mirror_updates_catalog_stock_count():
    from app.services.inventory import get_inventory
    _seed_catalog_item(stock_count=0)
    completed = _complete_wo(10)
    assert completed["status"] == "completed"
    assert get_inventory(SKU)["available"] == 10
    assert _get_catalog_sc() == 10


def test_mirror_reflects_available_not_on_hand():
    from app.services.inventory import get_inventory
    from app.core.tables import T
    from app.routers.catalog import cat_pk, item_sk
    from app.services.inventory import _location_sk, _status_for
    sku = "WIDGET-RES"
    item = "item-res"
    T.catalog.put_item(Item={"PK": cat_pk(CAT), "SK": item_sk(item), "item_id": item, "stock_count": 0})
    # Seed an inventory row directly with 20 on_hand, 5 reserved -> available 15
    T.inventory.put_item(Item={
        "sku": sku, "location_sk": _location_sk("warehouse"), "location_id": "warehouse",
        "on_hand": 20, "reserved": 5, "available": 15, "reorder_point": 5,
        "status": _status_for(15, 5), "updated_at": 1,
    })
    assert get_inventory(sku)["available"] == 15
    # produce +10 -> on_hand 30, reserved 5, available 25
    _complete_wo(10, item=item, sku=sku, corr="res-corr")
    it = T.catalog.get_item(Key={"PK": cat_pk(CAT), "SK": item_sk(item)}).get("Item")
    assert int(it["stock_count"]) == 25
    assert get_inventory(sku)["on_hand"] == 30


def test_mirror_skipped_when_not_linked():
    from app.services.inventory import get_inventory
    sku = "WIDGET-NOLINK"
    _seed_catalog_item(stock_count=0)
    before = _get_catalog_sc()
    completed = _complete_wo(7, cat="", item="", sku=sku, corr="nolink")
    assert completed["status"] == "completed"
    assert get_inventory(sku)["available"] == 7
    # shared catalog item untouched
    assert _get_catalog_sc() == before


def test_mirror_skipped_when_catalog_item_absent():
    from app.services.inventory import get_inventory
    sku = "WIDGET-NOITEM"
    # link to a catalog item that does not exist -> no error, inventory still updated
    completed = _complete_wo(4, cat="ghost-cat", item="ghost-item", sku=sku, corr="ghost")
    assert completed["status"] == "completed"
    assert get_inventory(sku)["available"] == 4


def test_mirror_idempotent_on_replay():
    sku = "WIDGET-REPLAY"
    item = "item-replay"
    from app.core.tables import T
    from app.routers.catalog import cat_pk, item_sk
    T.catalog.put_item(Item={"PK": cat_pk(CAT), "SK": item_sk(item), "item_id": item, "stock_count": 0})
    from app.services.manufacturing_work_orders import (
        create_work_order, release_work_order, start_work_order, complete_work_order,
    )
    wo = create_work_order(sku, quantity=10, bom_id=_BOM_ID, user_sub="test",
                           catalog_category_id=CAT, catalog_item_id=item, correlation_id="replay")
    release_work_order(wo["work_order_id"], user_sub="test")
    start_work_order(wo["work_order_id"], user_sub="test")
    complete_work_order(wo["work_order_id"], user_sub="test")
    complete_work_order(wo["work_order_id"], user_sub="test")  # replay
    it = T.catalog.get_item(Key={"PK": cat_pk(CAT), "SK": item_sk(item)}).get("Item")
    assert int(it["stock_count"]) == 10  # not doubled


def test_flag_off_does_not_touch_catalog():
    from app.core.settings import S
    from app.services.manufacturing_work_orders import complete_work_order
    from fastapi import HTTPException
    _seed_catalog_item(stock_count=42)
    object.__setattr__(S, "inventory_reservations_enabled", False)
    try:
        # complete still requires the work order to exist; create one while mfg flag is on
        # then flip inventory flag off so the mirror no-ops.
        completed = _complete_wo(5, corr="invoff")
        assert completed["status"] == "completed"
        # mirror skipped because inventory flag off -> catalog stays 42
        assert _get_catalog_sc() == 42
    finally:
        object.__setattr__(S, "inventory_reservations_enabled", True)


def test_mirror_best_effort_never_breaks_completion():
    """If the catalog mirror write raises, completion still succeeds (swallowed)."""
    from app.services.inventory import get_inventory
    from app.core.tables import T
    from app.routers.catalog import cat_pk, item_sk
    sku = "WIDGET-BOOM"
    item = "item-boom"
    T.catalog.put_item(Item={"PK": cat_pk(CAT), "SK": item_sk(item), "item_id": item, "stock_count": 0})

    # Make ONLY the catalog mirror write raise, by patching the catalog table's
    # update_item (release/produce use inventory.adjust on T.inventory, untouched).
    orig_update = T.catalog.update_item

    def raising_update(*a, **k):
        raise RuntimeError("catalog down")

    T.catalog.update_item = raising_update
    try:
        completed = _complete_wo(3, item=item, sku=sku, corr="boom")
        assert completed["status"] == "completed"
        # finished goods still produced despite the mirror failure
        assert get_inventory(sku)["available"] == 3
    finally:
        T.catalog.update_item = orig_update
