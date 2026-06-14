"""MFG-004/014 hermetic tests - BOM service."""
from __future__ import annotations

import math
from decimal import Decimal
from types import SimpleNamespace

import boto3
import pytest


# ---------------------------------------------------------------------------
# Module-level autouse fixture (RULE-4)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _mfg_bom_tables():
    """Create in-memory DynamoDB tables and patch T in manufacturing modules."""
    import moto

    with moto.mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        boms_tbl = ddb.create_table(
            TableName="mfg_boms",
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

        fake_T = SimpleNamespace(mfg_boms=boms_tbl)

        import app.services.manufacturing_bom as bom_mod
        from app.core.settings import S

        orig_T = getattr(bom_mod, "T", None)
        orig_flag = getattr(S, "manufacturing_mrp_enabled", False)
        orig_depth = getattr(S, "mfg_bom_max_explosion_depth", 5)

        bom_mod.T = fake_T
        object.__setattr__(S, "manufacturing_mrp_enabled", True)
        object.__setattr__(S, "mfg_bom_max_explosion_depth", 5)

        yield

        if orig_T is not None:
            bom_mod.T = orig_T
        object.__setattr__(S, "manufacturing_mrp_enabled", orig_flag)
        object.__setattr__(S, "mfg_bom_max_explosion_depth", orig_depth)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_create_and_get_bom():
    """Single-level BOM creation and retrieval."""
    from app.services.manufacturing_bom import create_bom, get_bom, get_active_bom

    bom = create_bom(
        "SKU-WIDGET",
        "Widget BOM",
        1,
        [
            {"component_sku": "COMP-A", "quantity_per": 2, "scrap_pct": 0.0},
            {"component_sku": "COMP-B", "quantity_per": 1, "scrap_pct": 0.05},
        ],
        user_sub="test-user",
    )
    assert bom["product_sku"] == "SKU-WIDGET"
    assert bom["status"] == "active"
    assert len(bom["components"]) == 2

    fetched = get_bom(bom["bom_id"])
    assert fetched is not None
    assert fetched["bom_id"] == bom["bom_id"]
    assert len(fetched["components"]) == 2

    active = get_active_bom("SKU-WIDGET")
    assert active is not None
    assert active["bom_id"] == bom["bom_id"]


def test_explode_bom_single_level():
    """BOM explosion with scrap factor."""
    from app.services.manufacturing_bom import create_bom, explode_bom

    bom = create_bom(
        "SKU-GADGET",
        "Gadget BOM",
        1,
        [
            {"component_sku": "PART-X", "quantity_per": 3, "scrap_pct": 0.1},
        ],
        user_sub="test-user",
    )
    # required_qty = ceil(3 * 10 / 1 * 1.1) = ceil(33) = 33
    exploded = explode_bom(bom["bom_id"], 10)
    assert len(exploded) == 1
    assert exploded[0]["component_sku"] == "PART-X"
    assert exploded[0]["required_qty"] == math.ceil(3 * 10 * 1.1)
    assert exploded[0]["depth"] == 1


def test_explode_bom_nested():
    """Nested BOM (sub-assembly): verify leaf-level quantities appear."""
    from app.services.manufacturing_bom import create_bom, explode_bom

    create_bom(
        "SUB-SKU",
        "Sub-assembly BOM",
        1,
        [{"component_sku": "LEAF-COMP", "quantity_per": 2, "scrap_pct": 0.0}],
        user_sub="test-user",
    )
    top_bom = create_bom(
        "TOP-SKU",
        "Top-level BOM",
        1,
        [{"component_sku": "SUB-SKU", "quantity_per": 3, "scrap_pct": 0.0}],
        user_sub="test-user",
    )

    # SUB-SKU qty = ceil(3 * 2 / 1) = 6; LEAF-COMP qty = ceil(2 * 6 / 1) = 12
    exploded = explode_bom(top_bom["bom_id"], 2)
    leaf = next((c for c in exploded if c["component_sku"] == "LEAF-COMP"), None)
    assert leaf is not None
    assert leaf["required_qty"] == 12


def test_explode_bom_cycle_detection():
    """Cyclic BOM: A -> B -> A should raise 409."""
    from app.services.manufacturing_bom import create_bom, explode_bom
    from fastapi import HTTPException

    bom_a = create_bom(
        "CYCLE-A",
        "Cycle A",
        1,
        [{"component_sku": "CYCLE-B", "quantity_per": 1, "scrap_pct": 0.0}],
        user_sub="test-user",
    )
    create_bom(
        "CYCLE-B",
        "Cycle B",
        1,
        [{"component_sku": "CYCLE-A", "quantity_per": 1, "scrap_pct": 0.0}],
        user_sub="test-user",
    )

    with pytest.raises(HTTPException) as exc_info:
        explode_bom(bom_a["bom_id"], 1)
    assert exc_info.value.status_code == 409


def test_explode_bom_depth_limit():
    """Deep BOM beyond depth limit raises 409."""
    from app.services.manufacturing_bom import create_bom, explode_bom
    from app.core.settings import S
    from fastapi import HTTPException

    orig = getattr(S, "mfg_bom_max_explosion_depth", 5)
    object.__setattr__(S, "mfg_bom_max_explosion_depth", 1)
    try:
        create_bom("DEPTH-C", "C", 1, [{"component_sku": "RAW-C", "quantity_per": 1}], user_sub="u")
        create_bom("DEPTH-B", "B", 1, [{"component_sku": "DEPTH-C", "quantity_per": 1}], user_sub="u")
        bom_a = create_bom("DEPTH-A", "A", 1, [{"component_sku": "DEPTH-B", "quantity_per": 1}], user_sub="u")
        with pytest.raises(HTTPException) as exc_info:
            explode_bom(bom_a["bom_id"], 1)
        assert exc_info.value.status_code == 409
    finally:
        object.__setattr__(S, "mfg_bom_max_explosion_depth", orig)


def test_update_bom():
    """Update BOM status and name."""
    from app.services.manufacturing_bom import create_bom, update_bom

    bom = create_bom("SKU-UPDATE", "Original Name", 1, [], user_sub="u")
    updated = update_bom(bom["bom_id"], name="New Name", status="inactive", user_sub="u")
    assert updated["name"] == "New Name"
    assert updated["status"] == "inactive"


def test_get_active_bom_returns_none_when_inactive():
    """Inactive BOMs are not returned by get_active_bom."""
    from app.services.manufacturing_bom import create_bom, update_bom, get_active_bom

    bom = create_bom("SKU-INACTIVE-TEST", "To Deactivate", 1, [], user_sub="u")
    update_bom(bom["bom_id"], status="inactive", user_sub="u")
    result = get_active_bom("SKU-INACTIVE-TEST")
    assert result is None or result.get("status") != "inactive"


def test_flag_off_raises_404():
    """When manufacturing_mrp_enabled is False, all functions raise 404."""
    from app.services.manufacturing_bom import create_bom
    from app.core.settings import S
    from fastapi import HTTPException

    object.__setattr__(S, "manufacturing_mrp_enabled", False)
    try:
        with pytest.raises(HTTPException) as exc:
            create_bom("SKU", "name", 1, [], user_sub="u")
        assert exc.value.status_code == 404
    finally:
        object.__setattr__(S, "manufacturing_mrp_enabled", True)
