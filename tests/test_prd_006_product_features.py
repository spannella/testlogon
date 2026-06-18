"""
PRD-006 — Per-item feature categories & values (OFBiz Catalog Depth)

Hermetic offline tests using moto + object.__setattr__ on T.product_depth.
All tests call service functions directly; no HTTP stack needed.
"""
from __future__ import annotations

import hashlib
import os
import types

import boto3
import pytest
from fastapi import HTTPException
from moto import mock_aws

# ---------------------------------------------------------------------------
# Environment setup (must happen before any app imports)
# ---------------------------------------------------------------------------
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("UI_ACCESS_TOKEN_SECRET", "test-secret-prd006")
os.environ.setdefault("API_KEY_PEPPER", "test-pepper-prd006")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TABLE_NAME = "product_depth_test_prd006"


def _make_table(ddb_resource):
    """Create the product_depth table with the right key schema."""
    return ddb_resource.create_table(
        TableName=TABLE_NAME,
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _fc_id(item_id: str, name: str) -> str:
    raw = f"{item_id}:{name.strip().lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _fv_id(fc_id: str, value: str) -> str:
    raw = f"{fc_id}:{value.strip().lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def prd006_env():
    """Spin up moto DDB, patch T.product_depth and S.product_depth_enabled."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = _make_table(ddb)

        from app.core import tables as _tables_mod
        from app.core import settings as _settings_mod

        orig_table = _tables_mod.T.product_depth
        orig_flag = _settings_mod.S.product_depth_enabled

        object.__setattr__(_tables_mod.T, "product_depth", table)
        object.__setattr__(_settings_mod.S, "product_depth_enabled", True)

        yield table  # tests receive the raw moto table for direct inspection

        object.__setattr__(_tables_mod.T, "product_depth", orig_table)
        object.__setattr__(_settings_mod.S, "product_depth_enabled", orig_flag)


@pytest.fixture()
def disabled_env():
    """Patch S.product_depth_enabled to False."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        _make_table(ddb)

        from app.core import tables as _tables_mod
        from app.core import settings as _settings_mod

        orig_table = _tables_mod.T.product_depth
        orig_flag = _settings_mod.S.product_depth_enabled

        object.__setattr__(_tables_mod.T, "product_depth", ddb.Table(TABLE_NAME))
        object.__setattr__(_settings_mod.S, "product_depth_enabled", False)

        yield

        object.__setattr__(_tables_mod.T, "product_depth", orig_table)
        object.__setattr__(_settings_mod.S, "product_depth_enabled", orig_flag)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCreateItemFeatureCategory:
    def test_creates_category(self, prd006_env):
        from app.services.product_features import create_item_feature_category
        row = create_item_feature_category("item-001", "Color", position=0)
        assert row["feature_category_id"] == _fc_id("item-001", "Color")
        assert row["name"] == "Color"
        assert row["item_id"] == "item-001"
        assert row["position"] == 0
        assert "created_at" in row

    def test_idempotent_same_name(self, prd006_env):
        """Same item_id + name → same feature_category_id returned."""
        from app.services.product_features import create_item_feature_category
        row1 = create_item_feature_category("item-002", "Size", position=1)
        row2 = create_item_feature_category("item-002", "Size", position=1)
        assert row1["feature_category_id"] == row2["feature_category_id"]

    def test_different_items_can_have_same_name(self, prd006_env):
        from app.services.product_features import create_item_feature_category
        row1 = create_item_feature_category("item-A", "Material")
        row2 = create_item_feature_category("item-B", "Material")
        # IDs differ because item_id differs
        assert row1["feature_category_id"] != row2["feature_category_id"]

    def test_disabled_raises_501(self, disabled_env):
        from app.services.product_features import create_item_feature_category
        with pytest.raises(HTTPException) as exc_info:
            create_item_feature_category("item-X", "Color")
        assert exc_info.value.status_code == 501


class TestAddItemFeatureValue:
    def test_adds_value_with_price_delta(self, prd006_env):
        from app.services.product_features import (
            create_item_feature_category,
            add_item_feature_value,
        )
        fc = create_item_feature_category("item-003", "Color")
        fc_id = fc["feature_category_id"]
        fv = add_item_feature_value("item-003", fc_id, "Red", price_delta_cents=500)
        assert fv["value"] == "Red"
        assert fv["price_delta_cents"] == 500
        assert fv["feature_category_id"] == fc_id
        assert fv["feature_value_id"] == _fv_id(fc_id, "Red")

    def test_idempotent_same_value(self, prd006_env):
        from app.services.product_features import (
            create_item_feature_category,
            add_item_feature_value,
        )
        fc = create_item_feature_category("item-004", "Size")
        fc_id = fc["feature_category_id"]
        fv1 = add_item_feature_value("item-004", fc_id, "XL")
        fv2 = add_item_feature_value("item-004", fc_id, "XL")
        assert fv1["feature_value_id"] == fv2["feature_value_id"]

    def test_raises_404_if_category_not_found(self, prd006_env):
        from app.services.product_features import add_item_feature_value
        with pytest.raises(HTTPException) as exc_info:
            add_item_feature_value("item-missing", "nonexistent-fc-id", "Blue")
        assert exc_info.value.status_code == 404

    def test_disabled_raises_501(self, disabled_env):
        from app.services.product_features import add_item_feature_value
        with pytest.raises(HTTPException) as exc_info:
            add_item_feature_value("item-X", "any-fc-id", "Blue")
        assert exc_info.value.status_code == 501


class TestListItemFeatureCategories:
    def test_ordered_by_position(self, prd006_env):
        from app.services.product_features import (
            create_item_feature_category,
            list_item_feature_categories,
        )
        create_item_feature_category("item-005", "Bbb", position=2)
        create_item_feature_category("item-005", "Aaa", position=0)
        create_item_feature_category("item-005", "Ccc", position=1)
        cats = list_item_feature_categories("item-005")
        positions = [c["position"] for c in cats]
        assert positions == sorted(positions), "Categories not sorted by position"

    def test_returns_empty_for_unknown_item(self, prd006_env):
        from app.services.product_features import list_item_feature_categories
        cats = list_item_feature_categories("item-unknown-xyz")
        assert cats == []

    def test_disabled_raises_501(self, disabled_env):
        from app.services.product_features import list_item_feature_categories
        with pytest.raises(HTTPException) as exc_info:
            list_item_feature_categories("item-X")
        assert exc_info.value.status_code == 501


class TestListItemProductFeatures:
    def test_returns_correct_structure(self, prd006_env):
        from app.services.product_features import (
            create_item_feature_category,
            add_item_feature_value,
            list_item_product_features,
        )
        fc = create_item_feature_category("item-006", "Color")
        fc_id = fc["feature_category_id"]
        add_item_feature_value("item-006", fc_id, "Red", price_delta_cents=100)
        add_item_feature_value("item-006", fc_id, "Blue", price_delta_cents=200)

        result = list_item_product_features("item-006")
        assert result["item_id"] == "item-006"
        assert len(result["feature_categories"]) == 1
        assert result["feature_categories"][0]["name"] == "Color"
        assert len(result["values"]) == 2
        value_names = {v["value"] for v in result["values"]}
        assert value_names == {"Red", "Blue"}

    def test_multiple_categories(self, prd006_env):
        from app.services.product_features import (
            create_item_feature_category,
            add_item_feature_value,
            list_item_product_features,
        )
        fc1 = create_item_feature_category("item-007", "Color", position=0)
        fc2 = create_item_feature_category("item-007", "Size", position=1)
        add_item_feature_value("item-007", fc1["feature_category_id"], "Red")
        add_item_feature_value("item-007", fc2["feature_category_id"], "M")
        add_item_feature_value("item-007", fc2["feature_category_id"], "L")

        result = list_item_product_features("item-007")
        assert len(result["feature_categories"]) == 2
        assert len(result["values"]) == 3

    def test_empty_item_returns_empty_lists(self, prd006_env):
        from app.services.product_features import list_item_product_features
        result = list_item_product_features("item-empty-99")
        assert result["item_id"] == "item-empty-99"
        assert result["feature_categories"] == []
        assert result["values"] == []


class TestDeleteItemFeatureCategory:
    def test_delete_blocked_when_values_exist(self, prd006_env):
        from app.services.product_features import (
            create_item_feature_category,
            add_item_feature_value,
            delete_item_feature_category,
        )
        fc = create_item_feature_category("item-008", "Color")
        fc_id = fc["feature_category_id"]
        add_item_feature_value("item-008", fc_id, "Red")

        with pytest.raises(HTTPException) as exc_info:
            delete_item_feature_category("item-008", fc_id)
        assert exc_info.value.status_code == 409

    def test_delete_succeeds_when_empty(self, prd006_env):
        from app.services.product_features import (
            create_item_feature_category,
            delete_item_feature_category,
            list_item_feature_categories,
        )
        fc = create_item_feature_category("item-009", "Style")
        fc_id = fc["feature_category_id"]

        # Should not raise
        delete_item_feature_category("item-009", fc_id)

        # Category should no longer be listed
        cats = list_item_feature_categories("item-009")
        assert not any(c["feature_category_id"] == fc_id for c in cats)

    def test_delete_raises_404_if_not_found(self, prd006_env):
        from app.services.product_features import delete_item_feature_category
        with pytest.raises(HTTPException) as exc_info:
            delete_item_feature_category("item-missing", "nonexistent-fc")
        assert exc_info.value.status_code == 404

    def test_disabled_raises_501(self, disabled_env):
        from app.services.product_features import delete_item_feature_category
        with pytest.raises(HTTPException) as exc_info:
            delete_item_feature_category("item-X", "any-fc-id")
        assert exc_info.value.status_code == 501
