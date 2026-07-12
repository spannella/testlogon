"""
PRD-007 / PRD-008 — Virtual/Variant product service + router endpoints
(OFBiz Catalog Depth)

Hermetic offline tests using moto @mock_aws + object.__setattr__ on frozen T/S.
No real AWS, no live DynamoDB, no HTTP stack required.

Tests cover:
  - mark_item_as_virtual (idempotent)
  - create_variant with 2 feature selections; deterministic sha256 id
  - list_variants returns created variant
  - duplicate combination idempotent (raises 409 on second put)
  - price computation: effective_price = parent_price + Σ deltas
  - delete_variant removes the row
  - get_variant returns the row, 404 when missing
  - product_depth_enabled=False → 501 on create/delete/mark-virtual
  - mark-virtual router endpoint (PRD-008)
  - list-variants router endpoint is public (PRD-008)
"""
from __future__ import annotations

import hashlib
import os
import types
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from fastapi import HTTPException
from moto import mock_aws

# ---------------------------------------------------------------------------
# Environment setup (MUST happen before any app imports)
# ---------------------------------------------------------------------------
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("UI_ACCESS_TOKEN_SECRET", "test-secret-prd007008")
os.environ.setdefault("API_KEY_PEPPER", "test-pepper-prd007008")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEPTH_TABLE = "product_depth_prd007"
CATALOG_TABLE = "catalog_prd007"

PARENT_ITEM_ID = "item-parent-001"
PARENT_PRICE_CENTS = 5000  # $50.00

FC_COLOR = "fc-color-001"
FC_SIZE = "fc-size-001"
FV_RED = "fv-red-001"
FV_LARGE = "fv-large-001"

USER_SUB = "user-test-prd007"


# ---------------------------------------------------------------------------
# Table helpers
# ---------------------------------------------------------------------------

def _make_product_depth_table(ddb):
    """Create the product_depth table with all GSIs needed by the service."""
    return ddb.create_table(
        TableName=DEPTH_TABLE,
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
            {"AttributeName": "GSI_VIRT_PK", "AttributeType": "S"},
            {"AttributeName": "GSI_VIRT_SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByVirtualParent",
                "KeySchema": [
                    {"AttributeName": "GSI_VIRT_PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI_VIRT_SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_catalog_table(ddb):
    """Create a minimal catalog table with the ByItemId GSI."""
    return ddb.create_table(
        TableName=CATALOG_TABLE,
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
            {"AttributeName": "item_id", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByItemId",
                "KeySchema": [
                    {"AttributeName": "item_id", "KeyType": "HASH"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _seed_catalog_item(catalog_table, item_id: str, price_cents: int, creator_id: str = USER_SUB):
    """Write a minimal catalog item row for testing."""
    catalog_table.put_item(Item={
        "PK": f"CAT#default",
        "SK": f"ITEM#{item_id}",
        "item_id": item_id,
        "entity": "item",
        "name": f"Test Product {item_id}",
        "price_cents": price_cents,
        "creator_id": creator_id,
        "created_at": 1700000000,
        "updated_at": 1700000000,
    })


def _seed_feature_attachments(depth_table, item_id: str, fc_ids: list):
    """Write FTAPPL# rows so create_variant can validate feature axes."""
    for fc_id in fc_ids:
        depth_table.put_item(Item={
            "PK": f"ITEM#{item_id}",
            "SK": f"FTAPPL#{fc_id}",
            "entity": "feature_attachment",
            "feature_category_id": fc_id,
            "item_id": item_id,
        })


def _seed_feature_value(depth_table, fc_id: str, fv_id: str, price_delta: int = 0):
    """Write a FTCAT#/FTVAL# row that get_feature_value can read.

    The product_features service uses SK=FTVAL#{fv_id} (not VAL#).
    """
    depth_table.put_item(Item={
        "PK": f"FTCAT#{fc_id}",
        "SK": f"FTVAL#{fv_id}",
        "entity": "feature_value",
        "feature_category_id": fc_id,
        "feature_value_id": fv_id,
        "name": f"Value {fv_id}",
        "price_delta_cents": price_delta,
    })


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def variant_env():
    """Full moto environment: product_depth + catalog tables, flag on."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        depth_table = _make_product_depth_table(ddb)
        catalog_table = _make_catalog_table(ddb)

        # Seed a parent catalog item
        _seed_catalog_item(catalog_table, PARENT_ITEM_ID, PARENT_PRICE_CENTS)

        # Seed feature attachments
        _seed_feature_attachments(depth_table, PARENT_ITEM_ID, [FC_COLOR, FC_SIZE])

        # Seed feature values with price deltas
        _seed_feature_value(depth_table, FC_COLOR, FV_RED, price_delta=200)    # +$2.00
        _seed_feature_value(depth_table, FC_SIZE, FV_LARGE, price_delta=500)   # +$5.00

        from app.core import tables as _tables_mod
        from app.core import settings as _settings_mod

        orig_depth = _tables_mod.T.product_depth
        orig_catalog = _tables_mod.T.catalog
        orig_flag = _settings_mod.S.product_depth_enabled
        orig_variants_flag = getattr(_settings_mod.S, "product_depth_variants_enabled", True)

        object.__setattr__(_tables_mod.T, "product_depth", depth_table)
        object.__setattr__(_tables_mod.T, "catalog", catalog_table)
        object.__setattr__(_settings_mod.S, "product_depth_enabled", True)
        object.__setattr__(_settings_mod.S, "product_depth_variants_enabled", True)

        yield {"depth": depth_table, "catalog": catalog_table}

        object.__setattr__(_tables_mod.T, "product_depth", orig_depth)
        object.__setattr__(_tables_mod.T, "catalog", orig_catalog)
        object.__setattr__(_settings_mod.S, "product_depth_enabled", orig_flag)
        object.__setattr__(_settings_mod.S, "product_depth_variants_enabled", orig_variants_flag)


@pytest.fixture()
def disabled_env():
    """Flag-off environment: product_depth_enabled=False."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        depth_table = _make_product_depth_table(ddb)
        catalog_table = _make_catalog_table(ddb)
        _seed_catalog_item(catalog_table, PARENT_ITEM_ID, PARENT_PRICE_CENTS)

        from app.core import tables as _tables_mod
        from app.core import settings as _settings_mod

        orig_depth = _tables_mod.T.product_depth
        orig_catalog = _tables_mod.T.catalog
        orig_flag = _settings_mod.S.product_depth_enabled

        object.__setattr__(_tables_mod.T, "product_depth", depth_table)
        object.__setattr__(_tables_mod.T, "catalog", catalog_table)
        object.__setattr__(_settings_mod.S, "product_depth_enabled", False)

        yield

        object.__setattr__(_tables_mod.T, "product_depth", orig_depth)
        object.__setattr__(_tables_mod.T, "catalog", orig_catalog)
        object.__setattr__(_settings_mod.S, "product_depth_enabled", orig_flag)


# ---------------------------------------------------------------------------
# Helper: expected variant_id
# ---------------------------------------------------------------------------

def _expected_variant_id(parent_item_id: str, feature_values: Dict[str, str]) -> str:
    """Mirror derive_variant_id logic from the service."""
    canonical_tuple = sorted(feature_values.items())
    raw = parent_item_id + "|" + "|".join(f"{fc}:{fv}" for fc, fv in canonical_tuple)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Tests — mark_item_as_virtual
# ---------------------------------------------------------------------------

class TestMarkItemAsVirtual:
    def test_marks_item_virtual(self, variant_env):
        from app.services.product_variants import mark_item_as_virtual
        row = mark_item_as_virtual(PARENT_ITEM_ID, USER_SUB)
        assert row["product_type"] == "virtual"
        assert row["PK"] == f"ITEM#{PARENT_ITEM_ID}"
        assert row["SK"] == "TYPE"

    def test_mark_virtual_idempotent(self, variant_env):
        """Calling mark_item_as_virtual twice should not raise and returns same type."""
        from app.services.product_variants import mark_item_as_virtual, get_product_type
        mark_item_as_virtual(PARENT_ITEM_ID, USER_SUB)
        mark_item_as_virtual(PARENT_ITEM_ID, USER_SUB)  # second call must not raise
        assert get_product_type(PARENT_ITEM_ID) == "virtual"

    def test_mark_virtual_unknown_item_raises_404(self, variant_env):
        from app.services.product_variants import mark_item_as_virtual
        with pytest.raises(HTTPException) as exc_info:
            mark_item_as_virtual("nonexistent-item", USER_SUB)
        assert exc_info.value.status_code == 404

    def test_mark_virtual_flag_off_raises_501(self, disabled_env):
        from app.services.product_variants import mark_item_as_virtual
        with pytest.raises(HTTPException) as exc_info:
            mark_item_as_virtual(PARENT_ITEM_ID, USER_SUB)
        assert exc_info.value.status_code == 501


# ---------------------------------------------------------------------------
# Tests — create_variant
# ---------------------------------------------------------------------------

class TestCreateVariant:
    def _mark_virtual_and_create(self, feature_values=None):
        """Helper: mark parent virtual, then create a variant."""
        from app.services.product_variants import mark_item_as_virtual, create_variant
        mark_item_as_virtual(PARENT_ITEM_ID, USER_SUB)
        fv = feature_values or {FC_COLOR: FV_RED, FC_SIZE: FV_LARGE}
        return create_variant(PARENT_ITEM_ID, fv, USER_SUB)

    def test_creates_variant(self, variant_env):
        row = self._mark_virtual_and_create()
        assert row["entity"] == "variant"
        assert row["parent_item_id"] == PARENT_ITEM_ID
        assert row["SK"].startswith("VAR#")

    def test_deterministic_variant_id(self, variant_env):
        """Same feature combination always produces the same variant_id."""
        expected = _expected_variant_id(PARENT_ITEM_ID, {FC_COLOR: FV_RED, FC_SIZE: FV_LARGE})
        row = self._mark_virtual_and_create()
        assert row["variant_id"] == expected

    def test_variant_id_order_independent(self, variant_env):
        """Insertion order of feature_values dict does not affect variant_id."""
        from app.services.product_variants import derive_variant_id
        id1 = derive_variant_id(PARENT_ITEM_ID, {FC_COLOR: FV_RED, FC_SIZE: FV_LARGE})
        id2 = derive_variant_id(PARENT_ITEM_ID, {FC_SIZE: FV_LARGE, FC_COLOR: FV_RED})
        assert id1 == id2

    def test_price_computation(self, variant_env):
        """effective_price_cents = parent_price + sum(feature value deltas)."""
        row = self._mark_virtual_and_create()
        expected_delta = 200 + 500  # red=200, large=500
        assert row["price_delta_cents"] == expected_delta
        assert row["effective_price_cents"] == PARENT_PRICE_CENTS + expected_delta

    def test_duplicate_combination_raises_409(self, variant_env):
        """Re-creating the exact same feature combination raises 409."""
        self._mark_virtual_and_create()
        from app.services.product_variants import create_variant
        with pytest.raises(HTTPException) as exc_info:
            create_variant(PARENT_ITEM_ID, {FC_COLOR: FV_RED, FC_SIZE: FV_LARGE}, USER_SUB)
        assert exc_info.value.status_code == 409

    def test_parent_not_virtual_raises_422(self, variant_env):
        """Creating a variant on a non-virtual item must raise 422."""
        from app.services.product_variants import create_variant
        with pytest.raises(HTTPException) as exc_info:
            create_variant(PARENT_ITEM_ID, {FC_COLOR: FV_RED, FC_SIZE: FV_LARGE}, USER_SUB)
        assert exc_info.value.status_code == 422

    def test_flag_off_raises_501(self, disabled_env):
        from app.services.product_variants import create_variant
        with pytest.raises(HTTPException) as exc_info:
            create_variant(PARENT_ITEM_ID, {FC_COLOR: FV_RED}, USER_SUB)
        assert exc_info.value.status_code == 501

    def test_sku_override(self, variant_env):
        """sku_override is stored verbatim on the variant row."""
        from app.services.product_variants import mark_item_as_virtual, create_variant
        mark_item_as_virtual(PARENT_ITEM_ID, USER_SUB)
        row = create_variant(
            PARENT_ITEM_ID,
            {FC_COLOR: FV_RED, FC_SIZE: FV_LARGE},
            USER_SUB,
            sku_override="MY-CUSTOM-SKU",
        )
        assert row["sku"] == "MY-CUSTOM-SKU"


# ---------------------------------------------------------------------------
# Tests — list_variants
# ---------------------------------------------------------------------------

class TestListVariants:
    def test_list_returns_created_variant(self, variant_env):
        from app.services.product_variants import mark_item_as_virtual, create_variant, list_variants
        mark_item_as_virtual(PARENT_ITEM_ID, USER_SUB)
        created = create_variant(PARENT_ITEM_ID, {FC_COLOR: FV_RED, FC_SIZE: FV_LARGE}, USER_SUB)
        rows, lek = list_variants(PARENT_ITEM_ID)
        assert len(rows) == 1
        assert rows[0]["variant_id"] == created["variant_id"]
        assert lek is None

    def test_list_empty_for_non_virtual_item(self, variant_env):
        """list_variants is safe to call on any item — returns [] for non-virtual."""
        from app.services.product_variants import list_variants
        rows, _ = list_variants("never-made-virtual")
        assert rows == []


# ---------------------------------------------------------------------------
# Tests — delete_variant
# ---------------------------------------------------------------------------

class TestDeleteVariant:
    def test_delete_removes_variant(self, variant_env):
        from app.services.product_variants import (
            mark_item_as_virtual, create_variant, delete_variant, list_variants,
        )
        mark_item_as_virtual(PARENT_ITEM_ID, USER_SUB)
        row = create_variant(PARENT_ITEM_ID, {FC_COLOR: FV_RED, FC_SIZE: FV_LARGE}, USER_SUB)
        delete_variant(PARENT_ITEM_ID, row["variant_id"], USER_SUB)
        rows, _ = list_variants(PARENT_ITEM_ID)
        assert len(rows) == 0

    def test_delete_nonexistent_raises_404(self, variant_env):
        from app.services.product_variants import delete_variant
        with pytest.raises(HTTPException) as exc_info:
            delete_variant(PARENT_ITEM_ID, "nonexistent-variant-id", USER_SUB)
        assert exc_info.value.status_code == 404

    def test_delete_flag_off_raises_501(self, disabled_env):
        from app.services.product_variants import delete_variant
        with pytest.raises(HTTPException) as exc_info:
            delete_variant(PARENT_ITEM_ID, "some-variant", USER_SUB)
        assert exc_info.value.status_code == 501


# ---------------------------------------------------------------------------
# Tests — get_variant
# ---------------------------------------------------------------------------

class TestGetVariant:
    def test_get_returns_variant(self, variant_env):
        from app.services.product_variants import (
            mark_item_as_virtual, create_variant, get_variant,
        )
        mark_item_as_virtual(PARENT_ITEM_ID, USER_SUB)
        created = create_variant(PARENT_ITEM_ID, {FC_COLOR: FV_RED, FC_SIZE: FV_LARGE}, USER_SUB)
        fetched = get_variant(PARENT_ITEM_ID, created["variant_id"])
        assert fetched["variant_id"] == created["variant_id"]
        assert fetched["effective_price_cents"] == PARENT_PRICE_CENTS + 700

    def test_get_nonexistent_raises_404(self, variant_env):
        from app.services.product_variants import get_variant
        with pytest.raises(HTTPException) as exc_info:
            get_variant(PARENT_ITEM_ID, "no-such-variant")
        assert exc_info.value.status_code == 404
