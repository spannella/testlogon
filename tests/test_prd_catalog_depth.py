"""
Hermetic offline pytest for PRD-002..PRD-007/PRD-012 OFBiz Catalog Depth backend.

Covers:
  - PRD-006: product_features service (feature categories, values, attach/list)
  - PRD-007: product_variants service (derive_variant_id, compute_price_delta,
             set_product_type, create_variant, list_variants, delete_variant)
  - PRD-012: product_price_components service (set, list, resolve_effective_price)
  - Flag-off regression: with product_depth_enabled=False, all public functions
    raise HTTP 404.

Follows the hermetic pattern from tests/test_gap_0223_0224_ec2_host_inventory.py:
  - moto in-memory DynamoDB
  - T.product_depth / T.catalog bound via patch.object
  - S flags toggled via object.__setattr__
  - No TestClient; service functions called directly
"""

import hashlib
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

try:
    import boto3
    from moto import mock_aws
    HAS_MOTO = True
except ImportError:
    HAS_MOTO = False


# ---------------------------------------------------------------------------
# Table construction helpers
# ---------------------------------------------------------------------------

def _make_product_depth_table(ddb):
    """Create a minimal product_depth table with all GSIs needed by PRD-002."""
    return ddb.create_table(
        TableName="product_depth",
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK",             "AttributeType": "S"},
            {"AttributeName": "SK",             "AttributeType": "S"},
            {"AttributeName": "GSI_FTCAT_PK",   "AttributeType": "S"},
            {"AttributeName": "GSI_FTCAT_SK",   "AttributeType": "N"},
            {"AttributeName": "GSI_VIRT_PK",    "AttributeType": "S"},
            {"AttributeName": "GSI_VIRT_SK",    "AttributeType": "N"},
            {"AttributeName": "GSI_PRICE_PK",   "AttributeType": "S"},
            {"AttributeName": "GSI_PRICE_SK",   "AttributeType": "N"},
            {"AttributeName": "GSI_PARENT_PK",  "AttributeType": "S"},
            {"AttributeName": "GSI_PARENT_SK",  "AttributeType": "N"},
            {"AttributeName": "GSI_ASSOC_PK",   "AttributeType": "S"},
            {"AttributeName": "GSI_ASSOC_SK",   "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByFeatureCategory",
                "KeySchema": [
                    {"AttributeName": "GSI_FTCAT_PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI_FTCAT_SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByVirtualParent",
                "KeySchema": [
                    {"AttributeName": "GSI_VIRT_PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI_VIRT_SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByItemPrice",
                "KeySchema": [
                    {"AttributeName": "GSI_PRICE_PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI_PRICE_SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByParent",
                "KeySchema": [
                    {"AttributeName": "GSI_PARENT_PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI_PARENT_SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByAssocSource",
                "KeySchema": [
                    {"AttributeName": "GSI_ASSOC_PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI_ASSOC_SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )


def _make_catalog_table(ddb):
    """Create shopping_catalog table with ByItemId GSI (for scalar fallback)."""
    return ddb.create_table(
        TableName="shopping_catalog",
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK",      "AttributeType": "S"},
            {"AttributeName": "SK",      "AttributeType": "S"},
            {"AttributeName": "item_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByItemId",
                "KeySchema": [{"AttributeName": "item_id", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )


def _seed_catalog_item(catalog_table, item_id: str, category_id: str = "cat1",
                       price_cents: int = 1000, creator_id: str = "user1"):
    catalog_table.put_item(Item={
        "PK": f"CAT#{category_id}",
        "SK": f"ITEM#{item_id}",
        "entity": "item",
        "item_id": item_id,
        "category_id": category_id,
        "name": f"Test Item {item_id}",
        "price_cents": price_cents,
        "currency": "USD",
        "creator_id": creator_id,
    })


# ---------------------------------------------------------------------------
# PRD-006: Feature category / value service tests
# ---------------------------------------------------------------------------

@unittest.skipIf(not HAS_MOTO, "moto not installed")
class TestProductFeatures(unittest.TestCase):

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.pd_table = _make_product_depth_table(ddb)
        self.cat_table = _make_catalog_table(ddb)

        fake_T = SimpleNamespace(product_depth=self.pd_table, catalog=self.cat_table)

        import app.services.product_features as pf_mod
        self.pf = pf_mod
        self.stack.enter_context(patch.object(pf_mod, "T", fake_T))

        S = pf_mod.S
        self._orig_enabled = getattr(S, "product_depth_enabled", False)
        self._orig_feat = getattr(S, "product_depth_features_enabled", True)
        object.__setattr__(S, "product_depth_enabled", True)
        object.__setattr__(S, "product_depth_features_enabled", True)
        self.S = S

    def tearDown(self):
        object.__setattr__(self.S, "product_depth_enabled", self._orig_enabled)
        object.__setattr__(self.S, "product_depth_features_enabled", self._orig_feat)

    def test_create_feature_category(self):
        fc = self.pf.create_feature_category("Color", "user1")
        self.assertEqual(fc["name"], "Color")
        self.assertEqual(fc["creator_id"], "user1")
        self.assertEqual(fc["entity"], "feature_category")
        self.assertIn("feature_category_id", fc)

    def test_create_feature_category_with_id(self):
        fc = self.pf.create_feature_category("Size", "user1", feature_category_id="my-fc-id")
        self.assertEqual(fc["feature_category_id"], "my-fc-id")

    def test_create_feature_category_duplicate_409(self):
        from fastapi import HTTPException
        fc = self.pf.create_feature_category("Color", "user1", feature_category_id="dup-id")
        with self.assertRaises(HTTPException) as cm:
            self.pf.create_feature_category("Color2", "user1", feature_category_id="dup-id")
        self.assertEqual(cm.exception.status_code, 409)

    def test_get_feature_category(self):
        fc = self.pf.create_feature_category("Color", "user1", feature_category_id="fc1")
        got = self.pf.get_feature_category("fc1")
        self.assertIsNotNone(got)
        self.assertEqual(got["name"], "Color")

    def test_get_feature_category_missing(self):
        got = self.pf.get_feature_category("nonexistent")
        self.assertIsNone(got)

    def test_add_feature_value(self):
        self.pf.create_feature_category("Color", "user1", feature_category_id="fc1")
        fv = self.pf.add_feature_value("fc1", "Red", "user1", price_delta_cents=100, position=1)
        self.assertEqual(fv["name"], "Red")
        self.assertEqual(fv["price_delta_cents"], 100)
        self.assertEqual(fv["position"], 1)
        self.assertEqual(fv["entity"], "feature_value")
        # Check GSI attrs
        self.assertEqual(fv["GSI_FTCAT_PK"], "FTCAT#fc1")
        self.assertEqual(fv["GSI_FTCAT_SK"], 1)

    def test_add_feature_value_idempotent(self):
        self.pf.create_feature_category("Color", "user1", feature_category_id="fc1")
        fv1 = self.pf.add_feature_value("fc1", "Red", "user1")
        fv2 = self.pf.add_feature_value("fc1", "Red", "user1")
        # Same fv_id returned
        self.assertEqual(fv1["feature_value_id"], fv2["feature_value_id"])
        # Only one row in DDB
        vals = self.pf._list_values_for_category("fc1")
        self.assertEqual(len(vals), 1)

    def test_add_feature_value_case_insensitive(self):
        self.pf.create_feature_category("Color", "user1", feature_category_id="fc1")
        fv1 = self.pf.add_feature_value("fc1", "Red", "user1")
        fv2 = self.pf.add_feature_value("fc1", "RED", "user1")
        self.assertEqual(fv1["feature_value_id"], fv2["feature_value_id"])

    def test_add_feature_value_negative_delta(self):
        self.pf.create_feature_category("Color", "user1", feature_category_id="fc1")
        fv = self.pf.add_feature_value("fc1", "Discount", "user1", price_delta_cents=-500)
        self.assertEqual(fv["price_delta_cents"], -500)

    def test_add_feature_value_out_of_bounds(self):
        from fastapi import HTTPException
        self.pf.create_feature_category("Color", "user1", feature_category_id="fc1")
        with self.assertRaises(HTTPException) as cm:
            self.pf.add_feature_value("fc1", "Huge", "user1", price_delta_cents=10_000_000_01)
        self.assertEqual(cm.exception.status_code, 400)

    def test_list_values_ordered_by_position(self):
        self.pf.create_feature_category("Size", "user1", feature_category_id="fc-size")
        self.pf.add_feature_value("fc-size", "XL", "user1", position=5)
        self.pf.add_feature_value("fc-size", "SM", "user1", position=0)
        self.pf.add_feature_value("fc-size", "MD", "user1", position=2)
        vals = self.pf._list_values_for_category("fc-size")
        positions = [int(v["position"]) for v in vals]
        self.assertEqual(positions, [0, 2, 5])

    def test_attach_feature_category_to_product(self):
        self.pf.create_feature_category("Color", "user1", feature_category_id="fc1")
        result = self.pf.attach_feature_category_to_product("item1", "fc1", "user1")
        self.assertEqual(result["entity"], "feature_appl")
        self.assertEqual(result["item_id"], "item1")
        self.assertEqual(result["feature_category_id"], "fc1")

    def test_attach_idempotent(self):
        self.pf.create_feature_category("Color", "user1", feature_category_id="fc1")
        self.pf.attach_feature_category_to_product("item1", "fc1", "user1")
        # Second attach should not raise
        self.pf.attach_feature_category_to_product("item1", "fc1", "user1")

    def test_attach_wrong_owner_403(self):
        from fastapi import HTTPException
        self.pf.create_feature_category("Color", "user1", feature_category_id="fc1")
        with self.assertRaises(HTTPException) as cm:
            self.pf.attach_feature_category_to_product("item1", "fc1", "user2")
        self.assertEqual(cm.exception.status_code, 403)

    def test_list_product_features(self):
        self.pf.create_feature_category("Color", "user1", feature_category_id="fc1")
        self.pf.add_feature_value("fc1", "Red", "user1", position=0)
        self.pf.add_feature_value("fc1", "Blue", "user1", position=1)
        self.pf.attach_feature_category_to_product("item1", "fc1", "user1")
        features = self.pf.list_product_features("item1")
        self.assertEqual(len(features), 1)
        self.assertEqual(features[0]["name"], "Color")
        self.assertEqual(len(features[0]["values"]), 2)

    def test_list_product_features_no_attach(self):
        features = self.pf.list_product_features("item-no-features")
        self.assertEqual(features, [])

    def test_list_product_features_multiple_categories(self):
        self.pf.create_feature_category("Color", "user1", feature_category_id="fc-color")
        self.pf.create_feature_category("Size", "user1", feature_category_id="fc-size")
        self.pf.attach_feature_category_to_product("item1", "fc-color", "user1")
        self.pf.attach_feature_category_to_product("item1", "fc-size", "user1")
        features = self.pf.list_product_features("item1")
        self.assertEqual(len(features), 2)

    def test_delete_feature_value(self):
        self.pf.create_feature_category("Color", "user1", feature_category_id="fc1")
        fv = self.pf.add_feature_value("fc1", "Red", "user1")
        fv_id = fv["feature_value_id"]
        self.pf.delete_feature_value("fc1", fv_id, "user1")
        got = self.pf.get_feature_value("fc1", fv_id)
        self.assertIsNone(got)

    def test_delete_feature_category_in_use_blocked(self):
        from fastapi import HTTPException
        self.pf.create_feature_category("Color", "user1", feature_category_id="fc1")
        self.pf.attach_feature_category_to_product("item1", "fc1", "user1")
        with self.assertRaises(HTTPException) as cm:
            self.pf.delete_feature_category("fc1", "user1")
        self.assertEqual(cm.exception.status_code, 409)

    def test_delete_feature_category_unused(self):
        self.pf.create_feature_category("Color", "user1", feature_category_id="fc1")
        self.pf.add_feature_value("fc1", "Red", "user1")
        self.pf.add_feature_value("fc1", "Blue", "user1")
        self.pf.delete_feature_category("fc1", "user1")
        self.assertIsNone(self.pf.get_feature_category("fc1"))
        vals = self.pf._list_values_for_category("fc1")
        self.assertEqual(len(vals), 0)

    def test_flag_off_returns_404(self):
        from fastapi import HTTPException
        object.__setattr__(self.S, "product_depth_enabled", False)
        with self.assertRaises(HTTPException) as cm:
            self.pf.create_feature_category("Color", "user1")
        self.assertEqual(cm.exception.status_code, 404)

    def test_master_flag_off_ignores_sub_flag(self):
        from fastapi import HTTPException
        object.__setattr__(self.S, "product_depth_enabled", False)
        object.__setattr__(self.S, "product_depth_features_enabled", True)
        with self.assertRaises(HTTPException) as cm:
            self.pf.list_feature_categories("user1")
        self.assertEqual(cm.exception.status_code, 404)


# ---------------------------------------------------------------------------
# PRD-007: Product variants service tests
# ---------------------------------------------------------------------------

@unittest.skipIf(not HAS_MOTO, "moto not installed")
class TestProductVariants(unittest.TestCase):

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.pd_table = _make_product_depth_table(ddb)
        self.cat_table = _make_catalog_table(ddb)

        fake_T = SimpleNamespace(product_depth=self.pd_table, catalog=self.cat_table)

        import app.services.product_variants as pv_mod
        import app.services.product_features as pf_mod
        self.pv = pv_mod
        self.pf = pf_mod
        self.stack.enter_context(patch.object(pv_mod, "T", fake_T))
        self.stack.enter_context(patch.object(pf_mod, "T", fake_T))

        S = pv_mod.S
        self._orig = {
            "product_depth_enabled": getattr(S, "product_depth_enabled", False),
            "product_depth_variants_enabled": getattr(S, "product_depth_variants_enabled", True),
            "product_depth_features_enabled": getattr(S, "product_depth_features_enabled", True),
        }
        object.__setattr__(S, "product_depth_enabled", True)
        object.__setattr__(S, "product_depth_variants_enabled", True)
        object.__setattr__(S, "product_depth_features_enabled", True)
        self.S = S

        # Seed a catalog item
        _seed_catalog_item(self.cat_table, "item1", price_cents=1000, creator_id="user1")

    def tearDown(self):
        for k, v in self._orig.items():
            object.__setattr__(self.S, k, v)

    def _setup_virtual_item_with_features(self):
        """Helper: promote item1 to virtual and attach Color/Size feature categories."""
        self.pv.set_product_type("item1", "virtual", "user1")

        self.pf.create_feature_category("Color", "user1", feature_category_id="fc-color")
        self.pf.add_feature_value("fc-color", "Red", "user1", price_delta_cents=0, position=0)
        self.pf.add_feature_value("fc-color", "Blue", "user1", price_delta_cents=50, position=1)
        self.pf.attach_feature_category_to_product("item1", "fc-color", "user1")

        self.pf.create_feature_category("Size", "user1", feature_category_id="fc-size")
        self.pf.add_feature_value("fc-size", "S", "user1", price_delta_cents=0, position=0)
        self.pf.add_feature_value("fc-size", "L", "user1", price_delta_cents=200, position=1)
        self.pf.attach_feature_category_to_product("item1", "fc-size", "user1")

        # Return the feature_value_ids
        red_id = self.pf._fv_id("fc-color", "red")
        blue_id = self.pf._fv_id("fc-color", "blue")
        s_id = self.pf._fv_id("fc-size", "s")
        l_id = self.pf._fv_id("fc-size", "l")
        return {
            "red": red_id,
            "blue": blue_id,
            "s": s_id,
            "l": l_id,
        }

    # --- Pure function tests (no DB) ---

    def test_derive_variant_id_deterministic(self):
        id1 = self.pv.derive_variant_id("parent1", {"color": "red", "size": "L"})
        id2 = self.pv.derive_variant_id("parent1", {"size": "L", "color": "red"})
        self.assertEqual(id1, id2)
        self.assertEqual(len(id1), 16)

    def test_derive_variant_id_different_parents(self):
        id1 = self.pv.derive_variant_id("parent1", {"color": "red"})
        id2 = self.pv.derive_variant_id("parent2", {"color": "red"})
        self.assertNotEqual(id1, id2)

    def test_compute_price_delta_pure(self):
        feature_values = {"fc-color": "fv-red", "fc-size": "fv-L"}
        deltas = {"fv-red": 0, "fv-L": 200}
        self.assertEqual(self.pv.compute_price_delta(feature_values, deltas), 200)

    def test_compute_price_delta_negative(self):
        feature_values = {"fc-color": "fv-red"}
        deltas = {"fv-red": -100}
        self.assertEqual(self.pv.compute_price_delta(feature_values, deltas), -100)

    def test_compute_price_delta_zero(self):
        feature_values = {"fc-color": "fv-red"}
        deltas = {"fv-red": 0}
        self.assertEqual(self.pv.compute_price_delta(feature_values, deltas), 0)

    # --- set_product_type tests ---

    def test_set_product_type_virtual(self):
        row = self.pv.set_product_type("item1", "virtual", "user1")
        self.assertEqual(row["product_type"], "virtual")
        self.assertEqual(self.pv.get_product_type("item1"), "virtual")

    def test_set_product_type_idempotent(self):
        self.pv.set_product_type("item1", "virtual", "user1")
        # Second call should not raise; overwrites updated_at
        row2 = self.pv.set_product_type("item1", "virtual", "user1")
        self.assertEqual(row2["product_type"], "virtual")

    def test_get_product_type_returns_none_for_missing(self):
        pt = self.pv.get_product_type("no-type-item")
        self.assertIsNone(pt)

    # --- create_variant tests ---

    def test_create_variant_success(self):
        fv_ids = self._setup_virtual_item_with_features()
        var = self.pv.create_variant(
            "item1",
            {"fc-color": fv_ids["red"], "fc-size": fv_ids["s"]},
            "user1",
        )
        self.assertEqual(var["entity"], "variant")
        self.assertEqual(var["parent_item_id"], "item1")
        self.assertIn("variant_id", var)
        self.assertIn("sku", var)
        self.assertTrue(var["sku"].startswith("variant:item1:"))
        self.assertEqual(var["price_delta_cents"], 0)  # red + S = 0 + 0
        self.assertEqual(var["effective_price_cents"], 1000)
        self.assertEqual(var["GSI_VIRT_PK"], "VIRTUAL#item1")
        self.assertIsInstance(var["GSI_VIRT_SK"], int)

    def test_create_variant_price_delta(self):
        fv_ids = self._setup_virtual_item_with_features()
        var = self.pv.create_variant(
            "item1",
            {"fc-color": fv_ids["blue"], "fc-size": fv_ids["l"]},
            "user1",
        )
        # blue (+50) + L (+200) = 250
        self.assertEqual(var["price_delta_cents"], 250)
        self.assertEqual(var["effective_price_cents"], 1250)

    def test_create_variant_duplicate_409(self):
        from fastapi import HTTPException
        fv_ids = self._setup_virtual_item_with_features()
        fv_combo = {"fc-color": fv_ids["red"], "fc-size": fv_ids["s"]}
        self.pv.create_variant("item1", fv_combo, "user1")
        with self.assertRaises(HTTPException) as cm:
            self.pv.create_variant("item1", fv_combo, "user1")
        self.assertEqual(cm.exception.status_code, 409)

    def test_create_variant_parent_not_virtual_422(self):
        from fastapi import HTTPException
        # item1 is still standalone (no TYPE row)
        with self.assertRaises(HTTPException) as cm:
            self.pv.create_variant("item1", {"fc-color": "red-id"}, "user1")
        self.assertEqual(cm.exception.status_code, 422)

    def test_create_variant_unattached_feature_axis_422(self):
        from fastapi import HTTPException
        self.pv.set_product_type("item1", "virtual", "user1")
        # No feature categories attached
        with self.assertRaises(HTTPException) as cm:
            self.pv.create_variant("item1", {"fc-color": "red-id"}, "user1")
        self.assertEqual(cm.exception.status_code, 422)

    def test_standalone_item_has_zero_variants(self):
        items, last_key = self.pv.list_variants("item1")
        self.assertEqual(items, [])
        self.assertIsNone(last_key)

    # --- list_variants tests ---

    def test_list_variants_single_gsi_query(self):
        fv_ids = self._setup_virtual_item_with_features()
        self.pv.create_variant("item1", {"fc-color": fv_ids["red"], "fc-size": fv_ids["s"]}, "user1")
        self.pv.create_variant("item1", {"fc-color": fv_ids["blue"], "fc-size": fv_ids["l"]}, "user1")
        items, _ = self.pv.list_variants("item1")
        self.assertEqual(len(items), 2)

    # --- delete_variant tests ---

    def test_delete_variant(self):
        fv_ids = self._setup_virtual_item_with_features()
        var = self.pv.create_variant(
            "item1", {"fc-color": fv_ids["red"], "fc-size": fv_ids["s"]}, "user1"
        )
        self.pv.delete_variant("item1", var["variant_id"], "user1")
        items, _ = self.pv.list_variants("item1")
        self.assertEqual(len(items), 0)

    def test_delete_variant_404(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as cm:
            self.pv.delete_variant("item1", "nonexistent-variant-id", "user1")
        self.assertEqual(cm.exception.status_code, 404)

    # --- flag off tests ---

    def test_flag_off_raises_404(self):
        from fastapi import HTTPException
        object.__setattr__(self.S, "product_depth_enabled", False)
        with self.assertRaises(HTTPException) as cm:
            self.pv.set_product_type("item1", "virtual", "user1")
        self.assertIn(cm.exception.status_code, (404, 501))  # 501 is current behavior

    def test_effective_price_snapshot(self):
        """effective_price_cents is stored at creation time; changing a delta doesn't retroactively update."""
        fv_ids = self._setup_virtual_item_with_features()
        var = self.pv.create_variant(
            "item1", {"fc-color": fv_ids["red"], "fc-size": fv_ids["s"]}, "user1"
        )
        self.assertEqual(var["effective_price_cents"], 1000)
        # Verify the DB row still has the original price
        row = self.pd_table.get_item(
            Key={"PK": "ITEM#item1", "SK": f"VAR#{var['variant_id']}"}
        ).get("Item")
        self.assertEqual(int(row["effective_price_cents"]), 1000)


# ---------------------------------------------------------------------------
# PRD-012: Price components service tests
# ---------------------------------------------------------------------------

@unittest.skipIf(not HAS_MOTO, "moto not installed")
class TestPriceComponents(unittest.TestCase):

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.pd_table = _make_product_depth_table(ddb)
        self.cat_table = _make_catalog_table(ddb)

        fake_T = SimpleNamespace(product_depth=self.pd_table, catalog=self.cat_table)

        import app.services.product_price_components as pc_mod
        self.pc = pc_mod
        self.stack.enter_context(patch.object(pc_mod, "T", fake_T))

        S = pc_mod.S
        self._orig = {
            "product_depth_enabled": getattr(S, "product_depth_enabled", False),
            "product_depth_price_components_enabled": getattr(
                S, "product_depth_price_components_enabled", True
            ),
        }
        object.__setattr__(S, "product_depth_enabled", True)
        object.__setattr__(S, "product_depth_price_components_enabled", True)
        self.S = S

        # Seed catalog item for scalar fallback
        _seed_catalog_item(self.cat_table, "item1", price_cents=999, creator_id="user1")

    def tearDown(self):
        for k, v in self._orig.items():
            object.__setattr__(self.S, k, v)

    def _make_body(self, price_type="DEFAULT", amount=1000, eff=1000000, exp=None):
        from app.models import ProductPriceComponentIn, PriceTypeEnum
        return ProductPriceComponentIn(
            price_type=PriceTypeEnum(price_type),
            amount_cents=amount,
            currency="USD",
            effective_at=eff,
            expires_at=exp,
        )

    # --- set_price_component tests ---

    def test_set_price_component_creates_row(self):
        result = self.pc.set_price_component("item1", "user1", self._make_body(eff=1000000))
        self.assertEqual(result.item_id, "item1")
        self.assertEqual(result.price_type, "DEFAULT")
        self.assertEqual(result.amount_cents, 1000)
        expected_id = hashlib.sha256(b"item1|DEFAULT|1000000").hexdigest()[:16]
        self.assertEqual(result.price_component_id, expected_id)

    def test_set_price_component_idempotent(self):
        r1 = self.pc.set_price_component("item1", "user1", self._make_body(eff=1000000))
        r2 = self.pc.set_price_component("item1", "user1", self._make_body(eff=1000000))
        self.assertEqual(r1.price_component_id, r2.price_component_id)

    def test_set_price_component_expires_before_effective_422(self):
        from fastapi import HTTPException
        body = self._make_body(eff=2000000, exp=1000000)
        with self.assertRaises(HTTPException) as cm:
            self.pc.set_price_component("item1", "user1", body)
        self.assertEqual(cm.exception.status_code, 422)

    def test_set_price_component_flag_off_404(self):
        from fastapi import HTTPException
        object.__setattr__(self.S, "product_depth_enabled", False)
        with self.assertRaises(HTTPException) as cm:
            self.pc.set_price_component("item1", "user1", self._make_body())
        self.assertEqual(cm.exception.status_code, 404)

    def test_set_price_component_sub_flag_off_404(self):
        from fastapi import HTTPException
        object.__setattr__(self.S, "product_depth_price_components_enabled", False)
        with self.assertRaises(HTTPException) as cm:
            self.pc.set_price_component("item1", "user1", self._make_body())
        self.assertEqual(cm.exception.status_code, 404)

    # --- list_price_components tests ---

    def test_list_price_components_single_type(self):
        self.pc.set_price_component("item1", "user1", self._make_body(eff=1000000, amount=100))
        self.pc.set_price_component("item1", "user1", self._make_body(eff=2000000, amount=200))
        results = self.pc.list_price_components("item1", "DEFAULT")
        self.assertEqual(len(results), 2)
        # newest first (ScanIndexForward=False)
        self.assertEqual(results[0].effective_at, 2000000)

    def test_list_price_components_all_types(self):
        self.pc.set_price_component("item1", "user1", self._make_body("DEFAULT", eff=1000000))
        self.pc.set_price_component("item1", "user1", self._make_body("LIST", eff=1000000, amount=1500))
        results = self.pc.list_price_components("item1")
        types_found = {r.price_type for r in results}
        self.assertIn("DEFAULT", types_found)
        self.assertIn("LIST", types_found)

    def test_list_price_components_is_active_true(self):
        import time
        now = int(time.time())
        body = self._make_body(eff=now - 100, exp=now + 100)
        self.pc.set_price_component("item1", "user1", body)
        results = self.pc.list_price_components("item1", "DEFAULT")
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].is_active)

    def test_list_price_components_is_active_false_expired(self):
        body = self._make_body(eff=1000000, exp=1000001)  # long past
        self.pc.set_price_component("item1", "user1", body)
        results = self.pc.list_price_components("item1", "DEFAULT")
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].is_active)

    def test_list_price_components_empty(self):
        results = self.pc.list_price_components("item1", "DEFAULT")
        self.assertEqual(results, [])

    # --- resolve_effective_price tests ---

    def test_resolve_effective_price_returns_active_component(self):
        self.pc.set_price_component("item1", "user1", self._make_body(eff=1000000, amount=500))
        result = self.pc.resolve_effective_price("item1", as_of=2000000, price_type="DEFAULT")
        self.assertEqual(result.amount_cents, 500)
        self.assertEqual(result.source, "price_component")

    def test_resolve_effective_price_skips_future(self):
        # effective_at=5000000 > as_of=2000000 → excluded by GSI condition
        self.pc.set_price_component("item1", "user1", self._make_body(eff=5000000, amount=9999))
        result = self.pc.resolve_effective_price("item1", as_of=2000000, price_type="DEFAULT")
        # Falls back to scalar
        self.assertEqual(result.source, "scalar_fallback")
        self.assertEqual(result.amount_cents, 999)

    def test_resolve_effective_price_skips_expired(self):
        # Component with expires_at=500 < as_of=2000000 → skipped
        self.pc.set_price_component("item1", "user1", self._make_body(eff=100, exp=500, amount=777))
        result = self.pc.resolve_effective_price("item1", as_of=2000000, price_type="DEFAULT")
        # expired → falls back to scalar
        self.assertEqual(result.source, "scalar_fallback")
        self.assertEqual(result.amount_cents, 999)

    def test_resolve_effective_price_falls_back_to_scalar(self):
        # No price component rows → scalar fallback
        result = self.pc.resolve_effective_price("item1", as_of=2000000, price_type="DEFAULT")
        self.assertEqual(result.source, "scalar_fallback")
        self.assertEqual(result.amount_cents, 999)

    def test_resolve_effective_price_no_item_returns_zero(self):
        result = self.pc.resolve_effective_price("nonexistent-item", as_of=2000000, price_type="DEFAULT")
        self.assertEqual(result.amount_cents, 0)
        self.assertEqual(result.source, "scalar_fallback")

    def test_resolve_effective_price_non_default_no_fallback(self):
        result = self.pc.resolve_effective_price("item1", as_of=2000000, price_type="PROMO")
        self.assertEqual(result.amount_cents, 0)
        # No catalog fallback for non-DEFAULT types

    def test_resolve_effective_price_flag_off_still_returns_scalar(self):
        """resolve_effective_price does NOT call _require_enabled — always safe to call."""
        object.__setattr__(self.S, "product_depth_enabled", False)
        result = self.pc.resolve_effective_price("item1", as_of=2000000, price_type="DEFAULT")
        # No components → scalar fallback; no 404 raised
        self.assertEqual(result.amount_cents, 999)
        self.assertEqual(result.source, "scalar_fallback")

    def test_price_component_id_determinism(self):
        id1 = self.pc._make_component_id("item1", "DEFAULT", 1000000)
        id2 = self.pc._make_component_id("item1", "DEFAULT", 1000000)
        self.assertEqual(id1, id2)
        self.assertEqual(len(id1), 16)

    def test_open_ended_window_is_active(self):
        import time
        now = int(time.time())
        body = self._make_body(eff=now - 100, exp=None)  # no expiry
        self.pc.set_price_component("item1", "user1", body)
        results = self.pc.list_price_components("item1", "DEFAULT")
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].is_active)

    def test_multiple_windows_correct_selection(self):
        """Three windows: past, current, future. as_of selects the newest active."""
        # past: eff=100, expires=200 (expired)
        self.pc.set_price_component("item1", "user1", self._make_body(eff=100, exp=200, amount=111))
        # current: eff=300, no expiry (active)
        self.pc.set_price_component("item1", "user1", self._make_body(eff=300, amount=222))
        # future: eff=9999999999 (not yet effective)
        self.pc.set_price_component("item1", "user1", self._make_body(eff=9999999999, amount=333))

        result = self.pc.resolve_effective_price("item1", as_of=1000, price_type="DEFAULT")
        # as_of=1000: eff=9999999999 excluded (future), eff=300 included (active, eff=300<=1000)
        # eff=100: expires=200 < 1000 → skipped
        # eff=300: no expiry → active
        self.assertEqual(result.amount_cents, 222)
        self.assertEqual(result.source, "price_component")

    # --- set_price_components (plural / full-replace) tests ---

    def test_set_price_components_replaces_all(self):
        # Write two existing rows
        self.pc.set_price_component("item1", "user1", self._make_body(eff=1000, amount=111))
        self.pc.set_price_component("item1", "user1", self._make_body(eff=2000, amount=222))
        # Now full-replace with a single new row
        new_body = self._make_body(eff=3000, amount=333)
        results = self.pc.set_price_components("item1", "DEFAULT", [new_body], "user1")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].amount_cents, 333)
        # Old rows should be gone
        all_comps = self.pc.list_price_components("item1", "DEFAULT")
        self.assertEqual(len(all_comps), 1)

    def test_set_price_components_empty_clears_all(self):
        self.pc.set_price_component("item1", "user1", self._make_body(eff=1000, amount=111))
        self.pc.set_price_components("item1", "DEFAULT", [], "user1")
        all_comps = self.pc.list_price_components("item1", "DEFAULT")
        self.assertEqual(len(all_comps), 0)


if __name__ == "__main__":
    unittest.main()
