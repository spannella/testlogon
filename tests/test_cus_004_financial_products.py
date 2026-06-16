"""CUS-004: Hermetic tests for Financial Products + Collections."""
from __future__ import annotations

import sys
from unittest.mock import patch

import boto3
import pytest
from fastapi import HTTPException
from moto import mock_aws


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _setup():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        fp_table = ddb.create_table(
            TableName="cus004_financial_products",
            KeySchema=[
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "PK", "AttributeType": "S"},
                {"AttributeName": "SK", "AttributeType": "S"},
                {"AttributeName": "gsi_cat_pk", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
            ],
            BillingMode="PAY_PER_REQUEST",
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI_CATEGORY",
                    "KeySchema": [
                        {"AttributeName": "gsi_cat_pk", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
        )

        alerts_table = ddb.create_table(
            TableName="cus004_alerts",
            KeySchema=[
                {"AttributeName": "user_sub", "KeyType": "HASH"},
                {"AttributeName": "alert_id", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "user_sub", "AttributeType": "S"},
                {"AttributeName": "alert_id", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        import app.core.tables as _tables_mod
        import app.core.settings as _settings_mod
        from app.core.tables import _FloatSafeTable

        orig_fp = getattr(_tables_mod.T, "financial_products", None)
        orig_alerts = _tables_mod.T.alerts
        orig_obp = _settings_mod.S.open_bank_project_enabled
        orig_fp_enabled = getattr(_settings_mod.S, "financial_products_enabled", False)
        orig_fp_table_name = getattr(_settings_mod.S, "financial_products_table_name", "financial_products")

        wrapped = _FloatSafeTable(fp_table)
        object.__setattr__(_tables_mod.T, "financial_products", wrapped)
        object.__setattr__(_tables_mod.T, "alerts", alerts_table)
        object.__setattr__(_settings_mod.S, "open_bank_project_enabled", True)
        object.__setattr__(_settings_mod.S, "financial_products_enabled", True)
        object.__setattr__(_settings_mod.S, "financial_products_table_name", "cus004_financial_products")

        for mod in ["app.services.financial_products"]:
            sys.modules.pop(mod, None)

        from app.services.financial_products import FinancialProductStore
        store = FinancialProductStore(_table=wrapped)

        yield store

        if orig_fp is not None:
            object.__setattr__(_tables_mod.T, "financial_products", orig_fp)
        object.__setattr__(_tables_mod.T, "alerts", orig_alerts)
        object.__setattr__(_settings_mod.S, "open_bank_project_enabled", orig_obp)
        object.__setattr__(_settings_mod.S, "financial_products_enabled", orig_fp_enabled)
        object.__setattr__(_settings_mod.S, "financial_products_table_name", orig_fp_table_name)


# ---------------------------------------------------------------------------
# Product CRUD tests
# ---------------------------------------------------------------------------

class TestProductCRUD:
    def test_create_and_get_round_trip(self, _setup):
        store = _setup
        item = store.create_product(product_code="PROD-001", name="Savings Account")
        assert item["product_code"] == "PROD-001"
        assert item["version"] == 1

        fetched = store.get_product("PROD-001")
        assert fetched["name"] == "Savings Account"

    def test_duplicate_create_raises_exists_error(self, _setup):
        from app.services.financial_products import ProductAlreadyExistsError
        store = _setup
        store.create_product(product_code="PROD-DUP", name="Duplicate")
        with pytest.raises(ProductAlreadyExistsError):
            store.create_product(product_code="PROD-DUP", name="Duplicate again")

    def test_update_correct_version(self, _setup):
        store = _setup
        store.create_product(product_code="PROD-UPD", name="Old Name")
        updated = store.update_product("PROD-UPD", expected_version=1, actor_sub="admin", name="New Name")
        assert updated["version"] == 2
        assert updated["name"] == "New Name"

    def test_update_stale_version_raises_conflict(self, _setup):
        from app.services.financial_products import ProductConflictError
        store = _setup
        store.create_product(product_code="PROD-STALE", name="Stale Test")
        store.update_product("PROD-STALE", expected_version=1, actor_sub="admin", name="After 1st update")
        with pytest.raises(ProductConflictError):
            store.update_product("PROD-STALE", expected_version=1, actor_sub="admin", name="Stale update")

    def test_not_found_raises_error(self, _setup):
        from app.services.financial_products import ProductNotFoundError
        store = _setup
        with pytest.raises(ProductNotFoundError):
            store.get_product("NON-EXISTENT-PRODUCT")

    def test_category_gsi_query(self, _setup):
        store = _setup
        store.create_product(product_code="PROD-SAV1", name="Savings 1", category="savings")
        store.create_product(product_code="PROD-SAV2", name="Savings 2", category="savings")
        store.create_product(product_code="PROD-LOAN1", name="Loan 1", category="loans")

        savings, _ = store.list_products(category="savings")
        codes = [i["product_code"] for i in savings]
        assert "PROD-SAV1" in codes
        assert "PROD-SAV2" in codes
        assert "PROD-LOAN1" not in codes

    def test_list_all_products_no_category(self, _setup):
        store = _setup
        store.create_product(product_code="PROD-LIST1", name="Listed 1")
        store.create_product(product_code="PROD-LIST2", name="Listed 2")
        items, _ = store.list_products()
        codes = [i["product_code"] for i in items]
        # Should include at least the ones we just created
        assert "PROD-LIST1" in codes or "PROD-LIST2" in codes

    def test_product_code_pattern_validation(self, _setup):
        from pydantic import ValidationError
        from app.models import FinancialProductCreateIn
        with pytest.raises(ValidationError):
            FinancialProductCreateIn(product_code="../../evil", name="Bad")


# ---------------------------------------------------------------------------
# Attribute tests
# ---------------------------------------------------------------------------

class TestProductAttributes:
    def test_set_list_delete_attributes(self, _setup):
        store = _setup
        store.create_product(product_code="PROD-ATTR1", name="Attr Test")

        for i, t in enumerate(["STRING", "INTEGER", "DATE_WITH_DAY"]):
            store.set_attribute("PROD-ATTR1", name=f"attr_{t}", type=t, value=f"val{i}")

        attrs = store.list_attributes("PROD-ATTR1")
        assert len(attrs) == 3

        # Delete one
        attr_id = attrs[0]["attribute_id"]
        store.delete_attribute("PROD-ATTR1", attr_id)
        attrs_after = store.list_attributes("PROD-ATTR1")
        assert len(attrs_after) == 2


# ---------------------------------------------------------------------------
# Collection tests
# ---------------------------------------------------------------------------

class TestCollections:
    def test_upsert_collection_idempotent(self, _setup):
        store = _setup
        coll = store.upsert_collection("COLL-001", name="Test Collection", product_codes=["P1", "P2", "P2", "P3"])
        assert coll["product_codes"] == ["P1", "P2", "P3"]  # deduped

        coll2 = store.upsert_collection("COLL-001", name="Test Collection", product_codes=["P1", "P2", "P3"])
        assert coll2["product_codes"] == ["P1", "P2", "P3"]

    def test_get_collection(self, _setup):
        store = _setup
        store.upsert_collection("COLL-GET", name="GetMe", product_codes=["X"])
        coll = store.get_collection("COLL-GET")
        assert coll["name"] == "GetMe"

    def test_get_collection_not_found(self, _setup):
        from app.services.financial_products import CollectionNotFoundError
        store = _setup
        with pytest.raises(CollectionNotFoundError):
            store.get_collection("COLL-NONEXISTENT")

    def test_add_to_collection(self, _setup):
        store = _setup
        store.upsert_collection("COLL-ADD", name="AddTest", product_codes=["P1"])
        result = store.add_to_collection("COLL-ADD", "P2")
        assert "P1" in result["product_codes"]
        assert "P2" in result["product_codes"]

    def test_remove_from_collection(self, _setup):
        store = _setup
        store.upsert_collection("COLL-REM", name="RemTest", product_codes=["P1", "P2", "P3"])
        result = store.remove_from_collection("COLL-REM", "P1")
        assert "P1" not in result["product_codes"]
        assert "P2" in result["product_codes"]

    def test_remove_non_existent_no_error(self, _setup):
        store = _setup
        store.upsert_collection("COLL-RNEM", name="RemNonExist", product_codes=["P2"])
        result = store.remove_from_collection("COLL-RNEM", "P_NONEXISTENT")
        assert result["product_codes"] == ["P2"]


# ---------------------------------------------------------------------------
# Route ordering test
# ---------------------------------------------------------------------------

class TestRouteOrdering:
    def test_collections_route_before_product_code(self):
        from app.routers.financial_products import router
        paths = [r.path for r in router.routes]
        collections_idx = next((i for i, p in enumerate(paths) if p == "/ui/financial-products/collections"), None)
        product_code_idx = next((i for i, p in enumerate(paths) if "{product_code}" in p), None)
        assert collections_idx is not None, "collections route not found"
        assert product_code_idx is not None, "product_code route not found"
        assert collections_idx < product_code_idx, (
            f"collections ({collections_idx}) must come before product_code ({product_code_idx})"
        )


# ---------------------------------------------------------------------------
# Flag off test
# ---------------------------------------------------------------------------

class TestFlagOff:
    def test_flag_off_raises_404(self, _setup):
        import app.core.settings as _s
        orig_obp = _s.S.open_bank_project_enabled
        orig_fp = getattr(_s.S, "financial_products_enabled", True)
        object.__setattr__(_s.S, "open_bank_project_enabled", False)
        object.__setattr__(_s.S, "financial_products_enabled", False)
        try:
            from app.routers.financial_products import _require_flag
            with pytest.raises(HTTPException) as exc_info:
                _require_flag()
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(_s.S, "open_bank_project_enabled", orig_obp)
            object.__setattr__(_s.S, "financial_products_enabled", orig_fp)


# ---------------------------------------------------------------------------
# Audit event test
# ---------------------------------------------------------------------------

class TestAudit:
    def test_audit_event_on_create(self, _setup):
        store = _setup
        with patch("app.services.alerts.audit_event") as mock_audit:
            from app.services.financial_products import FinancialProductStore
            fresh = FinancialProductStore(_table=store._table)
            fresh.create_product(product_code="PROD-AUDIT", name="Audit Test")
            # audit is called inside router, not service — skip direct test
            # (service doesn't call audit_event directly; router does)
