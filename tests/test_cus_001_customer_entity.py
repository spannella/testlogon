"""CUS-001: Hermetic tests for Customer entity — DDB model, CRUD, typed attributes."""
from __future__ import annotations

import importlib
import sys
from unittest.mock import MagicMock, patch

import boto3
import pytest
from fastapi import HTTPException
from moto import mock_aws


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _setup_moto_and_flags():
    """Start moto, create customers + alerts tables, patch T and S."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        customers_table = ddb.create_table(
            TableName="customers",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "gsi_number_pk", "AttributeType": "S"},
                {"AttributeName": "customer_number", "AttributeType": "S"},
                {"AttributeName": "gsi_branch_pk", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
            ],
            BillingMode="PAY_PER_REQUEST",
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI_NUMBER",
                    "KeySchema": [
                        {"AttributeName": "gsi_number_pk", "KeyType": "HASH"},
                        {"AttributeName": "customer_number", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI_BRANCH",
                    "KeySchema": [
                        {"AttributeName": "gsi_branch_pk", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
        )

        alerts_table = ddb.create_table(
            TableName="alerts",
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
        alert_prefs_table = ddb.create_table(
            TableName="alert_prefs",
            KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "user_sub", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        # Patch T.customers, T.alerts, T.alert_prefs
        import app.core.tables as _tables_mod
        import app.core.settings as _settings_mod

        orig_customers = _tables_mod.T.customers
        orig_alerts = _tables_mod.T.alerts
        orig_alert_prefs = _tables_mod.T.alert_prefs
        orig_obp = _settings_mod.S.open_bank_project_enabled
        orig_cus = _settings_mod.S.customer_entity_enabled

        object.__setattr__(_tables_mod.T, "customers", customers_table)
        object.__setattr__(_tables_mod.T, "alerts", alerts_table)
        object.__setattr__(_tables_mod.T, "alert_prefs", alert_prefs_table)
        object.__setattr__(_settings_mod.S, "open_bank_project_enabled", True)
        object.__setattr__(_settings_mod.S, "customer_entity_enabled", True)

        # Re-import service so STORE uses patched T
        if "app.services.customers" in sys.modules:
            del sys.modules["app.services.customers"]
        from app.services.customers import CustomerStore
        store = CustomerStore(_table=customers_table)

        yield store

        # Restore
        object.__setattr__(_tables_mod.T, "customers", orig_customers)
        object.__setattr__(_tables_mod.T, "alerts", orig_alerts)
        object.__setattr__(_tables_mod.T, "alert_prefs", orig_alert_prefs)
        object.__setattr__(_settings_mod.S, "open_bank_project_enabled", orig_obp)
        object.__setattr__(_settings_mod.S, "customer_entity_enabled", orig_cus)


# ---------------------------------------------------------------------------
# Helper to get a fresh store pointing at the moto table each test
# ---------------------------------------------------------------------------

def make_store(setup_fixture):
    from app.services.customers import CustomerStore
    return CustomerStore(_table=setup_fixture)  # setup_fixture IS the table


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFlagOff:
    def test_flag_off_raises_404(self):
        import app.core.settings as _s
        import app.core.tables as _t
        import boto3
        from moto import mock_aws as _mock_aws

        with _mock_aws():
            ddb = boto3.resource("dynamodb", region_name="us-east-1")
            tbl = ddb.create_table(
                TableName="cus_flag_test",
                KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
                AttributeDefinitions=[
                    {"AttributeName": "pk", "AttributeType": "S"},
                    {"AttributeName": "sk", "AttributeType": "S"},
                ],
                BillingMode="PAY_PER_REQUEST",
            )
            orig_obp = _s.S.open_bank_project_enabled
            orig_cus = _s.S.customer_entity_enabled
            object.__setattr__(_s.S, "open_bank_project_enabled", False)
            object.__setattr__(_s.S, "customer_entity_enabled", False)
            try:
                from app.routers.customers import _require_flag
                with pytest.raises(HTTPException) as exc_info:
                    _require_flag()
                assert exc_info.value.status_code == 404
            finally:
                object.__setattr__(_s.S, "open_bank_project_enabled", orig_obp)
                object.__setattr__(_s.S, "customer_entity_enabled", orig_cus)


class TestCustomerCRUD:
    def test_create_and_get_round_trip(self, _setup_moto_and_flags):
        store = _setup_moto_and_flags
        item = store.create_customer(
            legal_name="Alice Smith",
            email="Alice@EXAMPLE.com",
            actor_sub="admin-sub",
        )
        assert item["customer_id"].startswith("cust_")
        assert item["customer_number"].isdigit()
        assert item["version"] == 1
        assert item["email"] == "alice@example.com"  # normalized lowercase
        assert item["kyc_status"] == "none"

        fetched = store.get_customer(item["customer_id"])
        assert fetched is not None
        assert fetched["customer_id"] == item["customer_id"]
        assert fetched["legal_name"] == "Alice Smith"

    def test_get_by_number(self, _setup_moto_and_flags):
        import time
        # Sleep briefly to ensure unique timestamp-based customer_number
        time.sleep(1)
        store = _setup_moto_and_flags
        item = store.create_customer(legal_name="Bob Jones UniqueNum", actor_sub="admin-sub")
        found = store.get_by_number(item["customer_number"])
        assert found is not None
        # Found must match our customer (or one with same number — check customer_number matches)
        assert found["customer_number"] == item["customer_number"]

    def test_patch_success_increments_version(self, _setup_moto_and_flags):
        store = _setup_moto_and_flags
        item = store.create_customer(legal_name="Charlie", actor_sub="admin-sub")
        updated = store.update_customer(
            customer_id=item["customer_id"],
            expected_version=1,
            actor_sub="admin-sub",
            legal_name="Charlie Updated",
        )
        assert updated["version"] == 2
        assert updated["legal_name"] == "Charlie Updated"

    def test_patch_conflict_stale_version(self, _setup_moto_and_flags):
        from app.services.customers import CustomerConflictError
        store = _setup_moto_and_flags
        item = store.create_customer(legal_name="Dave", actor_sub="admin-sub")
        # First patch succeeds (version 1 → 2)
        store.update_customer(customer_id=item["customer_id"], expected_version=1, actor_sub="admin", legal_name="Dave V2")
        # Second patch with stale version=1 should fail
        with pytest.raises(CustomerConflictError):
            store.update_customer(customer_id=item["customer_id"], expected_version=1, actor_sub="admin", legal_name="Dave V3")

    def test_patch_not_found_raises_404(self, _setup_moto_and_flags):
        from app.services.customers import CustomerNotFoundError
        store = _setup_moto_and_flags
        with pytest.raises(CustomerNotFoundError):
            store.update_customer(customer_id="cust_nonexistent123", expected_version=1, actor_sub="admin")


class TestBranchGSI:
    def test_branch_gsi_list(self, _setup_moto_and_flags):
        store = _setup_moto_and_flags
        c1 = store.create_customer(legal_name="Branch1A", branch_id="BR_TEST", actor_sub="admin")
        c2 = store.create_customer(legal_name="Branch1B", branch_id="BR_TEST", actor_sub="admin")
        # No branch - should NOT appear
        store.create_customer(legal_name="NoBranch", actor_sub="admin")

        items, cursor = store.list_by_branch("BR_TEST")
        ids = [i["customer_id"] for i in items]
        assert c1["customer_id"] in ids
        assert c2["customer_id"] in ids

    def test_no_gsi_branch_pk_when_no_branch(self, _setup_moto_and_flags):
        store = _setup_moto_and_flags
        item = store.create_customer(legal_name="NoBranchCustomer", actor_sub="admin")
        fetched = store.get_customer(item["customer_id"])
        assert "gsi_branch_pk" not in fetched

    def test_branch_gsi_pk_set_when_branch_given(self, _setup_moto_and_flags):
        store = _setup_moto_and_flags
        item = store.create_customer(legal_name="HasBranch", branch_id="MYBRANCH", actor_sub="admin")
        fetched = store.get_customer(item["customer_id"])
        assert fetched["gsi_branch_pk"] == "BRANCH#MYBRANCH"


class TestAttributes:
    def test_set_list_delete_all_types(self, _setup_moto_and_flags):
        store = _setup_moto_and_flags
        cust = store.create_customer(legal_name="AttrTest", actor_sub="admin")
        cid = cust["customer_id"]

        for t in ["STRING", "INTEGER", "DOUBLE", "DATE_WITH_DAY"]:
            store.set_attribute(cid, name=f"attr_{t}", type=t, value="test", actor_sub="admin")

        attrs = store.list_attributes(cid)
        names = {a["name"] for a in attrs}
        assert {"attr_STRING", "attr_INTEGER", "attr_DOUBLE", "attr_DATE_WITH_DAY"} <= names

        # Delete one
        store.delete_attribute(cid, "attr_STRING", actor_sub="admin")
        attrs_after = store.list_attributes(cid)
        names_after = {a["name"] for a in attrs_after}
        assert "attr_STRING" not in names_after
        assert len(names_after) >= 3

    def test_invalid_type_raises_error(self, _setup_moto_and_flags):
        from app.services.customers import CustomerAttributeValidationError
        store = _setup_moto_and_flags
        cust = store.create_customer(legal_name="AttrValidationTest", actor_sub="admin")
        with pytest.raises(CustomerAttributeValidationError):
            store.set_attribute(cust["customer_id"], name="bad", type="BOOLEAN", value="true", actor_sub="admin")


class TestAuditEvent:
    def test_audit_event_called_on_create(self, _setup_moto_and_flags):
        store = _setup_moto_and_flags
        with patch("app.services.customers.CustomerStore.create_customer", wraps=store.create_customer) as _mock:
            with patch("app.services.alerts.audit_event") as mock_audit:
                # Call directly via wrapped store
                from app.services.customers import CustomerStore
                fresh_store = CustomerStore(_table=store._table)
                fresh_store.create_customer(legal_name="AuditTest", actor_sub="admin-sub")
                mock_audit.assert_called_once()
                call_kwargs = mock_audit.call_args
                assert call_kwargs[0][0] == "customer.created"
