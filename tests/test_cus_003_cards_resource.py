"""CUS-003: Hermetic tests for Cards as a managed resource."""
from __future__ import annotations

import sys
from decimal import Decimal
from unittest.mock import MagicMock, patch

import boto3
import pytest
from fastapi import HTTPException
from moto import mock_aws


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _moto_billing():
    """Create billing + alerts tables with moto; patch T and S."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        billing_table = ddb.create_table(
            TableName="cus003_billing",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        alerts_table = ddb.create_table(
            TableName="cus003_alerts",
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

        orig_billing = _tables_mod.T.billing
        orig_alerts = _tables_mod.T.alerts
        orig_obp = _settings_mod.S.open_bank_project_enabled
        orig_cus = _settings_mod.S.customer_entity_enabled

        wrapped_billing = _FloatSafeTable(billing_table)
        object.__setattr__(_tables_mod.T, "billing", wrapped_billing)
        object.__setattr__(_tables_mod.T, "alerts", alerts_table)
        object.__setattr__(_settings_mod.S, "open_bank_project_enabled", True)
        object.__setattr__(_settings_mod.S, "customer_entity_enabled", True)

        for mod in ["app.services.cards_resource"]:
            sys.modules.pop(mod, None)

        from app.services.cards_resource import CardResourceStore
        store = CardResourceStore(_table=wrapped_billing)

        yield store, billing_table, wrapped_billing

        object.__setattr__(_tables_mod.T, "billing", orig_billing)
        object.__setattr__(_tables_mod.T, "alerts", orig_alerts)
        object.__setattr__(_settings_mod.S, "open_bank_project_enabled", orig_obp)
        object.__setattr__(_settings_mod.S, "customer_entity_enabled", orig_cus)


def _seed_pm(billing_table, user_sub: str, pm_id: str, method_type: str = "card", **extra):
    """Seed a PM# row directly into the billing table."""
    item = {
        "pk": f"USER#{user_sub}",
        "sk": f"PM#{pm_id}",
        "payment_method_id": pm_id,
        "method_type": method_type,
        "provider": "stripe",
        "brand": "visa",
        "last4": "4242",
        "exp_month": 12,
        "exp_year": 2030,
        "label": "Visa •••• 4242",
        "created_at": 1700000000,
    }
    item.update(extra)
    billing_table.put_item(Item=item)
    return item


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestListCards:
    def test_list_cards_empty(self, _moto_billing):
        store, billing_table, wrapped = _moto_billing
        with patch("app.routers.billing.list_payment_methods_ddb", return_value=[]):
            with patch("app.routers.billing.current_default_pm", return_value=None):
                cards = store.list_cards("user-empty")
                assert cards == []

    def test_list_cards_one_card_no_status_field(self, _moto_billing):
        store, billing_table, wrapped = _moto_billing
        pm = _seed_pm(billing_table, "user-card1", "pm-001")
        with patch("app.routers.billing.list_payment_methods_ddb", return_value=[pm]):
            with patch("app.routers.billing.current_default_pm", return_value=None):
                cards = store.list_cards("user-card1")
        assert len(cards) == 1
        assert cards[0]["card_status"] == "ACTIVE"
        assert cards[0]["card_version"] == 1
        assert cards[0]["is_default"] is False

    def test_list_cards_excludes_bank_accounts(self, _moto_billing):
        store, billing_table, wrapped = _moto_billing
        bank_pm = _seed_pm(billing_table, "user-bank", "pm-bank", method_type="us_bank_account")
        card_pm = _seed_pm(billing_table, "user-bank", "pm-card")
        with patch("app.routers.billing.list_payment_methods_ddb", return_value=[bank_pm, card_pm]):
            with patch("app.routers.billing.current_default_pm", return_value=None):
                cards = store.list_cards("user-bank")
        card_ids = [c["card_id"] for c in cards]
        assert "pm-bank" not in card_ids
        assert "pm-card" in card_ids


class TestStampNewCard:
    def test_stamp_new_card_writes_fields(self, _moto_billing):
        store, billing_table, wrapped = _moto_billing
        user_sub = "user-stamp"
        pm_id = "pm-stamp-001"
        _seed_pm(billing_table, user_sub, pm_id)

        with patch("app.services.alerts.audit_event"):
            store.stamp_new_card(user_sub, pm_id, actor_sub="admin-sub")

        item = billing_table.get_item(Key={"pk": f"USER#{user_sub}", "sk": f"PM#{pm_id}"})["Item"]
        assert item["card_status"] == "ACTIVE"
        assert int(item["card_version"]) == 1


class TestStatusLifecycle:
    def _seed_with_status(self, billing_table, user_sub, pm_id, status="ACTIVE", version=1):
        pm = _seed_pm(billing_table, user_sub, pm_id)
        billing_table.update_item(
            Key={"pk": f"USER#{user_sub}", "sk": f"PM#{pm_id}"},
            UpdateExpression="SET card_status = :s, card_version = :v",
            ExpressionAttributeValues={":s": status, ":v": version},
        )
        return pm

    def test_active_to_frozen(self, _moto_billing):
        store, billing_table, wrapped = _moto_billing
        self._seed_with_status(billing_table, "user-lc1", "pm-lc1")
        with patch("app.routers.billing.current_default_pm", return_value=None):
            with patch("app.services.alerts.audit_event"):
                with patch("app.routers.billing.list_payment_methods_ddb", return_value=[]):
                    result = store.set_card_status("user-lc1", "pm-lc1", "FROZEN", expected_version=1, actor_sub="admin")
        assert result["card_status"] == "FROZEN"

    def test_active_to_inactive(self, _moto_billing):
        store, billing_table, wrapped = _moto_billing
        self._seed_with_status(billing_table, "user-lc2", "pm-lc2")
        with patch("app.routers.billing.current_default_pm", return_value=None):
            with patch("app.services.alerts.audit_event"):
                with patch("app.routers.billing.list_payment_methods_ddb", return_value=[]):
                    result = store.set_card_status("user-lc2", "pm-lc2", "INACTIVE", expected_version=1, actor_sub="admin")
        assert result["card_status"] == "INACTIVE"

    def test_cancelled_to_active_is_illegal(self, _moto_billing):
        from app.services.cards_resource import CardIllegalTransitionError
        store, billing_table, wrapped = _moto_billing
        self._seed_with_status(billing_table, "user-lc3", "pm-lc3", status="CANCELLED", version=3)
        with pytest.raises(CardIllegalTransitionError):
            store.set_card_status("user-lc3", "pm-lc3", "ACTIVE", expected_version=3, actor_sub="admin")

    def test_stale_version_raises_conflict(self, _moto_billing):
        from app.services.cards_resource import CardConflictError
        store, billing_table, wrapped = _moto_billing
        self._seed_with_status(billing_table, "user-lc4", "pm-lc4", version=2)
        with pytest.raises(CardConflictError):
            store.set_card_status("user-lc4", "pm-lc4", "FROZEN", expected_version=1, actor_sub="admin")

    def test_not_found_raises_error(self, _moto_billing):
        from app.services.cards_resource import CardNotFoundError
        store, billing_table, wrapped = _moto_billing
        with pytest.raises(CardNotFoundError):
            store.set_card_status("user-lc5", "pm-nonexistent", "FROZEN", expected_version=1, actor_sub="admin")

    def test_non_chargeable_clears_default(self, _moto_billing):
        store, billing_table, wrapped = _moto_billing
        self._seed_with_status(billing_table, "user-lc6", "pm-lc6")
        # Set up BILLING row with default PM
        billing_table.put_item(Item={"pk": "USER#user-lc6", "sk": "BILLING", "default_payment_method_id": "pm-lc6"})

        with patch("app.routers.billing.list_payment_methods_ddb", return_value=[]):
            with patch("app.services.alerts.audit_event"):
                store.set_card_status("user-lc6", "pm-lc6", "FROZEN", expected_version=1, actor_sub="admin")

        billing_row = billing_table.get_item(Key={"pk": "USER#user-lc6", "sk": "BILLING"})["Item"]
        assert billing_row.get("default_payment_method_id") is None


class TestAttributes:
    def test_set_and_list_attributes(self, _moto_billing):
        store, billing_table, wrapped = _moto_billing
        user_sub = "user-attr-card"
        card_id = "pm-attr-001"
        _seed_pm(billing_table, user_sub, card_id)

        with patch("app.services.alerts.audit_event"):
            result = store.set_card_attribute(user_sub, card_id, "region", "STRING", "EU", actor_sub="admin")
        assert result["name"] == "region"
        assert result["value"] == "EU"

        attrs = store.list_card_attributes(user_sub, card_id)
        assert any(a["name"] == "region" for a in attrs)

    def test_set_same_name_preserves_attribute_id(self, _moto_billing):
        store, billing_table, wrapped = _moto_billing
        user_sub = "user-attr-stable"
        card_id = "pm-attr-stable-001"
        _seed_pm(billing_table, user_sub, card_id)

        with patch("app.services.alerts.audit_event"):
            r1 = store.set_card_attribute(user_sub, card_id, "spend_limit", "INTEGER", "1000", actor_sub="admin")
            r2 = store.set_card_attribute(user_sub, card_id, "spend_limit", "INTEGER", "2000", actor_sub="admin")
        assert r1["attribute_id"] == r2["attribute_id"]

    def test_delete_card_attribute(self, _moto_billing):
        store, billing_table, wrapped = _moto_billing
        user_sub = "user-attr-del"
        card_id = "pm-attr-del-001"
        _seed_pm(billing_table, user_sub, card_id)

        with patch("app.services.alerts.audit_event"):
            store.set_card_attribute(user_sub, card_id, "to_delete", "STRING", "bye", actor_sub="admin")
            store.delete_card_attribute(user_sub, card_id, "to_delete", actor_sub="admin")
        attrs = store.list_card_attributes(user_sub, card_id)
        assert all(a["name"] != "to_delete" for a in attrs)


class TestFlagOff:
    def test_flag_off_returns_404(self, _moto_billing):
        import app.core.settings as _s
        orig_obp = _s.S.open_bank_project_enabled
        orig_cus = _s.S.customer_entity_enabled
        object.__setattr__(_s.S, "open_bank_project_enabled", False)
        object.__setattr__(_s.S, "customer_entity_enabled", False)
        try:
            from app.routers.cards_resource import _require_flag
            with pytest.raises(HTTPException) as exc_info:
                _require_flag()
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(_s.S, "open_bank_project_enabled", orig_obp)
            object.__setattr__(_s.S, "customer_entity_enabled", orig_cus)
