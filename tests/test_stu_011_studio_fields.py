"""STU-011: Studio custom fields — offline hermetic tests."""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import boto3
import pytest

try:
    from moto import mock_aws
except Exception:
    mock_aws = None


def _make_fields_table(ddb):
    return ddb.create_table(
        TableName="crm_studio_fields_test",
        KeySchema=[
            {"AttributeName": "entity_type", "KeyType": "HASH"},
            {"AttributeName": "field_key", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "entity_type", "AttributeType": "S"},
            {"AttributeName": "field_key", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@pytest.fixture(autouse=True)
def moto_ddb():
    if mock_aws is None:
        pytest.skip("moto not available")
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = _make_fields_table(ddb)
        from app.core import tables as _tables_mod
        from app.core import settings as _settings_mod
        object.__setattr__(_tables_mod.T, "crm_studio_fields", table)
        object.__setattr__(_settings_mod.S, "crm_studio_enabled", True)
        # Clear field cache
        import app.services.crm_studio_fields as svc
        svc._field_cache.clear()
        svc._field_cache_ts.clear()
        yield table
        object.__setattr__(_settings_mod.S, "crm_studio_enabled", False)
        svc._field_cache.clear()
        svc._field_cache_ts.clear()


@pytest.fixture(autouse=True)
def patch_audit():
    with patch("app.services.alerts.audit_event", return_value=None):
        yield


class TestCreateField:
    def test_create_field_success(self):
        from app.services import crm_studio_fields as svc
        result = svc.create_field("root_sub", "contact", "custom_region", "Region", "text")
        assert result["field_key"] == "custom_region"
        assert result["is_active"] is True
        assert result["field_type"] == "text"
        assert result["created_by_sub"] == "root_sub"

    def test_create_field_duplicate(self):
        from app.services import crm_studio_fields as svc
        from app.services.crm_studio_fields import FieldAlreadyExistsError
        svc.create_field("root_sub", "contact", "custom_region", "Region", "text")
        with pytest.raises(FieldAlreadyExistsError):
            svc.create_field("root_sub", "contact", "custom_region", "Region2", "text")

    def test_create_field_invalid_entity_type(self):
        from app.services import crm_studio_fields as svc
        with pytest.raises(ValueError, match="invalid_entity_type"):
            svc.create_field("root_sub", "foobar", "custom_x", "X", "text")

    def test_create_field_invalid_field_key_short(self):
        from app.services import crm_studio_fields as svc
        with pytest.raises(ValueError, match="invalid_field_key"):
            svc.create_field("root_sub", "contact", "ab", "AB", "text")

    def test_create_field_invalid_field_key_upper(self):
        from app.services import crm_studio_fields as svc
        with pytest.raises(ValueError, match="invalid_field_key"):
            svc.create_field("root_sub", "contact", "UPPER", "Upper", "text")

    def test_create_field_invalid_field_key_starts_digit(self):
        from app.services import crm_studio_fields as svc
        with pytest.raises(ValueError, match="invalid_field_key"):
            svc.create_field("root_sub", "contact", "1abc", "Abc", "text")

    def test_create_field_picklist_missing_picklist_name(self):
        from app.services import crm_studio_fields as svc
        with pytest.raises(ValueError, match="picklist_name_required"):
            svc.create_field("root_sub", "contact", "custom_tier", "Tier", "picklist")


class TestListGetField:
    def test_list_fields_active_only(self):
        from app.services import crm_studio_fields as svc
        svc.create_field("root_sub", "contact", "custom_region", "Region", "text")
        svc.create_field("root_sub", "contact", "custom_score", "Score", "integer")
        svc.delete_field("root_sub", "contact", "custom_score")
        svc._field_cache.clear()
        items, _ = svc.list_fields("contact", include_inactive=False)
        keys = {i["field_key"] for i in items}
        assert "custom_region" in keys
        assert "custom_score" not in keys

    def test_list_fields_include_inactive(self):
        from app.services import crm_studio_fields as svc
        svc.create_field("root_sub", "contact", "custom_region", "Region", "text")
        svc.create_field("root_sub", "contact", "custom_score", "Score", "integer")
        svc.delete_field("root_sub", "contact", "custom_score")
        svc._field_cache.clear()
        items, _ = svc.list_fields("contact", include_inactive=True)
        keys = {i["field_key"] for i in items}
        assert "custom_region" in keys
        assert "custom_score" in keys

    def test_get_field_found(self):
        from app.services import crm_studio_fields as svc
        svc.create_field("root_sub", "contact", "custom_region", "Region", "text")
        item = svc.get_field("contact", "custom_region")
        assert item is not None
        assert item["label"] == "Region"

    def test_get_field_not_found(self):
        from app.services import crm_studio_fields as svc
        assert svc.get_field("contact", "nonexistent") is None


class TestUpdateField:
    def test_update_field_label(self):
        from app.services import crm_studio_fields as svc
        svc.create_field("root_sub", "contact", "custom_region", "Old Label", "text")
        svc._field_cache.clear()
        updated = svc.update_field("root_sub", "contact", "custom_region", label="New Label")
        assert updated["label"] == "New Label"
        assert updated["field_type"] == "text"  # unchanged

    def test_update_field_not_found(self):
        from app.services.crm_studio_fields import FieldNotFoundError
        from app.services import crm_studio_fields as svc
        with pytest.raises(FieldNotFoundError):
            svc.update_field("root_sub", "contact", "nonexistent_field", label="X")


class TestDeleteField:
    def test_delete_field_soft(self):
        from app.services import crm_studio_fields as svc
        svc.create_field("root_sub", "contact", "custom_region", "Region", "text")
        svc.delete_field("root_sub", "contact", "custom_region")
        svc._field_cache.clear()
        items, _ = svc.list_fields("contact", include_inactive=False)
        keys = {i["field_key"] for i in items}
        assert "custom_region" not in keys
        # Still exists with is_active=False
        item = svc.get_field("contact", "custom_region")
        assert item is not None
        assert item.get("is_active") is False


class TestValidateCustomFields:
    def test_validate_type_mismatch(self):
        from app.services import crm_studio_fields as svc
        from app.services.crm_studio_fields import CustomFieldValidationError
        svc.create_field("root_sub", "contact", "custom_region", "Region", "text", required=True)
        svc._field_cache.clear()
        with pytest.raises(CustomFieldValidationError):
            svc.validate_custom_fields("contact", {"custom_region": 123})

    def test_validate_required_missing(self):
        from app.services import crm_studio_fields as svc
        from app.services.crm_studio_fields import CustomFieldValidationError
        svc.create_field("root_sub", "contact", "custom_region", "Region", "text", required=True)
        svc._field_cache.clear()
        with pytest.raises(CustomFieldValidationError):
            svc.validate_custom_fields("contact", {})

    def test_validate_unknown_custom_key(self):
        from app.services import crm_studio_fields as svc
        from app.services.crm_studio_fields import CustomFieldValidationError
        with pytest.raises(CustomFieldValidationError):
            svc.validate_custom_fields("ticket", {"custom_foo": "bar"})

    def test_validate_default_applied(self):
        from app.services import crm_studio_fields as svc
        svc.create_field("root_sub", "contact", "custom_score", "Score", "integer",
                         required=False, default_value=0)
        svc._field_cache.clear()
        result = svc.validate_custom_fields("contact", {})
        assert result.get("custom_score") == 0

    def test_validate_flag_off_passthrough(self):
        from app.core.settings import S
        from app.services import crm_studio_fields as svc
        object.__setattr__(S, "crm_studio_enabled", False)
        # Should return unchanged dict, no DDB access
        result = svc.validate_custom_fields("contact", {"custom_region": 123})
        assert result == {"custom_region": 123}

    def test_validate_date_field_valid(self):
        from app.services import crm_studio_fields as svc
        svc.create_field("root_sub", "contact", "custom_due", "Due", "date")
        svc._field_cache.clear()
        result = svc.validate_custom_fields("contact", {"custom_due": "2025-12-31"})
        assert result["custom_due"] == "2025-12-31"

    def test_validate_date_field_invalid(self):
        from app.services import crm_studio_fields as svc
        from app.services.crm_studio_fields import CustomFieldValidationError
        svc.create_field("root_sub", "contact", "custom_due", "Due", "date")
        svc._field_cache.clear()
        with pytest.raises(CustomFieldValidationError):
            svc.validate_custom_fields("contact", {"custom_due": "not-a-date"})

    def test_validate_integer_bounds_valid(self):
        from app.services import crm_studio_fields as svc
        svc.create_field("root_sub", "contact", "custom_score", "Score", "integer",
                         min_value=1, max_value=10)
        svc._field_cache.clear()
        result = svc.validate_custom_fields("contact", {"custom_score": 5})
        assert result["custom_score"] == 5

    def test_validate_integer_below_min(self):
        from app.services import crm_studio_fields as svc
        from app.services.crm_studio_fields import CustomFieldValidationError
        svc.create_field("root_sub", "contact", "custom_score", "Score", "integer",
                         min_value=1, max_value=10)
        svc._field_cache.clear()
        with pytest.raises(CustomFieldValidationError):
            svc.validate_custom_fields("contact", {"custom_score": 0})

    def test_validate_integer_above_max(self):
        from app.services import crm_studio_fields as svc
        from app.services.crm_studio_fields import CustomFieldValidationError
        svc.create_field("root_sub", "contact", "custom_score", "Score", "integer",
                         min_value=1, max_value=10)
        svc._field_cache.clear()
        with pytest.raises(CustomFieldValidationError):
            svc.validate_custom_fields("contact", {"custom_score": 11})


class TestMaxFieldLimit:
    def test_max_field_count_limit(self):
        from app.core.settings import S
        from app.services import crm_studio_fields as svc
        from fastapi import HTTPException
        object.__setattr__(S, "crm_studio_max_fields_per_entity", 2)
        svc.create_field("root_sub", "contact", "custom_aaa", "A", "text")
        svc.create_field("root_sub", "contact", "custom_bbb", "B", "text")
        svc._field_cache.clear()
        with pytest.raises(HTTPException) as exc:
            svc.create_field("root_sub", "contact", "custom_ccc", "C", "text")
        assert exc.value.status_code == 409
        object.__setattr__(S, "crm_studio_max_fields_per_entity", 200)


class TestAuditEvents:
    def test_audit_events_emitted(self):
        from app.services import crm_studio_fields as svc

        with patch("app.services.alerts.audit_event") as mock_audit:
            svc.create_field("root_sub", "contact", "custom_region", "Region", "text")
            calls_create = [c.args[0] for c in mock_audit.call_args_list]
            assert "studio.field.created" in calls_create

        with patch("app.services.alerts.audit_event") as mock_audit:
            svc.update_field("root_sub", "contact", "custom_region", label="New")
            calls_update = [c.args[0] for c in mock_audit.call_args_list]
            assert "studio.field.updated" in calls_update

        with patch("app.services.alerts.audit_event") as mock_audit:
            svc.delete_field("root_sub", "contact", "custom_region")
            calls_delete = [c.args[0] for c in mock_audit.call_args_list]
            assert "studio.field.deactivated" in calls_delete


class TestCacheInvalidation:
    def test_cache_invalidation_on_create(self):
        from app.services import crm_studio_fields as svc
        # Warm cache (empty)
        svc._field_cache["contact"] = []
        svc._field_cache_ts["contact"] = 99999999999
        svc.create_field("root_sub", "contact", "custom_region", "Region", "text")
        # Cache should be cleared
        assert "contact" not in svc._field_cache
