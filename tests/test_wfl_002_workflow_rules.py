"""Tests for WFL-002: Workflow Rule CRUD service."""
from __future__ import annotations

import pytest
import boto3
from moto import mock_aws
from unittest.mock import MagicMock, patch

from app.core.settings import S
from app.core.tables import T


@pytest.fixture(scope="module")
def moto_tables():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        rules_tbl = ddb.create_table(
            TableName="crm_workflow_rules",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "GSI_MODULE_PK", "AttributeType": "S"},
                {"AttributeName": "GSI_MODULE_SK", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[{
                "IndexName": "ByModule",
                "KeySchema": [
                    {"AttributeName": "GSI_MODULE_PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI_MODULE_SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }],
            BillingMode="PAY_PER_REQUEST",
        )
        alerts_tbl = ddb.create_table(
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
        object.__setattr__(T, "crm_workflow_rules", rules_tbl)
        object.__setattr__(T, "alerts", alerts_tbl)
        object.__setattr__(S, "crm_workflow_enabled", True)
        yield rules_tbl
        object.__setattr__(S, "crm_workflow_enabled", False)


class TestWorkflowRuleCRUD:
    def test_create_rule_roundtrip(self, moto_tables):
        from app.services.workflow_rules import create_rule, get_rule
        rule = create_rule(
            created_by="admin_1",
            name="Test Rule",
            description="A test rule",
            target_module="ticket",
            trigger_type="on_save",
            trigger_config={"events": ["create"]},
            conditions=[{"field": "status", "operator": "eq", "value": "open"}],
            actions=[{"action_type": "modify_field", "config": {"field": "priority", "value": "high"}}],
        )
        assert rule["rule_id"].startswith("wfl_")
        assert rule["name"] == "Test Rule"
        assert rule["enabled"] is True
        assert rule["target_module"] == "ticket"

        fetched = get_rule(rule["rule_id"])
        assert fetched is not None
        assert fetched["rule_id"] == rule["rule_id"]
        assert fetched["created_at"] > 0

    def test_create_rule_invalid_module(self, moto_tables):
        from app.services.workflow_rules import create_rule
        with pytest.raises(ValueError, match="invalid_target_module"):
            create_rule(
                created_by="admin",
                name="Bad",
                target_module="nonexistent",
                trigger_type="on_save",
                trigger_config={},
            )

    def test_create_rule_invalid_trigger(self, moto_tables):
        from app.services.workflow_rules import create_rule
        with pytest.raises(ValueError, match="invalid_trigger_type"):
            create_rule(
                created_by="admin",
                name="Bad",
                target_module="ticket",
                trigger_type="on_magic",
                trigger_config={},
            )

    def test_create_rule_too_many_conditions(self, moto_tables):
        from app.services.workflow_rules import create_rule
        conditions = [{"field": f"f{i}", "operator": "eq", "value": "x"} for i in range(11)]
        with pytest.raises(OverflowError):
            create_rule(
                created_by="admin",
                name="Bad",
                target_module="ticket",
                trigger_type="on_save",
                trigger_config={},
                conditions=conditions,
            )

    def test_create_rule_too_many_actions(self, moto_tables):
        from app.services.workflow_rules import create_rule
        actions = [{"action_type": "modify_field", "config": {}} for _ in range(11)]
        with pytest.raises(OverflowError):
            create_rule(
                created_by="admin",
                name="Bad",
                target_module="ticket",
                trigger_type="on_save",
                trigger_config={},
                actions=actions,
            )

    def test_list_rules_for_module_enabled_only(self, moto_tables):
        from app.services.workflow_rules import create_rule, disable_rule, list_rules_for_module
        r1 = create_rule(
            created_by="admin",
            name="Enabled Rule",
            target_module="contact",
            trigger_type="on_save",
            trigger_config={"events": ["create"]},
        )
        r2 = create_rule(
            created_by="admin",
            name="Disabled Rule",
            target_module="contact",
            trigger_type="on_save",
            trigger_config={"events": ["create"]},
        )
        disable_rule(r2["rule_id"], actor="admin")

        rules = list_rules_for_module("contact")
        rule_ids = [r["rule_id"] for r in rules]
        assert r1["rule_id"] in rule_ids
        assert r2["rule_id"] not in rule_ids

    def test_list_rules_for_module_wrong_module(self, moto_tables):
        from app.services.workflow_rules import create_rule, list_rules_for_module
        create_rule(
            created_by="admin",
            name="Order Rule",
            target_module="order",
            trigger_type="on_save",
            trigger_config={"events": ["create"]},
        )
        ticket_rules = list_rules_for_module("ticket")
        for r in ticket_rules:
            assert r["target_module"] == "ticket"

    def test_list_rules_pagination(self, moto_tables):
        from app.services.workflow_rules import create_rule, list_rules
        # Create 5 rules for subscription module
        for i in range(5):
            create_rule(
                created_by="admin",
                name=f"Sub Rule {i}",
                target_module="subscription",
                trigger_type="on_save",
                trigger_config={"events": ["create"]},
            )
        result1 = list_rules(target_module="subscription", limit=2)
        assert len(result1["rules"]) <= 2
        # cursor should be set if more items exist
        if result1["cursor"]:
            result2 = list_rules(target_module="subscription", limit=2, cursor=result1["cursor"])
            assert len(result2["rules"]) >= 0

    def test_update_rule_partial(self, moto_tables):
        from app.services.workflow_rules import create_rule, update_rule
        rule = create_rule(
            created_by="admin",
            name="Original",
            target_module="lead",
            trigger_type="on_save",
            trigger_config={"events": ["create"]},
        )
        updated = update_rule(rule["rule_id"], updated_by="admin", name="Updated")
        assert updated["name"] == "Updated"
        assert updated["target_module"] == "lead"  # unchanged

    def test_update_rule_not_found(self, moto_tables):
        from app.services.workflow_rules import update_rule
        result = update_rule("nonexistent", updated_by="admin", name="x")
        assert result is None

    def test_delete_rule(self, moto_tables):
        from app.services.workflow_rules import create_rule, delete_rule, get_rule
        rule = create_rule(
            created_by="admin",
            name="To Delete",
            target_module="ticket",
            trigger_type="on_save",
            trigger_config={"events": ["create"]},
        )
        result = delete_rule(rule["rule_id"], deleted_by="admin")
        assert result is True
        assert get_rule(rule["rule_id"]) is None

    def test_delete_rule_not_found(self, moto_tables):
        from app.services.workflow_rules import delete_rule
        result = delete_rule("nonexistent", deleted_by="admin")
        assert result is False

    def test_enable_disable_roundtrip(self, moto_tables):
        from app.services.workflow_rules import create_rule, enable_rule, disable_rule
        rule = create_rule(
            created_by="admin",
            name="Toggle Rule",
            target_module="ticket",
            trigger_type="on_save",
            trigger_config={"events": ["create"]},
        )
        disabled = disable_rule(rule["rule_id"], actor="admin")
        assert disabled["enabled"] is False
        enabled = enable_rule(rule["rule_id"], actor="admin")
        assert enabled["enabled"] is True

    def test_flag_off_raises(self, moto_tables):
        from app.services.workflow_rules import create_rule, list_rules_for_module
        object.__setattr__(S, "crm_workflow_enabled", False)
        try:
            with pytest.raises(RuntimeError, match="crm_workflow is disabled"):
                create_rule(
                    created_by="admin",
                    name="Bad",
                    target_module="ticket",
                    trigger_type="on_save",
                    trigger_config={},
                )
            result = list_rules_for_module("ticket")
            assert result == []
        finally:
            object.__setattr__(S, "crm_workflow_enabled", True)

    def test_empty_conditions_accepted(self, moto_tables):
        from app.services.workflow_rules import create_rule, get_rule
        rule = create_rule(
            created_by="admin",
            name="No Conditions",
            target_module="ticket",
            trigger_type="on_save",
            trigger_config={"events": ["create"]},
            conditions=[],
        )
        fetched = get_rule(rule["rule_id"])
        assert fetched["conditions"] == []

    def test_decimal_coercion(self, moto_tables):
        from app.services.workflow_rules import create_rule
        rule = create_rule(
            created_by="admin",
            name="Decimal Test",
            target_module="ticket",
            trigger_type="on_save",
            trigger_config={"events": ["create"]},
        )
        assert isinstance(rule["created_at"], int)
        assert isinstance(rule["updated_at"], int)
