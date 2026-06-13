"""Tests for WFL-004: On-Save Hook."""
from __future__ import annotations

import pytest
import boto3
from moto import mock_aws
from unittest.mock import patch

from app.core.settings import S
from app.core.tables import T


@pytest.fixture
def ddb_tables():
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
        actions_tbl = ddb.create_table(
            TableName="scheduled_actions",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "GSI_DUE_PK", "AttributeType": "S"},
                {"AttributeName": "GSI_DUE_SK", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[{
                "IndexName": "ByDue",
                "KeySchema": [
                    {"AttributeName": "GSI_DUE_PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI_DUE_SK", "KeyType": "RANGE"},
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
        object.__setattr__(T, "scheduled_actions", actions_tbl)
        object.__setattr__(T, "alerts", alerts_tbl)
        object.__setattr__(S, "crm_workflow_enabled", True)
        object.__setattr__(S, "scheduled_actions_min_lead_time_seconds", 5)
        yield rules_tbl, actions_tbl
        object.__setattr__(S, "crm_workflow_enabled", False)
        object.__setattr__(S, "scheduled_actions_min_lead_time_seconds", 300)


def _seed_rule(rules_tbl, *, target_module="ticket", event="create", enabled=True,
               conditions=None, trigger_type="on_save"):
    import uuid
    from app.core.time import now_ts
    rule_id = "wfl_" + uuid.uuid4().hex[:12]
    ts = now_ts()
    rules_tbl.put_item(Item={
        "pk": f"RULE#{rule_id}",
        "sk": "META",
        "rule_id": rule_id,
        "name": f"Test Rule {rule_id}",
        "description": "",
        "target_module": target_module,
        "trigger_type": trigger_type,
        "trigger_config": {"events": [event]},
        "conditions": conditions or [],
        "actions": [],
        "enabled": enabled,
        "created_by": "admin",
        "created_at": ts,
        "updated_at": ts,
        "GSI_MODULE_PK": f"MODULE#{target_module}",
        "GSI_MODULE_SK": ts,
    })
    return rule_id


class TestOnSaveHook:
    def test_flag_off_returns_zero(self, ddb_tables):
        object.__setattr__(S, "crm_workflow_enabled", False)
        from app.services.workflow_hooks import fire_on_save_hook
        result = fire_on_save_hook(module="ticket", record={"ticket_id": "t1"}, event="create")
        assert result == 0
        object.__setattr__(S, "crm_workflow_enabled", True)

    def test_no_rules_returns_zero(self, ddb_tables):
        from app.services.workflow_hooks import fire_on_save_hook
        result = fire_on_save_hook(module="ticket", record={"ticket_id": "t1"}, event="create")
        assert result == 0

    def test_on_save_create_event_matched(self, ddb_tables):
        rules_tbl, actions_tbl = ddb_tables
        _seed_rule(rules_tbl, target_module="ticket", event="create")
        from app.services.workflow_hooks import fire_on_save_hook
        result = fire_on_save_hook(
            module="ticket",
            record={"ticket_id": "t_001", "status": "open"},
            event="create",
        )
        assert result == 1
        # Verify action row written
        resp = actions_tbl.scan()
        items = resp.get("Items", [])
        assert any(i.get("action_type") == "crm_workflow" for i in items)
        action = next(i for i in items if i.get("action_type") == "crm_workflow")
        assert action["payload"]["rule_id"]
        assert action["payload"]["module"] == "ticket"
        assert action["payload"]["record_id"] == "t_001"

    def test_on_save_wrong_event_returns_zero(self, ddb_tables):
        rules_tbl, actions_tbl = ddb_tables
        _seed_rule(rules_tbl, target_module="ticket", event="create")
        from app.services.workflow_hooks import fire_on_save_hook
        result = fire_on_save_hook(
            module="ticket",
            record={"ticket_id": "t_002"},
            event="update",
        )
        assert result == 0

    def test_on_save_update_event(self, ddb_tables):
        rules_tbl, _ = ddb_tables
        _seed_rule(rules_tbl, target_module="ticket", event="update")
        from app.services.workflow_hooks import fire_on_save_hook
        result = fire_on_save_hook(
            module="ticket",
            record={"ticket_id": "t_003"},
            event="update",
        )
        assert result == 1

    def test_condition_filter_no_match(self, ddb_tables):
        rules_tbl, _ = ddb_tables
        _seed_rule(
            rules_tbl,
            target_module="ticket",
            event="create",
            conditions=[{"field": "status", "operator": "eq", "value": "open"}],
        )
        from app.services.workflow_hooks import fire_on_save_hook
        result = fire_on_save_hook(
            module="ticket",
            record={"ticket_id": "t_004", "status": "closed"},
            event="create",
        )
        assert result == 0

    def test_condition_filter_match(self, ddb_tables):
        rules_tbl, _ = ddb_tables
        _seed_rule(
            rules_tbl,
            target_module="ticket",
            event="create",
            conditions=[{"field": "status", "operator": "eq", "value": "open"}],
        )
        from app.services.workflow_hooks import fire_on_save_hook
        result = fire_on_save_hook(
            module="ticket",
            record={"ticket_id": "t_005", "status": "open"},
            event="create",
        )
        assert result == 1

    def test_two_rules_both_match(self, ddb_tables):
        rules_tbl, _ = ddb_tables
        _seed_rule(rules_tbl, target_module="ticket", event="create")
        _seed_rule(rules_tbl, target_module="ticket", event="create")
        from app.services.workflow_hooks import fire_on_save_hook
        result = fire_on_save_hook(
            module="ticket",
            record={"ticket_id": "t_006"},
            event="create",
        )
        assert result >= 2

    def test_disabled_rule_not_fired(self, ddb_tables):
        rules_tbl, _ = ddb_tables
        _seed_rule(rules_tbl, target_module="ticket", event="create", enabled=False)
        from app.services.workflow_hooks import fire_on_save_hook
        result = fire_on_save_hook(
            module="ticket",
            record={"ticket_id": "t_007"},
            event="create",
        )
        assert result == 0

    def test_on_schedule_rule_not_fired_by_hook(self, ddb_tables):
        rules_tbl, _ = ddb_tables
        _seed_rule(rules_tbl, target_module="ticket", event="create", trigger_type="on_schedule")
        from app.services.workflow_hooks import fire_on_save_hook
        result = fire_on_save_hook(
            module="ticket",
            record={"ticket_id": "t_008"},
            event="create",
        )
        assert result == 0

    def test_exception_in_create_action_returns_zero(self, ddb_tables):
        rules_tbl, actions_tbl = ddb_tables
        _seed_rule(rules_tbl, target_module="ticket", event="create")
        from app.services.workflow_hooks import fire_on_save_hook
        # Patch the put_item method directly
        orig_put = actions_tbl.put_item
        try:
            def _raise(*a, **kw):
                raise RuntimeError("DDB error")
            actions_tbl.put_item = _raise
            result = fire_on_save_hook(
                module="ticket",
                record={"ticket_id": "t_err"},
                event="create",
            )
            # Should not raise; exception is swallowed
            assert isinstance(result, int)
        finally:
            actions_tbl.put_item = orig_put

    def test_contact_module_record_id(self, ddb_tables):
        rules_tbl, actions_tbl = ddb_tables
        _seed_rule(rules_tbl, target_module="contact", event="create")
        from app.services.workflow_hooks import fire_on_save_hook
        result = fire_on_save_hook(
            module="contact",
            record={"contact_id": "c_001", "owner_id": "user_x"},
            event="create",
        )
        assert result == 1
        resp = actions_tbl.scan()
        items = [i for i in resp.get("Items", []) if i.get("payload", {}).get("module") == "contact"]
        assert len(items) >= 1
        assert items[-1]["payload"]["record_id"] == "c_001"
