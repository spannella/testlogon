"""Tests for WFL-006: Action Executor (modify_field, create_record)."""
from __future__ import annotations

import asyncio
import uuid
import pytest
import boto3
from moto import mock_aws
from unittest.mock import patch, MagicMock

from app.core.settings import S
from app.core.tables import T


def _create_tables(ddb):
    rules_tbl = ddb.create_table(
        TableName="crm_workflow_rules_exec",
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
    runs_tbl = ddb.create_table(
        TableName="crm_workflow_runs_exec",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI_RECORD_PK", "AttributeType": "S"},
            {"AttributeName": "GSI_RECORD_SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "ByRecord",
            "KeySchema": [
                {"AttributeName": "GSI_RECORD_PK", "KeyType": "HASH"},
                {"AttributeName": "GSI_RECORD_SK", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )
    alerts_tbl = ddb.create_table(
        TableName="alerts_exec",
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
    tickets_tbl = ddb.create_table(
        TableName="tickets_exec",
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
    contacts_tbl = ddb.create_table(
        TableName="contacts_exec",
        KeySchema=[
            {"AttributeName": "owner_id", "KeyType": "HASH"},
            {"AttributeName": "contact_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "owner_id", "AttributeType": "S"},
            {"AttributeName": "contact_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    return rules_tbl, runs_tbl, alerts_tbl, tickets_tbl, contacts_tbl


@pytest.fixture
def ddb_tables():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        rules_tbl, runs_tbl, alerts_tbl, tickets_tbl, contacts_tbl = _create_tables(ddb)
        object.__setattr__(T, "crm_workflow_rules", rules_tbl)
        object.__setattr__(T, "crm_workflow_runs", runs_tbl)
        object.__setattr__(T, "alerts", alerts_tbl)
        object.__setattr__(T, "tickets", tickets_tbl)
        object.__setattr__(T, "contacts", contacts_tbl)
        object.__setattr__(S, "crm_workflow_enabled", True)
        yield {
            "rules": rules_tbl,
            "runs": runs_tbl,
            "alerts": alerts_tbl,
            "tickets": tickets_tbl,
            "contacts": contacts_tbl,
        }
        object.__setattr__(S, "crm_workflow_enabled", False)


def _seed_rule(rules_tbl, *, module="ticket", trigger_type="on_save", actions=None, enabled=True):
    from app.core.time import now_ts
    rule_id = "wfl_" + uuid.uuid4().hex[:12]
    ts = now_ts()
    rules_tbl.put_item(Item={
        "pk": f"RULE#{rule_id}",
        "sk": "META",
        "rule_id": rule_id,
        "name": "Test Rule",
        "description": "",
        "target_module": module,
        "trigger_type": trigger_type,
        "trigger_config": {},
        "conditions": [],
        "actions": actions or [],
        "enabled": enabled,
        "created_by": "admin",
        "created_at": ts,
        "updated_at": ts,
        "GSI_MODULE_PK": f"MODULE#{module}",
        "GSI_MODULE_SK": ts,
    })
    return rule_id


def _seed_ticket(tickets_tbl, ticket_id, status="open"):
    from app.core.time import now_ts
    ts = now_ts()
    tickets_tbl.put_item(Item={
        "pk": f"TICKET#{ticket_id}",
        "sk": "META",
        "ticket_id": ticket_id,
        "subject": "Test Ticket",
        "description": "desc",
        "status": status,
        "owner_sub": "user_1",
        "created_at": ts,
        "updated_at": ts,
        "version": 1,
        "gsi2pk": f"STATUS#{status}",
        "gsi2sk": f"{ts}#{ticket_id}",
        "gsi3pk": "ASSIGNEE#unassigned",
        "gsi3sk": f"{ts}#{ticket_id}",
        "gsi1sk": f"{ts}#{ticket_id}",
    })


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestExecutorFlagOff:
    def test_flag_off_executor_is_noop(self, ddb_tables):
        object.__setattr__(S, "crm_workflow_enabled", False)
        from app.services.workflow_action_executor import execute_crm_workflow_action
        # Should return without doing anything
        _run_async(execute_crm_workflow_action("system", {"rule_id": "nonexistent"}))
        # No runs written
        resp = ddb_tables["runs"].scan()
        assert len(resp.get("Items", [])) == 0
        object.__setattr__(S, "crm_workflow_enabled", True)


class TestRuleNotFound:
    def test_rule_not_found(self, ddb_tables):
        from app.services.workflow_action_executor import execute_crm_workflow_action
        _run_async(execute_crm_workflow_action("system", {
            "rule_id": "nonexistent",
            "module": "ticket",
            "record_id": "t_1",
        }))
        resp = ddb_tables["runs"].scan()
        assert len(resp.get("Items", [])) == 0

    def test_rule_disabled_after_enqueue(self, ddb_tables):
        from app.services.workflow_action_executor import execute_crm_workflow_action
        rule_id = _seed_rule(ddb_tables["rules"], module="ticket", enabled=False)
        _run_async(execute_crm_workflow_action("system", {
            "rule_id": rule_id,
            "module": "ticket",
            "record_id": "t_2",
        }))
        resp = ddb_tables["runs"].scan()
        assert len(resp.get("Items", [])) == 0


class TestEmptyActions:
    def test_empty_actions_list(self, ddb_tables):
        from app.services.workflow_action_executor import execute_crm_workflow_action
        rule_id = _seed_rule(ddb_tables["rules"], module="ticket", actions=[])
        _run_async(execute_crm_workflow_action("system", {
            "rule_id": rule_id,
            "module": "ticket",
            "record_id": "t_3",
        }))
        resp = ddb_tables["runs"].scan()
        items = resp.get("Items", [])
        assert len(items) == 1
        assert items[0]["outcome"] == "matched"
        assert items[0]["actions_fired"] == []


class TestModifyFieldTicket:
    def test_modify_field_ticket_subject(self, ddb_tables):
        from app.services.workflow_action_executor import _modify_field_ticket
        _seed_ticket(ddb_tables["tickets"], "t_subj")
        result = _modify_field_ticket("t_subj", "subject", "New Subject")
        assert result == "ok"
        # Verify DDB update
        resp = ddb_tables["tickets"].get_item(Key={"pk": "TICKET#t_subj", "sk": "META"})
        assert resp["Item"]["subject"] == "New Subject"

    def test_modify_field_ticket_unsupported_field(self, ddb_tables):
        from app.services.workflow_action_executor import _modify_field_ticket
        _seed_ticket(ddb_tables["tickets"], "t_unsup")
        result = _modify_field_ticket("t_unsup", "created_at", "123")
        assert result == "skipped:unsupported_field"


class TestModifyFieldContact:
    def test_modify_field_contact_is_favorite(self, ddb_tables):
        from app.services.workflow_action_executor import _modify_field_contact
        ddb_tables["contacts"].put_item(Item={
            "owner_id": "user_x",
            "contact_id": "c_001",
            "is_favorite": False,
            "is_blocked": False,
        })
        result = _modify_field_contact("user_x", "c_001", "is_favorite", True)
        assert result == "ok"
        resp = ddb_tables["contacts"].get_item(Key={"owner_id": "user_x", "contact_id": "c_001"})
        assert resp["Item"]["is_favorite"] is True

    def test_modify_field_contact_unsupported(self, ddb_tables):
        from app.services.workflow_action_executor import _modify_field_contact
        ddb_tables["contacts"].put_item(Item={
            "owner_id": "user_y",
            "contact_id": "c_002",
        })
        result = _modify_field_contact("user_y", "c_002", "display_name", "Alice")
        assert result == "skipped:unsupported_contact_field"


class TestCreateRecord:
    def test_create_record_ticket_ok(self, ddb_tables):
        from app.services.workflow_action_executor import _create_record_ticket
        audit_calls = []
        with patch("app.services.alerts.audit_event", side_effect=lambda *a, **k: audit_calls.append(k)):
            result = _create_record_ticket({"subject": "Auto Ticket", "description": ""})
        assert result.startswith("ok:ticket_id=")
        # Verify ticket written to DDB
        resp = ddb_tables["tickets"].scan()
        ticket_items = [i for i in resp.get("Items", []) if i.get("sk") == "META"]
        assert any(i.get("subject") == "Auto Ticket" for i in ticket_items)

    def test_create_record_ticket_missing_subject(self, ddb_tables):
        from app.services.workflow_action_executor import _create_record_ticket
        result = _create_record_ticket({})
        assert result == "skipped:missing_subject"

    def test_create_record_unsupported_module(self, ddb_tables):
        from app.services.workflow_action_executor import _dispatch_create_record
        result = _dispatch_create_record({"module": "order", "fields": {}})
        assert result == "skipped:unsupported_module"


class TestUnknownActionType:
    def test_unknown_action_type_skipped(self, ddb_tables):
        from app.services.workflow_action_executor import _execute_action
        result = _run_async(_execute_action(
            {"action_type": "send_sms", "config": {}},
            module="ticket",
            record_id="t_unk",
            record={},
        ))
        assert result["result"] == "skipped"


class TestRunLogGsiKeys:
    def test_run_log_gsi_keys(self, ddb_tables):
        from app.services.workflow_action_executor import execute_crm_workflow_action
        rule_id = _seed_rule(ddb_tables["rules"], module="ticket", actions=[])
        _run_async(execute_crm_workflow_action("system", {
            "rule_id": rule_id,
            "module": "ticket",
            "record_id": "t_gsi",
        }))
        from boto3.dynamodb.conditions import Key
        resp = ddb_tables["runs"].query(
            IndexName="ByRecord",
            KeyConditionExpression=Key("GSI_RECORD_PK").eq("ticket#t_gsi"),
        )
        assert len(resp["Items"]) == 1


class TestMultiActionRule:
    def test_multi_action_rule_both_fire(self, ddb_tables):
        _seed_ticket(ddb_tables["tickets"], "t_multi", status="open")
        rule_id = _seed_rule(ddb_tables["rules"], module="ticket", actions=[
            {"action_type": "modify_field", "config": {"field": "subject", "value": "Updated"}},
            {"action_type": "modify_field", "config": {"field": "priority", "value": "high"}},
        ])
        from app.services.workflow_action_executor import execute_crm_workflow_action
        with patch("app.services.workflow_action_executor._fetch_record", return_value={"ticket_id": "t_multi", "status": "open"}):
            _run_async(execute_crm_workflow_action("system", {
                "rule_id": rule_id,
                "module": "ticket",
                "record_id": "t_multi",
            }))
        resp = ddb_tables["runs"].scan()
        items = resp.get("Items", [])
        assert len(items) >= 1
        run = items[0]
        assert len(run["actions_fired"]) == 2


class TestExecutorRegistered:
    def test_crm_workflow_in_executors(self):
        from app.services.unified_scheduler import _EXECUTORS
        assert "crm_workflow" in _EXECUTORS
        assert "crm_workflow_drip_stage" in _EXECUTORS
