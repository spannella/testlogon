"""Tests for WFL-009: Workflow Admin Router."""
from __future__ import annotations

import asyncio
import pytest
import boto3
from moto import mock_aws
from fastapi import HTTPException
from unittest.mock import patch, MagicMock

from app.core.settings import S
from app.core.tables import T


def _create_all_tables(ddb):
    rules_tbl = ddb.create_table(
        TableName="crm_workflow_rules_router",
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
        TableName="crm_workflow_runs_router",
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
        TableName="alerts_router",
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
    return rules_tbl, runs_tbl, alerts_tbl


@pytest.fixture(autouse=True)
def _setup():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        rules_tbl, runs_tbl, alerts_tbl = _create_all_tables(ddb)
        # Create alert_prefs table too (needed by audit_event -> get_alert_prefs)
        alert_prefs_tbl = ddb.create_table(
            TableName="alert_prefs_router",
            KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "user_sub", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        push_devices_tbl = ddb.create_table(
            TableName="push_devices_router",
            KeySchema=[
                {"AttributeName": "user_sub", "KeyType": "HASH"},
                {"AttributeName": "device_id", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "user_sub", "AttributeType": "S"},
                {"AttributeName": "device_id", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        object.__setattr__(T, "crm_workflow_rules", rules_tbl)
        object.__setattr__(T, "crm_workflow_runs", runs_tbl)
        object.__setattr__(T, "alerts", alerts_tbl)
        object.__setattr__(T, "alert_prefs", alert_prefs_tbl)
        object.__setattr__(T, "push_devices", push_devices_tbl)
        object.__setattr__(S, "crm_workflow_enabled", True)
        yield
        object.__setattr__(S, "crm_workflow_enabled", False)


def _make_actor(sub="admin_test"):
    """Create a mock AuthenticatedUser."""
    actor = MagicMock()
    actor.sub = sub
    return actor


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


VALID_RULE_BODY = {
    "name": "Test Rule",
    "description": "desc",
    "target_module": "ticket",
    "trigger_type": "on_save",
    "trigger_config": {"events": ["create"]},
    "conditions": [],
    "actions": [],
    "enabled": True,
}


class TestFlagGate:
    def test_flag_off_returns_404(self):
        object.__setattr__(S, "crm_workflow_enabled", False)
        from app.routers.workflow_rules import _require_flag
        with pytest.raises(HTTPException) as exc_info:
            _require_flag()
        assert exc_info.value.status_code == 404
        object.__setattr__(S, "crm_workflow_enabled", True)


class TestCreateRule:
    def test_create_rule_success(self):
        from app.routers.workflow_rules import create_workflow_rule
        from app.models import WorkflowRuleCreateIn
        body = WorkflowRuleCreateIn(**VALID_RULE_BODY)
        result = _run_async(create_workflow_rule(body, _actor=_make_actor()))
        assert result.rule_id.startswith("wfl_")
        assert result.name == "Test Rule"
        assert result.enabled is True
        assert result.created_by == "admin_test"

    def test_create_rule_invalid_module(self):
        from app.routers.workflow_rules import create_workflow_rule
        from app.models import WorkflowRuleCreateIn
        body = WorkflowRuleCreateIn(
            name="Bad",
            target_module="invalid_module",
            trigger_type="on_save",
            trigger_config={"events": ["create"]},
        )
        with pytest.raises(HTTPException) as exc_info:
            _run_async(create_workflow_rule(body, _actor=_make_actor()))
        assert exc_info.value.status_code == 422

    def test_create_rule_conditions_overflow(self):
        from app.routers.workflow_rules import create_workflow_rule
        from app.models import WorkflowRuleCreateIn, WorkflowConditionIn
        object.__setattr__(S, "crm_workflow_max_conditions_per_rule", 2)
        try:
            body = WorkflowRuleCreateIn(
                name="Overflow",
                target_module="ticket",
                trigger_type="on_save",
                trigger_config={"events": ["create"]},
                conditions=[
                    WorkflowConditionIn(field=f"f{i}", operator="eq", value="x")
                    for i in range(3)
                ],
            )
            with pytest.raises(HTTPException) as exc_info:
                _run_async(create_workflow_rule(body, _actor=_make_actor()))
            assert exc_info.value.status_code == 507
        finally:
            object.__setattr__(S, "crm_workflow_max_conditions_per_rule", 10)


class TestListRules:
    def test_list_rules_no_filter(self):
        from app.routers.workflow_rules import create_workflow_rule, list_workflow_rules
        from app.models import WorkflowRuleCreateIn
        for i in range(3):
            body = WorkflowRuleCreateIn(name=f"Rule {i}", target_module="ticket",
                                        trigger_type="on_save", trigger_config={"events": ["create"]})
            _run_async(create_workflow_rule(body, _actor=_make_actor()))
        result = _run_async(list_workflow_rules(
            target_module=None, enabled_only=False, limit=25, cursor=None, _actor=_make_actor()
        ))
        assert len(result.rules) >= 3

    def test_list_rules_filter_module(self):
        from app.routers.workflow_rules import create_workflow_rule, list_workflow_rules
        from app.models import WorkflowRuleCreateIn
        _run_async(create_workflow_rule(
            WorkflowRuleCreateIn(name="Contact Rule", target_module="contact",
                                 trigger_type="on_save", trigger_config={"events": ["create"]}),
            _actor=_make_actor(),
        ))
        result = _run_async(list_workflow_rules(
            target_module="contact", enabled_only=False, limit=25, cursor=None, _actor=_make_actor()
        ))
        for rule in result.rules:
            assert rule.target_module == "contact"

    def test_list_rules_enabled_only(self):
        from app.routers.workflow_rules import create_workflow_rule, list_workflow_rules
        from app.models import WorkflowRuleCreateIn
        from app.services.workflow_rules import disable_rule
        r1 = _run_async(create_workflow_rule(
            WorkflowRuleCreateIn(name="Enabled", target_module="lead",
                                 trigger_type="on_save", trigger_config={"events": ["create"]}),
            _actor=_make_actor(),
        ))
        r2 = _run_async(create_workflow_rule(
            WorkflowRuleCreateIn(name="Disabled", target_module="lead",
                                 trigger_type="on_save", trigger_config={"events": ["create"]}),
            _actor=_make_actor(),
        ))
        disable_rule(r2.rule_id, actor="admin")
        result = _run_async(list_workflow_rules(
            target_module="lead", enabled_only=True, limit=25, cursor=None, _actor=_make_actor()
        ))
        rule_ids = [r.rule_id for r in result.rules]
        assert r1.rule_id in rule_ids
        assert r2.rule_id not in rule_ids


class TestGetRule:
    def test_get_rule_not_found(self):
        from app.routers.workflow_rules import get_workflow_rule
        with pytest.raises(HTTPException) as exc_info:
            _run_async(get_workflow_rule("nonexistent", _actor=_make_actor()))
        assert exc_info.value.status_code == 404


class TestPatchRule:
    def test_patch_rule_partial(self):
        from app.routers.workflow_rules import create_workflow_rule, update_workflow_rule
        from app.models import WorkflowRuleCreateIn, WorkflowRuleUpdateIn
        rule = _run_async(create_workflow_rule(
            WorkflowRuleCreateIn(name="Original", target_module="ticket",
                                 trigger_type="on_save", trigger_config={"events": ["create"]}),
            _actor=_make_actor(),
        ))
        updated = _run_async(update_workflow_rule(
            rule.rule_id,
            WorkflowRuleUpdateIn(name="Updated"),
            _actor=_make_actor(),
        ))
        assert updated.name == "Updated"
        assert updated.target_module == "ticket"

    def test_patch_rule_no_fields(self):
        from app.routers.workflow_rules import create_workflow_rule, update_workflow_rule
        from app.models import WorkflowRuleCreateIn, WorkflowRuleUpdateIn
        rule = _run_async(create_workflow_rule(
            WorkflowRuleCreateIn(name="R", target_module="ticket",
                                 trigger_type="on_save", trigger_config={"events": ["create"]}),
            _actor=_make_actor(),
        ))
        with pytest.raises(HTTPException) as exc_info:
            _run_async(update_workflow_rule(rule.rule_id, WorkflowRuleUpdateIn(), _actor=_make_actor()))
        assert exc_info.value.status_code == 422


class TestDeleteRule:
    def test_delete_rule_idempotent(self):
        from app.routers.workflow_rules import create_workflow_rule, delete_workflow_rule
        from app.models import WorkflowRuleCreateIn
        rule = _run_async(create_workflow_rule(
            WorkflowRuleCreateIn(name="Del", target_module="ticket",
                                 trigger_type="on_save", trigger_config={"events": ["create"]}),
            _actor=_make_actor(),
        ))
        r1 = _run_async(delete_workflow_rule(rule.rule_id, _actor=_make_actor()))
        assert r1 == {"ok": True}
        r2 = _run_async(delete_workflow_rule(rule.rule_id, _actor=_make_actor()))
        assert r2 == {"ok": True}


class TestEnableDisableRule:
    def test_enable_disable_rule(self):
        from app.routers.workflow_rules import create_workflow_rule, enable_workflow_rule, disable_workflow_rule
        from app.models import WorkflowRuleCreateIn
        rule = _run_async(create_workflow_rule(
            WorkflowRuleCreateIn(name="Toggle", target_module="ticket",
                                 trigger_type="on_save", trigger_config={"events": ["create"]}),
            _actor=_make_actor(),
        ))
        disabled = _run_async(disable_workflow_rule(rule.rule_id, _actor=_make_actor()))
        assert disabled.enabled is False
        enabled = _run_async(enable_workflow_rule(rule.rule_id, _actor=_make_actor()))
        assert enabled.enabled is True


class TestListRuns:
    def test_list_runs_empty(self):
        from app.routers.workflow_rules import create_workflow_rule, list_rule_runs
        from app.models import WorkflowRuleCreateIn
        rule = _run_async(create_workflow_rule(
            WorkflowRuleCreateIn(name="RunsRule", target_module="ticket",
                                 trigger_type="on_save", trigger_config={"events": ["create"]}),
            _actor=_make_actor(),
        ))
        result = _run_async(list_rule_runs(rule.rule_id, limit=25, cursor=None, _actor=_make_actor()))
        assert result.runs == []
        assert result.cursor is None

    def test_list_runs_newest_first(self):
        from app.routers.workflow_rules import create_workflow_rule, list_rule_runs
        from app.models import WorkflowRuleCreateIn
        from app.core.time import now_ts
        rule = _run_async(create_workflow_rule(
            WorkflowRuleCreateIn(name="RunsRuleSort", target_module="ticket",
                                 trigger_type="on_save", trigger_config={"events": ["create"]}),
            _actor=_make_actor(),
        ))
        # Seed two run rows
        rule_id = rule.rule_id
        ts1, ts2 = now_ts() - 1000, now_ts()
        T.crm_workflow_runs.put_item(Item={
            "pk": f"RULE#{rule_id}",
            "sk": f"RUN#{ts1:010d}#run1",
            "run_id": "run1",
            "rule_id": rule_id,
            "target_module": "ticket",
            "record_id": "t1",
            "trigger_type": "on_save",
            "outcome": "matched",
            "actions_fired": [],
            "started_at": ts1,
            "finished_at": ts1 + 1,
            "GSI_RECORD_PK": "ticket#t1",
            "GSI_RECORD_SK": ts1,
        })
        T.crm_workflow_runs.put_item(Item={
            "pk": f"RULE#{rule_id}",
            "sk": f"RUN#{ts2:010d}#run2",
            "run_id": "run2",
            "rule_id": rule_id,
            "target_module": "ticket",
            "record_id": "t2",
            "trigger_type": "on_save",
            "outcome": "matched",
            "actions_fired": [],
            "started_at": ts2,
            "finished_at": ts2 + 1,
            "GSI_RECORD_PK": "ticket#t2",
            "GSI_RECORD_SK": ts2,
        })
        result = _run_async(list_rule_runs(rule_id, limit=25, cursor=None, _actor=_make_actor()))
        assert len(result.runs) == 2
        # Newest first (ts2 > ts1)
        assert result.runs[0].started_at >= result.runs[1].started_at


class TestDripSequenceRoutes:
    def test_create_drip_sequence(self):
        from app.routers.workflow_rules import create_drip_sequence
        from app.models import DripSequenceCreateIn, DripStageIn
        body = DripSequenceCreateIn(
            name="Welcome",
            stages=[DripStageIn(stage_number=1, delay_hours=24, template_id="t1", to_field="email")],
        )
        result = _run_async(create_drip_sequence(body, _actor=_make_actor()))
        assert result.sequence_id.startswith("drip_")
        assert result.name == "Welcome"

    def test_delete_drip_sequence(self):
        from app.routers.workflow_rules import create_drip_sequence, delete_drip_sequence, get_drip_sequence
        from app.models import DripSequenceCreateIn, DripStageIn
        body = DripSequenceCreateIn(
            name="ToDel",
            stages=[DripStageIn(stage_number=1, delay_hours=0, template_id="t1", to_field="email")],
        )
        seq = _run_async(create_drip_sequence(body, _actor=_make_actor()))
        r = _run_async(delete_drip_sequence(seq.sequence_id, _actor=_make_actor()))
        assert r == {"ok": True}
        with pytest.raises(HTTPException) as exc_info:
            _run_async(get_drip_sequence(seq.sequence_id, _actor=_make_actor()))
        assert exc_info.value.status_code == 404

    def test_list_drip_sequences(self):
        from app.routers.workflow_rules import create_drip_sequence, list_drip_sequences
        from app.models import DripSequenceCreateIn, DripStageIn
        for i in range(3):
            body = DripSequenceCreateIn(
                name=f"Seq {i}",
                stages=[DripStageIn(stage_number=1, delay_hours=i, template_id=f"t{i}", to_field="email")],
            )
            _run_async(create_drip_sequence(body, _actor=_make_actor()))
        result = _run_async(list_drip_sequences(limit=25, cursor=None, _actor=_make_actor()))
        assert len(result.sequences) >= 3
