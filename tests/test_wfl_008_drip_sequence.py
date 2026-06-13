"""Tests for WFL-008: Drip Sequence service."""
from __future__ import annotations

import asyncio
import uuid
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
            TableName="crm_workflow_rules_drip",
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
        actions_tbl = ddb.create_table(
            TableName="scheduled_actions_drip",
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
        alerts_tbl = ddb.create_table(
            TableName="alerts_drip",
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
        object.__setattr__(S, "scheduled_actions_ttl_days", 90)
        object.__setattr__(S, "scheduled_actions_max_retries", 3)
        yield {"rules": rules_tbl, "actions": actions_tbl}
        object.__setattr__(S, "crm_workflow_enabled", False)


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


VALID_STAGES = [
    {"stage_number": 1, "delay_hours": 24, "template_id": "tpl_1", "to_field": "email"},
    {"stage_number": 2, "delay_hours": 48, "template_id": "tpl_2", "to_field": "email"},
]


class TestSequenceCRUD:
    def test_create_sequence_valid(self, ddb_tables):
        from app.services.workflow_drip_sequences import create_sequence
        seq = create_sequence(
            created_by="admin",
            name="Welcome Series",
            stages=VALID_STAGES,
        )
        assert seq["sequence_id"].startswith("drip_")
        assert len(seq["stages"]) == 2
        assert seq["name"] == "Welcome Series"

    def test_create_sequence_empty_stages(self, ddb_tables):
        from app.services.workflow_drip_sequences import create_sequence
        with pytest.raises(ValueError, match="empty"):
            create_sequence(created_by="admin", name="Bad", stages=[])

    def test_create_sequence_nonconsecutive_stages(self, ddb_tables):
        from app.services.workflow_drip_sequences import create_sequence
        with pytest.raises(ValueError, match="contiguous"):
            create_sequence(
                created_by="admin",
                name="Bad",
                stages=[
                    {"stage_number": 1, "delay_hours": 24, "template_id": "t1", "to_field": "email"},
                    {"stage_number": 3, "delay_hours": 48, "template_id": "t2", "to_field": "email"},
                ],
            )

    def test_get_sequence_not_found(self, ddb_tables):
        from app.services.workflow_drip_sequences import get_sequence
        result = get_sequence("nonexistent")
        assert result is None

    def test_update_sequence_name(self, ddb_tables):
        from app.services.workflow_drip_sequences import create_sequence, update_sequence
        seq = create_sequence(created_by="admin", name="Original", stages=VALID_STAGES[:1])
        updated = update_sequence(seq["sequence_id"], updated_by="admin", name="Updated Name")
        assert updated["name"] == "Updated Name"
        assert len(updated["stages"]) == 1  # unchanged

    def test_delete_sequence(self, ddb_tables):
        from app.services.workflow_drip_sequences import create_sequence, delete_sequence, get_sequence
        seq = create_sequence(created_by="admin", name="To Delete", stages=VALID_STAGES[:1])
        result = delete_sequence(seq["sequence_id"], deleted_by="admin")
        assert result is True
        assert get_sequence(seq["sequence_id"]) is None

    def test_list_sequences_pagination(self, ddb_tables):
        from app.services.workflow_drip_sequences import create_sequence, list_sequences
        for i in range(5):
            create_sequence(
                created_by="admin",
                name=f"Sequence {i}",
                stages=VALID_STAGES[:1],
            )
        result = list_sequences(limit=3)
        assert len(result["sequences"]) <= 3


class TestEnrolment:
    def test_enrol_record_first_time(self, ddb_tables):
        from app.services.workflow_drip_sequences import create_sequence, enrol_record, get_enrolment
        seq = create_sequence(created_by="admin", name="S1", stages=VALID_STAGES[:1])
        enrolment = enrol_record(seq["sequence_id"], "ticket", "t_001", enrolled_at=1000)
        assert enrolment["current_stage"] == 0
        assert enrolment["completed"] is False
        assert enrolment["stopped"] is False

        fetched = get_enrolment(seq["sequence_id"], "ticket", "t_001")
        assert fetched is not None
        assert fetched["enrolled_at"] == 1000

    def test_enrol_record_idempotent(self, ddb_tables):
        from app.services.workflow_drip_sequences import create_sequence, enrol_record
        seq = create_sequence(created_by="admin", name="S2", stages=VALID_STAGES[:1])
        r1 = enrol_record(seq["sequence_id"], "ticket", "t_002", enrolled_at=2000)
        r2 = enrol_record(seq["sequence_id"], "ticket", "t_002", enrolled_at=9999)
        # Second call should return the existing row, not overwrite enrolled_at
        assert r2["enrolled_at"] == 2000

    def test_stop_drip_sequence(self, ddb_tables):
        from app.services.workflow_drip_sequences import create_sequence, enrol_record, stop_drip_sequence, get_enrolment
        seq = create_sequence(created_by="admin", name="S3", stages=VALID_STAGES[:1])
        enrol_record(seq["sequence_id"], "ticket", "t_003", enrolled_at=3000)
        result = stop_drip_sequence(seq["sequence_id"], "ticket", "t_003")
        assert result is True
        fetched = get_enrolment(seq["sequence_id"], "ticket", "t_003")
        assert fetched["stopped"] is True

    def test_stop_drip_sequence_missing(self, ddb_tables):
        from app.services.workflow_drip_sequences import stop_drip_sequence
        result = stop_drip_sequence("nonexistent", "ticket", "t_x")
        assert result is False

    def test_advance_enrolment(self, ddb_tables):
        from app.services.workflow_drip_sequences import create_sequence, enrol_record, advance_enrolment, get_enrolment
        seq = create_sequence(created_by="admin", name="S4", stages=VALID_STAGES)
        enrol_record(seq["sequence_id"], "ticket", "t_004", enrolled_at=4000)
        advance_enrolment(seq["sequence_id"], "ticket", "t_004", stage_number=1, now=5000)
        fetched = get_enrolment(seq["sequence_id"], "ticket", "t_004")
        assert fetched["current_stage"] == 1
        assert fetched["last_stage_sent_at"] == 5000

    def test_complete_enrolment(self, ddb_tables):
        from app.services.workflow_drip_sequences import create_sequence, enrol_record, complete_enrolment, get_enrolment
        seq = create_sequence(created_by="admin", name="S5", stages=VALID_STAGES[:1])
        enrol_record(seq["sequence_id"], "ticket", "t_005", enrolled_at=6000)
        complete_enrolment(seq["sequence_id"], "ticket", "t_005", now=7000)
        fetched = get_enrolment(seq["sequence_id"], "ticket", "t_005")
        assert fetched["completed"] is True


class TestExecuteDripSequence:
    def test_drip_sequence_flag_off(self, ddb_tables):
        from app.services.workflow_action_executor import _execute_drip_sequence
        object.__setattr__(S, "crm_workflow_enabled", False)
        result = _run_async(_execute_drip_sequence({"sequence_id": "x"}, module="ticket", record_id="t"))
        assert result["status"] == "skipped"
        assert result["reason"] == "flag_off"
        object.__setattr__(S, "crm_workflow_enabled", True)

    def test_drip_sequence_unknown_sequence(self, ddb_tables):
        from app.services.workflow_action_executor import _execute_drip_sequence
        result = _run_async(_execute_drip_sequence({"sequence_id": "nonexistent"}, module="ticket", record_id="t"))
        assert result["status"] == "skipped"
        assert result["reason"] == "sequence_not_found"

    def test_drip_sequence_enrolls_and_schedules_stage_1(self, ddb_tables):
        from app.services.workflow_drip_sequences import create_sequence
        from app.services.workflow_action_executor import _execute_drip_sequence
        from app.core.time import now_ts

        seq = create_sequence(created_by="admin", name="Welcome", stages=[
            {"stage_number": 1, "delay_hours": 0, "template_id": "tpl_w1", "to_field": "email"},
            {"stage_number": 2, "delay_hours": 24, "template_id": "tpl_w2", "to_field": "email"},
        ])
        result = _run_async(_execute_drip_sequence(
            {"sequence_id": seq["sequence_id"]},
            module="ticket",
            record_id="t_drip_1",
        ))
        assert result["status"] == "enrolled"
        # Check action row written
        resp = ddb_tables["actions"].scan()
        items = [i for i in resp.get("Items", []) if i.get("action_type") == "crm_workflow_drip_stage"]
        assert len(items) >= 1
        assert items[0]["payload"]["stage_number"] == 1

    def test_drip_sequence_already_enrolled(self, ddb_tables):
        from app.services.workflow_drip_sequences import create_sequence, enrol_record, advance_enrolment
        from app.services.workflow_action_executor import _execute_drip_sequence
        from app.core.time import now_ts

        seq = create_sequence(created_by="admin", name="S6", stages=VALID_STAGES)
        now = now_ts()
        enrol_record(seq["sequence_id"], "ticket", "t_already", enrolled_at=now)
        advance_enrolment(seq["sequence_id"], "ticket", "t_already", stage_number=1, now=now + 1)

        result = _run_async(_execute_drip_sequence(
            {"sequence_id": seq["sequence_id"]},
            module="ticket",
            record_id="t_already",
        ))
        assert result["status"] == "already_enrolled"


class TestStagePipelineRegistered:
    def test_drip_stage_in_executors(self):
        from app.services.unified_scheduler import _EXECUTORS
        assert "crm_workflow_drip_stage" in _EXECUTORS
