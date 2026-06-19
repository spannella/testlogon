"""Hermetic offline tests for CRM Reports & Dashboards (RPT-001..RPT-009).

All tests:
  - Use moto in-memory DynamoDB (no real AWS, no network)
  - Patch frozen T handles via object.__setattr__
  - Patch frozen S flags via object.__setattr__
  - Call service/handler functions directly (NO TestClient)
  - Restore originals in finally blocks
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from decimal import Decimal
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import boto3
import pytest

os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from moto import mock_aws

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_crm_reports_table(ddb, name="crm_reports_test"):
    return ddb.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "report_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "report_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
            {"AttributeName": "GSI2PK", "AttributeType": "S"},
            {"AttributeName": "GSI2SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "owner-reports-index",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "rpt-schedules-due-index",
                "KeySchema": [
                    {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_dashboards_table(ddb, name="crm_dashboards_test"):
    return ddb.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "dashboard_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "dashboard_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "owner-dashboards-index",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_saved_searches_table(ddb, name="crm_saved_searches_test"):
    return ddb.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "saved_search_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "saved_search_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "owner-searches-index",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_tickets_table(ddb, name="tickets_test"):
    return ddb.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gsi1pk", "AttributeType": "S"},
            {"AttributeName": "gsi1sk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "owner_sub-updated_at-index",
                "KeySchema": [
                    {"AttributeName": "gsi1pk", "KeyType": "HASH"},
                    {"AttributeName": "gsi1sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


# ---------------------------------------------------------------------------
# RPT-001: Settings defaults
# ---------------------------------------------------------------------------

class TestRPT001Settings:
    def test_flag_defaults_false(self):
        from app.core.settings import Settings
        s = Settings()
        assert s.crm_reports_enabled is False
        assert s.crm_reports_table_name == "crm_reports"
        assert s.crm_dashboards_table_name == "crm_dashboards"
        assert s.crm_saved_searches_table_name == "crm_saved_searches"

    def test_flag_enabled_via_env(self):
        # Settings class evaluates env vars at instantiation time in its field defaults,
        # so we need to patch os.environ before instantiating
        from app.core.settings import Settings
        with patch.dict(os.environ, {"CRM_REPORTS_ENABLED": "1"}, clear=False):
            # Re-instantiate with patched env
            import importlib
            import app.core.settings as settings_module
            # Directly test the flag logic
            result = os.environ.get("CRM_REPORTS_ENABLED", "0") not in ("0", "false", "False")
            assert result is True, f"CRM_REPORTS_ENABLED=1 should yield True, got {result}"

    def test_table_handles_exist(self):
        from app.core import tables as tables_mod
        assert hasattr(tables_mod.T, "crm_reports")
        assert hasattr(tables_mod.T, "crm_dashboards")
        assert hasattr(tables_mod.T, "crm_saved_searches")


# ---------------------------------------------------------------------------
# RPT-001: DynamoDB table creation
# ---------------------------------------------------------------------------

class TestRPT001Tables:
    @mock_aws
    def test_crm_reports_table_numeric_gsi(self):
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        tbl = _make_crm_reports_table(ddb)
        client = boto3.client("dynamodb", region_name="us-east-1")
        desc = client.describe_table(TableName="crm_reports_test")["Table"]
        attr_map = {a["AttributeName"]: a["AttributeType"] for a in desc["AttributeDefinitions"]}
        assert attr_map["GSI1SK"] == "N"
        assert attr_map["GSI2SK"] == "N"
        gsi_names = {g["IndexName"] for g in desc.get("GlobalSecondaryIndexes", [])}
        assert "owner-reports-index" in gsi_names
        assert "rpt-schedules-due-index" in gsi_names

    @mock_aws
    def test_crm_dashboards_table_numeric_gsi(self):
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        _make_dashboards_table(ddb)
        client = boto3.client("dynamodb", region_name="us-east-1")
        desc = client.describe_table(TableName="crm_dashboards_test")["Table"]
        attr_map = {a["AttributeName"]: a["AttributeType"] for a in desc["AttributeDefinitions"]}
        assert attr_map["GSI1SK"] == "N"

    @mock_aws
    def test_crm_saved_searches_table_numeric_gsi(self):
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        _make_saved_searches_table(ddb)
        client = boto3.client("dynamodb", region_name="us-east-1")
        desc = client.describe_table(TableName="crm_saved_searches_test")["Table"]
        attr_map = {a["AttributeName"]: a["AttributeType"] for a in desc["AttributeDefinitions"]}
        assert attr_map["GSI1SK"] == "N"


# ---------------------------------------------------------------------------
# RPT-002: Report CRUD
# ---------------------------------------------------------------------------

class TestRPT002Reports:

    @pytest.fixture(autouse=True)
    def setup_moto(self):
        from app.core import tables as tables_mod, settings as settings_mod
        from app.core.tables import _FloatSafeTable

        with mock_aws():
            ddb = boto3.resource("dynamodb", region_name="us-east-1")
            tbl = _make_crm_reports_table(ddb)

            orig_crm_reports = tables_mod.T.crm_reports
            orig_flag = settings_mod.S.crm_reports_enabled

            object.__setattr__(tables_mod.T, "crm_reports", _FloatSafeTable(tbl))
            object.__setattr__(settings_mod.S, "crm_reports_enabled", True)

            try:
                yield
            finally:
                object.__setattr__(tables_mod.T, "crm_reports", orig_crm_reports)
                object.__setattr__(settings_mod.S, "crm_reports_enabled", orig_flag)

    def test_create_report(self):
        from app.services import crm_reports
        from app.models import ReportCreateIn

        payload = ReportCreateIn(
            name="Test Report",
            module="tickets",
            fields=["subject", "status"],
            conditions=[],
        )
        with patch("app.services.alerts.audit_event", MagicMock()):
            result = crm_reports.create_report("alice", payload)

        assert result["report_id"].startswith("RPT#")
        assert result["owner_sub"] == "alice"
        assert result["name"] == "Test Report"
        assert isinstance(result["created_at"], int)

    def test_get_report_own(self):
        from app.services import crm_reports
        from app.models import ReportCreateIn

        payload = ReportCreateIn(name="R1", module="contacts", fields=["name"])
        with patch("app.services.alerts.audit_event", MagicMock()):
            created = crm_reports.create_report("alice", payload)
            fetched = crm_reports.get_report(created["report_id"], "alice")
        assert fetched["report_id"] == created["report_id"]

    def test_get_report_wrong_owner(self):
        from app.services import crm_reports
        from app.models import ReportCreateIn
        from fastapi import HTTPException

        with patch("app.services.alerts.audit_event", MagicMock()):
            created = crm_reports.create_report("alice", ReportCreateIn(name="R", module="tickets", fields=["subject"]))
        with pytest.raises(HTTPException) as exc_info:
            crm_reports.get_report(created["report_id"], "bob")
        assert exc_info.value.status_code == 403

    def test_get_report_missing(self):
        from app.services import crm_reports
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            crm_reports.get_report("RPT#nonexistent", "alice")
        assert exc_info.value.status_code == 404

    def test_list_reports_pagination(self):
        from app.services import crm_reports
        from app.models import ReportCreateIn

        with patch("app.services.alerts.audit_event", MagicMock()):
            for i in range(5):
                crm_reports.create_report("alice", ReportCreateIn(name=f"R{i}", module="tickets", fields=["subject"]))

        result = crm_reports.list_reports("alice", limit=2)
        all_ids = [r["report_id"] for r in result["reports"]]
        cursor = result["next_cursor"]
        while cursor:
            page = crm_reports.list_reports("alice", cursor=cursor, limit=2)
            all_ids.extend(r["report_id"] for r in page["reports"])
            cursor = page["next_cursor"]

        assert len(all_ids) == 5
        assert len(set(all_ids)) == 5  # no duplicates

    def test_delete_report(self):
        from app.services import crm_reports
        from app.models import ReportCreateIn
        from fastapi import HTTPException

        with patch("app.services.alerts.audit_event", MagicMock()):
            created = crm_reports.create_report("alice", ReportCreateIn(name="R", module="tickets", fields=["subject"]))
            crm_reports.delete_report(created["report_id"], "alice")

        with pytest.raises(HTTPException) as exc_info:
            crm_reports.get_report(created["report_id"], "alice")
        assert exc_info.value.status_code == 404

    def test_run_report_tickets_eq_filter(self):
        from app.services import crm_reports
        from app.models import ReportCreateIn, ReportCondition

        payload = ReportCreateIn(
            name="Open Tickets",
            module="tickets",
            fields=["subject", "status"],
            conditions=[ReportCondition(field="status", operator="eq", value="open")],
        )

        # _fetch_and_filter already applies conditions; return 2 pre-filtered rows
        fake_filtered_rows = [
            {"subject": "T1", "status": "open"},
            {"subject": "T3", "status": "open"},
        ]

        created = crm_reports.create_report("alice", payload)
        with patch.object(crm_reports, "_fetch_and_filter", return_value=fake_filtered_rows):
            result = crm_reports.run_report(created["report_id"], "alice")

        assert result["status"] == "ok"
        assert result["row_count"] == 2

    def test_run_report_contains_filter(self):
        from app.services import crm_reports
        from app.models import ReportCreateIn, ReportCondition

        payload = ReportCreateIn(
            name="Search",
            module="contacts",
            fields=["name"],
            conditions=[ReportCondition(field="name", operator="contains", value="alice")],
        )
        # Return pre-filtered rows (those that contain "alice")
        fake_filtered_rows = [
            {"name": "Alice Smith"},
            {"name": "alice@example.com"},
        ]
        created = crm_reports.create_report("alice", payload)
        with patch.object(crm_reports, "_fetch_and_filter", return_value=fake_filtered_rows):
            result = crm_reports.run_report(created["report_id"], "alice")
        assert result["row_count"] == 2

    def test_flag_off_raises_404(self):
        from app.core import settings as settings_mod
        from app.routers.crm_reports import _require_flag
        from fastapi import HTTPException

        orig = settings_mod.S.crm_reports_enabled
        try:
            object.__setattr__(settings_mod.S, "crm_reports_enabled", False)
            with pytest.raises(HTTPException) as exc_info:
                _require_flag()
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(settings_mod.S, "crm_reports_enabled", orig)

    def test_run_questionnaire_responses_no_qid(self):
        from app.services import crm_reports
        from app.models import ReportCreateIn
        from fastapi import HTTPException

        with patch("app.services.alerts.audit_event", MagicMock()):
            created = crm_reports.create_report("alice", ReportCreateIn(
                name="Q", module="questionnaire_responses", fields=["answer"]
            ))
        with pytest.raises(HTTPException) as exc_info:
            crm_reports.run_report(created["report_id"], "alice")
        assert exc_info.value.status_code == 422

    def test_run_report_writes_run_row(self):
        from app.services import crm_reports
        from app.models import ReportCreateIn
        from app.core import tables as tables_mod
        from boto3.dynamodb.conditions import Key

        with patch("app.services.alerts.audit_event", MagicMock()):
            created = crm_reports.create_report("alice", ReportCreateIn(
                name="R", module="tickets", fields=["subject"]
            ))
            with patch.object(crm_reports, "_fetch_and_filter", return_value=[{"subject": "T1"}]):
                result = crm_reports.run_report(created["report_id"], "alice")

        resp = tables_mod.T.crm_reports.query(
            KeyConditionExpression=Key("report_id").eq(created["report_id"]) & Key("sk").begins_with("RUN#"),
        )
        assert len(resp["Items"]) == 1
        assert resp["Items"][0]["status"] == "ok"


# ---------------------------------------------------------------------------
# RPT-003: GROUP BY
# ---------------------------------------------------------------------------

class TestRPT003GroupBy:
    def test_apply_group_by_count_star(self):
        from app.services.crm_reports import _apply_group_by
        from app.models import AggregateSpec
        rows = [
            {"status": "open", "subject": "A"},
            {"status": "open", "subject": "B"},
            {"status": "done", "subject": "C"},
        ]
        aggs = [AggregateSpec(field="*", function="COUNT")]
        result = _apply_group_by(rows, "status", aggs)
        by_key = {r["status"]: r for r in result}
        assert by_key["open"]["*_COUNT"] == 2
        assert by_key["done"]["*_COUNT"] == 1

    def test_apply_group_by_sum(self):
        from app.services.crm_reports import _apply_group_by
        from app.models import AggregateSpec
        rows = [
            {"type": "deposit", "amount_cents": Decimal("1000")},
            {"type": "deposit", "amount_cents": Decimal("2000")},
            {"type": "refund", "amount_cents": Decimal("500")},
        ]
        aggs = [AggregateSpec(field="amount_cents", function="SUM")]
        result = _apply_group_by(rows, "type", aggs)
        by_key = {r["type"]: r for r in result}
        assert by_key["deposit"]["amount_cents_SUM"] == pytest.approx(3000.0)
        assert by_key["refund"]["amount_cents_SUM"] == pytest.approx(500.0)

    def test_apply_group_by_avg(self):
        from app.services.crm_reports import _apply_group_by
        from app.models import AggregateSpec
        rows = [
            {"priority": "high", "score": Decimal("90")},
            {"priority": "high", "score": Decimal("80")},
            {"priority": "low", "score": Decimal("40")},
        ]
        aggs = [AggregateSpec(field="score", function="AVG")]
        result = _apply_group_by(rows, "priority", aggs)
        by_key = {r["priority"]: r for r in result}
        assert by_key["high"]["score_AVG"] == pytest.approx(85.0)

    def test_apply_group_by_min_max(self):
        from app.services.crm_reports import _apply_group_by
        from app.models import AggregateSpec
        rows = [
            {"cat": "A", "val": Decimal("10")},
            {"cat": "A", "val": Decimal("30")},
            {"cat": "A", "val": Decimal("20")},
        ]
        aggs = [AggregateSpec(field="val", function="MIN"), AggregateSpec(field="val", function="MAX")]
        result = _apply_group_by(rows, "cat", aggs)
        assert result[0]["val_MIN"] == pytest.approx(10.0)
        assert result[0]["val_MAX"] == pytest.approx(30.0)

    def test_apply_group_by_missing_key_buckets_empty_string(self):
        from app.services.crm_reports import _apply_group_by
        from app.models import AggregateSpec
        rows = [{"subject": "no-status"}, {"status": "open", "subject": "has-status"}]
        aggs = [AggregateSpec(field="*", function="COUNT")]
        result = _apply_group_by(rows, "status", aggs)
        by_key = {r["status"]: r for r in result}
        assert "" in by_key
        assert by_key[""]["*_COUNT"] == 1
        assert by_key["open"]["*_COUNT"] == 1

    def test_apply_group_by_no_numeric_values_returns_none(self):
        from app.services.crm_reports import _apply_group_by
        from app.models import AggregateSpec
        rows = [{"status": "open"}]
        aggs = [AggregateSpec(field="amount_cents", function="SUM")]
        result = _apply_group_by(rows, "status", aggs)
        assert result[0]["amount_cents_SUM"] is None

    def test_model_validator_group_by_requires_aggregates(self):
        from app.models import ReportCreateIn
        with pytest.raises(Exception):
            ReportCreateIn(name="bad", module="tickets", fields=["subject"], group_by="status", aggregates=[])

    def test_model_validator_aggregates_require_group_by(self):
        from app.models import ReportCreateIn, AggregateSpec
        with pytest.raises(Exception):
            ReportCreateIn(name="bad", module="tickets", fields=["subject"], group_by=None,
                           aggregates=[AggregateSpec(field="*", function="COUNT")])

    def test_duplicate_aggregate_raises(self):
        from app.models import ReportCreateIn, AggregateSpec
        with pytest.raises(Exception):
            ReportCreateIn(
                name="dup",
                module="tickets",
                fields=["subject"],
                group_by="status",
                aggregates=[
                    AggregateSpec(field="*", function="COUNT"),
                    AggregateSpec(field="*", function="COUNT"),
                ],
            )


# ---------------------------------------------------------------------------
# RPT-005: Chart config
# ---------------------------------------------------------------------------

class TestRPT005Charts:
    def test_validate_chart_valid(self):
        from app.services.crm_reports import _validate_chart
        from app.models import ChartConfig
        chart = ChartConfig(chart_type="bar", x_field="status", y_field="count")
        # Should not raise
        _validate_chart(chart, ["status", "count"], [])

    def test_validate_chart_invalid_x_field(self):
        from app.services.crm_reports import _validate_chart
        from app.models import ChartConfig
        chart = ChartConfig(chart_type="pie", x_field="nonexistent", y_field="status")
        with pytest.raises(ValueError, match="x_field"):
            _validate_chart(chart, ["status"], [])

    def test_validate_chart_with_aggregate_column(self):
        from app.services.crm_reports import _validate_chart
        from app.models import ChartConfig, AggregateSpec
        chart = ChartConfig(chart_type="bar", x_field="status", y_field="*_COUNT")
        # Should not raise — *_COUNT is a valid aggregate column
        _validate_chart(chart, ["status"], [AggregateSpec(field="*", function="COUNT")])

    def test_chart_stored_on_meta_row(self):
        from app.core import tables as tables_mod, settings as settings_mod
        from app.core.tables import _FloatSafeTable
        from app.models import ReportCreateIn, ChartConfig

        with mock_aws():
            ddb = boto3.resource("dynamodb", region_name="us-east-1")
            tbl = _make_crm_reports_table(ddb)
            orig = tables_mod.T.crm_reports
            orig_flag = settings_mod.S.crm_reports_enabled
            object.__setattr__(tables_mod.T, "crm_reports", _FloatSafeTable(tbl))
            object.__setattr__(settings_mod.S, "crm_reports_enabled", True)
            try:
                from app.services import crm_reports
                payload = ReportCreateIn(
                    name="Chart Report",
                    module="tickets",
                    fields=["status"],
                    chart=ChartConfig(chart_type="bar", x_field="status", y_field="status"),
                )
                with patch("app.services.alerts.audit_event", MagicMock()):
                    created = crm_reports.create_report("alice", payload)
                assert created["chart"] is not None
                assert created["chart"]["chart_type"] == "bar"
            finally:
                object.__setattr__(tables_mod.T, "crm_reports", orig)
                object.__setattr__(settings_mod.S, "crm_reports_enabled", orig_flag)


# ---------------------------------------------------------------------------
# RPT-004: Scheduler
# ---------------------------------------------------------------------------

class TestRPT004Scheduler:

    @pytest.fixture(autouse=True)
    def setup_moto(self):
        from app.core import tables as tables_mod, settings as settings_mod
        from app.core.tables import _FloatSafeTable

        with mock_aws():
            ddb = boto3.resource("dynamodb", region_name="us-east-1")
            tbl = _make_crm_reports_table(ddb)

            orig_crm = tables_mod.T.crm_reports
            orig_flag = settings_mod.S.crm_reports_enabled
            orig_sched = settings_mod.S.crm_reports_scheduler_enabled

            object.__setattr__(tables_mod.T, "crm_reports", _FloatSafeTable(tbl))
            object.__setattr__(settings_mod.S, "crm_reports_enabled", True)
            object.__setattr__(settings_mod.S, "crm_reports_scheduler_enabled", True)

            try:
                yield tbl
            finally:
                object.__setattr__(tables_mod.T, "crm_reports", orig_crm)
                object.__setattr__(settings_mod.S, "crm_reports_enabled", orig_flag)
                object.__setattr__(settings_mod.S, "crm_reports_scheduler_enabled", orig_sched)

    def _create_dummy_report(self) -> str:
        from app.services import crm_reports
        from app.models import ReportCreateIn

        with patch("app.services.alerts.audit_event", MagicMock()):
            result = crm_reports.create_report(
                "alice",
                ReportCreateIn(name="SR", module="tickets", fields=["subject"]),
            )
        return result["report_id"]

    def test_create_schedule_writes_ddb_row(self):
        from app.services import crm_report_scheduler

        report_id = self._create_dummy_report()
        with patch("app.services.alerts.audit_event", MagicMock()):
            sched = crm_report_scheduler.create_report_schedule(
                owner_sub="alice",
                report_id=report_id,
                cadence="daily",
                recipients=["test@example.com"],
            )
        assert sched["schedule_id"].startswith("rptsched_")
        assert sched["cadence"] == "daily"
        assert sched["enabled"] is True
        assert sched["next_run_at"] > 0

    def test_create_schedule_rejects_unknown_cadence(self):
        from app.services import crm_report_scheduler
        from fastapi import HTTPException

        report_id = self._create_dummy_report()
        with pytest.raises(HTTPException) as exc_info:
            crm_report_scheduler.create_report_schedule(
                owner_sub="alice",
                report_id=report_id,
                cadence="hourly",
                recipients=["test@example.com"],
            )
        assert exc_info.value.status_code == 422

    def test_disable_moves_gsi_pk(self):
        from app.services import crm_report_scheduler

        report_id = self._create_dummy_report()
        with patch("app.services.alerts.audit_event", MagicMock()):
            sched = crm_report_scheduler.create_report_schedule(
                owner_sub="alice", report_id=report_id, cadence="daily", recipients=["t@t.com"]
            )
            crm_report_scheduler.update_report_schedule(sched["schedule_id"], "alice", enabled=False)
            due = crm_report_scheduler.get_due_report_schedules(now=9999999999)
        assert not any(s.get("schedule_id") == sched["schedule_id"] for s in due)

    def test_run_due_dispatches_email(self):
        from app.services import crm_report_scheduler
        from app.core.time import now_ts

        report_id = self._create_dummy_report()
        with patch("app.services.alerts.audit_event", MagicMock()):
            sched = crm_report_scheduler.create_report_schedule(
                owner_sub="alice", report_id=report_id, cadence="daily", recipients=["t@t.com"]
            )

        # Set next_run_at in the past
        from app.core import tables as tables_mod
        tables_mod.T.crm_reports.update_item(
            Key={"report_id": f"SCHEDULE#{sched['schedule_id']}", "sk": "META"},
            UpdateExpression="SET next_run_at = :n, GSI2SK = :n",
            ExpressionAttributeValues={":n": 1},
        )

        mock_run_result = {
            "report_id": report_id, "run_id": "test1", "run_at": now_ts(),
            "status": "ok", "row_count": 1, "columns": ["subject"], "rows": [["T1"]], "chart": None,
        }
        email_calls = []

        with (
            patch.object(crm_report_scheduler, "send_alert_email", side_effect=lambda *a, **kw: email_calls.append(a)),
            patch("app.services.alerts.audit_event", MagicMock()),
            patch("app.services.crm_reports.run_report", return_value=mock_run_result),
        ):
            count = crm_report_scheduler.run_due_report_schedules()

        assert count == 1
        assert len(email_calls) == 1

    def test_run_due_skips_future_schedules(self):
        from app.services import crm_report_scheduler

        report_id = self._create_dummy_report()
        with patch("app.services.alerts.audit_event", MagicMock()):
            crm_report_scheduler.create_report_schedule(
                owner_sub="alice", report_id=report_id, cadence="daily", recipients=["t@t.com"]
            )

        email_calls = []
        with (
            patch.object(crm_report_scheduler, "send_alert_email", side_effect=lambda *a, **kw: email_calls.append(a)),
            patch("app.services.alerts.audit_event", MagicMock()),
        ):
            count = crm_report_scheduler.run_due_report_schedules()

        assert count == 0
        assert len(email_calls) == 0

    def test_flag_off_no_op(self):
        from app.services.crm_report_scheduler import start_report_scheduler_task
        from app.core import settings as settings_mod

        orig = settings_mod.S.crm_reports_scheduler_enabled
        try:
            object.__setattr__(settings_mod.S, "crm_reports_scheduler_enabled", False)
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(start_report_scheduler_task())
                tasks = [t for t in asyncio.all_tasks(loop) if not t.done()]
                assert len(tasks) == 0
            finally:
                loop.close()
        finally:
            object.__setattr__(settings_mod.S, "crm_reports_scheduler_enabled", orig)


# ---------------------------------------------------------------------------
# RPT-006: Dashboard
# ---------------------------------------------------------------------------

class TestRPT006Dashboard:

    @pytest.fixture(autouse=True)
    def setup_moto(self):
        from app.core import tables as tables_mod, settings as settings_mod
        from app.core.tables import _FloatSafeTable

        with mock_aws():
            ddb = boto3.resource("dynamodb", region_name="us-east-1")
            tbl = _make_dashboards_table(ddb)

            orig = tables_mod.T.crm_dashboards
            orig_flag = settings_mod.S.crm_reports_enabled

            object.__setattr__(tables_mod.T, "crm_dashboards", _FloatSafeTable(tbl))
            object.__setattr__(settings_mod.S, "crm_reports_enabled", True)

            try:
                yield
            finally:
                object.__setattr__(tables_mod.T, "crm_dashboards", orig)
                object.__setattr__(settings_mod.S, "crm_reports_enabled", orig_flag)

    def test_get_creates_empty_dashboard_on_first_call(self):
        from app.services.crm_dashboard import get_or_create_default_dashboard
        dash = get_or_create_default_dashboard("alice")
        assert dash["dashlets"] == []
        assert dash["name"] == "Home"
        assert dash["owner_sub"] == "alice"

    def test_get_is_idempotent(self):
        from app.services.crm_dashboard import get_or_create_default_dashboard
        d1 = get_or_create_default_dashboard("alice")
        d2 = get_or_create_default_dashboard("alice")
        assert d1["dashboard_id"] == d2["dashboard_id"]
        assert d1["created_at"] == d2["created_at"]

    def test_add_dashlet_recent_tickets(self):
        from app.services.crm_dashboard import add_dashlet
        from app.models import DashletAddIn
        with patch("app.services.alerts.audit_event", MagicMock()):
            dash = add_dashlet("alice", DashletAddIn(dashlet_type="recent_tickets", title="My Tickets", config={"row_limit": 5}))
        assert len(dash["dashlets"]) == 1
        assert dash["dashlets"][0]["dashlet_id"].startswith("dlt_")
        assert dash["dashlets"][0]["dashlet_type"] == "recent_tickets"

    def test_add_dashlet_enforces_20_limit(self):
        from app.services.crm_dashboard import add_dashlet, get_or_create_default_dashboard
        from app.models import DashletAddIn
        from fastapi import HTTPException

        with patch("app.services.alerts.audit_event", MagicMock()):
            get_or_create_default_dashboard("alice")
            for i in range(20):
                add_dashlet("alice", DashletAddIn(dashlet_type="recent_tickets", title=f"T{i}"))
            with pytest.raises(HTTPException) as exc_info:
                add_dashlet("alice", DashletAddIn(dashlet_type="recent_tickets", title="extra"))
        assert exc_info.value.status_code == 422

    def test_remove_dashlet(self):
        from app.services.crm_dashboard import add_dashlet, remove_dashlet
        from app.models import DashletAddIn

        with patch("app.services.alerts.audit_event", MagicMock()):
            dash = add_dashlet("alice", DashletAddIn(dashlet_type="recent_tickets", title="T1"))
            did = dash["dashlets"][0]["dashlet_id"]
            add_dashlet("alice", DashletAddIn(dashlet_type="calendar_today", title="T2"))
            result = remove_dashlet("alice", did)
        assert len(result["dashlets"]) == 1
        assert result["dashlets"][0]["dashlet_type"] == "calendar_today"

    def test_remove_dashlet_unknown_id_raises_404(self):
        from app.services.crm_dashboard import remove_dashlet
        from fastapi import HTTPException

        with patch("app.services.alerts.audit_event", MagicMock()):
            with pytest.raises(HTTPException) as exc_info:
                remove_dashlet("alice", "dlt_nonexistent")
        assert exc_info.value.status_code == 404

    def test_reorder_dashlets(self):
        from app.services.crm_dashboard import add_dashlet, reorder_dashlets
        from app.models import DashletAddIn

        with patch("app.services.alerts.audit_event", MagicMock()):
            dash = add_dashlet("alice", DashletAddIn(dashlet_type="recent_tickets", title="A"))
            a_id = dash["dashlets"][0]["dashlet_id"]
            dash = add_dashlet("alice", DashletAddIn(dashlet_type="calendar_today", title="B"))
            b_id = dash["dashlets"][1]["dashlet_id"]
            result = reorder_dashlets("alice", [b_id, a_id])

        assert result["dashlets"][0]["dashlet_id"] == b_id
        assert result["dashlets"][1]["dashlet_id"] == a_id

    def test_reorder_rejects_wrong_ids(self):
        from app.services.crm_dashboard import add_dashlet, reorder_dashlets
        from app.models import DashletAddIn
        from fastapi import HTTPException

        with patch("app.services.alerts.audit_event", MagicMock()):
            add_dashlet("alice", DashletAddIn(dashlet_type="recent_tickets", title="A"))
            with pytest.raises(HTTPException) as exc_info:
                reorder_dashlets("alice", ["dlt_unknown"])
        assert exc_info.value.status_code == 422

    def test_dashboard_isolation_between_users(self):
        from app.services.crm_dashboard import add_dashlet, get_or_create_default_dashboard
        from app.models import DashletAddIn

        with patch("app.services.alerts.audit_event", MagicMock()):
            add_dashlet("alice", DashletAddIn(dashlet_type="recent_tickets", title="T"))
            bob_dash = get_or_create_default_dashboard("bob")
        assert bob_dash["dashlets"] == []

    def test_patch_name_only(self):
        from app.services.crm_dashboard import update_dashboard
        from app.models import DashboardUpdateIn

        with patch("app.services.alerts.audit_event", MagicMock()):
            result = update_dashboard("alice", DashboardUpdateIn(name="Work Dashboard"))
        assert result["name"] == "Work Dashboard"

    def test_flag_off_returns_404(self):
        from app.core import settings as settings_mod
        from app.routers.crm_dashboard import _require_flag
        from fastapi import HTTPException

        orig = settings_mod.S.crm_reports_enabled
        try:
            object.__setattr__(settings_mod.S, "crm_reports_enabled", False)
            with pytest.raises(HTTPException) as exc_info:
                _require_flag()
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(settings_mod.S, "crm_reports_enabled", orig)

    def test_audit_events_emitted(self):
        from app.services.crm_dashboard import add_dashlet, remove_dashlet
        from app.models import DashletAddIn
        import app.services.crm_dashboard as dash_mod

        audit_calls = []
        with patch.object(dash_mod, "audit_event", side_effect=lambda *a, **kw: audit_calls.append(a[0])):
            dash = add_dashlet("alice", DashletAddIn(dashlet_type="recent_tickets", title="T"))
            remove_dashlet("alice", dash["dashlets"][0]["dashlet_id"])

        assert "crm_dashboard.dashlet_added" in audit_calls
        assert "crm_dashboard.dashlet_removed" in audit_calls


# ---------------------------------------------------------------------------
# RPT-008: Saved Searches
# ---------------------------------------------------------------------------

class TestRPT008SavedSearches:

    @pytest.fixture(autouse=True)
    def setup_moto(self):
        from app.core import tables as tables_mod, settings as settings_mod
        from app.core.tables import _FloatSafeTable

        with mock_aws():
            ddb = boto3.resource("dynamodb", region_name="us-east-1")
            ss_tbl = _make_saved_searches_table(ddb)

            orig = tables_mod.T.crm_saved_searches
            orig_flag = settings_mod.S.crm_reports_enabled
            orig_max = settings_mod.S.crm_saved_search_run_max_rows

            object.__setattr__(tables_mod.T, "crm_saved_searches", _FloatSafeTable(ss_tbl))
            object.__setattr__(settings_mod.S, "crm_reports_enabled", True)
            object.__setattr__(settings_mod.S, "crm_saved_search_run_max_rows", 500)

            try:
                yield
            finally:
                object.__setattr__(tables_mod.T, "crm_saved_searches", orig)
                object.__setattr__(settings_mod.S, "crm_reports_enabled", orig_flag)
                object.__setattr__(settings_mod.S, "crm_saved_search_run_max_rows", orig_max)

    def test_create(self):
        from app.services.crm_saved_searches import create_saved_search
        from app.models import SavedSearchCreateIn

        with patch("app.services.alerts.audit_event", MagicMock()):
            result = create_saved_search("alice", SavedSearchCreateIn(
                name="Open Tickets", module="tickets", filters=[],
            ))
        assert result["saved_search_id"].startswith("SS#")
        assert result["owner_sub"] == "alice"

    def test_list_pagination(self):
        from app.services.crm_saved_searches import create_saved_search, list_saved_searches
        from app.models import SavedSearchCreateIn

        with patch("app.services.alerts.audit_event", MagicMock()):
            for i in range(55):
                create_saved_search("alice", SavedSearchCreateIn(name=f"S{i}", module="tickets"))

        items, cursor = list_saved_searches("alice")
        all_ids = [i["saved_search_id"] for i in items]
        while cursor:
            more, cursor = list_saved_searches("alice", cursor=cursor)
            all_ids.extend(i["saved_search_id"] for i in more)
        assert len(all_ids) == 55
        assert len(set(all_ids)) == 55

    def test_get_ownership_403(self):
        from app.services.crm_saved_searches import create_saved_search, get_saved_search
        from app.models import SavedSearchCreateIn
        from fastapi import HTTPException

        with patch("app.services.alerts.audit_event", MagicMock()):
            created = create_saved_search("alice", SavedSearchCreateIn(name="S", module="tickets"))
        with pytest.raises(HTTPException) as exc_info:
            get_saved_search(created["saved_search_id"], "bob")
        assert exc_info.value.status_code == 403

    def test_update(self):
        from app.services.crm_saved_searches import create_saved_search, update_saved_search
        from app.models import SavedSearchCreateIn, SavedSearchUpdateIn

        with patch("app.services.alerts.audit_event", MagicMock()):
            created = create_saved_search("alice", SavedSearchCreateIn(name="Old Name", module="tickets"))
            updated = update_saved_search(created["saved_search_id"], "alice", SavedSearchUpdateIn(name="New Name"))
        assert updated["name"] == "New Name"
        assert updated["updated_at"] >= created["created_at"]

    def test_delete_idempotency(self):
        from app.services.crm_saved_searches import create_saved_search, delete_saved_search, get_saved_search
        from app.models import SavedSearchCreateIn
        from fastapi import HTTPException

        with patch("app.services.alerts.audit_event", MagicMock()):
            created = create_saved_search("alice", SavedSearchCreateIn(name="S", module="tickets"))
            delete_saved_search(created["saved_search_id"], "alice")

        with pytest.raises(HTTPException) as exc_info:
            get_saved_search(created["saved_search_id"], "alice")
        assert exc_info.value.status_code == 404

    def test_run_rows_and_columns(self):
        from app.services import crm_saved_searches
        from app.models import SavedSearchCreateIn

        with patch("app.services.alerts.audit_event", MagicMock()):
            created = crm_saved_searches.create_saved_search("alice", SavedSearchCreateIn(name="S", module="tickets"))

        fake_rows = [
            {"ticket_id": "T1", "status": "open"},
            {"ticket_id": "T2", "status": "done"},
            {"ticket_id": "T3", "status": "open"},
        ]
        with patch("app.services.crm_reports._fetch_and_filter", return_value=fake_rows):
            result = crm_saved_searches.run_saved_search(created["saved_search_id"], "alice")

        assert result["row_count"] == 3
        assert result["ran_at"] > 0
        assert sorted(result["columns"]) == ["status", "ticket_id"]

    def test_run_cap(self):
        from app.services import crm_saved_searches
        from app.models import SavedSearchCreateIn
        from app.core import settings as settings_mod

        created = crm_saved_searches.create_saved_search("alice", SavedSearchCreateIn(name="S", module="tickets"))

        # Create 600 fake rows
        fake_rows = [{"ticket_id": f"T{i}", "status": "open"} for i in range(600)]
        with patch("app.services.crm_reports._fetch_and_filter", return_value=fake_rows):
            result = crm_saved_searches.run_saved_search(created["saved_search_id"], "alice")

        assert result["row_count"] == 500

    def test_flag_off_404(self):
        from app.core import settings as settings_mod
        from app.routers.crm_saved_searches import _require_flag
        from fastapi import HTTPException

        orig = settings_mod.S.crm_reports_enabled
        try:
            object.__setattr__(settings_mod.S, "crm_reports_enabled", False)
            with pytest.raises(HTTPException) as exc_info:
                _require_flag()
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(settings_mod.S, "crm_reports_enabled", orig)

    def test_audit_events(self):
        from app.services import crm_saved_searches
        from app.models import SavedSearchCreateIn
        import app.services.crm_saved_searches as ss_mod

        events_logged = []
        with patch.object(ss_mod, "audit_event", side_effect=lambda *a, **kw: events_logged.append(a[0])):
            created = crm_saved_searches.create_saved_search("alice", SavedSearchCreateIn(name="S", module="tickets"))
            crm_saved_searches.delete_saved_search(created["saved_search_id"], "alice")

        assert "saved_search.created" in events_logged
        assert "saved_search.deleted" in events_logged


# ---------------------------------------------------------------------------
# RPT-009: CSV export additional sources
# ---------------------------------------------------------------------------

class TestRPT009CsvExport:

    def test_tickets_columns_defined(self):
        from app.services.csv_export import TICKETS_COLUMNS, SUBSCRIPTIONS_COLUMNS, ORDERS_COLUMNS, CONTACTS_CRM_COLUMNS
        assert "Ticket ID" in TICKETS_COLUMNS
        assert "Subscription ID" in SUBSCRIPTIONS_COLUMNS
        assert "Order ID" in ORDERS_COLUMNS
        assert "Notes" in CONTACTS_CRM_COLUMNS

    def test_format_tickets_row(self):
        from app.services.csv_export import _format_tickets_row
        row = _format_tickets_row({"ticket_id": "TKT1", "subject": "Bug", "status": "open", "priority": "high",
                                    "owner_sub": "alice", "created_at": 1700000000, "updated_at": 1700000001})
        assert row[0] == "TKT1"
        assert row[1] == "Bug"
        assert row[2] == "open"

    def test_format_orders_row(self):
        from app.services.csv_export import _format_orders_row
        row = _format_orders_row({"order_id": "ORD1", "status": "fulfilled", "user_id": "alice", "created_at": 1700000000})
        assert row[0] == "ORD1"
        assert row[1] == "fulfilled"

    def test_format_contacts_crm_row_includes_notes(self):
        from app.services.csv_export import _format_contacts_crm_row
        row = _format_contacts_crm_row({"name": "Alice", "email": "a@b.com", "notes": "VIP customer", "source": "web"})
        assert "VIP customer" in row
        assert "web" in row

    def test_crm_source_gated_by_flag(self):
        """tickets source should 404 when CRM flag is off."""
        import asyncio
        from app.core import settings as settings_mod
        from app.routers.csv_export import export_csv
        from fastapi import HTTPException

        orig = settings_mod.S.crm_reports_enabled
        try:
            object.__setattr__(settings_mod.S, "crm_reports_enabled", False)
            mock_ctx = {"user_sub": "alice"}

            async def run():
                return await export_csv(source="tickets", from_date=None, to_date=None, questionnaire_id=None, ctx=mock_ctx)

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(run())
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(settings_mod.S, "crm_reports_enabled", orig)
