"""Offline regression tests for GAP-0104 + GAP-0105.

GAP-0104: Marketing content scheduled via ``schedule_content`` (status set to
``"scheduled"`` with a future ``scheduled_publish_at``) was never auto-published
because no background loop existed. ``publish_due_scheduled_content`` (driven by
``run_marketing_publish_loop`` / ``start_marketing_publish_task``) now promotes
due items to ``"published"``.

GAP-0105: Accountant cost collection only ran on a manual HTTP call. The new
``run_cost_collection_if_enabled`` (driven by ``run_cost_collection_loop`` /
``start_cost_collection_task``) sweeps every user with an accountant config and
re-evaluates budgets when ``accountant_agent_auto_alert`` (or
``execute_commands``) is enabled, creating budget-exceeded alerts.

Uses moto's in-memory DynamoDB. No real AWS, no real sleeping — the loop bodies
are invoked directly for a single deterministic iteration. Each behavioural test
fails before the fix (the functions did not exist) and passes after.
"""
from __future__ import annotations

import contextlib
import os
from datetime import datetime, timezone
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws


@contextlib.contextmanager
def _set_settings(settings, **overrides):
    """Temporarily override fields on the frozen Settings dataclass."""
    sentinel = object()
    originals = {k: getattr(settings, k, sentinel) for k in overrides}
    for k, v in overrides.items():
        object.__setattr__(settings, k, v)
    try:
        yield
    finally:
        for k, orig in originals.items():
            if orig is sentinel:
                object.__delattr__(settings, k)
            else:
                object.__setattr__(settings, k, orig)


@pytest.fixture(autouse=True)
def _env():
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
    os.environ.setdefault("DDB_ENDPOINT_URL", "")
    os.environ.setdefault("DEV_MODE", "1")
    os.environ.setdefault("UI_ACCESS_TOKEN_SECRET", "test-secret")
    os.environ.setdefault("API_KEY_PEPPER", "test-pepper")


def _make_simple_table(ddb, name):
    return ddb.create_table(
        TableName=name,
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


# ---------------------------------------------------------------------------
# GAP-0104: marketing scheduled-publish loop
# ---------------------------------------------------------------------------


@pytest.fixture
def marketing_tables():
    """Wire marketing_content + agent_types to in-memory moto tables.

    ``marketing_content`` needs GSI3 because ``schedule_content`` writes
    ``GSI3PK``/``GSI3SK`` (numeric sort key).
    """
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        content = ddb.create_table(
            TableName="marketing_content",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "N"},
                {"AttributeName": "GSI2PK", "AttributeType": "S"},
                {"AttributeName": "GSI2SK", "AttributeType": "N"},
                {"AttributeName": "GSI3PK", "AttributeType": "S"},
                {"AttributeName": "GSI3SK", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI2",
                    "KeySchema": [
                        {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI3",
                    "KeySchema": [
                        {"AttributeName": "GSI3PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI3SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        agent_types = _make_simple_table(ddb, "agent_types")

        import app.core.tables as tables_mod
        from app.services import agent_marketing as svc

        orig_content = tables_mod.T.marketing_content
        orig_types = tables_mod.T.agent_types
        object.__setattr__(tables_mod.T, "marketing_content", content)
        object.__setattr__(tables_mod.T, "agent_types", agent_types)
        # ensure_tables() would try to create tables against the import-time ddb
        # resource (outside this mock); short-circuit it — tables already exist.
        orig_bootstrapped = svc._BOOTSTRAPPED
        svc._BOOTSTRAPPED = True
        try:
            yield {"content": content, "agent_types": agent_types, "svc": svc}
        finally:
            svc._BOOTSTRAPPED = orig_bootstrapped
            object.__setattr__(tables_mod.T, "marketing_content", orig_content)
            object.__setattr__(tables_mod.T, "agent_types", orig_types)


class TestMarketingScheduledPublish:
    def test_due_scheduled_content_is_published(self, marketing_tables):
        """A past-due scheduled item is promoted to published by the loop body."""
        svc = marketing_tables["svc"]
        user_id = "user-alice"

        content = svc.create_content(
            user_id=user_id,
            content_type="blog_post",
            title="Launch Post",
            body="Hello world",
        )
        cid = content["content_id"]
        svc.approve_content(user_id=user_id, content_id=cid)

        # Schedule "in the future" relative to a frozen past clock, so the item
        # ends up with a scheduled_publish_at that is already past by real now.
        past_now = 1_000_000
        publish_at = past_now + 60
        with patch.object(svc, "now_ts", return_value=past_now):
            svc.schedule_content(user_id=user_id, content_id=cid, publish_at=publish_at)

        assert svc.get_content(user_id=user_id, content_id=cid)["status"] == "scheduled"

        # Run the loop body with a "now" well past the publish time.
        promoted = svc.publish_due_scheduled_content(now=publish_at + 10)
        assert promoted == 1

        item = svc.get_content(user_id=user_id, content_id=cid)
        assert item["status"] == "published"
        assert item.get("published_at")

    def test_future_scheduled_content_is_not_published(self, marketing_tables):
        """Items scheduled for the future are left untouched."""
        svc = marketing_tables["svc"]
        user_id = "user-bob"

        content = svc.create_content(
            user_id=user_id,
            content_type="blog_post",
            title="Future Post",
            body="Coming soon",
        )
        cid = content["content_id"]
        svc.approve_content(user_id=user_id, content_id=cid)

        past_now = 1_000_000
        publish_at = past_now + 60
        with patch.object(svc, "now_ts", return_value=past_now):
            svc.schedule_content(user_id=user_id, content_id=cid, publish_at=publish_at)

        # Sweep with a "now" BEFORE the publish time → nothing due.
        promoted = svc.publish_due_scheduled_content(now=publish_at - 10)
        assert promoted == 0
        assert svc.get_content(user_id=user_id, content_id=cid)["status"] == "scheduled"

    def test_publish_loop_gated_in_dev_mode(self, marketing_tables):
        """The loop body calls publish_due_scheduled_content when dev_mode is on."""
        svc = marketing_tables["svc"]
        with patch.object(svc, "publish_due_scheduled_content", return_value=0) as pub, \
                _set_settings(svc.S, marketing_agent_execute_commands=False, dev_mode=True), \
                patch.object(svc.asyncio, "sleep", side_effect=RuntimeError("stop")):
            import asyncio as _asyncio
            with pytest.raises(RuntimeError, match="stop"):
                _asyncio.new_event_loop().run_until_complete(
                    svc.run_marketing_publish_loop()
                )
        assert pub.called

    def test_start_task_creates_coroutine(self, marketing_tables):
        svc = marketing_tables["svc"]
        with patch.object(svc.asyncio, "create_task") as ct:
            svc.start_marketing_publish_task()
        assert ct.called


# ---------------------------------------------------------------------------
# GAP-0105: accountant cost-collection loop
# ---------------------------------------------------------------------------


@pytest.fixture
def accountant_tables():
    """Wire agent_types + accountant cost tables to in-memory moto tables."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        agent_types = _make_simple_table(ddb, "agent_types")
        budgets = _make_simple_table(ddb, "accountant_budgets")
        # alerts table: GSI1 = alerts by created_at (numeric sort key) per
        # local-ddb-init; list_alerts queries it.
        alerts = ddb.create_table(
            TableName="accountant_alerts",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        # agent_costs needs GSI1 (per-date query). GSI1SK is a String
        # (``TYPE#{agent_type}#WORKER#{worker_id}``) per local-ddb-init.
        costs = ddb.create_table(
            TableName="accountant_costs",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        import app.core.tables as tables_mod
        from app.services import agent_accountant as svc

        originals = {
            "agent_types": tables_mod.T.agent_types,
            "agent_costs": tables_mod.T.agent_costs,
            "agent_cost_budgets": tables_mod.T.agent_cost_budgets,
            "agent_cost_alerts": tables_mod.T.agent_cost_alerts,
        }
        object.__setattr__(tables_mod.T, "agent_types", agent_types)
        object.__setattr__(tables_mod.T, "agent_costs", costs)
        object.__setattr__(tables_mod.T, "agent_cost_budgets", budgets)
        object.__setattr__(tables_mod.T, "agent_cost_alerts", alerts)
        try:
            with patch.object(svc, "ensure_tables", lambda: None):
                yield {"svc": svc}
        finally:
            for attr, tbl in originals.items():
                object.__setattr__(tables_mod.T, attr, tbl)


def _today_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class TestAccountantCostCollection:
    def test_noop_when_flags_off(self, accountant_tables):
        """With both flags off the sweep is a no-op and returns 0."""
        svc = accountant_tables["svc"]
        with _set_settings(
            svc.S,
            accountant_agent_auto_alert=False,
            accountant_agent_execute_commands=False,
        ):
            assert svc.run_cost_collection_if_enabled() == 0

    def test_collection_evaluates_budgets_and_creates_alert(self, accountant_tables):
        """When auto_alert is on, the sweep evaluates the user's exceeded budget
        and creates a budget_exceeded alert (GAP-0105 core behaviour)."""
        svc = accountant_tables["svc"]
        user_id = "user-charlie"

        # Register an accountant config so the cross-user scan finds the user.
        svc.update_config(user_id=user_id, fields={})

        # A tiny daily budget that the recorded cost will exceed.
        svc.create_budget(
            user_id=user_id,
            name="Tiny Budget",
            scope="overall",
            scope_ref=None,
            period="daily",
            limit_cents=1,
        )
        svc.record_cost_entry(
            user_id=user_id,
            worker_id="w1",
            agent_type="coder",
            agent_id="a1",
            date=_today_str(),
            llm_cost_cents=500,
        )

        # No alerts before the sweep.
        assert svc.list_alerts(user_id=user_id, limit=10)["alerts"] == []

        with _set_settings(svc.S, accountant_agent_auto_alert=True):
            evaluated = svc.run_cost_collection_if_enabled()

        assert evaluated == 1
        alerts = svc.list_alerts(user_id=user_id, limit=10)["alerts"]
        assert any(a["alert_type"] == "budget_exceeded" for a in alerts)

    def test_loop_body_invoked_by_coroutine(self, accountant_tables):
        svc = accountant_tables["svc"]
        with patch.object(svc, "run_cost_collection_if_enabled", return_value=0) as run, \
                patch.object(svc.asyncio, "sleep", side_effect=RuntimeError("stop")):
            import asyncio as _asyncio
            with pytest.raises(RuntimeError, match="stop"):
                _asyncio.new_event_loop().run_until_complete(
                    svc.run_cost_collection_loop()
                )
        assert run.called

    def test_start_task_creates_coroutine(self, accountant_tables):
        svc = accountant_tables["svc"]
        with patch.object(svc.asyncio, "create_task") as ct:
            svc.start_cost_collection_task()
        assert ct.called


# ---------------------------------------------------------------------------
# Both tasks registered as startup handlers (integration)
# ---------------------------------------------------------------------------


def test_both_startup_handlers_registered():
    """start_marketing_publish_task + start_cost_collection_task are registered."""
    from app.main import create_app

    app = create_app()
    names = [
        getattr(h, "__name__", str(h))
        for h in getattr(app.router, "on_startup", [])
    ]
    assert "start_marketing_publish_task" in names
    assert "start_cost_collection_task" in names
