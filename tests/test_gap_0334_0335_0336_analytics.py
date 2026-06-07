"""Regression tests for the PLATFORM-019 analytics subsystem.

GAP-0334: ``app/services/analytics_events.py`` recording functions write raw
          events to ``T.analytics_events`` with the correct schema + ttl_epoch.
GAP-0335: ``compute_daily_rollups`` aggregates seeded raw events and writes the
          summed daily rollup row via ``upsert_daily_rollup``; the
          ``start_analytics_rollup_task`` startup handler is registered.
GAP-0336: ``POST /ui/analytics/refresh`` calls ``compute_daily_rollups`` and
          reports the work done (no longer a no-op placeholder).

Fully offline: real in-memory DynamoDB tables via moto (no real AWS). The frozen
``T.analytics_events`` / ``T.analytics_rollups`` handles are rebound to the moto
tables via ``object.__setattr__`` and restored on cleanup. ``S`` flags are
flipped with ``object.__setattr__`` and restored.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from datetime import datetime, timezone
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_analytics_events_table(ddb):
    """Mirror scripts/local-ddb-init.py AnalyticsEvents TableDef."""
    return ddb.create_table(
        TableName="analytics_events",
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
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_analytics_rollups_table(ddb):
    """Mirror scripts/local-ddb-init.py AnalyticsRollups TableDef."""
    return ddb.create_table(
        TableName="AnalyticsRollups",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "date_scope", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByDateCreatedAt",
                "KeySchema": [
                    {"AttributeName": "date_scope", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestAnalyticsEventsGap0334(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.events = _make_analytics_events_table(ddb)

        from app.core.tables import T

        self._T = T
        orig = T.analytics_events
        object.__setattr__(T, "analytics_events", self.events)
        self.addCleanup(lambda: object.__setattr__(T, "analytics_events", orig))

    def test_record_page_view_writes_event(self):
        from app.services import analytics_events as ae

        ae.record_page_view("creator-1", "post-abc", viewer_id="user-x", watch_time_seconds=45)

        items = self.events.scan()["Items"]
        self.assertEqual(len(items), 1)
        it = items[0]
        self.assertEqual(it["event_type"], "page_view")
        self.assertEqual(it["creator_id"], "creator-1")
        self.assertEqual(it["viewer_id"], "user-x")
        self.assertEqual(int(it["watch_time_seconds"]), 45)
        self.assertTrue(it["pk"].startswith("EVENT#creator-1#"))
        self.assertEqual(it["GSI1PK"], "CREATOR#creator-1")
        self.assertTrue(it["GSI1SK"].startswith("DATE#"))
        # ttl_epoch present and ~90 days in the future.
        self.assertIn("ttl_epoch", it)
        self.assertGreater(int(it["ttl_epoch"]), int(it["created_at"]) + 80 * 86400)

    def test_record_revenue_subscriber_engagement(self):
        from app.services import analytics_events as ae

        ae.record_revenue_event("creator-1", "tip", 500, subscriber_id="user-b")
        ae.record_subscriber_event("creator-1", "user-c", "new")
        ae.record_engagement_event("creator-1", "post-1", "user-d", "reaction")

        items = self.events.scan()["Items"]
        by_type = {i["event_type"]: i for i in items}
        self.assertEqual(int(by_type["revenue"]["amount_cents"]), 500)
        self.assertEqual(by_type["revenue"]["revenue_type"], "tip")
        self.assertEqual(by_type["subscriber"]["event_kind"], "new")
        self.assertEqual(by_type["engagement"]["action"], "reaction")
        for i in items:
            self.assertIn("ttl_epoch", i)


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestRollupEngineGap0335(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.events = _make_analytics_events_table(ddb)
        self.rollups = _make_analytics_rollups_table(ddb)

        from app.core.tables import T

        for name, tbl in (("analytics_events", self.events), ("analytics_rollups", self.rollups)):
            orig = getattr(T, name)
            object.__setattr__(T, name, tbl)
            self.addCleanup(lambda n=name, o=orig: object.__setattr__(T, n, o))

    def test_compute_daily_rollups_aggregates_seeded_events(self):
        from app.services import analytics_events as ae
        from app.services.analytics_rollup_engine import compute_daily_rollups
        from boto3.dynamodb.conditions import Key

        creator = "creator-roll"
        # Seed via the real recording layer so the schema matches end-to-end.
        ae.record_page_view(creator, "post-1", viewer_id="v1", watch_time_seconds=30)
        ae.record_page_view(creator, "post-1", viewer_id="v2", watch_time_seconds=10)
        ae.record_revenue_event(creator, "tip", 500)
        ae.record_revenue_event(creator, "subscription", 999)
        ae.record_subscriber_event(creator, "s1", "new")

        processed = compute_daily_rollups(lookback_days=1)
        self.assertGreaterEqual(processed, 1)

        today = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
        resp = self.rollups.query(
            KeyConditionExpression=Key("pk").eq(f"CREATOR#{creator}")
            & Key("sk").eq(f"DAILY#{today}")
        )
        self.assertEqual(len(resp["Items"]), 1)
        row = resp["Items"][0]
        self.assertEqual(int(row["total_views"]), 2)
        self.assertEqual(int(row["unique_viewers"]), 2)
        self.assertEqual(int(row["watch_time_seconds"]), 40)
        self.assertEqual(int(row["revenue_cents"]), 1499)
        self.assertEqual(int(row["revenue_tips_cents"]), 500)
        self.assertEqual(int(row["revenue_subscriptions_cents"]), 999)
        self.assertEqual(int(row["new_subscribers"]), 1)

    def test_start_task_registered_in_app_startup(self):
        from app.main import create_app

        app = create_app()
        names = [getattr(h, "__name__", repr(h)) for h in app.router.on_startup]
        self.assertIn(
            "start_analytics_rollup_task", names,
            "analytics rollup startup handler not registered in app.on_startup",
        )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestRefreshEndpointGap0336(unittest.TestCase):
    def test_refresh_invokes_compute_daily_rollups(self):
        from app.routers import creator_analytics as router_mod

        # Clear in-process cooldown so the call isn't rate-limited.
        router_mod._refresh_timestamps.clear()

        with patch(
            "app.services.analytics_rollup_engine.compute_daily_rollups",
            return_value=3,
        ) as spy:
            out = router_mod.analytics_refresh(session={"user_sub": "creator-x"})

        spy.assert_called_once()
        # Canonical signature: lookback_days kwarg.
        self.assertIn("lookback_days", spy.call_args.kwargs)
        self.assertTrue(out.ok)
        self.assertIn("3 rows written", out.message)

    def test_refresh_rate_limited_on_second_call(self):
        from fastapi import HTTPException
        from app.routers import creator_analytics as router_mod

        router_mod._refresh_timestamps.clear()
        with patch(
            "app.services.analytics_rollup_engine.compute_daily_rollups",
            return_value=0,
        ):
            router_mod.analytics_refresh(session={"user_sub": "creator-y"})
            with self.assertRaises(HTTPException) as ctx:
                router_mod.analytics_refresh(session={"user_sub": "creator-y"})
        self.assertEqual(ctx.exception.status_code, 429)


if __name__ == "__main__":
    unittest.main()
