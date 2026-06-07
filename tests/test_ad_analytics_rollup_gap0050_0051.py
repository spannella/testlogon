"""Offline regression tests for GAP-0050 + GAP-0051: ad-analytics hourly rollups.

GAP-0050: ``compute_hourly_rollup`` was never triggered. A background loop
(``_ad_analytics_rollup_loop`` / ``start_ad_analytics_rollup_task``) now drives
it. These tests assert the loop wrapper invokes ``compute_hourly_rollup`` once
per active campaign per deterministic tick.

GAP-0051: the rollup wrote empty ``by_creative`` / ``by_surface`` /
``by_targeting`` maps. These tests assert the maps are now populated from the
billing ledger and the ad_impressions records.

Uses moto's in-memory DynamoDB and mocks for the loop — no real AWS, no real
sleeping. Each test fails before the fix and passes after.
"""
from __future__ import annotations

import os
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws


@pytest.fixture(autouse=True)
def _env():
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
    os.environ.setdefault("DDB_ENDPOINT_URL", "")
    os.environ.setdefault("DEV_MODE", "1")
    os.environ.setdefault("UI_ACCESS_TOKEN_SECRET", "test-secret")
    os.environ.setdefault("API_KEY_PEPPER", "test-pepper")


# Hour window for "2026-05-29T14": start = 1780063200, end = +3600.
HOUR_LABEL = "2026-05-29T14"
HOUR_START = 1780063200  # 2026-05-29T14:00:00Z
IN_WINDOW = HOUR_START + 100
OUT_OF_WINDOW = HOUR_START + 3700  # next hour


@pytest.fixture
def ad_tables():
    """Wire ad_analytics_rollups + ad_impressions to in-memory moto tables."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        rollups = ddb.create_table(
            TableName="ad_analytics_rollups",
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
        impressions = ddb.create_table(
            TableName="ad_impressions",
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

        import app.core.tables as tables_mod

        orig_r = tables_mod.T.ad_analytics_rollups
        orig_i = tables_mod.T.ad_impressions
        object.__setattr__(tables_mod.T, "ad_analytics_rollups", rollups)
        object.__setattr__(tables_mod.T, "ad_impressions", impressions)
        try:
            yield {"rollups": rollups, "impressions": impressions}
        finally:
            object.__setattr__(tables_mod.T, "ad_analytics_rollups", orig_r)
            object.__setattr__(tables_mod.T, "ad_impressions", orig_i)


def _put_impression(table, *, campaign_id, event_type, surface, slot_type,
                    geo_country, created_at, sk):
    table.put_item(Item={
        "pk": f"AD_IMP#2026-05-29",
        "sk": sk,
        "campaign_id": campaign_id,
        "event_type": event_type,
        "surface": surface,
        "slot_type": slot_type,
        "geo_country": geo_country,
        "created_at": created_at,
    })


BILLING_ENTRIES = [
    # In-window impression + click on creative cr1
    {"entry_type": "impression_charge", "amount_cents": 1,
     "created_at": IN_WINDOW, "meta": {"creative_id": "cr1"}},
    {"entry_type": "click_charge", "amount_cents": 10,
     "created_at": IN_WINDOW + 5, "meta": {"creative_id": "cr1"}},
    # In-window impression on creative cr2
    {"entry_type": "impression_charge", "amount_cents": 1,
     "created_at": IN_WINDOW + 6, "meta": {"creative_id": "cr2"}},
    # Out-of-window entry — must be excluded
    {"entry_type": "impression_charge", "amount_cents": 1,
     "created_at": OUT_OF_WINDOW, "meta": {"creative_id": "cr1"}},
]


# ── GAP-0051: breakdown maps populated ─────────────────────────────────


class TestBreakdownMapsPopulated:
    def test_breakdown_maps_non_empty(self, ad_tables):
        """compute_hourly_rollup writes non-empty by_* maps (GAP-0051)."""
        from app.services import ad_analytics

        _put_impression(
            ad_tables["impressions"], campaign_id="c1",
            event_type="impression", surface="feed",
            slot_type="native_post", geo_country="US",
            created_at=IN_WINDOW, sk="A",
        )
        _put_impression(
            ad_tables["impressions"], campaign_id="c1",
            event_type="click", surface="feed",
            slot_type="native_post", geo_country="DE",
            created_at=IN_WINDOW + 1, sk="B",
        )
        # Impression for a DIFFERENT campaign / out of window — excluded.
        _put_impression(
            ad_tables["impressions"], campaign_id="other",
            event_type="impression", surface="reels",
            slot_type="video", geo_country="FR",
            created_at=IN_WINDOW, sk="C",
        )

        with patch(
            "app.services.ad_billing.get_campaign_spending",
            return_value=BILLING_ENTRIES,
        ):
            rollup = ad_analytics.compute_hourly_rollup(
                "c1", "acct1", HOUR_LABEL
            )

        # FAILS BEFORE FIX: all three were hardcoded to {}.
        assert rollup["by_creative"] != {}
        assert rollup["by_surface"] != {}
        assert rollup["by_targeting"] != {}

        # by_creative built from billing ledger (in-window only).
        assert rollup["by_creative"]["cr1"]["impressions"] == 1
        assert rollup["by_creative"]["cr1"]["clicks"] == 1
        assert rollup["by_creative"]["cr1"]["spend_cents"] == 11
        assert rollup["by_creative"]["cr2"]["impressions"] == 1

        # by_surface / by_targeting built from ad_impressions for this campaign.
        assert rollup["by_surface"]["feed/native_post"]["impressions"] == 1
        assert rollup["by_surface"]["feed/native_post"]["clicks"] == 1
        assert "US" in rollup["by_targeting"]
        assert "DE" in rollup["by_targeting"]
        # Other-campaign impression must not leak in.
        assert "reels/video" not in rollup["by_surface"]

    def test_hourly_window_filter(self, ad_tables):
        """Only in-window billing entries are counted (GAP-0050 filter)."""
        from app.services import ad_analytics

        with patch(
            "app.services.ad_billing.get_campaign_spending",
            return_value=BILLING_ENTRIES,
        ):
            rollup = ad_analytics.compute_hourly_rollup(
                "c1", "acct1", HOUR_LABEL
            )

        # 2 in-window impressions + 1 in-window click; out-of-window excluded.
        assert rollup["impressions"] == 2
        assert rollup["clicks"] == 1
        assert rollup["spend_cents"] == 12  # 1 + 10 + 1

    def test_rollup_persisted(self, ad_tables):
        """The rollup row is written and readable from the table."""
        from app.services import ad_analytics

        with patch(
            "app.services.ad_billing.get_campaign_spending",
            return_value=BILLING_ENTRIES,
        ):
            ad_analytics.compute_hourly_rollup("c1", "acct1", HOUR_LABEL)

        got = ad_tables["rollups"].get_item(
            Key={"pk": "CAMP#c1", "sk": f"ROLLUP#hourly#{HOUR_LABEL}"}
        ).get("Item")
        assert got is not None
        assert got["by_creative"] != {}


# ── GAP-0050: background task wrapper drives compute_hourly_rollup ──────


class TestBackgroundTaskWrapper:
    def test_run_for_all_campaigns_calls_once_per_active_campaign(self):
        """One deterministic tick calls compute_hourly_rollup per active campaign."""
        from app.services import ad_analytics

        active = [
            {"campaign_id": "c1", "account_id": "a1", "status": "active"},
            {"campaign_id": "c2", "account_id": "a2", "status": "active"},
        ]

        class _FakeCampaigns:
            def scan(self, **kwargs):
                return {"Items": active}

        orig = ad_analytics.T.ad_campaigns
        object.__setattr__(ad_analytics.T, "ad_campaigns", _FakeCampaigns())
        try:
            with patch.object(
                ad_analytics, "compute_hourly_rollup"
            ) as mock_compute:
                ad_analytics._run_rollup_for_all_campaigns(HOUR_LABEL, "hourly")
        finally:
            object.__setattr__(ad_analytics.T, "ad_campaigns", orig)

        assert mock_compute.call_count == 2
        mock_compute.assert_any_call("c1", "a1", HOUR_LABEL)
        mock_compute.assert_any_call("c2", "a2", HOUR_LABEL)

    def test_loop_runs_one_tick_and_calls_rollups(self):
        """_ad_analytics_rollup_loop runs one deterministic iteration.

        FAILS BEFORE FIX: the loop / wrapper did not exist (no caller of
        compute_hourly_rollup anywhere).
        """
        import asyncio

        from app.services import ad_analytics

        calls: list = []

        async def _drive():
            # Patch sleep so the FIRST call returns immediately and the loop
            # body runs; subsequent sleep raises CancelledError to stop.
            sleeps = {"n": 0}

            async def _sleep(_secs):
                sleeps["n"] += 1
                if sleeps["n"] >= 2:
                    raise asyncio.CancelledError()
                return None

            with patch.object(ad_analytics.asyncio, "sleep", _sleep), \
                 patch.object(
                     ad_analytics, "_run_rollup_for_all_campaigns",
                     side_effect=lambda period, kind: calls.append((period, kind)),
                 ):
                await ad_analytics._ad_analytics_rollup_loop()

        asyncio.run(_drive())

        # The loop ran exactly one hourly rollup pass.
        hourly = [c for c in calls if c[1] == "hourly"]
        assert len(hourly) == 1

    def test_start_task_gated_by_ad_serving_enabled(self):
        """start_ad_analytics_rollup_task is a no-op when ad serving disabled."""
        from app.services import ad_analytics

        orig = ad_analytics.S.ad_serving_enabled
        try:
            object.__setattr__(ad_analytics.S, "ad_serving_enabled", False)
            with patch.object(ad_analytics.asyncio, "ensure_future") as mock_ef:
                ad_analytics.start_ad_analytics_rollup_task()
            mock_ef.assert_not_called()

            object.__setattr__(ad_analytics.S, "ad_serving_enabled", True)
            with patch.object(ad_analytics.asyncio, "ensure_future") as mock_ef:
                ad_analytics.start_ad_analytics_rollup_task()
            mock_ef.assert_called_once()
            # Close the un-awaited coroutine handed to the mocked ensure_future.
            coro = mock_ef.call_args[0][0]
            coro.close()
        finally:
            object.__setattr__(ad_analytics.S, "ad_serving_enabled", orig)
