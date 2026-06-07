"""Offline regression tests for GAP-0062: ROAS calculation service.

Before the fix, ``app/services/ad_roas.py`` did not exist and there was no way
to compute Return on Ad Spend from real affiliate conversion data, so the
optimization alert (``ad_optimization.check_performance_alerts``) always read
``roas = m.get("roas", 0) == 0`` because ``ad_analytics.get_summary`` never
produced a ``roas`` key.

These tests wire moto's in-memory DynamoDB (no real AWS, no sleeping) for the
``ad_campaigns``, ``ad_accounts``, ``ad_creatives`` and ``ad_creative_affiliates``
tables and assert:

1. ``calculate_campaign_roas`` returns the correct ratio from REDEEM# rows.
2. ROAS is 0.0 (not a ZeroDivisionError) when spend is 0.
3. Old REDEEM# rows outside the lookback window are excluded.
4. ``ad_analytics.get_summary`` now emits a real ``roas`` key, closing the
   optimization-alert loop.

Each test fails before the fix (import error / missing roas key) and passes
after.
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


ACCOUNT_ID = "acct-1"
OWNER_SUB = "owner-1"
CAMPAIGN_ID = "camp_roas01"
NOW = 1_780_000_000  # fixed "now" for deterministic windows


def _simple_table(ddb, name):
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


@pytest.fixture
def roas_tables():
    """Wire the tables ad_roas / its dependencies read, to moto."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        campaigns = _simple_table(ddb, "ad_campaigns")
        accounts = _simple_table(ddb, "ad_accounts")
        creatives = _simple_table(ddb, "ad_creatives")
        affiliates = _simple_table(ddb, "ad_creative_affiliates")

        # Seed the account, campaign, two creatives.
        accounts.put_item(Item={"pk": f"ACCT#{ACCOUNT_ID}", "sk": "META",
                                "account_id": ACCOUNT_ID, "owner_sub": OWNER_SUB})
        campaigns.put_item(Item={"pk": f"ACCT#{ACCOUNT_ID}",
                                 "sk": f"CAMPAIGN#{CAMPAIGN_ID}",
                                 "campaign_id": CAMPAIGN_ID,
                                 "account_id": ACCOUNT_ID})
        for cid in ("cr1", "cr2"):
            creatives.put_item(Item={"pk": f"CAMP#{CAMPAIGN_ID}",
                                     "sk": f"CREATIVE#{cid}",
                                     "creative_id": cid})

        import app.core.tables as tables_mod
        originals = {}
        for attr, tbl in (
            ("ad_campaigns", campaigns),
            ("ad_accounts", accounts),
            ("ad_creatives", creatives),
            ("ad_creative_affiliates", affiliates),
        ):
            originals[attr] = getattr(tables_mod.T, attr)
            object.__setattr__(tables_mod.T, attr, tbl)
        try:
            yield {"affiliates": affiliates}
        finally:
            for attr, orig in originals.items():
                object.__setattr__(tables_mod.T, attr, orig)


def _put_redeem(table, *, creative_id, final_price_cents, created_at, redeem_id):
    table.put_item(Item={
        "pk": f"CREATIVE#{creative_id}",
        "sk": f"REDEEM#{created_at}#{redeem_id}",
        "creative_id": creative_id,
        "final_price_cents": final_price_cents,
        "created_at": created_at,
    })


def test_roas_calculated_correctly(roas_tables):
    """ROAS == conversion_revenue / spend, summed across creatives."""
    aff = roas_tables["affiliates"]
    _put_redeem(aff, creative_id="cr1", final_price_cents=150000,
                created_at=NOW - 10, redeem_id="r1")
    _put_redeem(aff, creative_id="cr2", final_price_cents=50000,
                created_at=NOW - 10, redeem_id="r2")

    from app.services import ad_roas

    with (
        patch.object(ad_roas, "now_ts", return_value=NOW),
        patch.object(ad_roas, "get_summary", return_value={"spend_cents": 100000}),
    ):
        result = ad_roas.calculate_campaign_roas(
            account_id=ACCOUNT_ID, campaign_id=CAMPAIGN_ID, days=30
        )

    assert result["conversion_revenue_cents"] == 200000
    assert result["spend_cents"] == 100000
    assert result["roas"] == 2.0  # 200000 / 100000
    assert result["conversion_count"] == 2


def test_roas_zero_when_no_spend(roas_tables):
    """No ZeroDivisionError: roas == 0.0 when spend is 0."""
    aff = roas_tables["affiliates"]
    _put_redeem(aff, creative_id="cr1", final_price_cents=5000,
                created_at=NOW - 10, redeem_id="r1")

    from app.services import ad_roas

    with (
        patch.object(ad_roas, "now_ts", return_value=NOW),
        patch.object(ad_roas, "get_summary", return_value={"spend_cents": 0}),
    ):
        result = ad_roas.calculate_campaign_roas(
            account_id=ACCOUNT_ID, campaign_id=CAMPAIGN_ID, days=30
        )

    assert result["roas"] == 0.0
    assert result["conversion_revenue_cents"] == 5000


def test_old_conversions_excluded(roas_tables):
    """REDEEM# rows older than the lookback window do not count."""
    aff = roas_tables["affiliates"]
    in_window = NOW - 5 * 86400
    out_of_window = NOW - 40 * 86400  # older than days=30
    _put_redeem(aff, creative_id="cr1", final_price_cents=30000,
                created_at=in_window, redeem_id="recent")
    _put_redeem(aff, creative_id="cr1", final_price_cents=99999,
                created_at=out_of_window, redeem_id="old")

    from app.services import ad_roas

    with (
        patch.object(ad_roas, "now_ts", return_value=NOW),
        patch.object(ad_roas, "get_summary", return_value={"spend_cents": 60000}),
    ):
        result = ad_roas.calculate_campaign_roas(
            account_id=ACCOUNT_ID, campaign_id=CAMPAIGN_ID, days=30
        )

    assert result["conversion_revenue_cents"] == 30000
    assert result["conversion_count"] == 1
    assert result["roas"] == 0.5  # 30000 / 60000


def test_missing_campaign_returns_empty(roas_tables):
    from app.services import ad_roas

    result = ad_roas.calculate_campaign_roas(
        account_id=ACCOUNT_ID, campaign_id="does-not-exist", days=30
    )
    assert result == {}


def test_get_summary_emits_roas_key(roas_tables):
    """ad_analytics.get_summary now produces a real roas key (closes the
    optimization-alert loop). Before the fix this key was always absent."""
    aff = roas_tables["affiliates"]
    _put_redeem(aff, creative_id="cr1", final_price_cents=40000,
                created_at=NOW - 10, redeem_id="r1")

    from app.services import ad_analytics, ad_roas

    # Force a known spend and a fixed "now" inside the revenue helper.
    with (
        patch.object(ad_analytics, "_fetch_daily_rollups",
                     side_effect=lambda *a, **k: (
                         [] if k.get("offset_days") else
                         [{"spend_cents": 20000, "impressions": 100, "clicks": 5}]
                     )),
        patch.object(ad_roas, "now_ts", return_value=NOW),
    ):
        summary = ad_analytics.get_summary(ACCOUNT_ID, campaign_id=CAMPAIGN_ID, days=30)

    assert "roas" in summary
    assert summary["conversion_revenue_cents"] == 40000
    assert summary["roas"] == 2.0  # 40000 / 20000
