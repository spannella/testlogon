"""Offline regression tests for GAP-0001: daily ad budget reset task.

Verifies that ``app.services.ad_daily_reset._reset_daily_spend_once`` zeroes
``spent_today_cents`` for daily-budget campaigns and is idempotent within the
same UTC day. Uses moto's in-memory DynamoDB — no real AWS, no sleeping.
"""
from __future__ import annotations

import os

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


@pytest.fixture
def ad_campaigns_table():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = ddb.create_table(
            TableName="ad_campaigns",
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

        original = tables_mod.T.ad_campaigns
        object.__setattr__(tables_mod.T, "ad_campaigns", table)
        try:
            yield table
        finally:
            object.__setattr__(tables_mod.T, "ad_campaigns", original)


def _put_campaign(table, *, campaign_id, budget_type, spent, daily_budget=1000):
    table.put_item(
        Item={
            "pk": f"ACCT#{campaign_id}",
            "sk": f"CAMPAIGN#{campaign_id}",
            "campaign_id": campaign_id,
            "budget_type": budget_type,
            "spent_today_cents": spent,
            "daily_budget_cents": daily_budget,
            "budget_cents": 50000,
            "lifetime_spent_cents": spent,
        }
    )


def _get_spent(table, campaign_id):
    item = table.get_item(
        Key={"pk": f"ACCT#{campaign_id}", "sk": f"CAMPAIGN#{campaign_id}"}
    )["Item"]
    return int(item["spent_today_cents"])


def test_reset_zeroes_daily_budget_campaigns(ad_campaigns_table):
    from app.services.ad_daily_reset import _reset_daily_spend_once

    _put_campaign(ad_campaigns_table, campaign_id="c1", budget_type="daily", spent=1000)
    _put_campaign(ad_campaigns_table, campaign_id="c2", budget_type="daily", spent=500)

    n = _reset_daily_spend_once()

    assert n == 2
    assert _get_spent(ad_campaigns_table, "c1") == 0
    assert _get_spent(ad_campaigns_table, "c2") == 0


def test_reset_leaves_lifetime_campaigns_untouched(ad_campaigns_table):
    from app.services.ad_daily_reset import _reset_daily_spend_once

    _put_campaign(ad_campaigns_table, campaign_id="d1", budget_type="daily", spent=1000)
    _put_campaign(
        ad_campaigns_table, campaign_id="l1", budget_type="lifetime", spent=1000
    )

    _reset_daily_spend_once()

    assert _get_spent(ad_campaigns_table, "d1") == 0
    # Lifetime campaigns must not have their accumulator zeroed.
    assert _get_spent(ad_campaigns_table, "l1") == 1000


def test_reset_is_idempotent_same_day(ad_campaigns_table):
    """Second run on the same UTC day is a no-op (resets zero campaigns)."""
    from app.services.ad_daily_reset import _reset_daily_spend_once

    _put_campaign(ad_campaigns_table, campaign_id="c1", budget_type="daily", spent=1000)

    first = _reset_daily_spend_once()
    second = _reset_daily_spend_once()

    assert first == 1
    assert second == 0
    assert _get_spent(ad_campaigns_table, "c1") == 0


def test_reset_restores_serving_eligibility(ad_campaigns_table):
    """After reset, an exhausted daily campaign passes _has_budget again."""
    from app.services.ad_daily_reset import _reset_daily_spend_once
    from app.services.ad_serving import _has_budget

    exhausted = {
        "budget_type": "daily",
        "daily_budget_cents": 1000,
        "spent_today_cents": 1000,
        "budget_cents": 50000,
        "lifetime_spent_cents": 1000,
    }
    assert _has_budget(exhausted) is False

    _put_campaign(ad_campaigns_table, campaign_id="c1", budget_type="daily", spent=1000)
    _reset_daily_spend_once()

    item = ad_campaigns_table.get_item(
        Key={"pk": "ACCT#c1", "sk": "CAMPAIGN#c1"}
    )["Item"]
    assert _has_budget(item) is True


def test_seconds_until_midnight_utc_in_range():
    from app.services.ad_daily_reset import _seconds_until_midnight_utc

    secs = _seconds_until_midnight_utc()
    assert 0 < secs <= 86400
