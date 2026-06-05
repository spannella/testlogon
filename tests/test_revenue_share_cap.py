"""GAP-0004 regression: creator self-service revenue share is capped at a
platform ceiling (70% = 7000 bps) so a creator cannot self-set a 100% share and
zero out the platform's ad-revenue margin.

Offline: moto in-memory DynamoDB, no real AWS.
"""
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
def billing_table():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="billing",
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
        original = tables_mod.T.billing
        object.__setattr__(tables_mod.T, "billing", ddb.Table("billing"))
        try:
            yield ddb
        finally:
            object.__setattr__(tables_mod.T, "billing", original)


# ── Service-layer clamp ────────────────────────────────────────────────────


def test_creator_cannot_exceed_platform_ceiling(billing_table):
    """A creator setting 10000 bps (100%) is clamped to the platform ceiling."""
    from app.services.content_ad_controls import (
        set_creator_revenue_share_bps,
        get_creator_revenue_share_bps,
        MAX_CREATOR_REVENUE_SHARE_BPS,
    )

    assert MAX_CREATOR_REVENUE_SHARE_BPS == 7000

    result = set_creator_revenue_share_bps("creator_1", 10000)
    assert result["revenue_share_bps"] == MAX_CREATOR_REVENUE_SHARE_BPS
    assert result["revenue_share_bps"] <= 7000

    # And it is the value actually persisted.
    assert get_creator_revenue_share_bps("creator_1") == 7000


def test_creator_can_set_share_within_ceiling(billing_table):
    """Values at or below the ceiling are stored as-is."""
    from app.services.content_ad_controls import set_creator_revenue_share_bps

    assert set_creator_revenue_share_bps("creator_2", 5000)["revenue_share_bps"] == 5000
    assert set_creator_revenue_share_bps("creator_2", 7000)["revenue_share_bps"] == 7000


def test_creator_cannot_set_negative_share(billing_table):
    """Negative values are clamped to 0."""
    from app.services.content_ad_controls import set_creator_revenue_share_bps

    assert set_creator_revenue_share_bps("creator_3", -100)["revenue_share_bps"] == 0


# ── Pydantic model bound ───────────────────────────────────────────────────


def test_revenue_share_in_model_rejects_above_ceiling():
    """RevenueShareIn rejects any value above 7000 (e.g. the 10000 exploit)."""
    from pydantic import ValidationError
    from app.models import RevenueShareIn

    with pytest.raises(ValidationError):
        RevenueShareIn(revenue_share_bps=10000)
    with pytest.raises(ValidationError):
        RevenueShareIn(revenue_share_bps=7001)


def test_revenue_share_in_model_accepts_at_ceiling():
    """RevenueShareIn accepts the exact ceiling value and below."""
    from app.models import RevenueShareIn

    assert RevenueShareIn(revenue_share_bps=7000).revenue_share_bps == 7000
    assert RevenueShareIn(revenue_share_bps=0).revenue_share_bps == 0
