"""GAP-0042 regression: serve_ad must enforce the creator's
allowed_ad_categories whitelist (and min_cpm_cents floor).

Before the fix, serve_ad fetched creator_settings, checked only allow_ads, and
silently discarded allowed_ad_categories / min_cpm_cents -- so a creator who
whitelisted only "sports" still received "gambling" campaigns.

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
def ddb_tables():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        # billing table -- holds creator AD_SETTINGS + AD_BLOCK rows
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

        # ad_campaigns table -- ByStatusCreatedAt GSI used by list_campaigns_by_status
        ddb.create_table(
            TableName="ad_campaigns",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "status", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "ByStatusCreatedAt",
                    "KeySchema": [
                        {"AttributeName": "status", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # ad_creatives table
        ddb.create_table(
            TableName="ad_creatives",
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

        # ad_targeting table
        ddb.create_table(
            TableName="ad_targeting",
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

        # ad_frequency_caps table
        ddb.create_table(
            TableName="ad_frequency_caps",
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

        # ad_accounts table (read by is_account_suspended)
        ddb.create_table(
            TableName="ad_accounts",
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
        names = {
            "billing": "billing",
            "ad_campaigns": "ad_campaigns",
            "ad_creatives": "ad_creatives",
            "ad_targeting": "ad_targeting",
            "ad_frequency_caps": "ad_frequency_caps",
            "ad_accounts": "ad_accounts",
        }
        originals = {attr: getattr(tables_mod.T, attr) for attr in names}
        for attr, table_name in names.items():
            object.__setattr__(tables_mod.T, attr, ddb.Table(table_name))

        yield ddb

        for attr, orig in originals.items():
            object.__setattr__(tables_mod.T, attr, orig)


def _seed_active_campaign(ddb, *, campaign_id, account_id="acct_001",
                          category="general", bid_cpm_cents=500):
    """Seed an active campaign with one approved creative."""
    ddb.Table("ad_campaigns").put_item(Item={
        "pk": f"ACCT#{account_id}",
        "sk": f"CAMPAIGN#{campaign_id}",
        "campaign_id": campaign_id,
        "account_id": account_id,
        "name": f"Campaign {campaign_id}",
        "objective": "awareness",
        "budget_cents": 100000,
        "budget_type": "lifetime",
        "daily_budget_cents": 0,
        "spent_today_cents": 0,
        "lifetime_spent_cents": 0,
        "status": "active",
        "category": category,
        "bid_cpm_cents": bid_cpm_cents,
        "created_at": 1700000000,
        "updated_at": 1700000000,
    })
    ddb.Table("ad_creatives").put_item(Item={
        "pk": f"CAMP#{campaign_id}",
        "sk": f"CREATIVE#cr_{campaign_id}",
        "creative_id": f"cr_{campaign_id}",
        "campaign_id": campaign_id,
        "account_id": account_id,
        "status": "approved",
        "format": "native_post",
        "title": "Ad",
        "rotation_weight": 50,
        "created_at": 1700000000,
        "updated_at": 1700000000,
    })


def _seed_creator_settings(ddb, creator_id, *, allowed_categories, min_cpm_cents=0):
    ddb.Table("billing").put_item(Item={
        "pk": f"USER#{creator_id}",
        "sk": "AD_SETTINGS",
        "allow_ads": True,
        "allowed_ad_categories": allowed_categories,
        "min_cpm_cents": min_cpm_cents,
        "updated_at": 1700000000,
    })


def _serve(creator_id):
    from app.services.ad_serving import serve_ad
    return serve_ad(
        surface="feed",
        content_type="post",
        creator_id=creator_id,
        content_id="post_001",
        slot_type="in_feed",
        user_id="user_001",
    )


def test_category_whitelist_filters_non_matching_campaign(ddb_tables):
    """A gambling campaign must be skipped when the creator whitelists only sports.

    FAILS before the fix: serve_ad ignored allowed_ad_categories and returned
    the gambling campaign as filled.
    """
    _seed_active_campaign(ddb_tables, campaign_id="camp_gambling_01", category="gambling")
    _seed_creator_settings(ddb_tables, "creator_001", allowed_categories=["sports"])

    result = _serve("creator_001")

    assert result.get("is_house_ad") is True
    assert result.get("fill_reason") in ("no_eligible_campaigns", "no_active_campaigns")


def test_category_whitelist_allows_matching_campaign(ddb_tables):
    """A sports campaign must be served when sports is whitelisted."""
    _seed_active_campaign(ddb_tables, campaign_id="camp_sports_01", category="sports")
    _seed_creator_settings(ddb_tables, "creator_002", allowed_categories=["sports"])

    result = _serve("creator_002")

    assert result.get("filled") is True
    assert result.get("is_house_ad") is False
    assert result.get("campaign_id") == "camp_sports_01"


def test_empty_allowed_categories_skips_filter(ddb_tables):
    """Empty allowed_ad_categories means no restriction -- any category passes."""
    _seed_active_campaign(ddb_tables, campaign_id="camp_any_01", category="gambling")
    _seed_creator_settings(ddb_tables, "creator_003", allowed_categories=[])

    result = _serve("creator_003")

    assert result.get("filled") is True
    assert result.get("is_house_ad") is False
    assert result.get("campaign_id") == "camp_any_01"


def test_min_cpm_floor_filters_low_bid_campaign(ddb_tables):
    """A campaign bidding below the creator's min_cpm_cents must be skipped."""
    _seed_active_campaign(ddb_tables, campaign_id="camp_lowbid_01",
                          category="sports", bid_cpm_cents=100)
    _seed_creator_settings(ddb_tables, "creator_004",
                           allowed_categories=["sports"], min_cpm_cents=500)

    result = _serve("creator_004")

    assert result.get("is_house_ad") is True
    assert result.get("fill_reason") in ("no_eligible_campaigns", "no_active_campaigns")
