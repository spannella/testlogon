"""GAP-0044 regression: campaigns must persist bid_cpm_cents end-to-end so the
serving engine can rank by real auction bids.

Before the fix:
  * CampaignCreateIn had no bid_cpm_cents field (rejected as an unexpected arg).
  * create_campaign never wrote bid_cpm_cents to DynamoDB.
  * serve_ad therefore always fell back to the hardcoded default of 500, so
    every campaign scored identically and the auction could not differentiate
    a high bid from a low one.

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
                          bid_cpm_cents=500, created_at=1700000000):
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
        "category": "general",
        "bid_cpm_cents": bid_cpm_cents,
        "created_at": created_at,
        "updated_at": created_at,
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
        "created_at": created_at,
        "updated_at": created_at,
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


def test_create_campaign_stores_default_bid_cpm_cents(ddb_tables):
    """create_campaign must persist bid_cpm_cents; default must be 500."""
    from app.services.ad_campaigns import create_campaign
    from app.models import CampaignCreateIn
    from app.core.tables import T

    data = CampaignCreateIn(
        name="Test Campaign",
        objective="awareness",
        budget_cents=5000,
        budget_type="lifetime",
    )
    item = create_campaign("acct_001", data)
    assert item.get("bid_cpm_cents") == 500

    stored = T.ad_campaigns.get_item(
        Key={"pk": "ACCT#acct_001", "sk": f"CAMPAIGN#{item['campaign_id']}"}
    )["Item"]
    assert int(stored["bid_cpm_cents"]) == 500


def test_create_campaign_stores_custom_bid_cpm_cents(ddb_tables):
    """create_campaign must persist a non-default bid_cpm_cents.

    FAILS before the fix: CampaignCreateIn rejected bid_cpm_cents as an
    unexpected field, so the model could not even be constructed.
    """
    from app.services.ad_campaigns import create_campaign
    from app.models import CampaignCreateIn
    from app.core.tables import T

    data = CampaignCreateIn(
        name="High Bid Campaign",
        objective="traffic",
        budget_cents=10000,
        budget_type="daily",
        bid_cpm_cents=1500,
    )
    item = create_campaign("acct_002", data)
    assert item.get("bid_cpm_cents") == 1500

    stored = T.ad_campaigns.get_item(
        Key={"pk": "ACCT#acct_002", "sk": f"CAMPAIGN#{item['campaign_id']}"}
    )["Item"]
    assert int(stored["bid_cpm_cents"]) == 1500


def test_serve_ad_ranks_by_bid_cpm(ddb_tables):
    """serve_ad must select the highest-bid campaign from the eligible set.

    FAILS before the fix: all campaigns fell back to the default 500 score, so
    the GSI ordering (most-recent-first) picked the winner, not the bid.
    """
    # Seed in a misleading order: the highest bid is the OLDEST campaign, so a
    # creation-order winner would pick the low-bid campaign instead.
    _seed_active_campaign(ddb_tables, campaign_id="camp_high_01",
                          bid_cpm_cents=1500, created_at=1700000000)
    _seed_active_campaign(ddb_tables, campaign_id="camp_mid_01",
                          bid_cpm_cents=800, created_at=1700000100)
    _seed_active_campaign(ddb_tables, campaign_id="camp_low_01",
                          bid_cpm_cents=200, created_at=1700000200)

    winners = set()
    for _ in range(10):
        result = _serve("creator_rank_test")
        winners.add(result.get("campaign_id"))

    assert winners == {"camp_high_01"}, (
        f"Expected high-bid campaign to win all auctions, got {winners}"
    )
