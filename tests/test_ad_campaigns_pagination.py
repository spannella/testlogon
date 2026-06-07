"""Offline regression test for GAP-0043: list_campaigns_by_status pagination.

``app.services.ad_campaigns.list_campaigns_by_status`` queried the
``ByStatusCreatedAt`` GSI with a single ``query()`` call and returned only
``resp["Items"]`` — silently dropping every campaign on subsequent DynamoDB
pages (campaigns beyond the first ~1 MB page were never served).

This verifies the function now follows ``LastEvaluatedKey`` and accumulates
all pages. Uses moto's in-memory DynamoDB with a mocked ``query`` to simulate
paginated responses — no real AWS, no sleeping.
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
                }
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


def _put_active_campaign(table, *, campaign_id, created_at):
    table.put_item(
        Item={
            "pk": f"ACCT#acct_test",
            "sk": f"CAMPAIGN#{campaign_id}",
            "campaign_id": campaign_id,
            "account_id": "acct_test",
            "status": "active",
            "created_at": created_at,
        }
    )


def test_list_campaigns_by_status_paginates_all_pages(ad_campaigns_table):
    """Must return campaigns from every DynamoDB page, not just the first."""
    from app.core.tables import T
    from app.services.ad_campaigns import list_campaigns_by_status

    _put_active_campaign(ad_campaigns_table, campaign_id="c1", created_at=100)
    _put_active_campaign(ad_campaigns_table, campaign_id="c2", created_at=200)
    _put_active_campaign(ad_campaigns_table, campaign_id="c3", created_at=300)

    # Fetch the real items so we can split them across simulated pages.
    from boto3.dynamodb.conditions import Key

    all_items = T.ad_campaigns.query(
        IndexName="ByStatusCreatedAt",
        KeyConditionExpression=Key("status").eq("active"),
    )["Items"]
    assert len(all_items) == 3

    call_count = [0]

    def mock_query(**kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return {"Items": all_items[:1], "LastEvaluatedKey": {"pk": "sentinel"}}
        return {"Items": all_items[1:]}

    with patch.object(T.ad_campaigns, "query", side_effect=mock_query):
        result = list_campaigns_by_status("active")

    # Before the fix: only the first page (1 item) was returned.
    assert len(result) == 3, f"Expected 3 campaigns across all pages, got {len(result)}"
    assert call_count[0] == 2, "Expected two Query calls (followed LastEvaluatedKey)"


def test_list_campaigns_by_status_respects_limit(ad_campaigns_table):
    """The hard limit bounds total items and stops further pagination."""
    from app.core.tables import T
    from app.services.ad_campaigns import list_campaigns_by_status

    call_count = [0]

    def mock_query(**kwargs):
        call_count[0] += 1
        # Always return one item plus a continuation cursor.
        return {
            "Items": [{"campaign_id": f"c{call_count[0]}", "status": "active"}],
            "LastEvaluatedKey": {"pk": "sentinel"},
        }

    with patch.object(T.ad_campaigns, "query", side_effect=mock_query):
        result = list_campaigns_by_status("active", limit=3)

    assert len(result) == 3
    # Loop stops once the accumulated count reaches the limit.
    assert call_count[0] == 3
