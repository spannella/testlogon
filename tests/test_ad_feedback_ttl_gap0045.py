"""Regression tests for GAP-0045: ad_feedback records accumulate without TTL.

Offline / in-memory only: uses moto's in-memory DynamoDB (no real AWS). The
billing table handle on app.core.tables.T is swapped for a moto-backed table
for the duration of each test.

Before the fix, record_ad_feedback wrote feedback items with no TTL attribute,
so they could never be expired by DynamoDB and accumulated unbounded. After the
fix, every feedback item carries an "expires_at" Unix-epoch attribute 90 days in
the future, which DynamoDB TTL uses to delete the item automatically.
"""
from __future__ import annotations

import boto3
import pytest
from boto3.dynamodb.conditions import Key
from moto import mock_aws

from app.core.time import now_ts
from app.services.ad_feedback import _FEEDBACK_TTL_DAYS, record_ad_feedback


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
            yield ddb.Table("billing")
        finally:
            object.__setattr__(tables_mod.T, "billing", original)


def test_record_ad_feedback_writes_expires_at(billing_table):
    """FAILS BEFORE FIX (KeyError): feedback item must carry an expires_at TTL attr."""
    before = now_ts()
    record_ad_feedback(
        user_id="user_ttl_test",
        creative_id="creative_001",
        campaign_id="camp_001",
        feedback_type="hide",
    )
    after = now_ts()

    resp = billing_table.query(
        KeyConditionExpression=(
            Key("pk").eq("USER#user_ttl_test")
            & Key("sk").begins_with("AD_FEEDBACK#")
        ),
    )
    items = resp["Items"]
    assert len(items) == 1

    expires_at = int(items[0]["expires_at"])
    expected_min = before + _FEEDBACK_TTL_DAYS * 86400
    expected_max = after + _FEEDBACK_TTL_DAYS * 86400
    assert expected_min <= expires_at <= expected_max, (
        f"expires_at={expires_at} outside expected range "
        f"[{expected_min}, {expected_max}]"
    )


def test_record_ad_feedback_ttl_window_is_90_days():
    """The configured retention window must be exactly 90 days."""
    assert _FEEDBACK_TTL_DAYS == 90
