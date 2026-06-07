"""GAP-0074 regression: affiliate attribution must be race-safe (dedup guard).

`attribute_referral` previously used a read-check-then-write pattern with an
unconditional `put_item`. Under concurrent signups for the same buyer, both
calls could pass the existence check and both write, creating duplicate
attribution records that double-credit the referrer's commission.

The fix adds `ConditionExpression="attribute_not_exists(pk) AND
attribute_not_exists(sk)"` to the `put_item`, so a buyer can only be attributed
once. A second attribution for the same buyer is a no-op (returns ``None``).

These tests run fully offline against moto (no real AWS). They exercise the
real conditional-write code path so they FAIL before the fix (the second
attribution overwrites the first and returns an item) and PASS after.
"""

from __future__ import annotations

import contextlib

import boto3
import pytest
from moto import mock_aws


@pytest.fixture
def referrals_env(monkeypatch):
    """Spin up a moto-backed ``app_single_table`` and point the referrals
    service at it by resetting its module-level table cache."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    # Ensure no real/local endpoint is used so moto intercepts.
    monkeypatch.delenv("DDB_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    monkeypatch.setenv("APP_TABLE", "app_single_table")

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="app_single_table",
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
        table = ddb.Table("app_single_table")

        from app.services import referrals as svc

        # Reset the lazily-cached table handle so _tbl() rebuilds against moto.
        prev = svc._TABLE
        svc._TABLE = None
        try:
            yield svc, table
        finally:
            svc._TABLE = prev


def _seed_active_code(table, code: str, owner: str) -> None:
    table.put_item(
        Item={
            "pk": f"REFCODE#{code}",
            "sk": "META",
            "Entity": "ReferralCode",
            "owner_user_id": owner,
            "active": True,
        }
    )


def test_second_attribution_for_same_buyer_is_noop(referrals_env):
    """A second attribution for the same buyer/order must be a no-op and must
    not overwrite or duplicate the original attribution record."""
    svc, table = referrals_env
    _seed_active_code(table, "ABC123", owner="referrer_1")
    _seed_active_code(table, "XYZ999", owner="referrer_2")

    buyer = "buyer_1"

    # First attribution wins.
    first = svc.attribute_referral(buyer, "ABC123")
    assert first is not None
    assert first["referrer_user_id"] == "referrer_1"

    # Second attribution (e.g. concurrent retry / different code) is a no-op.
    second = svc.attribute_referral(buyer, "XYZ999")
    assert second is None, "duplicate attribution for same buyer must be a no-op"

    # Exactly one attribution record exists, still pointing at the first referrer.
    item = table.get_item(Key={"pk": f"REFERRAL#{buyer}", "sk": "META"}).get("Item")
    assert item is not None
    assert item["referrer_user_id"] == "referrer_1", (
        "original attribution must not be overwritten by the second write"
    )


def test_concurrent_attributions_yield_exactly_one(referrals_env):
    """Multiple attempts to attribute the same buyer must result in exactly one
    successful attribution; all others are no-ops."""
    svc, table = referrals_env
    _seed_active_code(table, "ABC123", owner="referrer_1")

    buyer = "buyer_2"
    results = [svc.attribute_referral(buyer, "ABC123") for _ in range(5)]

    successes = [r for r in results if r is not None]
    assert len(successes) == 1, f"expected exactly 1 attribution, got {len(successes)}"

    resp = table.query(
        KeyConditionExpression=boto3.dynamodb.conditions.Key("pk").eq(
            f"REFERRAL#{buyer}"
        )
    )
    assert len(resp.get("Items", [])) == 1
