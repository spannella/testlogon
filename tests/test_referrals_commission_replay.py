"""GAP-0008 regression: affiliate commission replay must be idempotent.

`record_affiliate_commission()` must credit a referrer exactly once per
`transaction_id`, even if the same billing event is replayed (network retry,
webhook redelivery, double-call). Before the fix the sort key embedded a
wall-clock timestamp (``COMMISSION#{ts}#{tx}``) so two calls in different
seconds produced two distinct DynamoDB items — a double payout. After the fix
the SK is deterministic (``COMMISSION#{tx}``) with a conditional write, so the
second call is suppressed.

Offline only: in-memory boto3 + moto, no real AWS.
"""

from __future__ import annotations

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


@pytest.fixture(autouse=True)
def _mock_env(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("APP_TABLE", "app_single_table")
    # Force the referrals service to talk to in-process moto, not :8001.
    monkeypatch.delenv("DDB_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)


@pytest.fixture()
def referral_table(monkeypatch):
    """Create app_single_table (with GSI1) via moto and seed alice->bob attribution.

    Yields the boto3 Table handle. Resets the referrals service module-level
    table cache so it binds to the moto-backed resource.
    """
    import boto3
    from moto import mock_aws

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

        # Reset the lazily-cached table handle so the service uses moto.
        import app.services.referrals as referrals_svc

        monkeypatch.setattr(referrals_svc, "_TABLE", None)

        # Seed a referral code owned by alice and an active attribution bob->alice.
        table.put_item(Item={
            "pk": "REFCODE#ALICECODE",
            "sk": "META",
            "Entity": "ReferralCode",
            "code": "ALICECODE",
            "owner_user_id": "alice",
            "active": True,
            "commission_tier": "standard",
        })
        table.put_item(Item={
            "pk": "REFERRAL#bob",
            "sk": "META",
            "Entity": "ReferralAttribution",
            "referred_user_id": "bob",
            "referrer_user_id": "alice",
            "referral_code": "ALICECODE",
            "status": "active",
            # Far-future window so commission is in-window.
            "commission_window_ends_at": "2999-01-01T00:00:00Z",
        })

        yield table


def _count_commissions(table) -> int:
    resp = table.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={
            ":pk": "AFFILIATE#alice",
            ":prefix": "COMMISSION#",
        },
    )
    return len(resp.get("Items", []))


def test_commission_replay_credits_once(referral_table):
    """Same transaction_id recorded twice => exactly one commission item.

    FAILS before fix (two items / non-None second result),
    PASSES after fix (second result None, one item).
    """
    from app.services.referrals import record_affiliate_commission

    kwargs = dict(
        referred_user_id="bob",
        transaction_id="txn_stripe_pi_9999",
        source_type="purchase",
        gross_amount_cents=1000,
    )

    result1 = record_affiliate_commission(**kwargs)
    result2 = record_affiliate_commission(**kwargs)

    assert result1 is not None, "First write must succeed"
    assert result1["commission_cents"] > 0
    assert result2 is None, "Duplicate transaction must be suppressed"

    assert _count_commissions(referral_table) == 1, "Expected exactly one commission item"


def test_distinct_transactions_each_credited(referral_table):
    """Different transaction_ids must each produce a commission record."""
    from app.services.referrals import record_affiliate_commission

    r1 = record_affiliate_commission(
        referred_user_id="bob",
        transaction_id="txn_a",
        source_type="purchase",
        gross_amount_cents=500,
    )
    r2 = record_affiliate_commission(
        referred_user_id="bob",
        transaction_id="txn_b",
        source_type="purchase",
        gross_amount_cents=500,
    )

    assert r1 is not None
    assert r2 is not None
    assert _count_commissions(referral_table) == 2
