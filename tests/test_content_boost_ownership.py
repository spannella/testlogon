"""Regression test for GAP-0058 (ADS-012).

`app/services/content_boost.create_boost` charged the caller's wallet and created
a boost record WITHOUT verifying the caller actually owns the content being
boosted. Any authenticated user could pay to elevate another creator's post,
video, or broadcast in the feed/serving ranking.

These tests are fully offline: real DynamoDB tables are stood up in-process with
moto (no real AWS, no DynamoDB Local). They fail before the
`_verify_content_ownership` fix (wallet charged, no exception) and pass after
(non-owner rejected with PermissionError, wallet untouched; owner succeeds).
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

import boto3
import pytest
from moto import mock_aws

import app.services.content_boost as svc
import app.routers.newsfeed as newsfeed
from app.services.billing_shared import user_pk, WALLET_SK

POST_OWNER = "user_alice"
STRANGER = "user_bob"
POST_ID = "post_001"


def _make_table(ddb, name):
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


def _make_boosts_table(ddb, name):
    """content_boosts table WITH GSI2 (matches scripts/local-ddb-init.py). The
    GAP-0059 duplicate guard in create_boost queries GSI2, so the fixture must
    mirror the prod schema."""
    return ddb.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI2PK", "AttributeType": "S"},
            {"AttributeName": "GSI2SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI2",
                "KeySchema": [
                    {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@pytest.fixture
def moto_tables(monkeypatch):
    """Stand up billing, content_boosts and newsfeed tables in moto and wire
    the service/router module handles to them. Seed a post owned by Alice and a
    funded wallet for both users."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        billing = _make_table(ddb, "billing_test")
        boosts = _make_boosts_table(ddb, "content_boosts_test")
        feed = _make_table(ddb, "newsfeed_test")

        # Wire the table handles the service + router reach for. ``T`` is a
        # frozen dataclass, so swap the whole singleton the service module sees
        # for a lightweight stand-in carrying the moto tables.
        fake_T = SimpleNamespace(billing=billing, content_boosts=boosts)
        monkeypatch.setattr(svc, "T", fake_T)
        monkeypatch.setattr(newsfeed, "tbl", feed, raising=False)

        # Seed: a post owned by Alice.
        feed.put_item(
            Item={
                "pk": newsfeed.pk_post(POST_ID),
                "sk": newsfeed.sk_post(),
                "post_id": POST_ID,
                "user_id": POST_OWNER,
            }
        )
        # Seed: funded wallets so an unguarded charge WOULD succeed.
        for sub in (POST_OWNER, STRANGER):
            billing.put_item(
                Item={
                    "pk": user_pk(sub),
                    "sk": WALLET_SK,
                    "wallet_balance_cents": Decimal(10000),
                    "currency": "usd",
                }
            )
        yield {"billing": billing, "boosts": boosts, "feed": feed}


def _balance(billing, sub):
    item = billing.get_item(Key={"pk": user_pk(sub), "sk": WALLET_SK}).get("Item") or {}
    return int(item.get("wallet_balance_cents", 0))


def test_non_owner_cannot_boost_and_wallet_not_charged(moto_tables):
    """A user cannot boost content they don't own: rejected, no charge."""
    billing = moto_tables["billing"]
    boosts = moto_tables["boosts"]

    before = _balance(billing, STRANGER)
    with pytest.raises(PermissionError, match="do not own"):
        svc.create_boost(
            STRANGER,
            content_type="post",
            content_id=POST_ID,
            budget_cents=500,
            duration_seconds=3600,
        )

    # Wallet untouched.
    assert _balance(billing, STRANGER) == before
    # No boost record written.
    assert boosts.scan().get("Items", []) == []


def test_owner_can_boost_and_wallet_charged(moto_tables):
    """The legitimate owner can boost their own content; wallet is debited."""
    billing = moto_tables["billing"]

    before = _balance(billing, POST_OWNER)
    result = svc.create_boost(
        POST_OWNER,
        content_type="post",
        content_id=POST_ID,
        budget_cents=500,
        duration_seconds=3600,
    )

    assert result["owner_sub"] == POST_OWNER
    assert result["content_id"] == POST_ID
    assert result["status"] == "active"
    assert _balance(billing, POST_OWNER) == before - 500


def test_boost_nonexistent_content_raises_not_found(moto_tables):
    """Boosting content that does not exist raises ValueError('not found')
    before any wallet charge."""
    billing = moto_tables["billing"]
    before = _balance(billing, POST_OWNER)

    with pytest.raises(ValueError, match="not found"):
        svc.create_boost(
            POST_OWNER,
            content_type="post",
            content_id="ghost_post",
            budget_cents=500,
            duration_seconds=3600,
        )
    assert _balance(billing, POST_OWNER) == before
