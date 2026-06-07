"""Regression test for GAP-0059 (ADS-012).

`app/services/content_boost.create_boost` charged the caller's wallet and wrote a
new boost record WITHOUT checking whether an ACTIVE boost already existed for the
same ``(content_type, content_id)`` pair. An owner could stack multiple active
boosts for the same content, paying the budget repeatedly with no validation
(double-charge / distorted ranking weights).

The fix queries the existing GSI2 read path (``active_boost_for_content``) right
after the GAP-0058 ownership check and BEFORE any wallet money moves, raising
``DuplicateBoostError`` (mapped to HTTP 409 in the router) when a live boost
already exists.

These tests are fully offline: real DynamoDB tables are stood up in-process with
moto (no real AWS, no DynamoDB Local). The content_boosts table is created with
the GSI2 index so the actual ``active_boost_for_content`` query path runs.

Fails before the fix (second boost succeeds, wallet charged twice). Passes after
(second boost rejected with DuplicateBoostError, wallet charged exactly once).
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
POST_ID = "post_001"


def _make_kv_table(ddb, name):
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
    """content_boosts table WITH GSI2 (matches scripts/local-ddb-init.py) so the
    real active_boost_for_content GSI2 query exercises end-to-end."""
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
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        billing = _make_kv_table(ddb, "billing_test")
        boosts = _make_boosts_table(ddb, "content_boosts_test")
        feed = _make_kv_table(ddb, "newsfeed_test")

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
        # Seed: a well-funded wallet so an unguarded second charge WOULD succeed.
        billing.put_item(
            Item={
                "pk": user_pk(POST_OWNER),
                "sk": WALLET_SK,
                "wallet_balance_cents": Decimal(10000),
                "currency": "usd",
            }
        )
        yield {"billing": billing, "boosts": boosts, "feed": feed}


def _balance(billing, sub):
    item = billing.get_item(Key={"pk": user_pk(sub), "sk": WALLET_SK}).get("Item") or {}
    return int(item.get("wallet_balance_cents", 0))


def test_duplicate_active_boost_rejected_and_wallet_charged_once(moto_tables):
    """A second boost for content that already has a live boost is rejected
    BEFORE any second wallet charge."""
    billing = moto_tables["billing"]
    boosts = moto_tables["boosts"]
    before = _balance(billing, POST_OWNER)

    # First boost succeeds (now=1000 -> ends_at = 1000 + 3600).
    first = svc.create_boost(
        POST_OWNER,
        content_type="post",
        content_id=POST_ID,
        budget_cents=500,
        duration_seconds=3600,
        now=1000,
    )
    assert first["status"] == "active"
    assert _balance(billing, POST_OWNER) == before - 500

    # Second boost while the first is still active -> DuplicateBoostError, no charge.
    with pytest.raises(svc.DuplicateBoostError, match="active boost already exists"):
        svc.create_boost(
            POST_OWNER,
            content_type="post",
            content_id=POST_ID,
            budget_cents=500,
            duration_seconds=3600,
            now=1500,  # still within the first boost's window
        )

    # Wallet charged exactly once; only one boost record persisted.
    assert _balance(billing, POST_OWNER) == before - 500
    assert len(boosts.scan().get("Items", [])) == 1
    # DuplicateBoostError remains a ValueError for backward-compatible handlers.
    assert issubclass(svc.DuplicateBoostError, ValueError)


def test_new_boost_allowed_after_previous_expires(moto_tables):
    """Once the prior boost has expired (by duration), a new boost is allowed."""
    billing = moto_tables["billing"]
    before = _balance(billing, POST_OWNER)

    svc.create_boost(
        POST_OWNER,
        content_type="post",
        content_id=POST_ID,
        budget_cents=500,
        duration_seconds=3600,
        now=1000,  # ends_at = 4600
    )

    # now well past ends_at -> first boost no longer active -> second allowed.
    second = svc.create_boost(
        POST_OWNER,
        content_type="post",
        content_id=POST_ID,
        budget_cents=500,
        duration_seconds=3600,
        now=10000,
    )
    assert second["status"] == "active"
    assert _balance(billing, POST_OWNER) == before - 1000
