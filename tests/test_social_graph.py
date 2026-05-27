"""Unit tests for SOC-001: Follow System (social graph service)."""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


@pytest.fixture(autouse=True)
def _mock_env(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "1")
    monkeypatch.setenv("DDB_ENDPOINT_URL", "http://localhost:8001")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("UI_ACCESS_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("API_KEY_PEPPER", "test-pepper")
    monkeypatch.setenv("APP_TABLE", "app_single_table")
    monkeypatch.setenv("PROFILE_TABLE_NAME", "profiles")


@pytest.fixture()
def social_tables():
    """Create app_single_table with GSI5 and profiles table using moto."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        # Create app_single_table with GSI5
        ddb.create_table(
            TableName="app_single_table",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "GSI5PK", "AttributeType": "S"},
                {"AttributeName": "GSI5SK", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI5",
                    "KeySchema": [
                        {"AttributeName": "GSI5PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI5SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Create profiles table
        ddb.create_table(
            TableName="profiles",
            KeySchema=[
                {"AttributeName": "user_sub", "KeyType": "HASH"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "user_sub", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        app_table = ddb.Table("app_single_table")
        profile_table = ddb.Table("profiles")

        # Seed profiles for test users
        for user_sub in ["alice", "bob", "charlie", "target", "popular", "source"]:
            profile_table.put_item(Item={
                "user_sub": user_sub,
                "display_name": user_sub.capitalize(),
            })
        # Seed profiles for follower_ and target_ and f_ test IDs
        for i in range(210):
            profile_table.put_item(Item={
                "user_sub": f"follower_{i}",
                "display_name": f"Follower {i}",
            })
            profile_table.put_item(Item={
                "user_sub": f"target_{i}",
                "display_name": f"Target {i}",
            })
            profile_table.put_item(Item={
                "user_sub": f"f_{i}",
                "display_name": f"F {i}",
            })

        # Patch the social module's table references to use moto tables
        with patch("app.services.social.tbl", app_table), \
             patch("app.services.social.T") as mock_T:
            mock_T.profile = profile_table
            yield {
                "app_table": app_table,
                "profile_table": profile_table,
            }


# ── Follow / Unfollow ─────────────────────────────────────────────────────

def test_follow_user_creates_record(social_tables):
    from app.services.social import follow_user

    result = follow_user("alice", "bob")
    assert result["ok"] is True
    assert result["status"] == "followed"
    assert result["follower_count"] >= 1

    # Verify DDB item directly
    item = social_tables["app_table"].get_item(
        Key={"pk": "USER#alice", "sk": "FOLLOWING#bob"}
    ).get("Item")
    assert item is not None
    assert item["state"] == "following"
    assert item["GSI5PK"] == "FOLLOWERS#bob"
    assert "GSI5SK" in item
    assert item["Entity"] == "Following"
    assert item["created_at"] is not None


def test_follow_idempotency(social_tables):
    from app.services.social import follow_user, get_follow_counts

    follow_user("alice", "bob")
    result = follow_user("alice", "bob")
    assert result["status"] == "already_following"
    counts = get_follow_counts("bob")
    assert counts["follower_count"] == 1  # Not 2


def test_unfollow_user(social_tables):
    from app.services.social import follow_user, unfollow_user

    follow_user("alice", "bob")
    result = unfollow_user("alice", "bob")
    assert result["status"] == "unfollowed"

    item = social_tables["app_table"].get_item(
        Key={"pk": "USER#alice", "sk": "FOLLOWING#bob"}
    ).get("Item")
    assert item["state"] == "unfollowed"
    assert "GSI5PK" not in item
    assert "GSI5SK" not in item


def test_unfollow_when_not_following(social_tables):
    from app.services.social import unfollow_user

    result = unfollow_user("alice", "bob")
    assert result["status"] == "not_following"


def test_self_follow_prevention(social_tables):
    from app.services.social import follow_user

    with pytest.raises(ValueError, match="self_follow"):
        follow_user("alice", "alice")


def test_user_not_found(social_tables):
    from app.services.social import follow_user

    with pytest.raises(ValueError, match="user_not_found"):
        follow_user("alice", "nonexistent_user_12345")


# ── Follower / Following lists ────────────────────────────────────────────

def test_follower_list(social_tables):
    from app.services.social import follow_user, get_followers

    follow_user("alice", "bob")
    followers, cursor = get_followers("bob", limit=20)
    follower_ids = [f.get("user_id") for f in followers]
    assert "alice" in follower_ids


def test_follower_list_excludes_unfollowed(social_tables):
    from app.services.social import follow_user, unfollow_user, get_followers

    follow_user("alice", "bob")
    unfollow_user("alice", "bob")
    followers, _ = get_followers("bob")
    follower_ids = [f.get("user_id") for f in followers]
    assert "alice" not in follower_ids


def test_following_list(social_tables):
    from app.services.social import follow_user, get_following

    follow_user("alice", "bob")
    following, cursor = get_following("alice", limit=20)
    following_ids = [f.get("target_user_id") for f in following]
    assert "bob" in following_ids


# ── Counts ────────────────────────────────────────────────────────────────

def test_follow_counts_accuracy(social_tables):
    from app.services.social import follow_user, get_follow_counts

    for i in range(5):
        follow_user("alice", f"target_{i}")
    counts = get_follow_counts("alice")
    assert counts["following_count"] == 5

    for i in range(3):
        follow_user(f"follower_{i}", "bob")
    counts = get_follow_counts("bob")
    assert counts["follower_count"] == 3


def test_count_clamp_at_zero(social_tables):
    from app.services.social import follow_user, unfollow_user, get_follow_counts

    # Set up: create profiles with count=0 then force an unfollow
    social_tables["profile_table"].put_item(
        Item={"user_sub": "bob", "follower_count": 0}
    )
    social_tables["profile_table"].put_item(
        Item={"user_sub": "alice", "following_count": 0}
    )
    # Write a fake follow record directly
    social_tables["app_table"].put_item(
        Item={"pk": "USER#alice", "sk": "FOLLOWING#bob", "state": "following"}
    )
    unfollow_user("alice", "bob")
    assert get_follow_counts("bob")["follower_count"] == 0
    assert get_follow_counts("alice")["following_count"] == 0


# ── Follow status ─────────────────────────────────────────────────────────

def test_follow_status_all_permutations(social_tables):
    from app.services.social import follow_user, get_follow_status

    # Neither follows
    status = get_follow_status("alice", "bob")
    assert not status["is_following"]
    assert not status["is_followed_by"]
    assert not status["is_mutual"]

    # Alice follows Bob
    follow_user("alice", "bob")
    status = get_follow_status("alice", "bob")
    assert status["is_following"]
    assert not status["is_followed_by"]
    assert not status["is_mutual"]

    # Bob follows Alice (mutual)
    follow_user("bob", "alice")
    status = get_follow_status("alice", "bob")
    assert status["is_following"]
    assert status["is_followed_by"]
    assert status["is_mutual"]


# ── Block ─────────────────────────────────────────────────────────────────

def test_block_prevents_follow(social_tables):
    from app.services.social import follow_user

    social_tables["app_table"].put_item(
        Item={"pk": "USER#bob", "sk": "BLOCKED#alice", "state": "blocked"}
    )
    with pytest.raises(ValueError, match="blocked"):
        follow_user("alice", "bob")


# ── Mutual followers ──────────────────────────────────────────────────────

def test_mutual_followers(social_tables):
    from app.services.social import follow_user, get_mutual_followers

    # Alice follows Bob, Charlie follows Bob, Alice follows Charlie
    follow_user("alice", "bob")
    follow_user("charlie", "bob")
    follow_user("alice", "charlie")

    # Mutual(Alice, Bob) = users that Alice follows AND who follow Bob
    # Alice follows: bob, charlie
    # Bob's followers: alice, charlie
    # Intersection: charlie (alice can't be mutual of herself)
    mutuals, _ = get_mutual_followers("alice", "bob")
    mutual_ids = [m["user_id"] for m in mutuals]
    assert "charlie" in mutual_ids


# ── Count reconciliation ──────────────────────────────────────────────────

def test_count_reconciliation(social_tables):
    from app.services.social import follow_user, reconcile_follow_counts

    follow_user("follower_100", "target")
    follow_user("follower_101", "target")

    # Corrupt the count
    social_tables["profile_table"].update_item(
        Key={"user_sub": "target"},
        UpdateExpression="SET follower_count = :bad",
        ExpressionAttributeValues={":bad": 999},
    )

    result = reconcile_follow_counts("target")
    assert result["follower_count"] == 2
