"""Offline regression test for GAP-0106: top-content view attribution.

Bug: ``get_top_content`` (and the ``get_overview`` top-content block) credited
every content ID listed in a day's ``top_content_ids`` with the day's AGGREGATE
``total_views`` rollup figure, instead of that item's own per-content view count.
A day with two content IDs and 300 total views showed 300 views for BOTH items.

The fix resolves per-content live view counts from the source-of-truth metadata
tables (video_metadata / app_single_table) before ranking, so each item shows
its own count and the sort order reflects real popularity.

Uses moto's in-memory DynamoDB — no real AWS, no dev stack required.
This test fails before the fix and passes after.
"""
from __future__ import annotations

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
def analytics_tables():
    """Wire analytics_rollups + video_metadata to in-memory moto tables and
    point the creator_analytics module-level ddb resource at moto."""
    with mock_aws():
        from app.core.settings import S as _S

        video_table_name = _S.video_metadata_table_name
        ddb_res = boto3.resource("dynamodb", region_name="us-east-1")

        rollups = ddb_res.create_table(
            TableName="analytics_rollups",
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
        video_meta = ddb_res.create_table(
            TableName=video_table_name,
            KeySchema=[{"AttributeName": "video_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "video_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        # _resolve_content_details resolves posts from APP_TABLE; create it so
        # the post branch (if exercised) does not error.
        app_table_name = os.environ.get("APP_TABLE", "app_single_table")
        ddb_res.create_table(
            TableName=app_table_name,
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
        import app.services.creator_analytics as ca

        orig_rollups = tables_mod.T.analytics_rollups
        orig_video = tables_mod.T.video_metadata
        orig_ca_ddb = ca.ddb

        object.__setattr__(tables_mod.T, "analytics_rollups", rollups)
        object.__setattr__(tables_mod.T, "video_metadata", video_meta)
        ca.ddb = ddb_res
        try:
            yield {"rollups": rollups, "video_meta": video_meta}
        finally:
            object.__setattr__(tables_mod.T, "analytics_rollups", orig_rollups)
            object.__setattr__(tables_mod.T, "video_metadata", orig_video)
            ca.ddb = orig_ca_ddb


def _seed(tables):
    """Three rollup days. vid_bbb appears on all three days; vid_aaa on one.

    With the OLD per-cid accumulation of the day's aggregate total_views:
      vid_aaa score = 300              (one day)
      vid_bbb score = 300 + 300 + 300  (three days) = 900
    so vid_bbb would inflate to the top of the ranking and each item's views
    would be a multiple of the day totals.

    Live per-content counts are the source of truth: vid_aaa=200, vid_bbb=100.
    After the fix, ranking and views use the live counts, so vid_aaa ranks
    first and each item shows its own count (not the day aggregate)."""
    for day in ("2026-01-01", "2026-01-02", "2026-01-03"):
        ids = ["vid_aaa", "vid_bbb"] if day == "2026-01-01" else ["vid_bbb"]
        tables["rollups"].put_item(Item={
            "pk": "CREATOR#creator_test",
            "sk": f"DAILY#{day}",
            "total_views": 300,
            "revenue_cents": 0,
            "top_content_ids": ids,
        })
    tables["video_meta"].put_item(
        Item={"video_id": "vid_aaa", "title": "A", "view_count": 200}
    )
    tables["video_meta"].put_item(
        Item={"video_id": "vid_bbb", "title": "B", "view_count": 100}
    )


def test_top_content_uses_per_content_views_not_day_total(analytics_tables):
    from app.services.creator_analytics import get_top_content

    _seed(analytics_tables)

    result = get_top_content("creator_test", "2026-01-01", "2026-01-03")
    by_id = {i["content_id"]: i for i in result["items"]}

    # Before fix: both items showed views == 300 (the day's aggregate total).
    assert by_id["vid_aaa"]["views"] == 200, "vid_aaa must show its own count"
    assert by_id["vid_bbb"]["views"] == 100, "vid_bbb must show its own count"
    # Sort order must reflect real per-content view counts.
    assert result["items"][0]["content_id"] == "vid_aaa"
    assert result["items"][1]["content_id"] == "vid_bbb"


def test_overview_top_content_uses_per_content_views_not_day_total(analytics_tables):
    from app.services.creator_analytics import get_overview

    _seed(analytics_tables)

    result = get_overview("creator_test", "2026-01-01", "2026-01-03")
    by_id = {i["content_id"]: i for i in result["top_content"]}

    # Before fix: both items showed views == 300.
    assert by_id["vid_aaa"]["views"] == 200, "vid_aaa must show its own count"
    assert by_id["vid_bbb"]["views"] == 100, "vid_bbb must show its own count"
    assert result["top_content"][0]["content_id"] == "vid_aaa"
