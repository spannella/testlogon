from __future__ import annotations

from unittest.mock import Mock, patch

from scripts.backfill_newsfeed_plain_fields import (
    infer_body_format,
    infer_body_plain,
    is_newsfeed_content_row,
    plan_update,
)
from scripts.backfill_newsfeed_lock_type import (
    infer_lock_type,
    is_post_row,
    plan_update as plan_lock_type_update,
    run as run_lock_type_backfill,
)


def test_infer_body_plain_prefers_existing_plain_then_legacy_then_markdown_then_rich() -> None:
    assert infer_body_plain({"body_plain": "  plain  ", "body": "legacy"}) == "plain"
    assert infer_body_plain({"body": " legacy "}) == "legacy"
    assert infer_body_plain({"body_markdown": " # title "}) == "# title"
    assert (
        infer_body_plain({"body_rich": {"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Hello"}]}]}})
        == "Hello"
    )


def test_infer_body_format_defaults_and_inference() -> None:
    assert infer_body_format({"body_format": "markdown"}) == "markdown"
    assert infer_body_format({"body_rich": {"type": "doc", "content": []}}) == "rich"
    assert infer_body_format({"body_markdown": "- item"}) == "markdown"
    assert infer_body_format({"body": "legacy"}) == "plain"
    assert infer_body_format({"body_format": "html", "body": "legacy"}) == "plain"


def test_is_newsfeed_content_row_matches_post_and_comment_entities() -> None:
    assert is_newsfeed_content_row({"Entity": "Post", "post_id": "p1"}) is True
    assert is_newsfeed_content_row({"Entity": "Comment", "comment_id": "c1"}) is True
    assert is_newsfeed_content_row({"Entity": "FeedRef", "post_id": "p1"}) is False


def test_plan_update_flags_missing_plain_source_as_malformed() -> None:
    should_update, values, reason = plan_update({"Entity": "Post", "post_id": "p1", "pk": "POST#p1", "sk": "META"})
    assert should_update is False
    assert values == {}
    assert reason == "missing_plain_source"


def test_plan_update_is_idempotent_when_fields_already_match() -> None:
    item = {
        "Entity": "Comment",
        "comment_id": "c1",
        "pk": "POST#p1#COMMENTS",
        "sk": "2026-01-01#CMT#c1",
        "body": "legacy",
        "body_plain": "legacy",
        "body_format": "plain",
    }
    should_update, values, reason = plan_update(item)
    assert should_update is False
    assert values == {}
    assert reason is None


def test_plan_update_sets_plain_and_default_format_for_legacy_row() -> None:
    item = {
        "Entity": "Post",
        "post_id": "p1",
        "pk": "POST#p1",
        "sk": "META",
        "body": " legacy body ",
        "body_format": "html",
    }
    should_update, values, reason = plan_update(item)
    assert should_update is True
    assert reason is None
    assert values[":bp"] == "legacy body"
    assert values[":bf"] == "plain"


def test_infer_lock_type_defaults_to_fixed_price_for_legacy_unlock_posts() -> None:
    assert infer_lock_type({"unlock_price_cents": 250}) == "fixed_price"
    assert infer_lock_type({"unlock_price_cents": "500"}) == "fixed_price"
    assert infer_lock_type({"lock_type": "fixed_price", "unlock_price_cents": 500}) == "fixed_price"
    assert infer_lock_type({"lock_type": "tip_lottery", "unlock_price_cents": 0}) == "tip_lottery"
    assert infer_lock_type({"unlock_price_cents": 0}) is None


def test_backfill_is_post_row_filters_only_post_entities() -> None:
    assert is_post_row({"Entity": "Post", "post_id": "p1"}) is True
    assert is_post_row({"Entity": "Post", "post_id": ""}) is False
    assert is_post_row({"Entity": "Comment", "comment_id": "c1"}) is False
    assert is_post_row({"Entity": "FeedRef", "post_id": "p1"}) is False


def test_plan_lock_type_update_updates_only_posts_missing_derived_lock_type() -> None:
    should_update, values = plan_lock_type_update(
        {
            "Entity": "Post",
            "post_id": "p1",
            "pk": "POST#p1",
            "sk": "META",
            "unlock_price_cents": 700,
        },
    )
    assert should_update is True
    assert values[":lt"] == "fixed_price"

    should_update, values = plan_lock_type_update(
        {
            "Entity": "Post",
            "post_id": "p2",
            "pk": "POST#p2",
            "sk": "META",
            "unlock_price_cents": 900,
            "lock_type": "fixed_price",
        },
    )
    assert should_update is False
    assert values == {}

    should_update, values = plan_lock_type_update(
        {
            "Entity": "Post",
            "post_id": "p3",
            "pk": "POST#p3",
            "sk": "META",
            "lock_type": "tip_lottery",
            "unlock_price_cents": 900,
        },
    )
    assert should_update is False
    assert values == {}


def test_plan_lock_type_update_non_post_rows_are_noop() -> None:
    should_update, values = plan_lock_type_update(
        {
            "Entity": "Comment",
            "comment_id": "c1",
            "pk": "POST#p1",
            "sk": "COMMENT#1",
            "unlock_price_cents": 100,
        },
    )
    assert should_update is False
    assert values == {}


def test_lock_type_backfill_run_dry_run_plans_without_writes() -> None:
    table = Mock()
    table.scan.side_effect = [
        {
            "Items": [
                {"Entity": "Post", "post_id": "p1", "pk": "POST#p1", "sk": "META", "unlock_price_cents": 100},
                {"Entity": "Comment", "comment_id": "c1", "pk": "POST#p1", "sk": "COMMENT#1"},
                {"Entity": "Post", "post_id": "p2", "pk": "POST#p2", "sk": "META", "lock_type": "fixed_price", "unlock_price_cents": 250},
            ],
            "LastEvaluatedKey": {"pk": "NEXT", "sk": "NEXT"},
        },
        {
            "Items": [
                {"Entity": "Post", "post_id": "p3", "pk": "POST#p3", "sk": "META", "unlock_price_cents": 0},
            ],
        },
    ]
    with patch("scripts.backfill_newsfeed_lock_type._table", return_value=table):
        report = run_lock_type_backfill(page_limit=2, dry_run=True)

    assert report["dry_run"] is True
    assert report["scanned"] == 4
    assert report["eligible"] == 3
    assert report["planned_updates"] == 1
    assert report["applied_updates"] == 0
    assert isinstance(report["duration_seconds"], float)
    table.update_item.assert_not_called()


def test_lock_type_backfill_run_apply_mode_is_idempotent() -> None:
    table = Mock()
    first_pass_items = [
        {"Entity": "Post", "post_id": "p1", "pk": "POST#p1", "sk": "META", "unlock_price_cents": 100},
        {"Entity": "Post", "post_id": "p2", "pk": "POST#p2", "sk": "META", "lock_type": "fixed_price", "unlock_price_cents": 250},
    ]
    second_pass_items = [
        {"Entity": "Post", "post_id": "p1", "pk": "POST#p1", "sk": "META", "lock_type": "fixed_price", "unlock_price_cents": 100},
        {"Entity": "Post", "post_id": "p2", "pk": "POST#p2", "sk": "META", "lock_type": "fixed_price", "unlock_price_cents": 250},
    ]

    table.scan.return_value = {"Items": first_pass_items}
    with patch("scripts.backfill_newsfeed_lock_type._table", return_value=table):
        first_report = run_lock_type_backfill(page_limit=50, dry_run=False)

    assert first_report["planned_updates"] == 1
    assert first_report["applied_updates"] == 1
    assert isinstance(first_report["duration_seconds"], float)
    table.update_item.assert_called_once_with(
        Key={"pk": "POST#p1", "sk": "META"},
        UpdateExpression="SET lock_type = :lt",
        ExpressionAttributeValues={":lt": "fixed_price"},
    )

    table.reset_mock()
    table.scan.return_value = {"Items": second_pass_items}
    with patch("scripts.backfill_newsfeed_lock_type._table", return_value=table):
        second_report = run_lock_type_backfill(page_limit=50, dry_run=False)

    assert second_report["planned_updates"] == 0
    assert second_report["applied_updates"] == 0
    assert isinstance(second_report["duration_seconds"], float)
    table.update_item.assert_not_called()
