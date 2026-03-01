from __future__ import annotations

from scripts.backfill_newsfeed_plain_fields import (
    infer_body_format,
    infer_body_plain,
    is_newsfeed_content_row,
    plan_update,
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
