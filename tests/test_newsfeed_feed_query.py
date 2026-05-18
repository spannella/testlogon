from datetime import datetime, timezone

import pytest

from app.services.newsfeed_feed_query import (
    FeedFilterParams,
    parse_filter_dt,
    parse_filter_window,
    post_matches_filters,
    sort_posts_deterministically,
)


def test_parse_filter_dt_accepts_zulu_and_normalizes_utc() -> None:
    dt = parse_filter_dt("2026-03-25T12:00:00Z")
    assert dt == datetime(2026, 3, 25, 12, 0, 0, tzinfo=timezone.utc)


def test_parse_filter_window_expands_date_only_bounds_inclusively() -> None:
    from_dt, to_dt = parse_filter_window("2026-03-01", "2026-03-31")
    assert from_dt == datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert to_dt == datetime(2026, 3, 31, 23, 59, 59, tzinfo=timezone.utc)


def test_post_matches_filters_enforces_author_before_other_predicates() -> None:
    post = {
        "user_id": "author_b",
        "created_at": "2026-03-20T00:00:00Z",
        "body": "release notes",
        "image_urls": ["x.png"],
    }
    params = FeedFilterParams(
        author_id="author_a",
        q="release",
        from_dt=datetime(2026, 3, 1, tzinfo=timezone.utc),
        to_dt=datetime(2026, 3, 30, tzinfo=timezone.utc),
        has_media=True,
    )

    assert post_matches_filters(post, params) is False


def test_post_matches_filters_requires_all_predicates() -> None:
    post = {
        "user_id": "author_a",
        "created_at": "2026-03-20T00:00:00Z",
        "body_plain": "release notes",
        "file_attachments": [{"name": "a.pdf"}],
    }
    params = FeedFilterParams(
        author_id="author_a",
        q="release",
        from_dt=datetime(2026, 3, 1, tzinfo=timezone.utc),
        to_dt=datetime(2026, 3, 30, tzinfo=timezone.utc),
        has_media=True,
    )

    assert post_matches_filters(post, params) is True


def test_parse_filter_window_rejects_inverted_ranges() -> None:
    with pytest.raises(ValueError, match="from"):
        parse_filter_window("2026-03-20T00:00:00Z", "2026-03-10T00:00:00Z")


def test_parse_filter_dt_rejects_invalid_iso8601() -> None:
    with pytest.raises(ValueError, match="ISO-8601"):
        parse_filter_dt("not-a-date")


def test_parse_filter_dt_date_only_defaults_to_start_of_day_for_general_bound() -> None:
    dt = parse_filter_dt("2026-04-10")
    assert dt == datetime(2026, 4, 10, 0, 0, 0, tzinfo=timezone.utc)


def test_sort_posts_deterministically_orders_by_created_at_then_post_id_desc() -> None:
    posts = [
        {"post_id": "p2", "created_at": "2026-03-20T00:00:00Z"},
        {"post_id": "p3", "created_at": "2026-03-20T00:00:00Z"},
        {"post_id": "p1", "created_at": "2026-03-21T00:00:00Z"},
    ]
    out = sort_posts_deterministically(posts)
    assert [p["post_id"] for p in out] == ["p1", "p3", "p2"]
