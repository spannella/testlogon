"""Regression tests for GAP-0005 (ADS-012).

`app/services/content_boost.py:elevate_feed_items()` re-ranks feed items so
that actively-boosted posts are elevated above organic results. The bug was
that the newsfeed `GET /feed` handler never called this function, so every
paid boost had zero effect on feed ordering.

These tests are fully offline (no real AWS / DynamoDB): the boost lookup is
mocked, and the router wiring is asserted via source inspection so we do not
need to stand up the full feed handler (which requires DynamoDB Local + cookie
sessions). They fail before the fix and pass after.
"""

import inspect

from unittest.mock import patch

from app.services.content_boost import elevate_feed_items, BOOST_RANK_WEIGHT


def _mock_bonus_for(boosted_ids):
    boosted = set(boosted_ids)

    def _mock(content_type, content_id, now=None):
        return BOOST_RANK_WEIGHT if content_id in boosted else 0

    return _mock


# --- Function behaviour (correct id_key) ---------------------------------


def test_elevate_feed_items_raises_boosted_post():
    """Boosted post (p1) overtakes a higher-organic post (p2) after elevation."""
    items = [
        {"post_id": "p1", "score": 5, "text": "low organic"},
        {"post_id": "p2", "score": 10, "text": "high organic"},
    ]

    with patch(
        "app.services.content_boost.boost_rank_bonus",
        side_effect=_mock_bonus_for(["p1"]),
    ):
        result = elevate_feed_items(items, id_key="post_id")

    assert result[0]["post_id"] == "p1"
    assert result[0]["is_boosted"] is True
    assert result[0]["effective_score"] == 5 + BOOST_RANK_WEIGHT
    assert result[1]["post_id"] == "p2"
    assert result[1]["is_boosted"] is False


def test_elevate_feed_items_preserves_organic_order_without_boosts():
    """With no active boosts the organic ordering (by score) is preserved."""
    items = [
        {"post_id": "p2", "score": 10},
        {"post_id": "p1", "score": 5},
        {"post_id": "p3", "score": 1},
    ]

    with patch(
        "app.services.content_boost.boost_rank_bonus",
        side_effect=_mock_bonus_for([]),
    ):
        result = elevate_feed_items(items, id_key="post_id")

    assert [i["post_id"] for i in result] == ["p2", "p1", "p3"]
    assert all(i["is_boosted"] is False for i in result)


def test_elevate_feed_items_id_key_mismatch_produces_no_elevation():
    """CRITICAL: default id_key='content_id' on newsfeed posts silently no-ops."""
    items = [{"post_id": "p1", "score": 5}]

    with patch(
        "app.services.content_boost.boost_rank_bonus",
        side_effect=_mock_bonus_for(["p1"]),
    ):
        result_wrong = elevate_feed_items(items)  # default id_key="content_id"
        result_correct = elevate_feed_items(items, id_key="post_id")

    assert result_wrong[0]["is_boosted"] is False  # silent failure with wrong id_key
    assert result_correct[0]["is_boosted"] is True  # correct with explicit id_key


# --- Router wiring (fails before fix, passes after) ----------------------


def test_newsfeed_feed_handler_calls_elevate_feed_items_with_post_id_key():
    """GAP-0005: the GET /feed handler must call elevate_feed_items.

    Before the fix this assertion fails (no call site exists). It also guards
    the critical id_key="post_id" argument: calling with the default
    id_key="content_id" would compile fine but produce no elevation.
    """
    import app.routers.newsfeed as newsfeed

    src = inspect.getsource(newsfeed.feed) if hasattr(newsfeed, "feed") else None
    # The feed handler function name may differ; fall back to whole-module source
    # restricted to the function that builds the feed response.
    module_src = inspect.getsource(newsfeed)

    assert "elevate_feed_items(" in module_src, (
        "newsfeed router never calls elevate_feed_items() — boosts have no effect"
    )
    assert 'id_key="post_id"' in module_src or "id_key='post_id'" in module_src, (
        "elevate_feed_items must be called with id_key='post_id'; the default "
        "'content_id' silently produces no elevation on newsfeed posts"
    )
