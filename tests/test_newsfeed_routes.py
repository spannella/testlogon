import unittest
import asyncio
from unittest.mock import Mock, patch

from fastapi import HTTPException

from app.routers import newsfeed


class TestNewsfeedRoutes(unittest.TestCase):
    def test_can_view_post_public_visibility_allows_non_follower_when_access_ok(self):
        post = {"user_id": "author_1", "visibility": "public"}
        with (
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "is_following", return_value=False),
        ):
            self.assertTrue(newsfeed.can_view_post("viewer_1", post))

    def test_can_view_post_followers_visibility_requires_following(self):
        post = {"user_id": "author_1", "visibility": "followers"}
        with (
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "is_following", return_value=False),
        ):
            self.assertFalse(newsfeed.can_view_post("viewer_1", post))

    def test_can_view_post_blocks_when_creator_access_denied(self):
        post = {"user_id": "author_1", "visibility": "public"}
        with patch.object(newsfeed, "can_access_creator", return_value=False):
            self.assertFalse(newsfeed.can_view_post("viewer_1", post))

    def test_view_feed_author_filter_only_returns_matching_author_posts(self):
        refs = [{"post_id": "p1"}, {"post_id": "p2"}]
        posts = [
            {"post_id": "p1", "user_id": "author_a", "locked": False},
            {"post_id": "p2", "user_id": "author_b", "locked": False},
        ]
        likes = [{"post_id": "p1"}, {"post_id": "p2"}]

        with (
            patch.object(newsfeed, "ddb_query", return_value={"Items": refs, "LastEvaluatedKey": None}),
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
            patch.object(newsfeed, "encode_cursor", return_value=None),
            patch.object(newsfeed, "is_hidden", return_value=False),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "is_following", return_value=True),
            patch.object(newsfeed, "has_unlocked", return_value=True),
            patch.object(
                newsfeed,
                "_post_to_dict",
                side_effect=lambda post, **_: {"post_id": post["post_id"], "author_id": post["user_id"]},
            ),
        ):
            ddb.batch_get_item.side_effect = [
                {"Responses": {newsfeed.APP_TABLE: posts}},
                {"Responses": {newsfeed.APP_TABLE: likes}},
            ]

            out = newsfeed.view_feed(limit=20, cursor=None, author_id="author_b", user_id="viewer_1")

        self.assertEqual(out["next_cursor"], None)
        self.assertEqual([it["post_id"] for it in out["items"]], ["p2"])
        self.assertEqual([it["author_id"] for it in out["items"]], ["author_b"])

    def test_view_feed_without_author_filter_returns_all_visible_posts(self):
        refs = [{"post_id": "p1"}, {"post_id": "p2"}]
        posts = [
            {"post_id": "p1", "user_id": "author_a", "locked": False},
            {"post_id": "p2", "user_id": "author_b", "locked": False},
        ]

        with (
            patch.object(newsfeed, "ddb_query", return_value={"Items": refs, "LastEvaluatedKey": None}),
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
            patch.object(newsfeed, "encode_cursor", return_value=None),
            patch.object(newsfeed, "is_hidden", return_value=False),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "is_following", return_value=True),
            patch.object(newsfeed, "has_unlocked", return_value=True),
            patch.object(
                newsfeed,
                "_post_to_dict",
                side_effect=lambda post, **_: {"post_id": post["post_id"], "author_id": post["user_id"]},
            ),
        ):
            ddb.batch_get_item.side_effect = [
                {"Responses": {newsfeed.APP_TABLE: posts}},
                {"Responses": {newsfeed.APP_TABLE: []}},
            ]

            out = newsfeed.view_feed(limit=20, cursor=None, author_id=None, user_id="viewer_1")

        self.assertEqual([it["post_id"] for it in out["items"]], ["p1", "p2"])

    def test_view_feed_applies_search_and_has_media_filters(self):
        refs = [{"post_id": "p1"}, {"post_id": "p2"}, {"post_id": "p3"}]
        posts = [
            {"post_id": "p1", "user_id": "author_a", "body": "hello release notes", "image_urls": ["a.png"], "created_at": "2026-03-20T00:00:00+00:00", "locked": False},
            {"post_id": "p2", "user_id": "author_a", "body": "hello world", "image_urls": [], "created_at": "2026-03-20T00:00:00+00:00", "locked": False},
            {"post_id": "p3", "user_id": "author_a", "body": "release checklist", "image_urls": [], "created_at": "2026-03-20T00:00:00+00:00", "locked": False},
        ]

        with (
            patch.object(newsfeed, "ddb_query", return_value={"Items": refs, "LastEvaluatedKey": None}),
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
            patch.object(newsfeed, "encode_cursor", return_value=None),
            patch.object(newsfeed, "is_hidden", return_value=False),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "is_following", return_value=True),
            patch.object(newsfeed, "has_unlocked", return_value=True),
            patch.object(newsfeed, "_post_to_dict", side_effect=lambda post, **_: {"post_id": post["post_id"]}),
        ):
            ddb.batch_get_item.side_effect = [
                {"Responses": {newsfeed.APP_TABLE: posts}},
                {"Responses": {newsfeed.APP_TABLE: []}},
            ]

            out = newsfeed.view_feed(
                limit=20,
                cursor=None,
                author_id="author_a",
                q="release",
                has_media=True,
                user_id="viewer_1",
            )

        self.assertEqual([it["post_id"] for it in out["items"]], ["p1"])

    def test_view_feed_applies_date_range_filters(self):
        refs = [{"post_id": "p1"}, {"post_id": "p2"}, {"post_id": "p3"}]
        posts = [
            {"post_id": "p1", "user_id": "author_a", "body": "a", "created_at": "2026-03-01T00:00:00+00:00", "locked": False},
            {"post_id": "p2", "user_id": "author_a", "body": "b", "created_at": "2026-03-15T00:00:00+00:00", "locked": False},
            {"post_id": "p3", "user_id": "author_a", "body": "c", "created_at": "2026-03-25T00:00:00+00:00", "locked": False},
        ]
        with (
            patch.object(newsfeed, "ddb_query", return_value={"Items": refs, "LastEvaluatedKey": None}),
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
            patch.object(newsfeed, "encode_cursor", return_value=None),
            patch.object(newsfeed, "is_hidden", return_value=False),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "is_following", return_value=True),
            patch.object(newsfeed, "has_unlocked", return_value=True),
            patch.object(newsfeed, "_post_to_dict", side_effect=lambda post, **_: {"post_id": post["post_id"]}),
        ):
            ddb.batch_get_item.side_effect = [
                {"Responses": {newsfeed.APP_TABLE: posts}},
                {"Responses": {newsfeed.APP_TABLE: []}},
            ]

            out = newsfeed.view_feed(
                limit=20,
                cursor=None,
                author_id="author_a",
                from_ts="2026-03-10T00:00:00Z",
                to_ts="2026-03-20T00:00:00Z",
                user_id="viewer_1",
            )

        self.assertEqual([it["post_id"] for it in out["items"]], ["p2"])

    def test_view_feed_fetches_additional_pages_to_fill_filtered_limit(self):
        first_refs = {"Items": [{"post_id": "p1"}, {"post_id": "p2"}], "LastEvaluatedKey": {"pk": "next1"}}
        second_refs = {"Items": [{"post_id": "p3"}], "LastEvaluatedKey": None}
        first_posts = [
            {"post_id": "p1", "user_id": "other_author", "created_at": "2026-03-21T00:00:00Z", "locked": False},
            {"post_id": "p2", "user_id": "target_author", "created_at": "2026-03-20T00:00:00Z", "locked": False},
        ]
        second_posts = [
            {"post_id": "p3", "user_id": "target_author", "created_at": "2026-03-19T00:00:00Z", "locked": False},
        ]

        with (
            patch.object(newsfeed, "ddb_query", side_effect=[first_refs, second_refs]) as ddb_query,
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
            patch.object(newsfeed, "encode_cursor", side_effect=lambda v: v),
            patch.object(newsfeed, "is_hidden", return_value=False),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "is_following", return_value=True),
            patch.object(newsfeed, "has_unlocked", return_value=True),
            patch.object(newsfeed, "_post_to_dict", side_effect=lambda post, **_: {"post_id": post["post_id"]}),
        ):
            ddb.batch_get_item.side_effect = [
                {"Responses": {newsfeed.APP_TABLE: first_posts}},
                {"Responses": {newsfeed.APP_TABLE: []}},
                {"Responses": {newsfeed.APP_TABLE: second_posts}},
                {"Responses": {newsfeed.APP_TABLE: []}},
            ]

            out = newsfeed.view_feed(limit=2, cursor=None, author_id="target_author", user_id="viewer_1")

        self.assertEqual([it["post_id"] for it in out["items"]], ["p2", "p3"])
        self.assertEqual(out["next_cursor"], None)
        self.assertEqual(ddb_query.call_count, 2)

    def test_view_feed_enforces_scanned_pages_budget(self):
        first_page = {"Items": [], "LastEvaluatedKey": {"pk": "next"}}
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "ddb_query", return_value=first_page),
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
            patch.object(newsfeed, "record_newsfeed_feed_budget_hit") as budget_hit,
        ):
            settings.newsfeed_feed_max_scanned_pages = 1
            settings.newsfeed_feed_max_elapsed_ms = 999999
            with self.assertRaises(HTTPException) as exc:
                newsfeed.view_feed(limit=20, cursor=None, author_id="author_a", user_id="viewer_1")

        self.assertEqual(exc.exception.status_code, 422)
        self.assertEqual(exc.exception.detail["code"], "feed_query_budget_exceeded")
        self.assertEqual(exc.exception.detail["reason"], "max_scanned_pages")
        budget_hit.assert_called_once_with(mode="profile", reason="max_scanned_pages")

    def test_view_feed_enforces_elapsed_time_budget(self):
        first_page = {"Items": [], "LastEvaluatedKey": {"pk": "next"}}
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "ddb_query", return_value=first_page),
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
            patch.object(newsfeed, "record_newsfeed_feed_budget_hit") as budget_hit,
        ):
            settings.newsfeed_feed_max_scanned_pages = 100
            settings.newsfeed_feed_max_elapsed_ms = 1
            with self.assertRaises(HTTPException) as exc:
                newsfeed.view_feed(limit=20, cursor=None, author_id="author_a", user_id="viewer_1")

        self.assertEqual(exc.exception.status_code, 422)
        self.assertEqual(exc.exception.detail["code"], "feed_query_budget_exceeded")
        self.assertEqual(exc.exception.detail["reason"], "max_elapsed_ms")
        budget_hit.assert_called_once_with(mode="profile", reason="max_elapsed_ms")

    def test_view_feed_author_mode_queries_gsi2_author_index(self):
        resp = {
            "Items": [
                {"post_id": "p2", "user_id": "target_author", "created_at": "2026-03-20T00:00:00Z", "locked": False},
            ],
            "LastEvaluatedKey": None,
        }
        with (
            patch.object(newsfeed, "ddb_query", return_value=resp) as ddb_query,
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
            patch.object(newsfeed, "encode_cursor", return_value=None),
            patch.object(newsfeed, "is_hidden", return_value=False),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "is_following", return_value=True),
            patch.object(newsfeed, "has_unlocked", return_value=True),
            patch.object(newsfeed, "_post_to_dict", side_effect=lambda post, **_: {"post_id": post["post_id"]}),
        ):
            ddb.batch_get_item.side_effect = [
                {"Responses": {newsfeed.APP_TABLE: []}},  # likes lookup only
            ]
            out = newsfeed.view_feed(limit=20, cursor=None, author_id="target_author", user_id="viewer_1")

        self.assertEqual([it["post_id"] for it in out["items"]], ["p2"])
        call_kwargs = ddb_query.call_args.kwargs
        self.assertEqual(call_kwargs["IndexName"], "GSI2")
        self.assertEqual(call_kwargs["ExpressionAttributeValues"][":pk"], "POST_AUTHOR#target_author")

    def test_view_feed_applies_deterministic_ordering_for_same_timestamp(self):
        refs = {
            "Items": [
                {"post_id": "p2", "user_id": "author_a", "created_at": "2026-03-20T00:00:00Z", "locked": False},
                {"post_id": "p3", "user_id": "author_a", "created_at": "2026-03-20T00:00:00Z", "locked": False},
            ],
            "LastEvaluatedKey": None,
        }
        with (
            patch.object(newsfeed, "ddb_query", return_value=refs),
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
            patch.object(newsfeed, "encode_cursor", return_value=None),
            patch.object(newsfeed, "is_hidden", return_value=False),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "is_following", return_value=True),
            patch.object(newsfeed, "has_unlocked", return_value=True),
            patch.object(newsfeed, "_post_to_dict", side_effect=lambda post, **_: {"post_id": post["post_id"]}),
        ):
            ddb.batch_get_item.side_effect = [{"Responses": {newsfeed.APP_TABLE: []}}]
            out = newsfeed.view_feed(limit=20, cursor=None, author_id="author_a", user_id="viewer_1")

        self.assertEqual([it["post_id"] for it in out["items"]], ["p3", "p2"])

    def test_view_feed_excludes_private_posts_for_non_owner(self):
        refs = {
            "Items": [
                {"post_id": "p_private", "user_id": "author_a", "created_at": "2026-03-20T00:00:00Z", "visibility": "private", "locked": False},
                {"post_id": "p_public", "user_id": "author_a", "created_at": "2026-03-19T00:00:00Z", "visibility": "public", "locked": False},
            ],
            "LastEvaluatedKey": None,
        }
        with (
            patch.object(newsfeed, "ddb_query", return_value=refs),
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
            patch.object(newsfeed, "encode_cursor", return_value=None),
            patch.object(newsfeed, "is_hidden", return_value=False),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "is_following", return_value=True),
            patch.object(newsfeed, "has_unlocked", return_value=True),
            patch.object(newsfeed, "_post_to_dict", side_effect=lambda post, **_: {"post_id": post["post_id"]}),
        ):
            ddb.batch_get_item.side_effect = [{"Responses": {newsfeed.APP_TABLE: []}}]
            out = newsfeed.view_feed(limit=20, cursor=None, author_id="author_a", user_id="viewer_b")

        self.assertEqual([it["post_id"] for it in out["items"]], ["p_public"])

    def test_view_feed_rejects_invalid_date_range(self):
        with (
            patch.object(newsfeed, "record_newsfeed_feed_error") as metric_error,
            patch.object(newsfeed, "record_newsfeed_feed_request") as metric_request,
            patch.object(newsfeed, "record_newsfeed_feed_latency") as metric_latency,
        ):
            with self.assertRaises(HTTPException) as exc:
                newsfeed.view_feed(
                    limit=20,
                    cursor=None,
                    from_ts="2026-03-20T00:00:00Z",
                    to_ts="2026-03-10T00:00:00Z",
                    user_id="viewer_1",
                )

        metric_error.assert_called_once_with(mode="global", error_type="validation")
        metric_request.assert_called_once_with(mode="global", outcome="error")
        metric_latency.assert_called_once()

        self.assertEqual(exc.exception.status_code, 400)
        self.assertIn("from", str(exc.exception.detail))

    def test_view_feed_rejects_time_window_exceeding_max_days(self):
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "rate_limit_feed_query") as rate_limit,
            patch.object(newsfeed, "ddb_query") as ddb_query,
            patch.object(newsfeed, "record_newsfeed_feed_error") as metric_error,
            patch.object(newsfeed, "record_newsfeed_feed_request") as metric_request,
        ):
            settings.newsfeed_feed_max_window_days = 7
            with self.assertRaises(HTTPException) as exc:
                newsfeed.view_feed(
                    limit=20,
                    cursor=None,
                    from_ts="2026-03-01T00:00:00Z",
                    to_ts="2026-03-10T00:00:00Z",
                    user_id="viewer_1",
                )

        self.assertEqual(exc.exception.status_code, 400)
        self.assertEqual(exc.exception.detail["code"], "invalid_time_window")
        self.assertEqual(exc.exception.detail["max_window_days"], 7)
        rate_limit.assert_not_called()
        ddb_query.assert_not_called()
        metric_error.assert_called_once_with(mode="global", error_type="code_invalid_time_window")
        metric_request.assert_called_once_with(mode="global", outcome="error")

    def test_view_feed_rejects_invalid_author_id(self):
        with (
            patch.object(newsfeed, "ddb_query") as ddb_query,
            patch.object(newsfeed, "record_newsfeed_feed_error") as metric_error,
            patch.object(newsfeed, "record_newsfeed_feed_request") as metric_request,
        ):
            with self.assertRaises(HTTPException) as exc:
                newsfeed.view_feed(
                    limit=20,
                    cursor=None,
                    author_id="author bad!!",
                    user_id="viewer_1",
                )

        self.assertEqual(exc.exception.status_code, 400)
        self.assertEqual(exc.exception.detail["code"], "invalid_author_id")
        ddb_query.assert_not_called()
        metric_error.assert_called_once_with(mode="profile", error_type="code_invalid_author_id")
        metric_request.assert_called_once_with(mode="profile", outcome="error")

    def test_view_feed_rejects_overlong_query(self):
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "ddb_query") as ddb_query,
            patch.object(newsfeed, "record_newsfeed_feed_error") as metric_error,
            patch.object(newsfeed, "record_newsfeed_feed_request") as metric_request,
        ):
            settings.newsfeed_feed_max_query_chars = 5
            with self.assertRaises(HTTPException) as exc:
                newsfeed.view_feed(
                    limit=20,
                    cursor=None,
                    author_id="author_ok",
                    q="too-long-query",
                    user_id="viewer_1",
                )

        self.assertEqual(exc.exception.status_code, 400)
        self.assertEqual(exc.exception.detail["code"], "invalid_query")
        ddb_query.assert_not_called()
        metric_error.assert_called_once_with(mode="profile", error_type="code_invalid_query")
        metric_request.assert_called_once_with(mode="profile", outcome="error")

    def test_view_feed_rejects_invalid_cursor_without_rate_limit_charge(self):
        with (
            patch.object(newsfeed, "rate_limit_feed_query") as rate_limit,
            patch.object(newsfeed, "ddb_query") as ddb_query,
            patch.object(newsfeed, "record_newsfeed_feed_error") as metric_error,
            patch.object(newsfeed, "record_newsfeed_feed_request") as metric_request,
        ):
            with self.assertRaises(HTTPException) as exc:
                newsfeed.view_feed(
                    limit=20,
                    cursor="bad-cursor",
                    author_id="author_ok",
                    user_id="viewer_1",
                )

        self.assertEqual(exc.exception.status_code, 400)
        self.assertEqual(exc.exception.detail["code"], "invalid_cursor")
        rate_limit.assert_not_called()
        ddb_query.assert_not_called()
        metric_error.assert_called_once_with(mode="profile", error_type="code_invalid_cursor")
        metric_request.assert_called_once_with(mode="profile", outcome="error")

    def test_view_feed_rejects_cursor_exceeding_max_chars(self):
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "rate_limit_feed_query") as rate_limit,
            patch.object(newsfeed, "ddb_query") as ddb_query,
            patch.object(newsfeed, "record_newsfeed_feed_error") as metric_error,
            patch.object(newsfeed, "record_newsfeed_feed_request") as metric_request,
        ):
            settings.newsfeed_feed_max_cursor_chars = 8
            with self.assertRaises(HTTPException) as exc:
                newsfeed.view_feed(
                    limit=20,
                    cursor="x" * 20,
                    author_id="author_ok",
                    user_id="viewer_1",
                )

        self.assertEqual(exc.exception.status_code, 400)
        self.assertEqual(exc.exception.detail["code"], "invalid_cursor")
        self.assertEqual(exc.exception.detail["max_cursor_chars"], 8)
        rate_limit.assert_not_called()
        ddb_query.assert_not_called()
        metric_error.assert_called_once_with(mode="profile", error_type="code_invalid_cursor")
        metric_request.assert_called_once_with(mode="profile", outcome="error")

    def test_view_feed_rate_limited_records_semantic_error_and_skips_query(self):
        with (
            patch.object(newsfeed, "ddb_query") as ddb_query,
            patch.object(
                newsfeed,
                "rate_limit_feed_query",
                side_effect=HTTPException(
                    status_code=429,
                    detail={"code": "feed_rate_limited"},
                    headers={"Retry-After": "60"},
                ),
            ) as rate_limit,
            patch.object(newsfeed, "record_newsfeed_feed_error") as metric_error,
            patch.object(newsfeed, "record_newsfeed_feed_request") as metric_request,
        ):
            with self.assertRaises(HTTPException) as exc:
                newsfeed.view_feed(
                    limit=20,
                    cursor=None,
                    author_id="author_ok",
                    user_id="viewer_1",
                )

        self.assertEqual(exc.exception.status_code, 429)
        self.assertEqual(exc.exception.headers.get("Retry-After"), "60")
        rate_limit.assert_called_once_with("viewer_1", "profile")
        ddb_query.assert_not_called()
        metric_error.assert_called_once_with(mode="profile", error_type="code_feed_rate_limited")
        metric_request.assert_called_once_with(mode="profile", outcome="error")

    def test_view_feed_profile_mode_records_observability_metrics(self):
        refs = {
            "Items": [
                {"post_id": "p2", "user_id": "target_author", "created_at": "2026-03-20T00:00:00Z", "locked": False},
            ],
            "LastEvaluatedKey": None,
        }
        with (
            patch.object(newsfeed, "ddb_query", return_value=refs),
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
            patch.object(newsfeed, "encode_cursor", return_value=None),
            patch.object(newsfeed, "is_hidden", return_value=False),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "is_following", return_value=True),
            patch.object(newsfeed, "has_unlocked", return_value=True),
            patch.object(newsfeed, "_post_to_dict", side_effect=lambda post, **_: {"post_id": post["post_id"]}),
            patch.object(newsfeed, "record_newsfeed_feed_request") as metric_request,
            patch.object(newsfeed, "record_newsfeed_feed_latency") as metric_latency,
            patch.object(newsfeed, "record_newsfeed_feed_page_depth") as metric_depth,
            patch.object(newsfeed, "record_newsfeed_feed_filter_usage") as metric_filter,
            patch.object(newsfeed, "logger") as logger_mock,
        ):
            ddb.batch_get_item.side_effect = [
                {"Responses": {newsfeed.APP_TABLE: []}},
            ]
            out = newsfeed.view_feed(
                limit=20,
                cursor=None,
                author_id="target_author",
                q="release",
                has_media=True,
                user_id="viewer_1",
            )

        self.assertEqual([it["post_id"] for it in out["items"]], ["p2"])
        metric_request.assert_called_once_with(mode="profile", outcome="success")
        metric_latency.assert_called_once()
        metric_depth.assert_called_once_with(mode="profile", depth=1)
        self.assertEqual(metric_filter.call_count, 2)
        metric_filter.assert_any_call(mode="profile", filter_name="q")
        metric_filter.assert_any_call(mode="profile", filter_name="has_media")
        logger_mock.info.assert_called_once()

    def test_meter_newsfeed_post_publish_builds_deterministic_idempotency_key(self):
        table = Mock()
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "record_usage_event_and_aggregates") as record_usage,
        ):
            settings.filemgr_table_name = "FileManager"
            ddb.Table.return_value = table

            newsfeed._meter_newsfeed_post_publish(user_id="u1", post_id="p1")

        ddb.Table.assert_called_once_with("FileManager")
        record_usage.assert_called_once()
        event = record_usage.call_args.args[1]
        self.assertEqual(event["source"], "newsfeed_post")
        self.assertEqual(event["idempotency_key"], "u1|newsfeed_post|p1")

    def test_create_post_success_records_usage_once(self):
        req = newsfeed.CreatePostRequest(
            body=newsfeed.RichTextDoc(format="tiptap-json", doc={"type": "doc", "content": []}),
        )

        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "record_usage_event_and_aggregates") as record_usage,
            patch.object(newsfeed, "new_id", return_value="post_abc"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed, "ddb_put_item") as put_item,
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
        ):
            settings.filemgr_table_name = "FileManager"
            ddb.Table.return_value = Mock()
            newsfeed.create_post(req, x_user_id="u1")

        self.assertEqual(put_item.call_count, 2)
        record_usage.assert_called_once()
        event = record_usage.call_args.args[1]
        self.assertEqual(event["source"], "newsfeed_post")
        self.assertEqual(event["idempotency_key"], "u1|newsfeed_post|post_abc")

    def test_create_post_failed_create_does_not_record_usage(self):
        req = newsfeed.CreatePostRequest(
            body=newsfeed.RichTextDoc(format="tiptap-json", doc={"type": "doc", "content": []}),
        )

        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "record_usage_event_and_aggregates") as record_usage,
            patch.object(newsfeed, "new_id", return_value="post_abc"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed, "ddb_put_item", side_effect=RuntimeError("ddb down")),
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
        ):
            settings.filemgr_table_name = "FileManager"
            ddb.Table.return_value = Mock()
            with self.assertRaises(RuntimeError):
                newsfeed.create_post(req, x_user_id="u1")

        record_usage.assert_not_called()

    def test_create_post_meters_successful_create(self):
        req = newsfeed.CreatePostRequest(
            body=newsfeed.RichTextDoc(format="tiptap-json", doc={"type": "doc", "content": []}),
        )

        with (
            patch.object(newsfeed, "new_id", return_value="post_abc"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed, "ddb_put_item") as put_item,
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
            patch.object(newsfeed, "_meter_newsfeed_post_publish") as meter_post,
            patch.object(newsfeed, "_meter_newsfeed_attachment_uploads") as meter_attachments,
        ):
            resp = newsfeed.create_post(req, x_user_id="u1")

        self.assertEqual(put_item.call_count, 2)
        meter_post.assert_called_once_with(user_id="u1", post_id="post_abc")
        meter_attachments.assert_called_once()
        self.assertEqual(resp.post_id, "post_abc")

    def test_create_post_failed_create_does_not_meter(self):
        req = newsfeed.CreatePostRequest(
            body=newsfeed.RichTextDoc(format="tiptap-json", doc={"type": "doc", "content": []}),
        )

        with (
            patch.object(newsfeed, "new_id", return_value="post_abc"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed, "ddb_put_item", side_effect=RuntimeError("ddb down")),
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
            patch.object(newsfeed, "_meter_newsfeed_post_publish") as meter_post,
            patch.object(newsfeed, "_meter_newsfeed_attachment_uploads") as meter_attachments,
        ):
            with self.assertRaises(RuntimeError):
                newsfeed.create_post(req, x_user_id="u1")

        meter_post.assert_not_called()
        meter_attachments.assert_not_called()

    def test_meter_newsfeed_attachment_uploads_uses_authoritative_content_length(self):
        table = Mock()
        attachment = newsfeed.Attachment(
            attachment_id="att1",
            filename="a.png",
            content_type="image/png",
            s3_key="uploads/u1/att1/a.png",
        )
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "s3") as s3,
            patch.object(newsfeed, "UPLOAD_BUCKET", "bucket"),
            patch.object(newsfeed, "record_usage_event_and_aggregates") as record_usage,
        ):
            settings.filemgr_table_name = "FileManager"
            ddb.Table.return_value = table
            s3.head_object.return_value = {"ContentLength": 321}

            newsfeed._meter_newsfeed_attachment_uploads(
                user_id="u1",
                post_id="p1",
                attachments=[attachment],
            )

        s3.head_object.assert_called_once_with(Bucket="bucket", Key="uploads/u1/att1/a.png")
        record_usage.assert_called_once()
        event = record_usage.call_args.args[1]
        self.assertEqual(event["source"], "newsfeed_attachment_upload")
        self.assertEqual(event["bytes"], 321)
        self.assertEqual(
            event["idempotency_key"],
            "u1|newsfeed_attachment_upload|bucket/uploads/u1/att1/a.png|p1",
        )

    def test_meter_newsfeed_attachment_uploads_skips_nonpositive_head_size(self):
        table = Mock()
        attachment = newsfeed.Attachment(
            attachment_id="att1",
            filename="a.png",
            content_type="image/png",
            s3_key="uploads/u1/att1/a.png",
        )
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "s3") as s3,
            patch.object(newsfeed, "UPLOAD_BUCKET", "bucket"),
            patch.object(newsfeed, "record_usage_event_and_aggregates") as record_usage,
        ):
            settings.filemgr_table_name = "FileManager"
            ddb.Table.return_value = table
            s3.head_object.return_value = {"ContentLength": 0}

            newsfeed._meter_newsfeed_attachment_uploads(
                user_id="u1",
                post_id="p1",
                attachments=[attachment],
            )

        record_usage.assert_not_called()

    def test_record_newsfeed_attachment_download_builds_deterministic_key(self):
        table = Mock()
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "record_usage_event_and_aggregates") as record_usage,
        ):
            settings.filemgr_table_name = "FileManager"
            ddb.Table.return_value = table

            newsfeed._record_newsfeed_attachment_download(
                user_id="u1",
                post_id="p1",
                attachment_key="bucket/uploads/u1/att/a.png",
                bytes_count=77,
                idempotency_operation_id="req-1",
            )

        record_usage.assert_called_once()
        event = record_usage.call_args.args[1]
        self.assertEqual(event["source"], "newsfeed_attachment_download")
        self.assertEqual(event["bytes"], 77)
        self.assertEqual(event["idempotency_key"], "u1|newsfeed_attachment_download|bucket/uploads/u1/att/a.png|req-1")

    def test_download_post_attachment_streams_and_records_download_bytes(self):
        class _Body:
            def iter_chunks(self, chunk_size=65536):
                yield b"ab"
                yield b"cde"

        post = {
            "post_id": "p1",
            "user_id": "u1",
            "attachments": [
                {
                    "attachment_id": "att1",
                    "filename": "a.png",
                    "content_type": "image/png",
                    "s3_key": "uploads/u1/att1/a.png",
                }
            ],
        }
        with (
            patch.object(newsfeed, "UPLOAD_BUCKET", "bucket"),
            patch.object(newsfeed, "s3") as s3,
            patch.object(newsfeed, "ddb_get_item", return_value=post),
            patch.object(newsfeed, "_record_newsfeed_attachment_download") as meter_download,
        ):
            s3.get_object.return_value = {
                "Body": _Body(),
                "ContentLength": 5,
                "ContentType": "image/png",
            }
            resp = newsfeed.download_post_attachment("p1", "att1", x_user_id="u1", x_request_id="req-1")

            async def _collect() -> bytes:
                chunks = []
                async for chunk in resp.body_iterator:
                    chunks.append(chunk)
                return b"".join(chunks)

            self.assertEqual(asyncio.run(_collect()), b"abcde")

        meter_download.assert_called_once_with(
            user_id="u1",
            post_id="p1",
            attachment_key="bucket/uploads/u1/att1/a.png",
            bytes_count=5,
            idempotency_operation_id="req-1",
        )

    def test_download_post_attachment_locked_requires_unlock(self):
        post = {
            "post_id": "p1",
            "user_id": "u2",
            "locked": True,
            "attachments": [{"attachment_id": "att1", "s3_key": "uploads/u2/att1/a.png"}],
        }
        with (
            patch.object(newsfeed, "UPLOAD_BUCKET", "bucket"),
            patch.object(newsfeed, "s3", Mock()),
            patch.object(newsfeed, "ddb_get_item", return_value=post),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "is_following", return_value=True),
            patch.object(newsfeed, "has_unlocked", return_value=False),
        ):
            with self.assertRaises(HTTPException) as ctx:
                newsfeed.download_post_attachment("p1", "att1", x_user_id="u1", x_request_id=None)

        self.assertEqual(ctx.exception.status_code, 402)


    def test_newsfeed_post_quota_precheck_blocks_over_limit(self):
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "get_usage_summary", return_value={
                "period_id": "2026-04",
                "post_publish": {"used_count": 5, "limit_count": 5},
            }),
        ):
            settings.filemgr_table_name = "FileManager"
            settings.newsfeed_post_quota_overage_mode = "block"
            with self.assertRaises(HTTPException) as ctx:
                newsfeed._enforce_newsfeed_post_quota_precheck(user_id="u1")

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "newsfeed_post_quota_exceeded")

    def test_newsfeed_post_quota_precheck_allows_overage_mode_allow(self):
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "get_usage_summary", return_value={
                "period_id": "2026-04",
                "post_publish": {"used_count": 5, "limit_count": 5},
            }),
        ):
            settings.filemgr_table_name = "FileManager"
            settings.newsfeed_post_quota_overage_mode = "allow"
            newsfeed._enforce_newsfeed_post_quota_precheck(user_id="u1")

    def test_newsfeed_post_quota_warnings_emit_for_configured_thresholds(self):
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "get_usage_summary", return_value={
                "period_id": "2026-04",
                "post_publish": {"used_count": 0, "limit_count": 1},
            }),
            patch.object(newsfeed, "_emit_newsfeed_post_quota_warning") as emit_warning,
        ):
            settings.filemgr_table_name = "FileManager"
            settings.newsfeed_post_quota_soft_warnings_enabled = True
            settings.newsfeed_post_quota_warning_thresholds = "80,95"
            newsfeed._enforce_newsfeed_post_quota_precheck(user_id="u1")

        self.assertEqual(emit_warning.call_count, 2)
        self.assertEqual(emit_warning.call_args_list[0].kwargs["threshold_percent"], 80)
        self.assertEqual(emit_warning.call_args_list[1].kwargs["threshold_percent"], 95)


if __name__ == "__main__":
    unittest.main()
