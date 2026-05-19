import unittest
import asyncio
from concurrent.futures import ThreadPoolExecutor
import threading
from unittest.mock import Mock, patch

from fastapi import HTTPException
from botocore.exceptions import ClientError
from boto3.dynamodb.types import TypeDeserializer
from pydantic import ValidationError

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
        posts = [
            {"post_id": "p1", "user_id": "author_a", "locked": False, "created_at": "2026-03-20T00:00:00+00:00"},
            {"post_id": "p2", "user_id": "author_b", "locked": False, "created_at": "2026-03-20T00:00:00+00:00"},
        ]
        likes = [{"post_id": "p1"}, {"post_id": "p2"}]

        with (
            patch.object(newsfeed, "ddb_query", return_value={"Items": posts, "LastEvaluatedKey": None}),
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
            patch.object(newsfeed, "encode_cursor", return_value=None),
            patch.object(newsfeed, "is_hidden", return_value=False),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "is_following", return_value=True),
            patch.object(newsfeed, "has_unlocked", return_value=True),
            patch.object(newsfeed, "parse_filter_window", return_value=(None, None)),
            patch.object(newsfeed, "rate_limit_feed_query"),
            patch.object(
                newsfeed,
                "_post_to_dict",
                side_effect=lambda post, **_: {"post_id": post["post_id"], "author_id": post["user_id"]},
            ),
        ):
            ddb.batch_get_item.side_effect = [
                {"Responses": {newsfeed.APP_TABLE: likes}},
            ]

            out = newsfeed.view_feed(limit=20, cursor=None, author_id="author_b", q=None, from_ts=None, to_ts=None, has_media=None, user_id="viewer_1")

        self.assertEqual(out["next_cursor"], None)
        self.assertEqual([it["post_id"] for it in out["items"]], ["p2"])
        self.assertEqual([it["author_id"] for it in out["items"]], ["author_b"])

    def test_view_feed_without_author_filter_returns_all_visible_posts(self):
        refs = [{"post_id": "p1"}, {"post_id": "p2"}]
        posts = [
            {"post_id": "p1", "user_id": "author_a", "locked": False, "created_at": "2026-03-21T00:00:00+00:00"},
            {"post_id": "p2", "user_id": "author_b", "locked": False, "created_at": "2026-03-20T00:00:00+00:00"},
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
            patch.object(newsfeed, "parse_filter_window", return_value=(None, None)),
            patch.object(newsfeed, "rate_limit_feed_query"),
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

            out = newsfeed.view_feed(limit=20, cursor=None, author_id=None, q=None, from_ts=None, to_ts=None, has_media=None, user_id="viewer_1")

        self.assertEqual([it["post_id"] for it in out["items"]], ["p1", "p2"])

    def test_view_feed_applies_search_and_has_media_filters(self):
        posts = [
            {"post_id": "p1", "user_id": "author_a", "body": "hello release notes", "image_urls": ["a.png"], "created_at": "2026-03-20T00:00:00+00:00", "locked": False},
            {"post_id": "p2", "user_id": "author_a", "body": "hello world", "image_urls": [], "created_at": "2026-03-20T00:00:00+00:00", "locked": False},
            {"post_id": "p3", "user_id": "author_a", "body": "release checklist", "image_urls": [], "created_at": "2026-03-20T00:00:00+00:00", "locked": False},
        ]

        with (
            patch.object(newsfeed, "ddb_query", return_value={"Items": posts, "LastEvaluatedKey": None}),
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
            patch.object(newsfeed, "encode_cursor", return_value=None),
            patch.object(newsfeed, "is_hidden", return_value=False),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "is_following", return_value=True),
            patch.object(newsfeed, "has_unlocked", return_value=True),
            patch.object(newsfeed, "parse_filter_window", return_value=(None, None)),
            patch.object(newsfeed, "rate_limit_feed_query"),
            patch.object(newsfeed, "_post_to_dict", side_effect=lambda post, **_: {"post_id": post["post_id"]}),
        ):
            ddb.batch_get_item.side_effect = [
                {"Responses": {newsfeed.APP_TABLE: []}},
            ]

            out = newsfeed.view_feed(
                limit=20,
                cursor=None,
                author_id="author_a",
                q="release",
                from_ts=None,
                to_ts=None,
                has_media=True,
                user_id="viewer_1",
            )

        self.assertEqual([it["post_id"] for it in out["items"]], ["p1"])

    def test_view_feed_applies_date_range_filters(self):
        from datetime import datetime, timezone as tz
        posts = [
            {"post_id": "p1", "user_id": "author_a", "body": "a", "created_at": "2026-03-01T00:00:00+00:00", "locked": False},
            {"post_id": "p2", "user_id": "author_a", "body": "b", "created_at": "2026-03-15T00:00:00+00:00", "locked": False},
            {"post_id": "p3", "user_id": "author_a", "body": "c", "created_at": "2026-03-25T00:00:00+00:00", "locked": False},
        ]
        from_dt = datetime(2026, 3, 10, tzinfo=tz.utc)
        to_dt = datetime(2026, 3, 20, tzinfo=tz.utc)
        with (
            patch.object(newsfeed, "ddb_query", return_value={"Items": posts, "LastEvaluatedKey": None}),
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
            patch.object(newsfeed, "encode_cursor", return_value=None),
            patch.object(newsfeed, "is_hidden", return_value=False),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "is_following", return_value=True),
            patch.object(newsfeed, "has_unlocked", return_value=True),
            patch.object(newsfeed, "parse_filter_window", return_value=(from_dt, to_dt)),
            patch.object(newsfeed, "rate_limit_feed_query"),
            patch.object(newsfeed, "_post_to_dict", side_effect=lambda post, **_: {"post_id": post["post_id"]}),
        ):
            ddb.batch_get_item.side_effect = [
                {"Responses": {newsfeed.APP_TABLE: []}},
            ]

            out = newsfeed.view_feed(
                limit=20,
                cursor=None,
                author_id="author_a",
                q=None,
                from_ts="2026-03-10T00:00:00Z",
                to_ts="2026-03-20T00:00:00Z",
                has_media=None,
                user_id="viewer_1",
            )

        self.assertEqual([it["post_id"] for it in out["items"]], ["p2"])

    def test_view_feed_fetches_additional_pages_to_fill_filtered_limit(self):
        first_posts = [
            {"post_id": "p1", "user_id": "other_author", "created_at": "2026-03-21T00:00:00Z", "locked": False},
            {"post_id": "p2", "user_id": "target_author", "created_at": "2026-03-20T00:00:00Z", "locked": False},
        ]
        second_posts = [
            {"post_id": "p3", "user_id": "target_author", "created_at": "2026-03-19T00:00:00Z", "locked": False},
        ]
        first_page = {"Items": first_posts, "LastEvaluatedKey": {"pk": "next1"}}
        second_page = {"Items": second_posts, "LastEvaluatedKey": None}

        with (
            patch.object(newsfeed, "ddb_query", side_effect=[first_page, second_page]) as ddb_query,
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
            patch.object(newsfeed, "encode_cursor", side_effect=lambda v: v),
            patch.object(newsfeed, "is_hidden", return_value=False),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "is_following", return_value=True),
            patch.object(newsfeed, "has_unlocked", return_value=True),
            patch.object(newsfeed, "parse_filter_window", return_value=(None, None)),
            patch.object(newsfeed, "rate_limit_feed_query"),
            patch.object(newsfeed, "_post_to_dict", side_effect=lambda post, **_: {"post_id": post["post_id"]}),
        ):
            ddb.batch_get_item.side_effect = [
                {"Responses": {newsfeed.APP_TABLE: []}},
                {"Responses": {newsfeed.APP_TABLE: []}},
            ]

            out = newsfeed.view_feed(limit=2, cursor=None, author_id="target_author", q=None, from_ts=None, to_ts=None, has_media=None, user_id="viewer_1")

        self.assertEqual([it["post_id"] for it in out["items"]], ["p2", "p3"])
        self.assertEqual(out["next_cursor"], None)
        self.assertEqual(ddb_query.call_count, 2)

    def test_view_feed_enforces_scanned_pages_budget(self):
        first_page = {"Items": [], "LastEvaluatedKey": {"pk": "next"}}
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "ddb_query", return_value=first_page),
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
            patch.object(newsfeed, "parse_filter_window", return_value=(None, None)),
            patch.object(newsfeed, "rate_limit_feed_query"),
            patch.object(newsfeed, "record_newsfeed_feed_budget_hit") as budget_hit,
        ):
            settings.newsfeed_feed_max_scanned_pages = 1
            settings.newsfeed_feed_max_elapsed_ms = 999999
            with self.assertRaises(HTTPException) as exc:
                newsfeed.view_feed(limit=20, cursor=None, author_id="author_a", q=None, from_ts=None, to_ts=None, has_media=None, user_id="viewer_1")

        self.assertEqual(exc.exception.status_code, 422)
        self.assertEqual(exc.exception.detail["code"], "feed_query_budget_exceeded")
        self.assertEqual(exc.exception.detail["reason"], "max_scanned_pages")
        budget_hit.assert_called_once_with(mode="profile", reason="max_scanned_pages")

    def test_view_feed_enforces_elapsed_time_budget(self):
        first_page = {"Items": [], "LastEvaluatedKey": {"pk": "next"}}
        # Mock perf_counter to simulate elapsed time: call 1 = 0 (started),
        # call 2 = 0 (first loop check, 0ms elapsed, OK), call 3 = 1.0 (second loop
        # check, 1000ms > 1ms budget → raise), call 4 = 1.0 (error handler latency).
        counter_values = iter([0.0, 0.0, 1.0, 1.0])
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "ddb_query", return_value=first_page),
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
            patch.object(newsfeed, "parse_filter_window", return_value=(None, None)),
            patch.object(newsfeed, "rate_limit_feed_query"),
            patch.object(newsfeed, "record_newsfeed_feed_budget_hit") as budget_hit,
            patch.object(newsfeed, "record_newsfeed_feed_error"),
            patch.object(newsfeed, "record_newsfeed_feed_request"),
            patch.object(newsfeed, "record_newsfeed_feed_latency"),
            patch.object(newsfeed.time, "perf_counter", side_effect=counter_values),
        ):
            settings.newsfeed_feed_max_scanned_pages = 100
            settings.newsfeed_feed_max_elapsed_ms = 1
            with self.assertRaises(HTTPException) as exc:
                newsfeed.view_feed(limit=20, cursor=None, author_id="author_a", q=None, from_ts=None, to_ts=None, has_media=None, user_id="viewer_1")

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
            patch.object(newsfeed, "parse_filter_window", return_value=(None, None)),
            patch.object(newsfeed, "rate_limit_feed_query"),
            patch.object(newsfeed, "_post_to_dict", side_effect=lambda post, **_: {"post_id": post["post_id"]}),
        ):
            ddb.batch_get_item.side_effect = [
                {"Responses": {newsfeed.APP_TABLE: []}},  # likes lookup only
            ]
            out = newsfeed.view_feed(limit=20, cursor=None, author_id="target_author", q=None, from_ts=None, to_ts=None, has_media=None, user_id="viewer_1")

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
            patch.object(newsfeed, "parse_filter_window", return_value=(None, None)),
            patch.object(newsfeed, "rate_limit_feed_query"),
            patch.object(newsfeed, "_post_to_dict", side_effect=lambda post, **_: {"post_id": post["post_id"]}),
        ):
            ddb.batch_get_item.side_effect = [{"Responses": {newsfeed.APP_TABLE: []}}]
            out = newsfeed.view_feed(limit=20, cursor=None, author_id="author_a", q=None, from_ts=None, to_ts=None, has_media=None, user_id="viewer_1")

        self.assertEqual([it["post_id"] for it in out["items"]], ["p3", "p2"])

    def test_view_feed_excludes_private_posts_for_non_owner(self):
        refs = {
            "Items": [
                {"post_id": "p_private", "user_id": "author_a", "created_at": "2026-03-20T00:00:00Z", "visibility": "private", "locked": False},
                {"post_id": "p_public", "user_id": "author_a", "created_at": "2026-03-19T00:00:00Z", "visibility": "public", "locked": False},
            ],
            "LastEvaluatedKey": None,
        }

        def _mock_can_view(viewer_id, post):
            return post.get("visibility") == "public"

        with (
            patch.object(newsfeed, "ddb_query", return_value=refs),
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
            patch.object(newsfeed, "encode_cursor", return_value=None),
            patch.object(newsfeed, "is_hidden", return_value=False),
            patch.object(newsfeed, "can_view_post", side_effect=_mock_can_view),
            patch.object(newsfeed, "has_unlocked", return_value=True),
            patch.object(newsfeed, "parse_filter_window", return_value=(None, None)),
            patch.object(newsfeed, "rate_limit_feed_query"),
            patch.object(newsfeed, "_post_to_dict", side_effect=lambda post, **_: {"post_id": post["post_id"]}),
        ):
            ddb.batch_get_item.side_effect = [{"Responses": {newsfeed.APP_TABLE: []}}]
            out = newsfeed.view_feed(limit=20, cursor=None, author_id="author_a", q=None, from_ts=None, to_ts=None, has_media=None, user_id="viewer_b")

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
                    author_id=None,
                    q=None,
                    from_ts="2026-03-20T00:00:00Z",
                    to_ts="2026-03-10T00:00:00Z",
                    has_media=None,
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
                    author_id=None,
                    q=None,
                    from_ts="2026-03-01T00:00:00Z",
                    to_ts="2026-03-10T00:00:00Z",
                    has_media=None,
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
            patch.object(newsfeed, "parse_filter_window", return_value=(None, None)),
        ):
            with self.assertRaises(HTTPException) as exc:
                newsfeed.view_feed(
                    limit=20,
                    cursor="bad-cursor",
                    author_id="author_ok",
                    q=None,
                    from_ts=None,
                    to_ts=None,
                    has_media=None,
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
            patch.object(newsfeed, "parse_filter_window", return_value=(None, None)),
        ):
            settings.newsfeed_feed_max_cursor_chars = 8
            with self.assertRaises(HTTPException) as exc:
                newsfeed.view_feed(
                    limit=20,
                    cursor="x" * 20,
                    author_id="author_ok",
                    q=None,
                    from_ts=None,
                    to_ts=None,
                    has_media=None,
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
            patch.object(newsfeed, "parse_filter_window", return_value=(None, None)),
            patch.object(newsfeed, "decode_cursor_or_400", return_value=None),
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
                    q=None,
                    from_ts=None,
                    to_ts=None,
                    has_media=None,
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
                {"post_id": "p2", "user_id": "target_author", "created_at": "2026-03-20T00:00:00Z", "locked": False, "body": "release notes", "image_urls": ["a.png"]},
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
            patch.object(newsfeed, "parse_filter_window", return_value=(None, None)),
            patch.object(newsfeed, "rate_limit_feed_query"),
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
                from_ts=None,
                to_ts=None,
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

    def test_unlock_post_request_rejects_invalid_idempotency_key_format(self):
        with self.assertRaises(ValidationError):
            newsfeed.UnlockPostRequest(post_id="p1", idempotency_key="bad key with spaces")
        with self.assertRaises(ValidationError):
            newsfeed.UnlockPostRequest(post_id="p1", idempotency_key="bad\nnewline")

    def test_feed_capabilities_returns_enabled_when_rollout_allows_user(self):
        with (
            patch.object(newsfeed, "_is_unlock_limit_enabled_for_user", return_value=True),
            patch.object(newsfeed, "S") as settings,
        ):
            settings.newsfeed_unlock_limit_rollout_mode = "cohort"
            resp = newsfeed.feed_capabilities(user_id="u1")
        self.assertTrue(resp.unlock_limit_enabled)
        self.assertEqual(resp.unlock_limit_rollout_mode, "cohort")

    def test_feed_capabilities_returns_disabled_when_rollout_blocks_user(self):
        with (
            patch.object(newsfeed, "_is_unlock_limit_enabled_for_user", return_value=False),
            patch.object(newsfeed, "S") as settings,
        ):
            settings.newsfeed_unlock_limit_rollout_mode = "internal"
            resp = newsfeed.feed_capabilities(user_id="u_external")
        self.assertFalse(resp.unlock_limit_enabled)
        self.assertEqual(resp.unlock_limit_rollout_mode, "internal")

    def test_unlock_limit_rollout_internal_only(self):
        with patch.object(newsfeed, "S") as settings:
            settings.newsfeed_unlock_limit_enabled = True
            settings.newsfeed_unlock_limit_rollout_mode = "internal"
            settings.newsfeed_unlock_limit_internal_user_ids = "u_internal_1,u_internal_2"
            settings.newsfeed_unlock_limit_cohort_user_ids = ""
            self.assertTrue(newsfeed._is_unlock_limit_enabled_for_user("u_internal_1"))
            self.assertFalse(newsfeed._is_unlock_limit_enabled_for_user("u_external"))

    def test_unlock_limit_rollout_cohort_includes_internal(self):
        with patch.object(newsfeed, "S") as settings:
            settings.newsfeed_unlock_limit_enabled = True
            settings.newsfeed_unlock_limit_rollout_mode = "cohort"
            settings.newsfeed_unlock_limit_internal_user_ids = "u_internal"
            settings.newsfeed_unlock_limit_cohort_user_ids = "u_cohort_1,u_cohort_2"
            self.assertTrue(newsfeed._is_unlock_limit_enabled_for_user("u_internal"))
            self.assertTrue(newsfeed._is_unlock_limit_enabled_for_user("u_cohort_1"))
            self.assertFalse(newsfeed._is_unlock_limit_enabled_for_user("u_external"))

    def test_unlock_limit_rollout_disabled_global_flag(self):
        with patch.object(newsfeed, "S") as settings:
            settings.newsfeed_unlock_limit_enabled = False
            settings.newsfeed_unlock_limit_rollout_mode = "broad"
            settings.newsfeed_unlock_limit_internal_user_ids = ""
            settings.newsfeed_unlock_limit_cohort_user_ids = ""
            self.assertFalse(newsfeed._is_unlock_limit_enabled_for_user("u_any"))

    def test_unlock_attempt_throttle_blocks_rapid_retries(self):
        newsfeed._UNLOCK_ATTEMPT_THROTTLE.clear()
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed.time, "time", side_effect=[100, 101]),
        ):
            settings.newsfeed_unlock_throttle_window_seconds = 60
            settings.newsfeed_unlock_throttle_max_attempts = 1
            newsfeed._enforce_unlock_attempt_throttle("u1", "p1")
            with self.assertRaises(HTTPException) as ctx:
                newsfeed._enforce_unlock_attempt_throttle("u1", "p1")

        self.assertEqual(ctx.exception.status_code, 429)
        self.assertEqual(ctx.exception.detail["code"], "unlock_attempt_throttled")

    def test_unlock_attempt_throttle_allows_attempt_after_window(self):
        newsfeed._UNLOCK_ATTEMPT_THROTTLE.clear()
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed.time, "time", side_effect=[100, 170]),
        ):
            settings.newsfeed_unlock_throttle_window_seconds = 60
            settings.newsfeed_unlock_throttle_max_attempts = 1
            newsfeed._enforce_unlock_attempt_throttle("u1", "p1")
            # second attempt after window should be allowed
            newsfeed._enforce_unlock_attempt_throttle("u1", "p1")

    def test_reserve_unlock_slot_uses_conditional_expression_with_missing_count_support(self):
        with patch.object(newsfeed, "tbl") as table:
            table.update_item.return_value = {}
            newsfeed._reserve_unlock_slot_or_raise("post_1")

        kwargs = table.update_item.call_args.kwargs
        self.assertEqual(
            kwargs["ConditionExpression"],
            "attribute_not_exists(unlock_limit) OR attribute_not_exists(unlock_count) OR unlock_count < unlock_limit",
        )
        self.assertEqual(kwargs["ExpressionAttributeValues"], {":z": 0, ":one": 1})

    def test_reserve_unlock_slot_raises_unlock_limit_reached_on_conditional_failure(self):
        err = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "condition failed"}},
            "UpdateItem",
        )
        with patch.object(newsfeed, "tbl") as table:
            table.update_item.side_effect = err
            with self.assertRaises(HTTPException) as ctx:
                newsfeed._reserve_unlock_slot_or_raise("post_1")

        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "unlock_limit_reached")
        self.assertEqual(ctx.exception.detail["message"], "unlock limit reached")

    def test_reserve_unlock_slot_does_not_raise_for_uncapped_posts(self):
        with patch.object(newsfeed, "tbl") as table:
            table.update_item.return_value = {}
            newsfeed._reserve_unlock_slot_or_raise("post_uncapped")

        table.update_item.assert_called_once()

    def test_reserve_unlock_slot_parallel_harness_caps_successes_at_limit(self):
        cap = 5
        attempts = cap + 17
        state_lock = threading.Lock()
        state = {"unlock_count": 0}

        def fake_update_item(**kwargs):
            with state_lock:
                if state["unlock_count"] >= cap:
                    raise ClientError(
                        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "condition failed"}},
                        "UpdateItem",
                    )
                state["unlock_count"] += 1
            return {}

        def attempt_once():
            try:
                newsfeed._reserve_unlock_slot_or_raise("post_cap")
                return "ok"
            except HTTPException as exc:
                self.assertEqual(exc.status_code, 409)
                self.assertEqual(exc.detail["code"], "unlock_limit_reached")
                return "cap_reached"

        with patch.object(newsfeed, "tbl") as table:
            table.update_item.side_effect = fake_update_item
            with ThreadPoolExecutor(max_workers=attempts) as executor:
                results = list(executor.map(lambda _: attempt_once(), range(attempts)))

        self.assertEqual(results.count("ok"), cap)
        self.assertEqual(results.count("cap_reached"), attempts - cap)
        self.assertEqual(state["unlock_count"], cap)

    def test_reserve_unlock_slot_parallel_harness_no_overcap_under_repeated_stress(self):
        cap = 3
        attempts = cap + 11
        rounds = 20

        for _ in range(rounds):
            state_lock = threading.Lock()
            state = {"unlock_count": 0}

            def fake_update_item(**kwargs):
                with state_lock:
                    if state["unlock_count"] >= cap:
                        raise ClientError(
                            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "condition failed"}},
                            "UpdateItem",
                        )
                    state["unlock_count"] += 1
                return {}

            def attempt_once():
                try:
                    newsfeed._reserve_unlock_slot_or_raise("post_cap_stress")
                    return "ok"
                except HTTPException as exc:
                    self.assertEqual(exc.status_code, 409)
                    self.assertEqual(exc.detail["code"], "unlock_limit_reached")
                    return "cap_reached"

            with patch.object(newsfeed, "tbl") as table:
                table.update_item.side_effect = fake_update_item
                with ThreadPoolExecutor(max_workers=attempts) as executor:
                    results = list(executor.map(lambda _: attempt_once(), range(attempts)))

            self.assertEqual(results.count("ok"), cap)
            self.assertEqual(results.count("cap_reached"), attempts - cap)
            self.assertEqual(state["unlock_count"], cap)

    def test_begin_unlock_attempt_returns_already_unlocked_when_unlock_exists(self):
        err = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "condition failed"}},
            "PutItem",
        )
        with (
            patch.object(newsfeed, "tbl") as table,
            patch.object(newsfeed, "ddb_get_item", return_value={"unlocked": True}),
        ):
            table.put_item.side_effect = err
            state = newsfeed._begin_unlock_attempt("u1", "p1")
        self.assertEqual(state, "already_unlocked")

    def test_begin_unlock_attempt_raises_idempotency_conflict_when_existing_key_differs(self):
        err = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "condition failed"}},
            "PutItem",
        )
        with (
            patch.object(newsfeed, "tbl") as table,
            patch.object(newsfeed, "ddb_get_item", return_value={"unlocked": True, "idempotency_key": "idem-existing"}),
        ):
            table.put_item.side_effect = err
            with self.assertRaises(HTTPException) as ctx:
                newsfeed._begin_unlock_attempt("u1", "p1", idempotency_key="idem-new")

        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "unlock_idempotency_conflict")

    def test_begin_unlock_attempt_raises_payload_mismatch_for_same_idempotency_key(self):
        err = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "condition failed"}},
            "PutItem",
        )
        with (
            patch.object(newsfeed, "tbl") as table,
            patch.object(
                newsfeed,
                "ddb_get_item",
                return_value={
                    "unlocked": True,
                    "idempotency_key": "idem-1",
                    "request_fingerprint": "fp-original",
                },
            ),
        ):
            table.put_item.side_effect = err
            with self.assertRaises(HTTPException) as ctx:
                newsfeed._begin_unlock_attempt(
                    "u1",
                    "p1",
                    idempotency_key="idem-1",
                    request_fingerprint="fp-other",
                )

        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "unlock_idempotency_payload_mismatch")

    def test_begin_unlock_attempt_persists_idempotency_key_when_provided(self):
        with patch.object(newsfeed, "tbl") as table:
            state = newsfeed._begin_unlock_attempt("u1", "p1", idempotency_key="idem-1")

        self.assertEqual(state, "new")
        item = table.put_item.call_args.kwargs["Item"]
        self.assertEqual(item["idempotency_key"], "idem-1")

    def test_begin_unlock_attempt_returns_in_progress_when_pending_exists(self):
        err = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "condition failed"}},
            "PutItem",
        )
        with (
            patch.object(newsfeed, "tbl") as table,
            patch.object(newsfeed, "ddb_get_item", return_value={"unlocked": False, "in_progress": True}),
        ):
            table.put_item.side_effect = err
            state = newsfeed._begin_unlock_attempt("u1", "p1")
        self.assertEqual(state, "in_progress")

    def test_unlock_post_reserves_slot_before_payment_intent(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None, idempotency_key="idem-1")
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}

        with (
            patch.object(newsfeed, "ddb_get_item", return_value=post),
            patch.object(newsfeed, "_enforce_unlock_attempt_throttle"),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation", return_value="new") as reserve_with_begin,
            patch.object(newsfeed, "payments") as payments,
            patch.object(newsfeed, "_finalize_unlock_attempt_success"),
            patch.object(newsfeed, "put_notification"),
            patch.object(newsfeed, "S") as settings,
        ):
            settings.billing_table_name = None
            payments.create_payment_intent.return_value = {"payment_intent_id": "pi_1", "status": "requires_confirmation"}
            payments.confirm_payment_intent.return_value = {"status": "succeeded"}

            newsfeed.unlock_post(req, user_id="u1")

        reserve_with_begin.assert_called_once()
        self.assertEqual(reserve_with_begin.call_args.args, ("u1", "post_1"))
        self.assertEqual(reserve_with_begin.call_args.kwargs["idempotency_key"], "idem-1")
        self.assertEqual(
            reserve_with_begin.call_args.kwargs["request_fingerprint"],
            newsfeed._unlock_request_fingerprint(post_id="post_1", payment_method_id=None, unlock_price_cents=123),
        )
        payments.create_payment_intent.assert_called_once()
        create_kwargs = payments.create_payment_intent.call_args.kwargs
        self.assertEqual(
            create_kwargs["metadata"],
            {
                "type": "unlock_post",
                "post_id": "post_1",
                "idempotency_key": "idem-1",
                "request_fingerprint": newsfeed._unlock_request_fingerprint(post_id="post_1", payment_method_id=None, unlock_price_cents=123),
            },
        )

    def test_unlock_post_returns_in_progress_without_reserve_or_charge(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None)
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}

        with (
            patch.object(newsfeed, "ddb_get_item", return_value=post),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation", return_value="in_progress"),
            patch.object(newsfeed, "payments") as payments,
        ):
            resp = newsfeed.unlock_post(req, user_id="u1")

        self.assertEqual(resp.payment_intent["status"], "in_progress")
        payments.create_payment_intent.assert_not_called()

    def test_unlock_post_already_unlocked_without_idempotency_bypasses_throttle(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None)
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}
        unlock_record = {"unlocked": True}

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[post, unlock_record]),
            patch.object(newsfeed, "_enforce_unlock_attempt_throttle") as enforce_throttle,
        ):
            resp = newsfeed.unlock_post(req, user_id="u1")

        self.assertEqual(resp.payment_intent["status"], "already_unlocked")
        enforce_throttle.assert_not_called()

    def test_unlock_post_emits_replay_event_for_already_unlocked_without_idempotency(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None)
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}
        unlock_record = {"unlocked": True}

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[post, unlock_record]),
            patch.object(newsfeed, "_emit_unlock_lifecycle_event") as emit_event,
        ):
            newsfeed.unlock_post(req, user_id="u1")

        emit_event.assert_any_call(
            "unlock_replay",
            user_id="u1",
            post_id="post_1",
            reason_code="existing_unlocked_precheck",
            payment_status="already_unlocked",
            replayed=False,
        )

    def test_unlock_post_passes_request_fingerprint_metadata_without_idempotency_key(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None)
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}

        with (
            patch.object(newsfeed, "ddb_get_item", return_value=post),
            patch.object(newsfeed, "_enforce_unlock_attempt_throttle"),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation", return_value="new"),
            patch.object(newsfeed, "_finalize_unlock_attempt_success"),
            patch.object(newsfeed, "put_notification"),
            patch.object(newsfeed, "payments") as payments,
            patch.object(newsfeed, "S") as settings,
        ):
            settings.billing_table_name = None
            payments.create_payment_intent.return_value = {"payment_intent_id": "pi_1", "status": "requires_confirmation"}
            payments.confirm_payment_intent.return_value = {"status": "succeeded"}
            newsfeed.unlock_post(req, user_id="u1")

        create_kwargs = payments.create_payment_intent.call_args.kwargs
        self.assertEqual(create_kwargs["metadata"]["idempotency_key"], "")
        self.assertEqual(
            create_kwargs["metadata"]["request_fingerprint"],
            newsfeed._unlock_request_fingerprint(post_id="post_1", payment_method_id=None, unlock_price_cents=123),
        )

    def test_unlock_post_writes_billing_ledger_with_idempotency_context(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None, idempotency_key="idem-1")
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}

        with (
            patch.object(newsfeed, "ddb_get_item", return_value=post),
            patch.object(newsfeed, "_enforce_unlock_attempt_throttle"),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation", return_value="new"),
            patch.object(newsfeed, "_finalize_unlock_attempt_success"),
            patch.object(newsfeed, "put_notification"),
            patch.object(newsfeed, "payments") as payments,
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "S") as settings,
        ):
            settings.billing_table_name = "billing"
            payments.create_payment_intent.return_value = {"payment_intent_id": "pi_1", "status": "requires_confirmation"}
            payments.confirm_payment_intent.return_value = {"status": "succeeded"}
            billing_table = Mock()
            ddb.Table.return_value = billing_table

            newsfeed.unlock_post(req, user_id="u1")

        ledger_item = billing_table.put_item.call_args.kwargs["Item"]
        self.assertEqual(ledger_item["meta"]["idempotency_key"], "idem-1")
        self.assertEqual(
            ledger_item["meta"]["request_fingerprint"],
            newsfeed._unlock_request_fingerprint(post_id="post_1", payment_method_id=None, unlock_price_cents=123),
        )
        self.assertEqual(ledger_item["meta"]["payment_intent_id"], "pi_1")

    def test_unlock_post_returns_in_progress_replay_for_matching_idempotency_key(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None, idempotency_key="idem-1")
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}
        in_progress_attempt = {"in_progress": True, "unlocked": False, "idempotency_key": "idem-1", "updated_at": "2999-01-01T00:00:00+00:00"}

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[post, in_progress_attempt]),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation", return_value="in_progress"),
            patch.object(newsfeed, "payments") as payments,
        ):
            resp = newsfeed.unlock_post(req, user_id="u1")

        self.assertEqual(resp.payment_intent["status"], "in_progress")
        self.assertTrue(resp.payment_intent["replayed"])
        payments.create_payment_intent.assert_not_called()

    def test_unlock_post_replay_bypasses_throttle_for_already_unlocked(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None, idempotency_key="idem-1")
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}
        existing_unlock = {"unlocked": True, "idempotency_key": "idem-1", "payment_intent_id": "pi_1"}

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[post, existing_unlock]),
            patch.object(newsfeed, "_enforce_unlock_attempt_throttle") as enforce_throttle,
        ):
            resp = newsfeed.unlock_post(req, user_id="u1")

        self.assertEqual(resp.payment_intent["status"], "succeeded")
        self.assertTrue(resp.payment_intent["replayed"])
        enforce_throttle.assert_not_called()

    def test_unlock_post_emits_replay_event_for_already_unlocked_replay(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None, idempotency_key="idem-1")
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}
        unlock_record = {"unlocked": True, "idempotency_key": "idem-1", "payment_intent_id": "pi_1"}

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[post, unlock_record]),
            patch.object(newsfeed, "_emit_unlock_lifecycle_event") as emit_event,
        ):
            newsfeed.unlock_post(req, user_id="u1")

        emit_event.assert_any_call(
            "unlock_replay",
            user_id="u1",
            post_id="post_1",
            reason_code="existing_unlocked_precheck",
            payment_status="already_unlocked",
            replayed=True,
        )

    def test_unlock_post_replay_bypasses_throttle_for_in_progress(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None, idempotency_key="idem-1")
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}
        existing_unlock = {"in_progress": True, "unlocked": False, "idempotency_key": "idem-1"}

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[post, existing_unlock]),
            patch.object(newsfeed, "_enforce_unlock_attempt_throttle") as enforce_throttle,
        ):
            resp = newsfeed.unlock_post(req, user_id="u1")

        self.assertEqual(resp.payment_intent["status"], "in_progress")
        self.assertTrue(resp.payment_intent["replayed"])
        enforce_throttle.assert_not_called()

    def test_unlock_post_emits_replay_event_for_in_progress_precheck(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None, idempotency_key="idem-1")
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}
        existing_unlock = {"in_progress": True, "unlocked": False, "idempotency_key": "idem-1"}

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[post, existing_unlock]),
            patch.object(newsfeed, "_emit_unlock_lifecycle_event") as emit_event,
        ):
            newsfeed.unlock_post(req, user_id="u1")

        emit_event.assert_any_call(
            "unlock_replay",
            user_id="u1",
            post_id="post_1",
            reason_code="existing_in_progress_precheck",
            payment_status="in_progress",
            replayed=True,
        )

    def test_unlock_post_emits_replay_event_for_in_progress_attempt_state(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None, idempotency_key="idem-1")
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}
        in_progress_unlock = {"in_progress": True, "unlocked": False, "idempotency_key": "idem-1"}

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[post, {}, in_progress_unlock]),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation", return_value="in_progress"),
            patch.object(newsfeed, "_emit_unlock_lifecycle_event") as emit_event,
        ):
            newsfeed.unlock_post(req, user_id="u1")

        emit_event.assert_any_call(
            "unlock_replay",
            user_id="u1",
            post_id="post_1",
            reason_code="attempt_state_in_progress",
            payment_status="in_progress",
            replayed=True,
        )

    def test_unlock_post_replay_stale_in_progress_recovers_then_continues_flow(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None, idempotency_key="idem-1")
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}
        stale_unlock = {
            "in_progress": True,
            "unlocked": False,
            "idempotency_key": "idem-1",
            "updated_at": "2000-01-01T00:00:00+00:00",
        }

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[post, stale_unlock]),
            patch.object(newsfeed, "_enforce_unlock_attempt_throttle"),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation", return_value="new") as begin_with_reservation,
            patch.object(newsfeed, "_clear_unlock_attempt_if_not_unlocked", return_value=True) as clear_attempt,
            patch.object(newsfeed, "_release_reserved_unlock_slot") as release_slot,
            patch.object(newsfeed, "_finalize_unlock_attempt_success"),
            patch.object(newsfeed, "payments") as payments,
            patch.object(newsfeed, "put_notification"),
            patch.object(newsfeed, "S") as settings,
        ):
            settings.billing_table_name = None
            settings.newsfeed_unlock_attempt_stale_seconds = 300
            payments.create_payment_intent.return_value = {"payment_intent_id": "pi_1", "status": "requires_confirmation"}
            payments.confirm_payment_intent.return_value = {"status": "succeeded"}

            resp = newsfeed.unlock_post(req, user_id="u1")

        self.assertEqual(resp.payment_intent["payment_intent_id"], "pi_1")
        begin_with_reservation.assert_called_once()
        clear_attempt.assert_called_once_with("u1", "post_1")
        release_slot.assert_called_once_with("post_1")

    def test_unlock_post_raises_conflict_for_in_progress_mismatched_idempotency_key(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None, idempotency_key="idem-new")
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}
        in_progress_attempt = {"in_progress": True, "unlocked": False, "idempotency_key": "idem-existing", "updated_at": "2999-01-01T00:00:00+00:00"}

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[post, in_progress_attempt]),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation", return_value="in_progress"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                newsfeed.unlock_post(req, user_id="u1")

        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "unlock_idempotency_conflict")

    def test_unlock_post_emits_event_for_idempotency_conflict(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None, idempotency_key="idem-new")
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}
        in_progress_attempt = {"in_progress": True, "unlocked": False, "idempotency_key": "idem-existing", "updated_at": "2999-01-01T00:00:00+00:00"}

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[post, in_progress_attempt]),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation", return_value="in_progress"),
            patch.object(newsfeed, "_emit_unlock_lifecycle_event") as emit_event,
        ):
            with self.assertRaises(HTTPException):
                newsfeed.unlock_post(req, user_id="u1")

        emit_event.assert_any_call(
            "unlock_payment_failed",
            user_id="u1",
            post_id="post_1",
            reason_code="unlock_idempotency_conflict",
            payment_status="idempotency_rejected",
        )

    def test_unlock_post_raises_payload_mismatch_for_in_progress_same_key(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id="pm_new", idempotency_key="idem-1")
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}
        in_progress_attempt = {
            "in_progress": True,
            "unlocked": False,
            "idempotency_key": "idem-1",
            "request_fingerprint": newsfeed._unlock_request_fingerprint(post_id="post_1", payment_method_id="pm_old", unlock_price_cents=123),
            "updated_at": "2999-01-01T00:00:00+00:00",
        }

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[post, in_progress_attempt]),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation", return_value="in_progress"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                newsfeed.unlock_post(req, user_id="u1")

        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "unlock_idempotency_payload_mismatch")

    def test_unlock_post_emits_event_for_idempotency_payload_mismatch(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id="pm_new", idempotency_key="idem-1")
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}
        in_progress_attempt = {
            "in_progress": True,
            "unlocked": False,
            "idempotency_key": "idem-1",
            "request_fingerprint": newsfeed._unlock_request_fingerprint(post_id="post_1", payment_method_id="pm_old", unlock_price_cents=123),
            "updated_at": "2999-01-01T00:00:00+00:00",
        }

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[post, in_progress_attempt]),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation", return_value="in_progress"),
            patch.object(newsfeed, "_emit_unlock_lifecycle_event") as emit_event,
        ):
            with self.assertRaises(HTTPException):
                newsfeed.unlock_post(req, user_id="u1")

        emit_event.assert_any_call(
            "unlock_payment_failed",
            user_id="u1",
            post_id="post_1",
            reason_code="unlock_idempotency_payload_mismatch",
            payment_status="idempotency_rejected",
        )

    def test_unlock_post_recovers_stale_in_progress_attempt_and_retries(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None)
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}
        stale_attempt = {
            "in_progress": True,
            "unlocked": False,
            "updated_at": "2000-01-01T00:00:00+00:00",
        }

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[post, {}, stale_attempt]),
            patch.object(newsfeed, "_enforce_unlock_attempt_throttle"),
            patch.object(newsfeed, "_is_unlock_limit_enabled_for_user", return_value=True),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation", side_effect=["in_progress", "new"]) as begin_with_reservation,
            patch.object(newsfeed, "_clear_unlock_attempt_if_not_unlocked", return_value=True) as clear_attempt,
            patch.object(newsfeed, "_release_reserved_unlock_slot") as release_slot,
            patch.object(newsfeed, "_finalize_unlock_attempt_success"),
            patch.object(newsfeed, "payments") as payments,
            patch.object(newsfeed, "put_notification"),
            patch.object(newsfeed, "S") as settings,
        ):
            settings.billing_table_name = None
            settings.newsfeed_unlock_attempt_stale_seconds = 300
            payments.create_payment_intent.return_value = {"payment_intent_id": "pi_1", "status": "requires_confirmation"}
            payments.confirm_payment_intent.return_value = {"status": "succeeded"}

            resp = newsfeed.unlock_post(req, user_id="u1")

        self.assertEqual(resp.payment_intent["payment_intent_id"], "pi_1")
        self.assertEqual(begin_with_reservation.call_count, 2)
        clear_attempt.assert_called_once_with("u1", "post_1")
        release_slot.assert_called_once_with("post_1")

    def test_unlock_post_keeps_fresh_in_progress_attempt(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None)
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}
        fresh_attempt = {
            "in_progress": True,
            "unlocked": False,
            "updated_at": "2999-01-01T00:00:00+00:00",
        }

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[post, {}, fresh_attempt]),
            patch.object(newsfeed, "_enforce_unlock_attempt_throttle"),
            patch.object(newsfeed, "_is_unlock_limit_enabled_for_user", return_value=True),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation", return_value="in_progress"),
            patch.object(newsfeed, "_clear_unlock_attempt_if_not_unlocked") as clear_attempt,
            patch.object(newsfeed, "_release_reserved_unlock_slot") as release_slot,
            patch.object(newsfeed, "payments") as payments,
            patch.object(newsfeed, "S") as settings,
        ):
            settings.newsfeed_unlock_attempt_stale_seconds = 300
            resp = newsfeed.unlock_post(req, user_id="u1")

        self.assertEqual(resp.payment_intent["status"], "in_progress")
        clear_attempt.assert_not_called()
        release_slot.assert_not_called()
        payments.create_payment_intent.assert_not_called()

    def test_unlock_post_returns_replayed_success_for_matching_idempotency_key(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None, idempotency_key="idem-1")
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}
        unlock_record = {"unlocked": True, "idempotency_key": "idem-1", "payment_intent_id": "pi_1"}

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[post, unlock_record]),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation", return_value="already_unlocked"),
        ):
            resp = newsfeed.unlock_post(req, user_id="u1")

        self.assertEqual(resp.payment_intent["status"], "succeeded")
        self.assertTrue(resp.payment_intent["replayed"])
        self.assertEqual(resp.payment_intent["payment_intent_id"], "pi_1")

    def test_unlock_post_raises_idempotency_conflict_for_already_unlocked_mismatched_key(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None, idempotency_key="idem-new")
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}
        unlock_record = {"unlocked": True, "idempotency_key": "idem-existing", "payment_intent_id": "pi_1"}

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[post, unlock_record]),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation", return_value="already_unlocked"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                newsfeed.unlock_post(req, user_id="u1")

        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "unlock_idempotency_conflict")

    def test_unlock_post_clears_attempt_when_reservation_fails(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None)
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}
        reservation_error = HTTPException(status_code=409, detail={"code": "unlock_limit_reached", "message": "unlock limit reached"})

        with (
            patch.object(newsfeed, "ddb_get_item", return_value=post),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation", side_effect=reservation_error),
            patch.object(newsfeed, "_clear_unlock_attempt_if_not_unlocked") as clear_attempt,
        ):
            with self.assertRaises(HTTPException) as ctx:
                newsfeed.unlock_post(req, user_id="u1")

        self.assertEqual(ctx.exception.status_code, 409)
        clear_attempt.assert_not_called()

    def test_unlock_post_releases_slot_and_clears_attempt_on_payment_failure(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None)
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}

        with (
            patch.object(newsfeed, "ddb_get_item", return_value=post),
            patch.object(newsfeed, "_enforce_unlock_attempt_throttle"),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation", return_value="new"),
            patch.object(newsfeed, "_release_reserved_unlock_slot") as release_slot,
            patch.object(newsfeed, "_clear_unlock_attempt_if_not_unlocked") as clear_attempt,
            patch.object(newsfeed, "payments") as payments,
            patch.object(newsfeed, "S") as settings,
        ):
            settings.billing_table_name = None
            payments.create_payment_intent.return_value = {"payment_intent_id": "pi_1", "status": "requires_confirmation"}
            payments.confirm_payment_intent.return_value = {"status": "requires_payment_method"}
            with self.assertRaises(HTTPException) as ctx:
                newsfeed.unlock_post(req, user_id="u1")

        self.assertEqual(ctx.exception.status_code, 402)
        release_slot.assert_called_once_with("post_1")
        clear_attempt.assert_called_once_with("u1", "post_1")

    def test_unlock_post_emits_unlock_payment_failed_event_on_confirm_failure(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None)
        post = {"post_id": "post_1", "user_id": "author_1", "locked": True, "unlock_price_cents": 123}

        with (
            patch.object(newsfeed, "ddb_get_item", return_value=post),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation", return_value="new"),
            patch.object(newsfeed, "_release_reserved_unlock_slot"),
            patch.object(newsfeed, "_clear_unlock_attempt_if_not_unlocked"),
            patch.object(newsfeed, "payments") as payments,
            patch.object(newsfeed, "_emit_unlock_lifecycle_event") as emit_event,
            patch.object(newsfeed, "S") as settings,
        ):
            settings.billing_table_name = None
            payments.create_payment_intent.return_value = {"payment_intent_id": "pi_1", "status": "requires_confirmation"}
            payments.confirm_payment_intent.return_value = {"status": "requires_payment_method"}
            with self.assertRaises(HTTPException):
                newsfeed.unlock_post(req, user_id="u1")

        event_names = [call.args[0] for call in emit_event.call_args_list]
        self.assertIn("unlock_attempt", event_names)
        self.assertIn("unlock_payment_failed", event_names)

    def test_begin_unlock_attempt_with_reservation_falls_back_when_transaction_unavailable(self):
        err = ClientError({"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "throttled"}}, "TransactWriteItems")
        with (
            patch.object(newsfeed, "tbl") as table,
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation_fallback", return_value="new") as fallback,
        ):
            table.meta.client.transact_write_items.side_effect = err
            state = newsfeed._begin_unlock_attempt_with_reservation("u1", "p1", idempotency_key="idem-1")
        self.assertEqual(state, "new")
        fallback.assert_called_once_with("u1", "p1", idempotency_key="idem-1", request_fingerprint=None)

    def test_begin_unlock_attempt_with_reservation_persists_idempotency_key_in_transaction_put(self):
        with patch.object(newsfeed, "tbl") as table:
            state = newsfeed._begin_unlock_attempt_with_reservation("u1", "p1", idempotency_key="idem-1")

        self.assertEqual(state, "new")
        transact_items = table.meta.client.transact_write_items.call_args.kwargs["TransactItems"]
        put_item = transact_items[1]["Put"]["Item"]
        deserializer = TypeDeserializer()
        python_item = {k: deserializer.deserialize(v) for k, v in put_item.items()}
        self.assertEqual(python_item["idempotency_key"], "idem-1")

    def test_begin_unlock_attempt_with_reservation_emits_cap_reached_event(self):
        err = ClientError({"Error": {"Code": "TransactionCanceledException", "Message": "cancelled"}}, "TransactWriteItems")
        with (
            patch.object(newsfeed, "tbl") as table,
            patch.object(newsfeed, "ddb_get_item", return_value=None),
            patch.object(newsfeed, "_emit_unlock_lifecycle_event") as emit_event,
        ):
            table.meta.client.transact_write_items.side_effect = err
            with self.assertRaises(HTTPException) as ctx:
                newsfeed._begin_unlock_attempt_with_reservation("u1", "p1")

        self.assertEqual(ctx.exception.status_code, 409)
        emit_event.assert_any_call(
            "unlock_limit_reached",
            user_id="u1",
            post_id="p1",
            reason_code="cap_reached_transaction",
        )

    def test_begin_unlock_attempt_with_reservation_raises_idempotency_conflict_on_existing_key_mismatch(self):
        err = ClientError({"Error": {"Code": "TransactionCanceledException", "Message": "cancelled"}}, "TransactWriteItems")
        with (
            patch.object(newsfeed, "tbl") as table,
            patch.object(newsfeed, "ddb_get_item", return_value={"unlocked": True, "idempotency_key": "idem-existing"}),
        ):
            table.meta.client.transact_write_items.side_effect = err
            with self.assertRaises(HTTPException) as ctx:
                newsfeed._begin_unlock_attempt_with_reservation("u1", "p1", idempotency_key="idem-new")

        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "unlock_idempotency_conflict")

    def test_notify_author_unlock_limit_reached_once_deduplicates(self):
        conditional_fail = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "duplicate"}},
            "PutItem",
        )
        post = {"post_id": "p1", "user_id": "author_1", "unlock_limit": 1, "unlock_count": 1}
        with (
            patch.object(newsfeed, "ddb_get_item", return_value=post),
            patch.object(newsfeed, "tbl") as table,
            patch.object(newsfeed, "put_notification") as notify,
        ):
            table.put_item.side_effect = [None, conditional_fail]
            newsfeed._notify_author_unlock_limit_reached_once(post_id="p1", triggered_by_user_id="u2")
            newsfeed._notify_author_unlock_limit_reached_once(post_id="p1", triggered_by_user_id="u3")

        notify.assert_called_once()
        self.assertEqual(notify.call_args.kwargs["recipient_user_id"], "author_1")
        self.assertEqual(notify.call_args.kwargs["notif_type"], "post_unlock_limit_reached")

    def test_create_post_rejects_unlock_limit_for_unlocked_posts(self):
        req = newsfeed.CreatePostRequest(body="hello", unlock_limit=2)

        with (
            patch.object(newsfeed, "_is_unlock_limit_enabled_for_user", return_value=True),
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck") as quota_precheck,
        ):
            with self.assertRaises(HTTPException) as ctx:
                newsfeed.create_post(req, user_id="u1")

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "unlock_limit_requires_locked_post")
        self.assertEqual(ctx.exception.detail["message"], "unlock_limit can only be set for locked posts")
        quota_precheck.assert_not_called()

    def test_edit_post_rejects_unlock_limit_for_unlocked_posts(self):
        req = newsfeed.EditPostRequest(body="updated", unlock_limit=2)
        post = {"post_id": "p1", "user_id": "u1", "locked": False}

        with (
            patch.object(newsfeed, "_is_unlock_limit_enabled_for_user", return_value=True),
            patch.object(newsfeed, "ddb_get_item", return_value=post),
        ):
            with self.assertRaises(HTTPException) as ctx:
                newsfeed.edit_post("p1", req, user_id="u1")

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "unlock_limit_requires_locked_post")
        self.assertEqual(ctx.exception.detail["message"], "unlock_limit can only be set for locked posts")

    def test_edit_post_rejects_unlock_limit_below_unlock_count(self):
        req = newsfeed.EditPostRequest(body="updated", unlock_limit=1)
        post = {"post_id": "p1", "user_id": "u1", "locked": True, "unlock_count": 2}

        with (
            patch.object(newsfeed, "_is_unlock_limit_enabled_for_user", return_value=True),
            patch.object(newsfeed, "ddb_get_item", return_value=post),
        ):
            with self.assertRaises(HTTPException) as ctx:
                newsfeed.edit_post("p1", req, user_id="u1")

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "unlock_limit_below_unlock_count")
        self.assertEqual(ctx.exception.detail["message"], "unlock_limit cannot be lower than current unlock_count")

    def test_create_post_rejects_unlock_limit_when_feature_disabled_for_user(self):
        req = newsfeed.CreatePostRequest(body="hello", unlock_price_cents=123, unlock_limit=2)

        with patch.object(newsfeed, "_is_unlock_limit_enabled_for_user", return_value=False):
            with self.assertRaises(HTTPException) as ctx:
                newsfeed.create_post(req, user_id="u1")

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "unlock_limit_feature_disabled")

    def test_edit_post_rejects_unlock_limit_when_feature_disabled_for_user(self):
        req = newsfeed.EditPostRequest(body="updated", unlock_limit=2)
        post = {"post_id": "p1", "user_id": "u1", "locked": True, "unlock_count": 0}

        with (
            patch.object(newsfeed, "_is_unlock_limit_enabled_for_user", return_value=False),
            patch.object(newsfeed, "ddb_get_item", return_value=post),
        ):
            with self.assertRaises(HTTPException) as ctx:
                newsfeed.edit_post("p1", req, user_id="u1")

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "unlock_limit_feature_disabled")

    def test_create_post_persists_unlock_limit_and_initial_unlock_count_when_capped(self):
        req = newsfeed.CreatePostRequest(body="hello", unlock_price_cents=250, unlock_limit=3)
        with (
            patch.object(newsfeed, "new_id", return_value="post_1"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed, "ddb_put_item") as put_item,
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
            patch.object(newsfeed, "_meter_newsfeed_post_publish"),
        ):
            newsfeed.create_post(req, user_id="u1")

        post_item = put_item.call_args_list[0].args[0]
        self.assertEqual(post_item["unlock_limit"], 3)
        self.assertEqual(post_item["unlock_count"], 0)

    def test_create_post_omits_unlock_limit_fields_for_unlocked_posts(self):
        req = newsfeed.CreatePostRequest(body="hello")
        with (
            patch.object(newsfeed, "new_id", return_value="post_2"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed, "ddb_put_item") as put_item,
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
            patch.object(newsfeed, "_meter_newsfeed_post_publish"),
        ):
            newsfeed.create_post(req, user_id="u1")

        post_item = put_item.call_args_list[0].args[0]
        self.assertNotIn("unlock_limit", post_item)
        self.assertNotIn("unlock_count", post_item)

    def test_edit_post_sets_unlock_limit_without_affecting_image_fields(self):
        req = newsfeed.EditPostRequest(body="updated", unlock_limit=5)
        post = {"post_id": "p1", "user_id": "u1", "locked": True, "unlock_count": 0}

        with (
            patch.object(newsfeed, "ddb_get_item", return_value=post),
            patch.object(newsfeed, "ddb_update_item", return_value=post) as update_item,
            patch.object(newsfeed, "_post_to_dict", return_value={"ok": True}),
        ):
            newsfeed.edit_post("p1", req, user_id="u1")

        update_expr = update_item.call_args.kwargs["update_expr"]
        expr_vals = update_item.call_args.kwargs["expr_vals"]
        self.assertIn("unlock_limit = :unlock_limit", update_expr)
        self.assertNotIn("REMOVE unlock_limit", update_expr)
        self.assertNotIn("image_urls", update_expr)
        self.assertEqual(expr_vals[":unlock_limit"], 5)

    def test_edit_post_clears_unlock_limit_without_affecting_image_fields(self):
        req = newsfeed.EditPostRequest(body="updated", unlock_limit=None)
        post = {"post_id": "p1", "user_id": "u1", "locked": True, "unlock_count": 0}

        with (
            patch.object(newsfeed, "ddb_get_item", return_value=post),
            patch.object(newsfeed, "ddb_update_item", return_value=post) as update_item,
            patch.object(newsfeed, "_post_to_dict", return_value={"ok": True}),
        ):
            newsfeed.edit_post("p1", req, user_id="u1")

        update_expr = update_item.call_args.kwargs["update_expr"]
        expr_vals = update_item.call_args.kwargs["expr_vals"]
        self.assertIn("REMOVE unlock_limit", update_expr)
        self.assertNotIn("image_urls", update_expr)
        self.assertNotIn(":unlock_limit", expr_vals)

    def test_post_to_dict_includes_unlock_limit_fields(self):
        post = {
            "post_id": "post_1",
            "user_id": "author_1",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body": "hello",
            "locked": True,
            "unlock_price_cents": 250,
            "unlock_limit": 3,
            "unlock_count": 2,
        }

        payload = newsfeed._post_to_dict(post)

        self.assertEqual(payload["unlock_limit"], 3)
        self.assertEqual(payload["unlock_count"], 2)
        self.assertFalse(payload["unlock_limit_reached"])

    def test_post_to_dict_unlock_limit_reached_when_count_meets_limit(self):
        post = {
            "post_id": "post_2",
            "user_id": "author_2",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body": "hello",
            "locked": True,
            "unlock_price_cents": 250,
            "unlock_limit": 2,
            "unlock_count": 2,
        }

        payload = newsfeed._post_to_dict(post)
        self.assertTrue(payload["unlock_limit_reached"])

    def test_post_to_dict_unlock_limit_defaults_for_legacy_posts(self):
        post = {
            "post_id": "post_legacy",
            "user_id": "author_legacy",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body": "hello",
            "locked": False,
        }

        payload = newsfeed._post_to_dict(post)
        self.assertIsNone(payload["unlock_limit"])
        self.assertEqual(payload["unlock_count"], 0)
        self.assertFalse(payload["unlock_limit_reached"])

    def test_post_to_dict_unlock_limit_defaults_for_malformed_storage_values(self):
        post = {
            "post_id": "post_bad",
            "user_id": "author_bad",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body": "hello",
            "locked": True,
            "unlock_limit": "not-a-number",
            "unlock_count": "not-a-number",
        }

        payload = newsfeed._post_to_dict(post)
        self.assertIsNone(payload["unlock_limit"])
        self.assertEqual(payload["unlock_count"], 0)
        self.assertFalse(payload["unlock_limit_reached"])

    def test_post_to_dict_marks_lock_expired_and_prioritizes_over_sold_out(self):
        post = {
            "post_id": "post_expired",
            "user_id": "author_expired",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body": "hello",
            "locked": True,
            "unlock_limit": 1,
            "unlock_count": 1,
            "lock_expires_at": "2000-01-01T00:00:00+00:00",
        }

        payload = newsfeed._post_to_dict(post)
        self.assertTrue(payload["lock_expired"])
        self.assertFalse(payload["unlock_limit_reached"])

    def test_unlock_post_returns_lock_expired_before_sold_out(self):
        req = newsfeed.UnlockPostRequest(post_id="post_1", payment_method_id=None)
        post = {
            "post_id": "post_1",
            "user_id": "author_1",
            "locked": True,
            "unlock_price_cents": 123,
            "unlock_limit": 1,
            "unlock_count": 1,
            "lock_expires_at": "2000-01-01T00:00:00+00:00",
        }
        with (
            patch.object(newsfeed, "ddb_get_item", return_value=post),
            patch.object(newsfeed, "_begin_unlock_attempt_with_reservation") as begin_with_reservation,
        ):
            with self.assertRaises(HTTPException) as ctx:
                newsfeed.unlock_post(req, user_id="u1")

        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "post_lock_expired")
        self.assertEqual(ctx.exception.detail["message"], "post lock expired")
        begin_with_reservation.assert_not_called()

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
            body="test content",
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
            newsfeed.create_post(req, user_id="u1")

        self.assertEqual(put_item.call_count, 2)
        record_usage.assert_called_once()
        event = record_usage.call_args.args[1]
        self.assertEqual(event["source"], "newsfeed_post")
        self.assertEqual(event["idempotency_key"], "u1|newsfeed_post|post_abc")

    def test_create_post_failed_create_does_not_record_usage(self):
        req = newsfeed.CreatePostRequest(
            body="test content",
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
                newsfeed.create_post(req, user_id="u1")

        record_usage.assert_not_called()

    def test_create_post_meters_successful_create(self):
        req = newsfeed.CreatePostRequest(
            body="test content",
        )

        with (
            patch.object(newsfeed, "new_id", return_value="post_abc"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed, "ddb_put_item") as put_item,
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
            patch.object(newsfeed, "_meter_newsfeed_post_publish") as meter_post,
        ):
            resp = newsfeed.create_post(req, user_id="u1")

        self.assertEqual(put_item.call_count, 2)
        meter_post.assert_called_once_with(user_id="u1", post_id="post_abc")
        self.assertEqual(resp.post_id, "post_abc")

    def test_create_post_failed_create_does_not_meter(self):
        req = newsfeed.CreatePostRequest(
            body="test content",
        )

        with (
            patch.object(newsfeed, "new_id", return_value="post_abc"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed, "ddb_put_item", side_effect=RuntimeError("ddb down")),
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
            patch.object(newsfeed, "_meter_newsfeed_post_publish") as meter_post,
        ):
            with self.assertRaises(RuntimeError):
                newsfeed.create_post(req, user_id="u1")

        meter_post.assert_not_called()

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
            resp = newsfeed.download_post_attachment("p1", "att1", user_id="u1", x_request_id="req-1")

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
                newsfeed.download_post_attachment("p1", "att1", user_id="u1", x_request_id=None)

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
