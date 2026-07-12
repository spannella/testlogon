"""Offline regression tests for GAP-0356.

`emit_mention_alerts()` (`app/services/social_alerts.py`) was fully implemented but
never invoked from `create_post` or `create_comment` in `app/routers/newsfeed.py`,
so @mentions never produced notifications.

These tests spy on the `emit_mention_alerts` name in the *caller* namespace
(`app.routers.newsfeed.emit_mention_alerts`), stub the DDB helpers the handlers
use, and call the handlers directly (the FastAPI TestClient is unusable in this
repo). Assertions verify the spy fires with the right text/context on the success
path, that empty bodies / media comments do not fire, and that a spy exception
does not break the underlying create (best-effort).
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.routers import newsfeed
from app.routers.newsfeed import CreatePostRequest


def _create_post_req(body="hello world"):
    return CreatePostRequest(body=body, visibility="public")


class TestCreatePostMentionAlerts(unittest.TestCase):
    def _run_create_post(self, body, spy_side_effect=None):
        spy = MagicMock(side_effect=spy_side_effect)
        # The Pydantic model rejects a wholly-empty body; use a placeholder for
        # model validation but drive the handler's mention logic off the patched
        # _content_from_payload return (body_plain == `body`).
        model_body = body or "placeholder"
        content = {
            "body": body,
            "body_plain": body,
            "body_markdown": None,
            "body_markdown_html": None,
            "body_rich": None,
            "body_format": "plain",
            "body_version": 1,
        }
        with patch.object(newsfeed, "emit_mention_alerts", spy), \
             patch.object(newsfeed, "_content_from_payload", return_value=content), \
             patch.object(newsfeed, "_post_fadt_display_name", return_value="Alice"), \
             patch.object(newsfeed, "_is_unlock_limit_enabled_for_user", return_value=False), \
             patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"), \
             patch.object(newsfeed, "_extract_hashtags", return_value=[]), \
             patch.object(newsfeed, "ddb_put_item"), \
             patch.object(newsfeed, "_write_feed_ref_for_published_post"), \
             patch.object(newsfeed, "_meter_newsfeed_post_publish"), \
             patch.object(newsfeed, "record_engagement_event"), \
             patch.object(newsfeed, "_T", create=True, new=SimpleNamespace(profile=MagicMock())):
            resp = newsfeed.create_post(_create_post_req(model_body), "user_alice")
        return spy, resp

    def test_mention_in_post_emits_alert(self):
        spy, resp = self._run_create_post("Hello @bob check this!")
        self.assertTrue(spy.called)
        kwargs = spy.call_args.kwargs
        self.assertEqual(kwargs["context_type"], "post")
        self.assertEqual(kwargs["author_user_id"], "user_alice")
        self.assertIn("@bob", kwargs["text"])
        self.assertEqual(resp.author_id, "user_alice")

    def test_empty_body_no_alert(self):
        spy, _ = self._run_create_post("")
        self.assertFalse(spy.called)

    def test_spy_exception_does_not_break_post(self):
        spy, resp = self._run_create_post(
            "Hello @bob", spy_side_effect=RuntimeError("boom")
        )
        self.assertTrue(spy.called)
        # create_post must still return successfully despite the alert failure.
        self.assertEqual(resp.status, "published")


class TestCreateCommentMentionAlerts(unittest.TestCase):
    def _run_create_comment(self, kind, body, spy_side_effect=None):
        spy = MagicMock(side_effect=spy_side_effect)
        req = SimpleNamespace(
            kind=kind,
            parent_comment_id=None,
            gif_url=None, gif_alt_text=None, gif_width=None, gif_height=None,
            sticker_id=None, sticker_collection_id=None, sticker_url=None,
            sticker_alt_text=None,
            image_url=None, image_alt_text=None, image_width=None, image_height=None,
        )
        content = {
            "body": body, "body_plain": body, "body_markdown": None,
            "body_markdown_html": None, "body_rich": None,
            "body_format": "plain", "body_version": 1,
        }
        post = {"pk": "x", "sk": "y", "user_id": "user_alice", "locked": False}
        with patch.object(newsfeed, "emit_mention_alerts", spy), \
             patch.object(newsfeed, "emit_social_alert"), \
             patch.object(newsfeed, "ddb_get_item", return_value=post), \
             patch.object(newsfeed, "_content_from_payload", return_value=content), \
             patch.object(newsfeed, "_post_fadt_display_name", return_value="Alice"), \
             patch.object(newsfeed, "_emit_newsfeed_content_metric"), \
             patch.object(newsfeed, "ddb_put_item"), \
             patch.object(newsfeed, "ddb_update_item"), \
             patch.object(newsfeed, "put_notification"), \
             patch.object(newsfeed, "record_engagement_event"), \
             patch.object(newsfeed, "can_view_post", return_value=True), \
             patch.object(newsfeed, "has_unlocked", return_value=True):
            resp = newsfeed.create_comment("post_1", req, "user_charlie")
        return spy, resp

    def test_text_comment_with_mention_emits_alert(self):
        spy, resp = self._run_create_comment("text", "great post @alice!")
        self.assertTrue(spy.called)
        kwargs = spy.call_args.kwargs
        self.assertEqual(kwargs["context_type"], "comment")
        self.assertEqual(kwargs["post_id"], "post_1")

    def test_media_comment_no_alert(self):
        # gif comments have body_plain=None → no mention alert
        spy, _ = self._run_create_comment("gif", None)
        self.assertFalse(spy.called)

    def test_spy_exception_does_not_break_comment(self):
        spy, resp = self._run_create_comment(
            "text", "hi @alice", spy_side_effect=RuntimeError("boom")
        )
        self.assertTrue(spy.called)
        self.assertEqual(resp.post_id, "post_1")


if __name__ == "__main__":
    unittest.main()
