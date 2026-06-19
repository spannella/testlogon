"""Offline regression tests for GAP-0355.

`emit_social_alert()` (`app/services/social_alerts.py`) had zero external callers,
so reactions / comments / replies / post-tips / message-tips / follows /
subscriptions never produced a social alert (the bell badge stayed silent).

The fix adds best-effort `emit_social_alert(...)` calls at each event's success
path *alongside* the existing `put_notification` GSI3 writes. These tests spy on
`emit_social_alert` in the caller namespace (or at the source module for the
locally-imported call sites), stub the DDB helpers, drive each handler directly,
and assert the spy fires with the right recipient/type — and that a spy
exception never breaks the underlying action (best-effort).
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.routers import newsfeed


class TestReactionSocialAlert(unittest.TestCase):
    def _run(self, spy_side_effect=None):
        spy = MagicMock(side_effect=spy_side_effect)
        post = {"pk": "p", "sk": "s", "user_id": "author_a", "reactions": {}}
        req = SimpleNamespace(emoji="👍")
        with patch.object(newsfeed, "emit_social_alert", spy), \
             patch.object(newsfeed, "ddb_get_item", return_value=post), \
             patch.object(newsfeed, "ddb_update_item"), \
             patch.object(newsfeed, "_post_fadt_display_name", return_value="Bob"):
            out = newsfeed.add_reaction("post_1", req, "actor_bob")
        return spy, out

    def test_reaction_emits_alert_to_author(self):
        spy, out = self._run()
        self.assertTrue(spy.called)
        kwargs = spy.call_args.kwargs
        self.assertEqual(kwargs["alert_type"], "post_reaction")
        self.assertEqual(kwargs["recipient_user_id"], "author_a")
        self.assertEqual(kwargs["actor_user_id"], "actor_bob")
        self.assertTrue(out["ok"])

    def test_reaction_alert_failure_does_not_break(self):
        spy, out = self._run(spy_side_effect=RuntimeError("boom"))
        self.assertTrue(spy.called)
        self.assertTrue(out["ok"])


class TestCommentSocialAlert(unittest.TestCase):
    def _run_comment(self, parent=None, parent_user="author_p"):
        spy = MagicMock()
        req = SimpleNamespace(
            kind="text", parent_comment_id=parent,
            gif_url=None, gif_alt_text=None, gif_width=None, gif_height=None,
            sticker_id=None, sticker_collection_id=None, sticker_url=None,
            sticker_alt_text=None,
            image_url=None, image_alt_text=None, image_width=None, image_height=None,
        )
        content = {
            "body": "nice", "body_plain": "nice", "body_markdown": None,
            "body_markdown_html": None, "body_rich": None,
            "body_format": "plain", "body_version": 1,
        }
        post = {"pk": "x", "sk": "y", "user_id": "author_a", "locked": False}
        # For the reply branch, ddb_query returns the parent comment.
        query_resp = {"Items": [{"comment_id": parent, "user_id": parent_user}]} if parent else {"Items": []}
        with patch.object(newsfeed, "emit_social_alert", spy), \
             patch.object(newsfeed, "emit_mention_alerts"), \
             patch.object(newsfeed, "ddb_get_item", return_value=post), \
             patch.object(newsfeed, "ddb_query", return_value=query_resp), \
             patch.object(newsfeed, "_content_from_payload", return_value=content), \
             patch.object(newsfeed, "_post_fadt_display_name", return_value="Charlie"), \
             patch.object(newsfeed, "_emit_newsfeed_content_metric"), \
             patch.object(newsfeed, "ddb_put_item"), \
             patch.object(newsfeed, "ddb_update_item"), \
             patch.object(newsfeed, "put_notification"), \
             patch.object(newsfeed, "record_engagement_event"), \
             patch.object(newsfeed, "can_view_post", return_value=True), \
             patch.object(newsfeed, "has_unlocked", return_value=True):
            newsfeed.create_comment("post_1", req, "actor_charlie")
        return spy

    def test_comment_on_post_emits_alert(self):
        spy = self._run_comment(parent=None)
        self.assertTrue(spy.called)
        kwargs = spy.call_args.kwargs
        self.assertEqual(kwargs["alert_type"], "post_comment")
        self.assertEqual(kwargs["recipient_user_id"], "author_a")

    def test_reply_emits_comment_reply_alert(self):
        spy = self._run_comment(parent="cmt_parent", parent_user="author_p")
        self.assertTrue(spy.called)
        kwargs = spy.call_args.kwargs
        self.assertEqual(kwargs["alert_type"], "comment_reply")
        self.assertEqual(kwargs["recipient_user_id"], "author_p")


class TestPostTipSocialAlert(unittest.TestCase):
    def test_post_tip_emits_alert(self):
        spy = MagicMock()
        post = {"pk": "p", "sk": "s", "user_id": "author_a"}
        req = SimpleNamespace(amount_cents=500, currency="USD", payment_method_id=None)
        fake_payments = SimpleNamespace(
            create_payment_intent=lambda **kw: {"payment_intent_id": "pi_1"},
            confirm_payment_intent=lambda **kw: {"status": "succeeded"},
        )
        with patch.object(newsfeed, "emit_social_alert", spy), \
             patch.object(newsfeed, "ddb_get_item", return_value=post), \
             patch.object(newsfeed, "ddb_update_item", return_value={"tip_total_cents": 500}), \
             patch.object(newsfeed, "put_notification"), \
             patch.object(newsfeed, "payments", fake_payments), \
             patch.object(newsfeed, "_post_fadt_display_name", return_value="Bob"), \
             patch("app.services.tip_ledger.write_tip_ledger"):
            out = newsfeed.tip_post("post_1", req, "actor_bob")
        self.assertTrue(spy.called)
        kwargs = spy.call_args.kwargs
        self.assertEqual(kwargs["alert_type"], "post_tip")
        self.assertEqual(kwargs["recipient_user_id"], "author_a")
        self.assertTrue(out["ok"])


class TestFollowSocialAlert(unittest.TestCase):
    def test_follow_emits_new_follower_alert(self):
        from app.services import social
        spy = MagicMock()
        fake_T = SimpleNamespace(
            profile=MagicMock(get_item=MagicMock(return_value={"Item": {"user_sub": "followed_a"}}))
        )
        # social.follow_user uses local imports; patch emit at the source module.
        with patch("app.services.social_alerts.emit_social_alert", spy), \
             patch("app.services.profile.get_profile_identity", return_value={"display_name": "Bob"}), \
             patch("app.services.blocking.is_any_block", return_value=False), \
             patch.object(social, "T", fake_T), \
             patch.object(social, "tbl", MagicMock(get_item=MagicMock(return_value={"Item": None}), put_item=MagicMock())), \
             patch.object(social, "_increment_counts"), \
             patch.object(social, "get_follow_counts", return_value={"follower_count": 1, "following_count": 1}):
            out = social.follow_user("follower_bob", "followed_a")
        self.assertTrue(spy.called)
        kwargs = spy.call_args.kwargs
        self.assertEqual(kwargs["alert_type"], "new_follower")
        self.assertEqual(kwargs["recipient_user_id"], "followed_a")
        self.assertEqual(kwargs["actor_user_id"], "follower_bob")
        self.assertEqual(out["status"], "followed")


class TestMessageTipSocialAlert(unittest.TestCase):
    def test_message_tip_emits_alert(self):
        from app.routers import messaging
        spy = MagicMock()
        msg = {"sender_id": "author_a", "message_id": "m1"}
        inp = SimpleNamespace(amount_cents=100, currency="USD", payment_method_id=None)
        # send_message_tip imports emit_social_alert + get_profile_identity locally.
        with patch("app.services.social_alerts.emit_social_alert", spy), \
             patch("app.services.profile.get_profile_identity", return_value={"display_name": "Bob"}), \
             patch.object(messaging, "require_participant_active"), \
             patch.object(messaging, "_get_message_or_404", return_value=msg), \
             patch.object(messaging, "tbl_msgs", MagicMock()), \
             patch.object(messaging, "fanout_event_to_conversation"), \
             patch.object(messaging, "audit_event"), \
             patch("app.services.tip_ledger.write_tip_ledger"), \
             patch("app.services.invoices.create_invoice_safe"):
            out = messaging.send_message_tip("conv_1", "m1", inp, None, "actor_bob")
        self.assertTrue(spy.called)
        kwargs = spy.call_args.kwargs
        self.assertEqual(kwargs["alert_type"], "message_tip")
        self.assertEqual(kwargs["recipient_user_id"], "author_a")
        self.assertEqual(kwargs["actor_user_id"], "actor_bob")
        self.assertTrue(out.ok)


if __name__ == "__main__":
    unittest.main()
