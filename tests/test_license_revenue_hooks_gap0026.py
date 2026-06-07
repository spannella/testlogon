"""Regression test for GAP-0026.

`process_revenue_split` (app/services/license_revenue.py) was only ever reachable
through a debug endpoint (`POST /process-split`). None of the live billing flows
that generate revenue from potentially-licensed content invoked it, so licensors
were never paid their contractual revenue-share credits.

This test exercises the four qualifying money paths directly and asserts that the
best-effort revenue-split hook fires with the correct content id / amount /
source_type:

  * messaging tip   -> send_message_tip  (app/routers/messaging.py)
  * messaging unlock-> unlock_message    (app/routers/messaging.py)
  * newsfeed tip    -> tip_post          (app/routers/newsfeed.py)
  * newsfeed unlock -> unlock_post       (app/routers/newsfeed.py)

It FAILS before the fix (the hook is absent -> spy.call_count == 0) and PASSES
after it. Fully offline: the handlers are invoked directly with their I/O
collaborators stubbed out; no real AWS, no network, deterministic.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import patch, MagicMock

from app.routers import messaging as msg_router
from app.routers import newsfeed as feed_router


class TestMessagingRevenueSplitHooks(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        # Spy on the function the hooks must call. The handlers do
        # `from app.services import license_revenue as _lr_svc` and then call
        # `_lr_svc.process_revenue_split(...)`, so patch it at the source module.
        self.spy = self.stack.enter_context(
            patch(
                "app.services.license_revenue.process_revenue_split",
                return_value=[],
            )
        )
        # Neutralise the real I/O collaborators of the messaging handlers.
        self.stack.enter_context(
            patch.object(msg_router, "fanout_event_to_conversation", MagicMock())
        )
        self.stack.enter_context(patch.object(msg_router, "audit_event", MagicMock()))
        self.stack.enter_context(
            patch.object(msg_router, "tbl_msgs", MagicMock())
        )
        # `ddb.Table(...)` is used for the billing payment-method check / ledger.
        self.stack.enter_context(patch.object(msg_router, "ddb", MagicMock()))

    def test_send_message_tip_triggers_revenue_split(self):
        conv_id = "conv_gap0026_tip"
        msg_id = "msg_gap0026_tip"
        tipper = "alice_sub"
        author = "bob_sub"

        with patch.object(
            msg_router, "require_participant_active", MagicMock()
        ), patch.object(
            msg_router,
            "_get_message_or_404",
            MagicMock(return_value={"sender_id": author}),
        ), patch(
            "app.services.tip_ledger.write_tip_ledger", MagicMock()
        ), patch(
            "app.services.invoices.create_invoice_safe", MagicMock()
        ), patch(
            "app.services.profile.get_profile_identity",
            MagicMock(return_value={}),
        ):
            inp = msg_router.SendTipIn(amount_cents=1000, currency="usd")
            out = msg_router.send_message_tip(
                conversation_id=conv_id,
                message_id=msg_id,
                inp=inp,
                req=None,
                user_id=tipper,
            )

        self.assertTrue(out.ok)
        self.spy.assert_called_once()
        kwargs = self.spy.call_args.kwargs
        self.assertEqual(kwargs["content_id"], msg_id)
        self.assertEqual(kwargs["licensee_id"], tipper)
        self.assertEqual(kwargs["source_type"], "tip")
        self.assertEqual(kwargs["source_amount_cents"], 1000)
        self.assertEqual(kwargs["source_txn_id"], out.tip_payment_id)

    def test_unlock_message_triggers_revenue_split(self):
        conv_id = "conv_gap0026_unlock"
        msg_id = "msg_gap0026_unlock"
        unlocker = "alice_sub"
        author = "bob_sub"

        with patch.object(
            msg_router, "require_participant_active", MagicMock()
        ), patch.object(
            msg_router,
            "_get_message_or_404",
            MagicMock(
                return_value={
                    "sender_id": author,
                    "lock_price_cents": 500,
                    "unlocked_by": {},
                }
            ),
        ), patch(
            "app.services.invoices.create_invoice_safe", MagicMock()
        ), patch(
            "app.services.profile.get_profile_identity",
            MagicMock(return_value={}),
        ):
            inp = msg_router.UnlockMessageIn()
            out = msg_router.unlock_message(
                conversation_id=conv_id,
                message_id=msg_id,
                inp=inp,
                req=None,
                user_id=unlocker,
            )

        self.assertTrue(out.ok)
        self.spy.assert_called_once()
        kwargs = self.spy.call_args.kwargs
        self.assertEqual(kwargs["content_id"], msg_id)
        self.assertEqual(kwargs["licensee_id"], unlocker)
        self.assertEqual(kwargs["source_type"], "unlock")
        self.assertEqual(kwargs["source_amount_cents"], 500)


class TestNewsfeedRevenueSplitHooks(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.spy = self.stack.enter_context(
            patch(
                "app.services.license_revenue.process_revenue_split",
                return_value=[],
            )
        )
        # Fake payment processor: always succeeds with a deterministic intent id.
        fake_payments = MagicMock()
        fake_payments.create_payment_intent.return_value = {
            "payment_intent_id": "pi_gap0026"
        }
        fake_payments.confirm_payment_intent.return_value = {"status": "succeeded"}
        self.stack.enter_context(patch.object(feed_router, "payments", fake_payments))
        self.stack.enter_context(patch.object(feed_router, "put_notification", MagicMock()))
        # Stub the boto3 resource so the best-effort billing-ledger writes are
        # harmless (no real AWS). Tests pass no payment_method_id, so the PM
        # validation branch is skipped regardless.
        self.stack.enter_context(patch.object(feed_router, "ddb", MagicMock()))

    def test_tip_post_triggers_revenue_split(self):
        post_id = "post_gap0026_tip"
        tipper = "alice_sub"
        author = "bob_sub"

        with patch.object(
            feed_router,
            "ddb_get_item",
            MagicMock(return_value={"user_id": author}),
        ), patch.object(
            feed_router,
            "ddb_update_item",
            MagicMock(return_value={"tip_total_cents": 750}),
        ):
            req = feed_router.PostTipRequest(amount_cents=750, currency="usd")
            out = feed_router.tip_post(post_id=post_id, req=req, user_id=tipper)

        self.assertTrue(out["ok"])
        self.spy.assert_called_once()
        kwargs = self.spy.call_args.kwargs
        self.assertEqual(kwargs["content_id"], post_id)
        self.assertEqual(kwargs["licensee_id"], tipper)
        self.assertEqual(kwargs["source_type"], "post_tip")
        self.assertEqual(kwargs["source_amount_cents"], 750)
        self.assertEqual(kwargs["source_txn_id"], "pi_gap0026")

    def test_unlock_post_triggers_revenue_split(self):
        post_id = "post_gap0026_unlock"
        buyer = "alice_sub"
        author = "bob_sub"

        post_item = {
            "user_id": author,
            "locked": True,
            "unlock_price_cents": 900,
        }
        with patch.object(
            feed_router, "ddb_get_item", MagicMock(return_value=post_item)
        ), patch.object(
            feed_router, "_emit_unlock_lifecycle_event", MagicMock()
        ), patch.object(
            feed_router, "_emit_unlock_replay_event", MagicMock()
        ), patch.object(
            feed_router, "_unlock_request_fingerprint", MagicMock(return_value="fp")
        ), patch.object(
            feed_router, "_is_unlock_limit_enabled_for_user", MagicMock(return_value=False)
        ), patch.object(
            feed_router, "_enforce_unlock_attempt_throttle", MagicMock()
        ), patch.object(
            feed_router, "_is_lock_expired", MagicMock(return_value=False)
        ), patch.object(
            feed_router, "_begin_unlock_attempt", MagicMock(return_value="started")
        ), patch.object(
            feed_router, "_finalize_unlock_attempt_success", MagicMock()
        ):
            req = feed_router.UnlockPostRequest(post_id=post_id)
            feed_router.unlock_post(req=req, user_id=buyer)

        self.spy.assert_called_once()
        kwargs = self.spy.call_args.kwargs
        self.assertEqual(kwargs["content_id"], post_id)
        self.assertEqual(kwargs["licensee_id"], buyer)
        self.assertEqual(kwargs["source_type"], "post_unlock")
        self.assertEqual(kwargs["source_amount_cents"], 900)
        self.assertEqual(kwargs["source_txn_id"], "pi_gap0026")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
