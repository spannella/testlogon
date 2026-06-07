"""Regression tests for GAP-0135 and GAP-0136 (app/services/bot_scheduler.py).

GAP-0135: ``_next_run_from_cron()`` was a stub returning ``now_ts() + 3600`` for
every cron expression, so bot scheduled sends fired ~1 hour after creation and
then every hour, never converging to the configured time. The fix implements a
real, self-contained 5-field cron next-run computation.

GAP-0136: the dispatch loop only delivered messages for ``target_type ==
"conversation"`` targets; wildcard scopes (``all_dms`` / ``all_groups`` /
``all_broadcasts``) were silently skipped while the ``dispatched`` counter was
still incremented (inflated metric, zero delivery). The fix resolves wildcard
targets into conversation IDs, fans out the send, and only counts schedules that
actually delivered at least one message.

Both tests are fully offline: deterministic ``now`` (no real sleeps) and
in-memory mocks (no real AWS).
"""
from __future__ import annotations

import datetime
import unittest
from unittest.mock import patch

from app.services import bot_scheduler as bs


class TestNextRunFromCronGap0135(unittest.TestCase):
    """GAP-0135: cron next-run must reflect the expression, not now+3600."""

    # 2026-01-01 09:00:00 UTC is a Thursday — fixed base for all assertions.
    FIXED_NOW = int(
        datetime.datetime(2026, 1, 1, 9, 0, 0, tzinfo=datetime.timezone.utc).timestamp()
    )

    def test_daily_14_utc_next_occurrence(self):
        with patch.object(bs, "now_ts", return_value=self.FIXED_NOW):
            result = bs._next_run_from_cron("0 14 * * *", "UTC")

        expected = int(
            datetime.datetime(2026, 1, 1, 14, 0, 0, tzinfo=datetime.timezone.utc).timestamp()
        )
        self.assertEqual(
            result,
            expected,
            "expected next run at 2026-01-01 14:00 UTC, "
            f"got {datetime.datetime.fromtimestamp(result, datetime.timezone.utc)}",
        )
        # Explicit guard: the old stub value (now + 3600 = 10:00) must be gone.
        self.assertNotEqual(result, self.FIXED_NOW + 3600)

    def test_daily_14_utc_when_now_past_14_rolls_to_next_day(self):
        now_past = int(
            datetime.datetime(2026, 1, 1, 14, 1, 0, tzinfo=datetime.timezone.utc).timestamp()
        )
        with patch.object(bs, "now_ts", return_value=now_past):
            result = bs._next_run_from_cron("0 14 * * *", "UTC")

        expected = int(
            datetime.datetime(2026, 1, 2, 14, 0, 0, tzinfo=datetime.timezone.utc).timestamp()
        )
        self.assertEqual(result, expected)

    def test_weekly_monday_9am(self):
        # From Thursday 2026-01-01, next Monday is 2026-01-05.
        with patch.object(bs, "now_ts", return_value=self.FIXED_NOW):
            result = bs._next_run_from_cron("0 9 * * 1", "UTC")

        expected = int(
            datetime.datetime(2026, 1, 5, 9, 0, 0, tzinfo=datetime.timezone.utc).timestamp()
        )
        self.assertEqual(result, expected)

    def test_result_always_in_future(self):
        with patch.object(bs, "now_ts", return_value=self.FIXED_NOW):
            result = bs._next_run_from_cron("0 14 * * *", "UTC")
        self.assertGreater(result, self.FIXED_NOW)

    def test_invalid_cron_raises(self):
        with patch.object(bs, "now_ts", return_value=self.FIXED_NOW):
            with self.assertRaises(ValueError):
                bs._next_run_from_cron("not a cron", "UTC")

    def test_invalid_timezone_raises(self):
        with patch.object(bs, "now_ts", return_value=self.FIXED_NOW):
            with self.assertRaises(ValueError):
                bs._next_run_from_cron("0 14 * * *", "Imaginary/Zone")


class TestWildcardDispatchGap0136(unittest.TestCase):
    """GAP-0136: wildcard targets must fan out; counter must reflect real sends."""

    @staticmethod
    def _wildcard_item():
        return {
            "pk": "BOT#bot001",
            "sk": "SCHED#sched001",
            "schedule_id": "sched001",
            "bot_id": "bot001",
            "creator_id": "user001",
            "template_id": "tmpl001",
            "target_type": "all_dms",
            "cron_expression": "0 9 * * *",
            "timezone": "UTC",
            "next_run_at": 1000,
            "enabled": True,
            "created_at": 900,
        }

    def test_wildcard_all_dms_fans_out_and_counts_actual_sends(self):
        item = self._wildcard_item()
        with patch.object(bs, "_resolve_target_conversations",
                          return_value=["conv_a", "conv_b"]), \
             patch.object(bs, "T") as mock_T, \
             patch("app.services.chat_bot.get_bot",
                   return_value={"bot_id": "bot001", "status": "active",
                                 "creator_id": "user001"}), \
             patch("app.services.chat_bot.send_bot_message") as mock_send, \
             patch("app.services.bot_template.get_template",
                   return_value={"template_id": "tmpl001"}), \
             patch("app.services.bot_template.render_template",
                   return_value={"rendered_text": "Hello!"}), \
             patch("app.services.bot_template.record_impression"), \
             patch.object(bs, "_next_run_from_cron", return_value=99999):

            mock_T.bot_scheduled_sends.query.return_value = {"Items": [item]}
            mock_T.bot_scheduled_sends.update_item.return_value = {}

            result = bs.dispatch_due_scheduled_sends(now_ts_value=2000)

        self.assertEqual(
            mock_send.call_count, 2,
            "wildcard all_dms must send to each resolved conversation "
            f"(got {mock_send.call_count}; before fix this was 0)",
        )
        sent_convs = {c.kwargs["conversation_id"] for c in mock_send.call_args_list}
        self.assertEqual(sent_convs, {"conv_a", "conv_b"})
        self.assertEqual(result["dispatched"], 1)

    def test_wildcard_empty_resolution_does_not_count_as_dispatched(self):
        item = self._wildcard_item()
        with patch.object(bs, "_resolve_target_conversations", return_value=[]), \
             patch.object(bs, "T") as mock_T, \
             patch("app.services.chat_bot.get_bot",
                   return_value={"bot_id": "bot001", "status": "active",
                                 "creator_id": "user001"}), \
             patch("app.services.chat_bot.send_bot_message") as mock_send, \
             patch("app.services.bot_template.get_template",
                   return_value={"template_id": "tmpl001"}), \
             patch("app.services.bot_template.render_template",
                   return_value={"rendered_text": "Hello!"}), \
             patch.object(bs, "_next_run_from_cron", return_value=99999):

            mock_T.bot_scheduled_sends.query.return_value = {"Items": [item]}
            mock_T.bot_scheduled_sends.update_item.return_value = {}

            result = bs.dispatch_due_scheduled_sends(now_ts_value=2000)

        self.assertEqual(mock_send.call_count, 0)
        self.assertEqual(result["dispatched"], 0)

    def test_single_conversation_target_still_delivers(self):
        item = {
            "pk": "BOT#bot001",
            "sk": "SCHED#sched002",
            "schedule_id": "sched002",
            "bot_id": "bot001",
            "creator_id": "user001",
            "template_id": "tmpl001",
            "target_type": "conversation",
            "target_id": "conv_xyz",
            "cron_expression": "0 9 * * *",
            "timezone": "UTC",
            "next_run_at": 1000,
            "enabled": True,
            "created_at": 900,
        }
        with patch.object(bs, "T") as mock_T, \
             patch("app.services.chat_bot.get_bot",
                   return_value={"bot_id": "bot001", "status": "active",
                                 "creator_id": "user001"}), \
             patch("app.services.chat_bot.send_bot_message") as mock_send, \
             patch("app.services.bot_template.get_template",
                   return_value={"template_id": "tmpl001"}), \
             patch("app.services.bot_template.render_template",
                   return_value={"rendered_text": "Hello!"}), \
             patch("app.services.bot_template.record_impression"), \
             patch.object(bs, "_next_run_from_cron", return_value=99999):

            mock_T.bot_scheduled_sends.query.return_value = {"Items": [item]}
            mock_T.bot_scheduled_sends.update_item.return_value = {}

            result = bs.dispatch_due_scheduled_sends(now_ts_value=2000)

        self.assertEqual(mock_send.call_count, 1)
        self.assertEqual(mock_send.call_args.kwargs["conversation_id"], "conv_xyz")
        self.assertEqual(result["dispatched"], 1)


if __name__ == "__main__":
    unittest.main()
