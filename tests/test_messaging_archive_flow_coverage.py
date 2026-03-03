from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.routers import messaging
from app.services.messaging_archive_replay import replay_failed_archive_events
from app.services.messaging_archive_writer import MessagingArchiveWriteError, emit_messaging_archive_event


class _WriterFail:
    def write_event(self, _event):
        raise RuntimeError("sink_down")


class TestMessagingArchiveFlowCoverage(unittest.TestCase):
    def test_endpoint_to_event_coverage_matrix(self):
        matrix = []

        def _case_delete_for_me():
            with (
                patch.object(messaging, "require_participant_active"),
                patch.object(messaging, "_get_message_or_404", return_value={"message_id": "m1"}),
                patch.object(messaging.tbl_msgs, "update_item"),
                patch.object(messaging, "_sync_gallery_index_message"),
                patch.object(messaging, "now_ts", return_value=100),
                patch.object(messaging, "_emit_message_lifecycle_archive_event_or_503") as emit_mock,
            ):
                messaging.delete_message_for_me("c1", "m1", user_id="u1")
            return emit_mock.call_args.kwargs

        matrix.append(("delete_message_for_me", _case_delete_for_me, "message.deleted", "delete"))

        def _case_revoke_for_all():
            original = {
                "message_id": "m1",
                "conversation_id": "c1",
                "sender_id": "u1",
                "kind": "text",
                "created_at": 10,
                "text": "old",
            }
            with (
                patch.object(messaging, "require_participant_active"),
                patch.object(messaging, "_get_message_or_404", side_effect=[original, {**original, "revoked_at": 100}]),
                patch.object(messaging, "_ensure_can_revoke_message"),
                patch.object(messaging.tbl_msgs, "update_item"),
                patch.object(messaging, "remove_message_search"),
                patch.object(messaging, "_sync_gallery_index_message"),
                patch.object(messaging.tbl_convos, "get_item", return_value={"Item": {}}),
                patch.object(messaging, "fanout_event_to_conversation"),
                patch.object(messaging, "now_ts", return_value=100),
                patch.object(messaging, "_message_out_from_item", return_value={}),
                patch.object(messaging, "_serialize_message_event_payload", return_value={}),
                patch.object(messaging, "_emit_message_lifecycle_archive_event_or_503") as emit_mock,
            ):
                messaging.revoke_message_for_all("c1", "m1", user_id="u1")
            return emit_mock.call_args.kwargs

        matrix.append(("revoke_message_for_all", _case_revoke_for_all, "message.revoked", "revoke"))

        def _case_edit_message():
            before = {
                "message_id": "m1",
                "conversation_id": "c1",
                "sender_id": "u1",
                "kind": "text",
                "created_at": 10,
                "text": "old",
            }
            after = dict(before)
            after["text"] = "new"
            with (
                patch.object(messaging, "require_participant_active"),
                patch.object(messaging, "_get_message_or_404", side_effect=[before, after]),
                patch.object(messaging.tbl_edits, "put_item"),
                patch.object(messaging.tbl_msgs, "update_item"),
                patch.object(messaging, "remove_message_search"),
                patch.object(messaging, "index_message_search"),
                patch.object(messaging, "_sync_gallery_index_message"),
                patch.object(messaging, "fanout_event_to_conversation"),
                patch.object(messaging, "now_ts", return_value=100),
                patch.object(messaging, "_message_out_from_item", return_value={}),
                patch.object(messaging, "_serialize_message_event_payload", return_value={}),
                patch.object(messaging, "_emit_message_lifecycle_archive_event_or_503") as emit_mock,
            ):
                messaging.edit_message("c1", "m1", messaging.EditMessageIn(text="new"), user_id="u1")
            return emit_mock.call_args.kwargs

        matrix.append(("edit_message", _case_edit_message, "message.edited", "edit"))

        def _case_hide_message():
            with (
                patch.object(messaging, "_messaging_hide_controls_enabled", return_value=True),
                patch.object(messaging, "require_participant_active"),
                patch.object(messaging, "_get_message_or_404", return_value={"message_id": "m1"}),
                patch.object(messaging, "now_ts", return_value=100),
                patch.object(messaging.T.message_visibility_overrides, "update_item"),
                patch.object(messaging, "_emit_archive_event_or_503") as emit_mock,
            ):
                messaging.hide_message_for_me("c1", "m1", user_id="u1")
            return emit_mock.call_args.kwargs

        matrix.append(("hide_message_for_me", _case_hide_message, "message.deleted", None))

        def _case_report_message():
            with (
                patch.object(messaging, "_messaging_reporting_enabled", return_value=True),
                patch.object(messaging, "require_participant_active", return_value={"user_id": "u1"}),
                patch.object(messaging, "_get_message_or_404", return_value={"message_id": "m1"}),
                patch.object(messaging, "_load_report_context_message_ids", return_value=["m1"]),
                patch.object(messaging, "now_ts", return_value=100),
                patch.object(messaging, "new_id", return_value="abc"),
                patch.object(messaging, "_query_report_count", side_effect=[0, 0]),
                patch.object(messaging.T.message_reports, "put_item"),
                patch.object(messaging.T.message_report_context, "put_item"),
                patch.object(messaging, "_emit_report_archive_event_or_503") as emit_mock,
            ):
                messaging.report_message(
                    "c1",
                    "m1",
                    messaging.ReportMessageIn(reason_code="spam", statement="spam statement"),
                    user_id="u1",
                )
            return emit_mock.call_args.kwargs

        matrix.append(("report_message", _case_report_message, "report.submitted", None))

        for name, fn, expected_event_type, expected_mutation in matrix:
            with self.subTest(flow=name):
                kwargs = fn()
                self.assertEqual(kwargs["event_type"], expected_event_type)
                if expected_mutation is not None:
                    self.assertEqual(kwargs["mutation"], expected_mutation)

    def test_failure_mode_emit_helper_returns_503_when_sink_unavailable_fail_closed(self):
        with patch.object(messaging, "emit_messaging_archive_event", side_effect=MessagingArchiveWriteError("sink_down")):
            with self.assertRaises(HTTPException) as ctx:
                messaging._emit_archive_event_or_503(
                    event_id="e1",
                    event_ts=1,
                    conversation_id="c1",
                    message_id="m1",
                    actor_user_id="u1",
                    event_type="message.sent",
                    payload={"x": 1},
                )
        self.assertEqual(ctx.exception.status_code, 503)

    def test_retry_path_replays_spooled_events_after_sink_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("app.services.messaging_archive_writer._archive_enabled", return_value=True),
                patch("app.services.messaging_archive_writer._archive_root_dir", return_value=tmp),
            ):
                out = emit_messaging_archive_event(
                    event_id="evt_retry_1",
                    event_ts=1700000000,
                    tenant_id="tenant-1",
                    conversation_id="c1",
                    message_id="m1",
                    actor_user_id="u1",
                    effective_user_id="u1",
                    event_type="message.sent",
                    payload={"text": "hello"},
                    writer=_WriterFail(),
                )
            self.assertIsNone(out)

            replay = replay_failed_archive_events(root_dir=tmp)
            self.assertEqual(replay.failed, 0)
            self.assertEqual(replay.remaining, 0)
            self.assertGreaterEqual(replay.replayed, 1)


if __name__ == "__main__":
    unittest.main()
