from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError

from app.routers import messaging


class _FakeReportsTable:
    def __init__(self):
        self.calls = []

    def put_item(self, **kwargs):
        self.calls.append(kwargs)


class _FakeReportContextTable:
    def __init__(self):
        self.calls = []

    def put_item(self, **kwargs):
        self.calls.append(kwargs)


class TestReportMessageEndpoint(unittest.TestCase):
    def test_report_message_persists_valid_report_and_returns_success(self):
        fake_table = _FakeReportsTable()
        fake_context_table = _FakeReportContextTable()

        with (
            patch.object(messaging, "require_participant_active", return_value={"user_id": "u1"}),
            patch.object(messaging, "_get_message_or_404", return_value={"message_id": "m1"}),
            patch.object(messaging, "_load_report_context_message_ids", return_value=["m0", "m1", "m2"]),
            patch.object(messaging, "now_ts", return_value=1700000300),
            patch.object(messaging, "new_id", return_value="abc123"),
            patch.object(messaging, "_query_report_count", side_effect=[0, 0]),
            patch.object(messaging, "record_messaging_message_control_action") as metric_mock,
            patch.object(messaging, "_emit_report_archive_event_or_503") as archive_mock,
            patch.object(messaging.T.message_reports, "put_item", side_effect=fake_table.put_item),
            patch.object(messaging.T.message_report_context, "put_item", side_effect=fake_context_table.put_item),
        ):
            out = messaging.report_message(
                "c1",
                "m1",
                messaging.ReportMessageIn(reason_code=" Harassment ", statement="  This is abusive behavior.  "),
                user_id="u1",
            )

        self.assertTrue(out.ok)
        self.assertEqual(out.report_id, "rpt_abc123")
        self.assertEqual(out.reason_code, "harassment")
        self.assertEqual(len(fake_table.calls), 1)

        write = fake_table.calls[0]["Item"]
        self.assertEqual(write["report_id"], "rpt_abc123")
        self.assertEqual(write["conversation_id"], "c1")
        self.assertEqual(write["message_id"], "m1")
        self.assertEqual(write["reported_by_user_id"], "u1")
        self.assertEqual(write["reason_code"], "harassment")
        self.assertEqual(write["statement"], "This is abusive behavior.")
        self.assertEqual(write["context_message_ids"], ["m0", "m1", "m2"])
        self.assertEqual(write["created_at"], 1700000300)
        self.assertEqual(write["status"], "submitted")

        self.assertEqual(len(fake_context_table.calls), 3)
        metric_mock.assert_called_once_with(action="report", result="success")
        archive_mock.assert_called_once()
        self.assertEqual(fake_context_table.calls[0]["Item"]["message_id"], "m0")
        self.assertEqual(fake_context_table.calls[1]["Item"]["message_id"], "m1")
        self.assertEqual(fake_context_table.calls[2]["Item"]["message_id"], "m2")

    def test_report_message_rejects_non_participant_without_writing(self):
        fake_table = _FakeReportsTable()
        with (
            patch.object(
                messaging,
                "require_participant_active",
                side_effect=HTTPException(status_code=403, detail="Not a participant"),
            ),
            patch.object(messaging.T.message_reports, "put_item", side_effect=fake_table.put_item),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.report_message(
                    "c-forbidden",
                    "m1",
                    messaging.ReportMessageIn(reason_code="spam", statement="This is spam"),
                    user_id="u1",
                )

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(len(fake_table.calls), 0)

    def test_report_message_input_validation_rejects_blank_or_short_statement(self):
        with patch.object(messaging, "record_messaging_report_validation_error") as validation_metric:
            with self.assertRaises(ValidationError):
                messaging.ReportMessageIn(reason_code="spam", statement="   a ")
            with self.assertRaises(ValidationError):
                messaging.ReportMessageIn(reason_code="  ", statement="valid statement")

        self.assertEqual(validation_metric.call_count, 2)

    def test_context_selection_is_server_side_bounded_window(self):
        target_id = "m5"
        messages = [
            {"conversation_id": "c1", "message_id": f"m{i}", "created_at": i, "sender_id": "u2", "kind": "text", "text": f"msg-{i}"}
            for i in range(1, 12)
        ]

        with patch.object(messaging.tbl_msgs, "query", return_value={"Items": messages, "LastEvaluatedKey": None}):
            context_ids = messaging._load_report_context_message_ids("c1", target_id, "u1")

        self.assertEqual(context_ids, ["m1", "m2", "m3", "m4", "m5", "m6", "m7", "m8", "m9", "m10"])

    def test_context_selection_filters_revoked_messages(self):
        messages = [
            {"conversation_id": "c1", "message_id": "m1", "created_at": 1, "sender_id": "u2", "kind": "text", "text": "a"},
            {"conversation_id": "c1", "message_id": "m2", "created_at": 2, "sender_id": "u2", "kind": "text", "text": "b", "revoked_at": 10},
            {"conversation_id": "c1", "message_id": "m3", "created_at": 3, "sender_id": "u2", "kind": "text", "text": "c"},
        ]

        with patch.object(messaging.tbl_msgs, "query", return_value={"Items": messages, "LastEvaluatedKey": None}):
            context_ids = messaging._load_report_context_message_ids("c1", "m3", "u1")

        self.assertEqual(context_ids, ["m1", "m3"])

    def test_report_message_rate_limited_by_user_limit(self):
        fake_table = _FakeReportsTable()
        fake_context_table = _FakeReportContextTable()

        with (
            patch.object(messaging, "require_participant_active", return_value={"user_id": "u1"}),
            patch.object(messaging, "_get_message_or_404", return_value={"message_id": "m1"}),
            patch.object(messaging, "_load_report_context_message_ids", return_value=["m1"]),
            patch.object(messaging, "now_ts", return_value=1700000400),
            patch.object(messaging, "new_id", return_value="blocked"),
            patch.dict("os.environ", {
                "MESSAGING_REPORT_RATE_LIMIT_ENABLED": "true",
                "MESSAGING_REPORT_RATE_LIMIT_USER_MAX": "2",
                "MESSAGING_REPORT_RATE_LIMIT_USER_WINDOW_SECONDS": "60",
                "MESSAGING_REPORT_RATE_LIMIT_CONVERSATION_MAX": "10",
                "MESSAGING_REPORT_RATE_LIMIT_CONVERSATION_WINDOW_SECONDS": "60",
            }, clear=False),
            patch.object(messaging, "_query_report_count", side_effect=[2, 0]),
            patch.object(messaging.T.message_reports, "put_item", side_effect=fake_table.put_item),
            patch.object(messaging.T.message_report_context, "put_item", side_effect=fake_context_table.put_item),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.report_message(
                    "c1",
                    "m1",
                    messaging.ReportMessageIn(reason_code="spam", statement="Spam report statement"),
                    user_id="u1",
                )

        self.assertEqual(ctx.exception.status_code, 429)
        self.assertEqual(len(fake_table.calls), 0)
        self.assertEqual(len(fake_context_table.calls), 0)

    def test_report_message_rate_limited_by_conversation_limit(self):
        fake_table = _FakeReportsTable()
        fake_context_table = _FakeReportContextTable()

        with (
            patch.object(messaging, "require_participant_active", return_value={"user_id": "u1"}),
            patch.object(messaging, "_get_message_or_404", return_value={"message_id": "m1"}),
            patch.object(messaging, "_load_report_context_message_ids", return_value=["m1"]),
            patch.object(messaging, "now_ts", return_value=1700000400),
            patch.object(messaging, "new_id", return_value="blocked"),
            patch.dict("os.environ", {
                "MESSAGING_REPORT_RATE_LIMIT_ENABLED": "true",
                "MESSAGING_REPORT_RATE_LIMIT_USER_MAX": "5",
                "MESSAGING_REPORT_RATE_LIMIT_USER_WINDOW_SECONDS": "60",
                "MESSAGING_REPORT_RATE_LIMIT_CONVERSATION_MAX": "3",
                "MESSAGING_REPORT_RATE_LIMIT_CONVERSATION_WINDOW_SECONDS": "60",
            }, clear=False),
            patch.object(messaging, "_query_report_count", side_effect=[0, 3]),
            patch.object(messaging.T.message_reports, "put_item", side_effect=fake_table.put_item),
            patch.object(messaging.T.message_report_context, "put_item", side_effect=fake_context_table.put_item),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.report_message(
                    "c1",
                    "m1",
                    messaging.ReportMessageIn(reason_code="spam", statement="Spam report statement"),
                    user_id="u1",
                )

        self.assertEqual(ctx.exception.status_code, 429)
        self.assertEqual(len(fake_table.calls), 0)
        self.assertEqual(len(fake_context_table.calls), 0)

    def test_report_message_rate_limit_can_be_disabled(self):
        fake_table = _FakeReportsTable()
        fake_context_table = _FakeReportContextTable()

        with (
            patch.object(messaging, "require_participant_active", return_value={"user_id": "u1"}),
            patch.object(messaging, "_get_message_or_404", return_value={"message_id": "m1"}),
            patch.object(messaging, "_load_report_context_message_ids", return_value=["m1"]),
            patch.object(messaging, "now_ts", return_value=1700000400),
            patch.object(messaging, "new_id", return_value="ok1"),
            patch.dict("os.environ", {"MESSAGING_REPORT_RATE_LIMIT_ENABLED": "false"}, clear=False),
            patch.object(messaging, "_query_report_count") as count_mock,
            patch.object(messaging.T.message_reports, "put_item", side_effect=fake_table.put_item),
            patch.object(messaging.T.message_report_context, "put_item", side_effect=fake_context_table.put_item),
        ):
            out = messaging.report_message(
                "c1",
                "m1",
                messaging.ReportMessageIn(reason_code="spam", statement="Spam report statement"),
                user_id="u1",
            )

        self.assertTrue(out.ok)
        count_mock.assert_not_called()
        self.assertEqual(len(fake_table.calls), 1)



    def test_report_message_rejects_when_feature_disabled(self):
        with patch.object(messaging, "_messaging_reporting_enabled", return_value=False):
            with self.assertRaises(HTTPException) as ctx:
                messaging.report_message(
                    "c1",
                    "m1",
                    messaging.ReportMessageIn(reason_code="spam", statement="This is spam"),
                    user_id="u1",
                )

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail, "Message reporting is disabled")

    def test_update_report_status_persists_and_archives_transition(self):
        report_item = {
            "report_id": "rpt_1",
            "conversation_id": "c1",
            "message_id": "m1",
            "status": "submitted",
        }
        with (
            patch.object(messaging, "require_participant_role"),
            patch.object(messaging.T.message_reports, "get_item", return_value={"Item": report_item}),
            patch.object(messaging.T.message_reports, "update_item") as update_mock,
            patch.object(messaging, "_emit_report_archive_event_or_503") as archive_mock,
            patch.object(messaging, "now_ts", return_value=1700000500),
        ):
            out = messaging.update_report_status(
                "c1",
                "rpt_1",
                messaging.ReportStatusUpdateIn(status="under_review", note="triaged"),
                user_id="admin-1",
            )

        self.assertTrue(out.ok)
        self.assertEqual(out.status, "under_review")
        update_mock.assert_called_once()
        archive_mock.assert_called_once()
        self.assertEqual(archive_mock.call_args.kwargs["event_type"], "report.status_changed")
        self.assertEqual(archive_mock.call_args.kwargs["report_id"], "rpt_1")
        self.assertEqual(archive_mock.call_args.kwargs["payload"]["from_status"], "submitted")
        self.assertEqual(archive_mock.call_args.kwargs["payload"]["to_status"], "under_review")

    def test_update_report_status_404_when_report_not_found(self):
        with (
            patch.object(messaging, "require_participant_role"),
            patch.object(messaging.T.message_reports, "get_item", return_value={}),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.update_report_status(
                    "c1",
                    "missing",
                    messaging.ReportStatusUpdateIn(status="dismissed"),
                    user_id="admin-1",
                )

        self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
