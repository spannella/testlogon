from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.routers import messaging


class _FakePinsTable:
    def __init__(self):
        self.calls = []

    def update_item(self, **kwargs):
        self.calls.append(kwargs)


class TestUnpinMessageEndpoint(unittest.TestCase):
    def test_unpin_message_deactivates_pin_and_emits_audit(self):
        fake_table = _FakePinsTable()

        with (
            patch.object(messaging, "require_participant_active", return_value={"user_id": "u1"}),
            patch.object(messaging, "_get_message_or_404", return_value={"message_id": "m1"}),
            patch.object(messaging, "now_ts", return_value=1700000200),
            patch.object(messaging.T.conversation_pins, "update_item", side_effect=fake_table.update_item),
            patch.object(messaging, "fanout_event_to_conversation") as fanout_mock,
            patch.object(messaging, "audit_event") as audit_mock,
            patch.object(messaging, "record_messaging_message_control_action") as metric_mock,
            patch.object(messaging, "_emit_archive_event_or_503") as archive_mock,
        ):
            out = messaging.unpin_message("c1", "m1", user_id="u1")

        metric_mock.assert_called_once_with(action="unpin", result="success")
        archive_mock.assert_called_once()

        self.assertEqual(out.action, "unpinned")
        self.assertEqual(len(fake_table.calls), 1)

        call = fake_table.calls[0]
        self.assertEqual(call["Key"], {"conversation_id": "c1", "message_id": "m1"})
        self.assertEqual(call["ExpressionAttributeValues"][":is_active"], False)
        self.assertEqual(call["ExpressionAttributeValues"][":unpinned_by_user_id"], "u1")
        self.assertEqual(call["ExpressionAttributeValues"][":unpinned_at"], 1700000200)
        self.assertEqual(call["ExpressionAttributeValues"][":conversation_inactive"], "c1#0")

        fanout_mock.assert_called_once()
        audit_mock.assert_called_once()

    def test_unpin_message_rejects_non_participant_without_writing(self):
        fake_table = _FakePinsTable()

        with (
            patch.object(
                messaging,
                "require_participant_active",
                side_effect=HTTPException(status_code=403, detail="Not a participant"),
            ),
            patch.object(messaging.T.conversation_pins, "update_item", side_effect=fake_table.update_item),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.unpin_message("c-forbidden", "m1", user_id="u1")

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(len(fake_table.calls), 0)



    def test_unpin_message_rejects_when_feature_disabled(self):
        with patch.object(messaging, "_messaging_pins_enabled", return_value=False):
            with self.assertRaises(HTTPException) as ctx:
                messaging.unpin_message("c1", "m1", user_id="u1")

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail, "Message pin controls are disabled")

if __name__ == "__main__":
    unittest.main()
