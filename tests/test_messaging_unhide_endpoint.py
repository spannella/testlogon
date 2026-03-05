from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.routers import messaging


class _FakeVisibilityTable:
    def __init__(self):
        self.calls = []

    def update_item(self, **kwargs):
        self.calls.append(kwargs)


class TestUnhideMessageEndpoint(unittest.TestCase):
    def test_unhide_message_for_me_upserts_visible_state_and_is_idempotent(self):
        fake_table = _FakeVisibilityTable()

        with (
            patch.object(messaging, "require_participant_active", return_value={"user_id": "u1"}),
            patch.object(messaging, "_get_message_or_404", return_value={"message_id": "m1"}),
            patch.object(messaging, "now_ts", return_value=1700000011),
            patch.object(messaging.T.message_visibility_overrides, "update_item", side_effect=fake_table.update_item),
            patch.object(messaging, "record_messaging_message_control_action") as metric_mock,
            patch.object(messaging, "_emit_archive_event_or_503") as archive_mock,
        ):
            out1 = messaging.unhide_message_for_me("c1", "m1", user_id="u1")
            out2 = messaging.unhide_message_for_me("c1", "m1", user_id="u1")

        self.assertEqual(metric_mock.call_count, 2)
        self.assertEqual(archive_mock.call_count, 2)

        self.assertEqual(out1.action, "visible")
        self.assertEqual(out2.action, "visible")
        self.assertEqual(len(fake_table.calls), 2)

        first_call = fake_table.calls[0]
        self.assertEqual(first_call["Key"], {"conversation_id": "c1", "message_user": "m1#u1"})
        self.assertEqual(first_call["ExpressionAttributeValues"][":state"], "visible")
        self.assertEqual(first_call["ExpressionAttributeValues"][":updated_at"], 1700000011)
        self.assertEqual(first_call["ExpressionAttributeValues"][":conversation_user"], "c1#u1")

    def test_unhide_message_for_me_rejects_non_participant_without_writing(self):
        fake_table = _FakeVisibilityTable()
        with (
            patch.object(messaging, "require_participant_active", side_effect=HTTPException(status_code=403, detail="Not a participant")),
            patch.object(messaging.T.message_visibility_overrides, "update_item", side_effect=fake_table.update_item),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.unhide_message_for_me("c-forbidden", "m1", user_id="u1")

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(len(fake_table.calls), 0)

    def test_unhide_message_for_me_only_writes_callers_scope(self):
        fake_table = _FakeVisibilityTable()

        with (
            patch.object(messaging, "require_participant_active", return_value={"user_id": "u1"}),
            patch.object(messaging, "_get_message_or_404", return_value={"message_id": "m1"}),
            patch.object(messaging, "now_ts", return_value=1700000012),
            patch.object(messaging.T.message_visibility_overrides, "update_item", side_effect=fake_table.update_item),
        ):
            messaging.unhide_message_for_me("c1", "m1", user_id="u1")

        self.assertEqual(len(fake_table.calls), 1)
        key = fake_table.calls[0]["Key"]
        self.assertEqual(key["message_user"], "m1#u1")
        self.assertNotEqual(key["message_user"], "m1#u2")



    def test_unhide_message_for_me_rejects_when_feature_disabled(self):
        with patch.object(messaging, "_messaging_hide_controls_enabled", return_value=False):
            with self.assertRaises(HTTPException) as ctx:
                messaging.unhide_message_for_me("c1", "m1", user_id="u1")

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail, "Message hide controls are disabled")

if __name__ == "__main__":
    unittest.main()
