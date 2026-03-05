from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.routers import messaging


class TestPinsListingAndProjection(unittest.TestCase):
    def test_list_conversation_pins_returns_active_pins_desc(self):
        with (
            patch.object(messaging, "require_participant_active", return_value={"user_id": "u1"}),
            patch.object(messaging, "decode_cursor", return_value={"conversation_id": "c1", "message_id": "m3"}),
            patch.object(messaging, "encode_cursor", return_value="next-cursor"),
            patch.object(
                messaging.T.conversation_pins,
                "query",
                return_value={
                    "Items": [
                        {"message_id": "m2", "pinned_by_user_id": "u9", "pinned_at": 20, "is_active": True},
                        {"message_id": "m1", "pinned_by_user_id": "u8", "pinned_at": 10, "is_active": True},
                    ],
                    "LastEvaluatedKey": {"conversation_id": "c1", "message_id": "m1"},
                },
            ) as query_mock,
        ):
            out = messaging.list_conversation_pins("c1", cursor="cursor-1", limit=2, user_id="u1")

        self.assertEqual([p.message_id for p in out.items], ["m2", "m1"])
        self.assertEqual([p.pinned_at for p in out.items], [20, 10])
        self.assertEqual(out.next_cursor, "next-cursor")

        kwargs = query_mock.call_args.kwargs
        self.assertEqual(kwargs["IndexName"], "ByConversationActivePinnedAt")
        self.assertFalse(kwargs["ScanIndexForward"])
        self.assertEqual(kwargs["Limit"], 2)

    def test_list_conversation_pins_invalid_cursor_rejected(self):
        with (
            patch.object(messaging, "require_participant_active", return_value={"user_id": "u1"}),
            patch.object(messaging, "decode_cursor", return_value=None),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.list_conversation_pins("c1", cursor="bad", limit=10, user_id="u1")

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid cursor")

    def test_conversation_out_includes_latest_pin_projection(self):
        with patch.object(
            messaging,
            "_get_latest_active_pin",
            return_value={"message_id": "m9", "pinned_by_user_id": "u7", "pinned_at": 123},
        ):
            out = messaging._conversation_out_from_items(
                conversation_id="c1",
                convo={"type": "dm", "created_at": 1, "created_by": "u1", "participant_count": 2},
                participant={"status": "active", "muted_until": 0, "last_read_at": 0, "unread_count": 0},
                viewer_user_id="u1",
            )

        self.assertEqual(out.latest_pinned_message_id, "m9")
        self.assertEqual(out.latest_pinned_by_user_id, "u7")
        self.assertEqual(out.latest_pinned_at, 123)


if __name__ == "__main__":
    unittest.main()
