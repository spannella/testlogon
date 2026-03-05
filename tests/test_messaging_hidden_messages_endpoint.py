from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.routers import messaging


class TestHiddenMessagesEndpoint(unittest.TestCase):
    def test_list_hidden_messages_returns_paginated_hidden_items(self):
        query_resp = {
            "Items": [
                {"message_id": "m-hidden-1", "state": "hidden"},
                {"message_id": "m-hidden-2", "state": "hidden"},
            ],
            "LastEvaluatedKey": {"conversation_id": "c1", "message_user": "m-hidden-2#u1"},
        }

        message_rows = {
            "m-hidden-1": {"conversation_id": "c1", "message_id": "m-hidden-1", "kind": "text", "sender_id": "u2", "created_at": 1},
            "m-hidden-2": {"conversation_id": "c1", "message_id": "m-hidden-2", "kind": "text", "sender_id": "u2", "created_at": 2},
        }

        def _fake_get_item(*, Key):
            return {"Item": message_rows.get(Key["message_id"]) }

        with (
            patch.object(messaging, "require_participant_active", return_value={"user_id": "u1"}),
            patch.object(messaging, "decode_cursor", return_value={"conversation_id": "c1", "message_user": "m0#u1"}),
            patch.object(messaging, "encode_cursor", return_value="next-cursor"),
            patch.object(messaging.T.message_visibility_overrides, "query", return_value=query_resp) as query_mock,
            patch.object(messaging.tbl_msgs, "get_item", side_effect=_fake_get_item),
            patch.object(
                messaging,
                "_message_out_from_item",
                side_effect=lambda item, viewer: messaging.MessageOut(
                    conversation_id=item["conversation_id"],
                    message_id=item["message_id"],
                    sender_id=item["sender_id"],
                    created_at=item["created_at"],
                    kind="text",
                    text="hidden",
                ),
            ),
        ):
            out = messaging.list_hidden_messages("c1", cursor="cursor-1", limit=2, user_id="u1")

        self.assertEqual([it.message_id for it in out.items], ["m-hidden-1", "m-hidden-2"])
        self.assertEqual(out.next_cursor, "next-cursor")

        kwargs = query_mock.call_args.kwargs
        self.assertEqual(kwargs["IndexName"], "ByConversationUserUpdatedAt")
        self.assertEqual(kwargs["Limit"], 2)
        self.assertTrue(kwargs["ScanIndexForward"])

    def test_list_hidden_messages_invalid_cursor_rejected(self):
        with (
            patch.object(messaging, "require_participant_active", return_value={"user_id": "u1"}),
            patch.object(messaging, "decode_cursor", return_value=None),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.list_hidden_messages("c1", cursor="bad-cursor", limit=10, user_id="u1")

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid cursor")

    def test_list_hidden_messages_filters_non_hidden_states(self):
        query_resp = {
            "Items": [
                {"message_id": "m-hidden-1", "state": "hidden"},
                {"message_id": "m-visible", "state": "visible"},
            ],
            "LastEvaluatedKey": None,
        }

        message_rows = {
            "m-hidden-1": {"conversation_id": "c1", "message_id": "m-hidden-1", "kind": "text", "sender_id": "u2", "created_at": 1},
            "m-visible": {"conversation_id": "c1", "message_id": "m-visible", "kind": "text", "sender_id": "u2", "created_at": 2},
        }

        def _fake_get_item(*, Key):
            return {"Item": message_rows.get(Key["message_id"]) }

        with (
            patch.object(messaging, "require_participant_active", return_value={"user_id": "u1"}),
            patch.object(messaging.T.message_visibility_overrides, "query", return_value=query_resp),
            patch.object(messaging.tbl_msgs, "get_item", side_effect=_fake_get_item),
            patch.object(
                messaging,
                "_message_out_from_item",
                side_effect=lambda item, viewer: messaging.MessageOut(
                    conversation_id=item["conversation_id"],
                    message_id=item["message_id"],
                    sender_id=item["sender_id"],
                    created_at=item["created_at"],
                    kind="text",
                    text="hidden",
                ),
            ),
        ):
            out = messaging.list_hidden_messages("c1", cursor=None, limit=10, user_id="u1")

        self.assertEqual([it.message_id for it in out.items], ["m-hidden-1"])

    def test_list_hidden_messages_backfills_to_limit_when_first_page_filters_out_items(self):
        responses = [
            {
                "Items": [
                    {"message_id": "m-missing", "state": "hidden"},
                ],
                "LastEvaluatedKey": {"conversation_id": "c1", "message_user": "m-missing#u1"},
            },
            {
                "Items": [
                    {"message_id": "m-hidden-2", "state": "hidden"},
                ],
                "LastEvaluatedKey": None,
            },
        ]

        message_rows = {
            "m-hidden-2": {"conversation_id": "c1", "message_id": "m-hidden-2", "kind": "text", "sender_id": "u2", "created_at": 2},
        }

        def _fake_get_item(*, Key):
            return {"Item": message_rows.get(Key["message_id"]) }

        with (
            patch.object(messaging, "require_participant_active", return_value={"user_id": "u1"}),
            patch.object(messaging.T.message_visibility_overrides, "query", side_effect=responses) as query_mock,
            patch.object(messaging.tbl_msgs, "get_item", side_effect=_fake_get_item),
            patch.object(messaging, "encode_cursor", return_value=None),
            patch.object(
                messaging,
                "_message_out_from_item",
                side_effect=lambda item, viewer: messaging.MessageOut(
                    conversation_id=item["conversation_id"],
                    message_id=item["message_id"],
                    sender_id=item["sender_id"],
                    created_at=item["created_at"],
                    kind="text",
                    text="hidden",
                ),
            ),
        ):
            out = messaging.list_hidden_messages("c1", cursor=None, limit=1, user_id="u1")

        self.assertEqual([it.message_id for it in out.items], ["m-hidden-2"])
        self.assertEqual(query_mock.call_count, 2)


if __name__ == "__main__":
    unittest.main()
