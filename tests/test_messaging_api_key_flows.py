from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from app.routers import messaging


def _request_with_api_key_principal(user_sub: str = "u_api") -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/messaging/conversations/c1/messages",
        "headers": [(b"x-api-key", b"ak_k1.secret")],
        "query_string": b"",
        "client": ("127.0.0.1", 1234),
        "server": ("test", 80),
        "scheme": "http",
        "route": type("R", (), {"path": "/messaging/conversations/{conversation_id}/messages"})(),
    }
    req = Request(scope)
    req.state.api_key_principal = {"user_sub": user_sub, "api_key_id": "k1", "capabilities": ["messager:read"]}
    return req


class TestMessagingApiKeyFlows(unittest.TestCase):
    def test_get_messaging_user_id_prefers_api_key_principal(self):
        req = _request_with_api_key_principal("u_key_owner")
        with patch.object(messaging, "_ensure_user_indexed") as ensure_indexed:
            user_id = asyncio.run(messaging.get_messaging_user_id(req, authorization=None, x_session_id=None))
        self.assertEqual(user_id, "u_key_owner")
        ensure_indexed.assert_called_once_with("u_key_owner")

    def test_non_participant_api_key_actor_cannot_access_conversation_messages(self):
        with patch.object(
            messaging,
            "require_participant_active",
            side_effect=HTTPException(status_code=403, detail="Not a participant"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.list_messages("c_blocked", limit=10, user_id="u_non_participant")
        self.assertEqual(ctx.exception.status_code, 403)

    def test_api_key_actor_hidden_and_archived_visibility_filters_apply(self):
        page = {
            "Items": [
                {"conversation_id": "c1", "message_id": "m3", "sender_id": "u2", "created_at": 3, "kind": "text", "text": "hidden"},
                {"conversation_id": "c1", "message_id": "m2", "sender_id": "u2", "created_at": 2, "kind": "text", "text": "archived"},
                {"conversation_id": "c1", "message_id": "m1", "sender_id": "u2", "created_at": 1, "kind": "text", "text": "visible"},
            ]
        }

        with (
            patch.object(messaging, "require_participant_active", return_value={"user_id": "u1"}),
            patch.object(messaging.tbl_parts, "query", return_value={"Items": []}),
            patch.object(messaging.tbl_msgs, "query", return_value=page),
            patch.object(messaging, "_load_hidden_message_ids_for_user", return_value={"m3"}),
            patch.object(
                messaging,
                "_filter_message_visible",
                side_effect=lambda item, _viewer: item.get("message_id") != "m2",
            ),
            patch.object(
                messaging,
                "_message_out_from_item",
                side_effect=lambda item, viewer: messaging.MessageOut(
                    conversation_id=item["conversation_id"],
                    message_id=item["message_id"],
                    sender_id=item["sender_id"],
                    created_at=item["created_at"],
                    kind="text",
                    text=item.get("text") or "",
                ),
            ),
            patch.object(messaging, "_apply_message_receipts", side_effect=lambda msg, _raw, _parts: msg),
            patch.object(messaging, "MESSAGING_HIDDEN_TIMELINE_FILTER_ENABLED", True),
        ):
            out = messaging.list_messages("c1", limit=3, user_id="u1")

        self.assertEqual([m.message_id for m in out], ["m1"])


if __name__ == "__main__":
    unittest.main()
