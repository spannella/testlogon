from __future__ import annotations

import unittest
from unittest.mock import patch

from app.routers import messaging


class TestTimelineHiddenFilter(unittest.TestCase):
    def test_list_messages_excludes_hidden_messages_and_backfills_to_limit(self):
        page1 = {
            "Items": [
                {"conversation_id": "c1", "message_id": "m3", "sender_id": "u2", "created_at": 3, "kind": "text", "text": "three"},
                {"conversation_id": "c1", "message_id": "m2", "sender_id": "u2", "created_at": 2, "kind": "text", "text": "two"},
            ],
            "LastEvaluatedKey": {"conversation_id": "c1", "message_id": "m2"},
        }
        page2 = {
            "Items": [
                {"conversation_id": "c1", "message_id": "m1", "sender_id": "u2", "created_at": 1, "kind": "text", "text": "one"},
            ],
        }

        responses = [page1, page2]

        def _query_side_effect(**_kwargs):
            return responses.pop(0)

        def _batch_get_item(**kwargs):
            table_name = messaging.T.message_visibility_overrides.name
            keys = kwargs["RequestItems"][table_name]["Keys"]
            hidden = []
            for key in keys:
                if key["message_user"] == "m3#u1":
                    hidden.append(
                        {
                            "conversation_id": "c1",
                            "message_user": "m3#u1",
                            "message_id": "m3",
                            "user_id": "u1",
                            "state": "hidden",
                            "updated_at": 100,
                            "conversation_user": "c1#u1",
                        }
                    )
            return {"Responses": {table_name: hidden}}

        with (
            patch.object(messaging, "require_participant_active", return_value={"user_id": "u1"}),
            patch.object(messaging.tbl_parts, "query", return_value={"Items": []}),
            patch.object(messaging.tbl_msgs, "query", side_effect=_query_side_effect),
            patch.object(messaging.ddb.meta.client, "batch_get_item", side_effect=_batch_get_item),
            patch.object(messaging, "_filter_message_visible", return_value=True),
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
            out = messaging.list_messages("c1", limit=2, user_id="u1")

        self.assertEqual([m.message_id for m in out], ["m2", "m1"])

    def test_list_messages_without_filter_flag_keeps_all_messages(self):
        page = {
            "Items": [
                {"conversation_id": "c1", "message_id": "m2", "sender_id": "u2", "created_at": 2, "kind": "text", "text": "two"},
                {"conversation_id": "c1", "message_id": "m1", "sender_id": "u2", "created_at": 1, "kind": "text", "text": "one"},
            ],
        }

        with (
            patch.object(messaging, "require_participant_active", return_value={"user_id": "u1"}),
            patch.object(messaging.tbl_parts, "query", return_value={"Items": []}),
            patch.object(messaging.tbl_msgs, "query", return_value=page),
            patch.object(messaging.ddb.meta.client, "batch_get_item") as batch_get_mock,
            patch.object(messaging, "_filter_message_visible", return_value=True),
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
            patch.object(messaging, "MESSAGING_HIDDEN_TIMELINE_FILTER_ENABLED", False),
        ):
            out = messaging.list_messages("c1", limit=2, user_id="u1")

        self.assertEqual([m.message_id for m in out], ["m2", "m1"])
        batch_get_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
