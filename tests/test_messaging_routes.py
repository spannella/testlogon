import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from fastapi import HTTPException
from fastapi.responses import StreamingResponse

from app.routers import messaging


class TestMessagingRoutes(unittest.TestCase):
    def test_get_current_user_id_requires_header(self):
        with self.assertRaises(HTTPException) as ctx:
            messaging.get_current_user_id(None)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_get_messaging_user_id_uses_bearer(self):
        req = SimpleNamespace()
        user_id = asyncio.run(
            messaging.get_messaging_user_id(req, authorization="Bearer user-123", x_session_id=None)
        )
        self.assertEqual(user_id, "user-123")

    def test_get_messaging_user_id_prefers_session(self):
        req = SimpleNamespace()
        with (
            patch.object(messaging, "get_authenticated_user_sub", AsyncMock(return_value="user-1")),
            patch.object(
                messaging,
                "require_ui_session",
                AsyncMock(return_value={"user_sub": "user-1", "session_id": "sid"}),
            ),
        ):
            user_id = asyncio.run(
                messaging.get_messaging_user_id(req, authorization="Bearer ignored", x_session_id="sid")
            )
        self.assertEqual(user_id, "user-1")

    def test_start_conversation_creates_participants(self):
        with (
            patch.object(messaging, "now_ts", return_value=123),
            patch.object(messaging, "new_id", return_value="abc"),
            patch.object(messaging, "tbl_convos") as tbl_convos,
            patch.object(messaging, "tbl_parts") as tbl_parts,
        ):
            resp = messaging.start_conversation(
                messaging.StartConversationIn(participant_ids=["user-2"], type="dm"),
                user_id="user-1",
            )

        tbl_convos.put_item.assert_called_once()
        self.assertEqual(tbl_parts.put_item.call_count, 2)
        self.assertEqual(resp.conversation_id, "c_abc")
        self.assertEqual(resp.created_at, 123)
        self.assertEqual(resp.participant_count, 2)
        self.assertEqual(resp.status, "active")

    def test_list_messages_filters_deleted_and_sets_reactions(self):
        tbl_parts = Mock()
        tbl_msgs = Mock()
        tbl_parts.get_item.return_value = {"Item": {"status": "active"}}
        tbl_msgs.query.return_value = {
            "Items": [
                {
                    "conversation_id": "c1",
                    "message_id": "m1",
                    "sender_id": "user-1",
                    "created_at": 10,
                    "kind": "text",
                    "text": "hello",
                    "deleted_for": ["user-2"],
                    "reactions": {"👍": ["user-1", "user-2"]},
                },
                {
                    "conversation_id": "c1",
                    "message_id": "m2",
                    "sender_id": "user-2",
                    "created_at": 11,
                    "kind": "text",
                    "text": "secret",
                    "deleted_for": ["user-1"],
                    "reactions": {},
                },
            ]
        }

        with (
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
        ):
            messages = messaging.list_messages("c1", user_id="user-1")

        self.assertEqual(len(messages), 1)
        msg = messages[0]
        self.assertEqual(msg.message_id, "m1")
        self.assertEqual(msg.reactions_counts, {"👍": 2})
        self.assertEqual(msg.my_reactions, ["👍"])

    def test_send_text_message_updates_conversation_preview(self):
        tbl_msgs = Mock()
        tbl_convos = Mock()
        with (
            patch.object(messaging, "now_ts", return_value=55),
            patch.object(messaging, "new_id", return_value="xyz"),
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_convos", tbl_convos),
        ):
            resp = messaging.send_text_message(
                "c1",
                messaging.SendTextMessageIn(text="Hello world"),
                user_id="user-1",
            )

        tbl_msgs.put_item.assert_called_once()
        tbl_convos.update_item.assert_called_once()
        self.assertEqual(resp.message_id, "m_xyz")
        self.assertEqual(resp.text, "Hello world")

    def test_admin_upsert_user_writes_search_tokens(self):
        tbl_users = Mock()
        tbl_search = Mock()
        bw = Mock()
        tbl_search.batch_writer = MagicMock()
        tbl_search.batch_writer.return_value.__enter__.return_value = bw
        with (
            patch.object(messaging, "tbl_users", tbl_users),
            patch.object(messaging, "tbl_search", tbl_search),
            patch.object(messaging, "build_prefix_tokens", return_value=["a", "ab"]),
            patch.object(messaging, "now_ts", return_value=50),
        ):
            resp = messaging.admin_upsert_user(
                messaging.UpsertUserIn(user_id="u1", display_name="Alice", email="a@example.com")
            )

        tbl_users.put_item.assert_called_once()
        self.assertEqual(bw.put_item.call_count, 2)
        self.assertEqual(resp["tokens_written"], 2)

    def test_admin_upsert_user_indexes_name_tokens(self):
        tbl_users = Mock()
        tbl_search = Mock()
        bw = Mock()
        tbl_search.batch_writer = MagicMock()
        tbl_search.batch_writer.return_value.__enter__.return_value = bw
        with (
            patch.object(messaging, "tbl_users", tbl_users),
            patch.object(messaging, "tbl_search", tbl_search),
            patch.object(messaging, "now_ts", return_value=50),
        ):
            resp = messaging.admin_upsert_user(
                messaging.UpsertUserIn(user_id="u1", display_name="Ada Lovelace")
            )
        tokens = [call.kwargs["Item"]["token"] for call in bw.put_item.mock_calls]
        self.assertIn("lo", tokens)
        self.assertGreater(resp["tokens_written"], 0)

    def test_build_message_search_tokens_dedupes_prefixes(self):
        tokens = messaging.build_message_search_tokens("Hello hello")
        self.assertIn("hello", tokens)
        self.assertEqual(len(tokens), len(set(tokens)))

    def test_build_prefix_tokens_splits_names(self):
        tokens = messaging.build_prefix_tokens("Ada Lovelace")
        self.assertIn("ad", tokens)
        self.assertIn("lo", tokens)

    def test_search_messages_in_conversation_prefers_opensearch(self):
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_opensearch_search_messages", return_value=["c1#m1"]),
            patch.object(
                messaging,
                "_fetch_message_items",
                return_value=[
                    {
                        "conversation_id": "c1",
                        "message_id": "m1",
                        "sender_id": "u1",
                        "created_at": 3,
                        "kind": "text",
                        "text": "hello",
                        "deleted_for": [],
                        "reactions": {},
                    }
                ],
            ),
            patch.object(messaging, "_search_messages_index") as search_index,
        ):
            resp = messaging.search_messages_in_conversation("c1", q="hello", limit=50, user_id="u1")
        self.assertEqual(resp[0].message_id, "m1")
        search_index.assert_not_called()

    def test_search_messages_in_conversation_falls_back_to_index(self):
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_opensearch_search_messages", return_value=None),
            patch.object(
                messaging,
                "_search_messages_index",
                return_value=[{"message_key": "c1#m2", "created_at": 10}],
            ),
            patch.object(
                messaging,
                "_fetch_message_items",
                return_value=[
                    {
                        "conversation_id": "c1",
                        "message_id": "m2",
                        "sender_id": "u1",
                        "created_at": 10,
                        "kind": "text",
                        "text": "searchable",
                        "deleted_for": [],
                        "reactions": {},
                    }
                ],
            ),
        ):
            resp = messaging.search_messages_in_conversation("c1", q="searchable", limit=50, user_id="u1")
        self.assertEqual(resp[0].message_id, "m2")

    def test_search_messages_all_conversations_falls_back_to_scan(self):
        tbl_parts = Mock()
        tbl_parts.query.return_value = {
            "Items": [{"conversation_id": "c1", "status": "active"}]
        }
        with (
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "_opensearch_search_messages", return_value=None),
            patch.object(messaging, "_search_messages_index", return_value=None),
            patch.object(
                messaging,
                "_fallback_search_messages",
                return_value=[
                    {
                        "conversation_id": "c1",
                        "message_id": "m3",
                        "sender_id": "u1",
                        "created_at": 8,
                        "kind": "text",
                        "text": "fallback",
                        "deleted_for": [],
                        "reactions": {},
                    }
                ],
            ),
        ):
            resp = messaging.search_messages_all_conversations(q="fallback", limit=50, user_id="u1")
        self.assertEqual(resp[0].message_id, "m3")

    def test_opensearch_search_builds_filters(self):
        captured = {}

        def fake_request(method, path, *, body=None):
            captured["method"] = method
            captured["path"] = path
            captured["body"] = body
            return {"hits": {"hits": [{"_id": "c1#m1"}]}}

        with (
            patch.object(messaging, "_opensearch_enabled", return_value=True),
            patch.object(messaging, "_opensearch_request", side_effect=fake_request),
        ):
            resp = messaging._opensearch_search_messages(
                "hello",
                limit=5,
                allowed_conversation_ids={"c1", "c2"},
                sender_id="u1",
                after_ts=123,
            )
        self.assertEqual(resp, ["c1#m1"])
        filters = captured["body"]["query"]["bool"]["filter"]
        self.assertEqual(captured["method"], "POST")
        terms_filter = next((item for item in filters if "terms" in item), {})
        self.assertEqual(set(terms_filter.get("terms", {}).get("conversation_id", [])), {"c1", "c2"})
        sender_filter = next((item for item in filters if "term" in item and "sender_id" in item["term"]), {})
        self.assertEqual(sender_filter.get("term", {}).get("sender_id"), "u1")
        range_filter = next((item for item in filters if "range" in item), {})
        self.assertEqual(range_filter.get("range", {}).get("created_at", {}).get("gte"), 123)

    def test_search_messages_in_conversation_passes_filters(self):
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_opensearch_search_messages", return_value=None) as search_messages,
            patch.object(messaging, "_search_messages_index", return_value=[]),
        ):
            messaging.search_messages_in_conversation(
                "c1",
                q="hello",
                limit=10,
                sender_id="u2",
                after_ts=50,
                user_id="u1",
            )
        search_messages.assert_called_with(
            "hello",
            limit=10,
            conversation_id="c1",
            sender_id="u2",
            after_ts=50,
        )

    def test_fallback_search_messages_filters_sender_and_time(self):
        tbl_msgs = Mock()
        tbl_msgs.query.return_value = {
            "Items": [
                {
                    "conversation_id": "c1",
                    "message_id": "m1",
                    "sender_id": "u1",
                    "created_at": 40,
                    "kind": "text",
                    "text": "hello",
                    "deleted_for": [],
                    "reactions": {},
                },
                {
                    "conversation_id": "c1",
                    "message_id": "m2",
                    "sender_id": "u2",
                    "created_at": 60,
                    "kind": "text",
                    "text": "hello there",
                    "deleted_for": [],
                    "reactions": {},
                },
            ]
        }
        with patch.object(messaging, "tbl_msgs", tbl_msgs):
            resp = messaging._fallback_search_messages(
                "c1",
                "hello",
                limit=10,
                user_id="u1",
                sender_id="u2",
                after_ts=50,
            )
        self.assertEqual(len(resp), 1)
        self.assertEqual(resp[0]["message_id"], "m2")

    def test_search_contact_filters_self(self):
        tbl_search = Mock()
        tbl_search.query.return_value = {
            "Items": [
                {"user_id": "me", "display_name": "Me"},
                {"user_id": "other", "display_name": "Other"},
            ]
        }
        with patch.object(messaging, "tbl_search", tbl_search):
            resp = messaging.search_contact("o", user_id="me")
        self.assertEqual(len(resp), 1)
        self.assertEqual(resp[0].user_id, "other")

    def test_start_group_conversation_delegates(self):
        with patch.object(messaging, "start_conversation") as start_convo:
            messaging.start_group_conversation(
                messaging.StartGroupConversationIn(participant_ids=["a", "b"], title="Group"),
                user_id="u1",
            )
        start_convo.assert_called_once()

    def test_accept_conversation_updates_pending(self):
        tbl_parts = Mock()
        with (
            patch.object(messaging, "get_participant_any", return_value={"status": "pending"}),
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "now_ts", return_value=10),
        ):
            resp = messaging.accept_conversation("c1", user_id="u1")
        self.assertTrue(resp["ok"])
        tbl_parts.update_item.assert_called_once()

    def test_list_conversations_returns_items(self):
        tbl_parts = Mock()
        tbl_convos = Mock()
        tbl_parts.query.return_value = {"Items": [{"conversation_id": "c1", "status": "active"}]}
        tbl_convos.get_item.return_value = {
            "Item": {
                "conversation_id": "c1",
                "created_at": 1,
                "created_by": "u1",
                "type": "dm",
                "participant_count": 2,
                "last_message_at": 0,
                "last_message_preview": "",
            }
        }
        with (
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_convos", tbl_convos),
        ):
            resp = messaging.list_conversations(user_id="u1")
        self.assertEqual(len(resp), 1)
        self.assertEqual(resp[0].conversation_id, "c1")

    def test_mute_conversation_updates(self):
        tbl_parts = Mock()
        with (
            patch.object(messaging, "get_participant_any", return_value={"status": "active"}),
            patch.object(messaging, "tbl_parts", tbl_parts),
        ):
            resp = messaging.mute_conversation("c1", messaging.MuteIn(muted_until=123), user_id="u1")
        self.assertEqual(resp["muted_until"], 123)
        tbl_parts.update_item.assert_called_once()

    def test_leave_conversation_updates(self):
        tbl_parts = Mock()
        tbl_convos = Mock()
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_convos", tbl_convos),
            patch.object(messaging, "now_ts", return_value=10),
        ):
            resp = messaging.leave_conversation("c1", user_id="u1")
        self.assertTrue(resp["ok"])
        tbl_parts.update_item.assert_called_once()
        tbl_convos.update_item.assert_called_once()

    def test_delete_conversation_if_last(self):
        tbl_convos = Mock()
        tbl_parts = Mock()
        tbl_parts.query.return_value = {
            "Items": [{"user_id": "u1", "status": "active"}, {"user_id": "u2", "status": "left"}]
        }
        with (
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_convos", tbl_convos),
        ):
            resp = messaging.delete_conversation_if_last("c1", user_id="u1")
        self.assertTrue(resp["deleted"])
        tbl_convos.delete_item.assert_called_once()
        self.assertEqual(tbl_parts.delete_item.call_count, 2)

    def test_list_participants_returns_items(self):
        tbl_parts = Mock()
        tbl_parts.query.return_value = {
            "Items": [
                {"user_id": "u1", "status": "active", "role": "admin"},
                {"user_id": "u2", "status": "pending", "role": "member"},
            ]
        }
        with (
            patch.object(messaging, "get_participant_any", return_value={"status": "active"}),
            patch.object(messaging, "tbl_parts", tbl_parts),
        ):
            resp = messaging.list_participants("c1", user_id="u1")
        self.assertEqual(len(resp), 2)
        self.assertEqual(resp[0].user_id, "u1")

    def test_presign_image_upload(self):
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "s3") as s3,
            patch.object(messaging, "now_ts", return_value=10),
        ):
            s3.generate_presigned_url.return_value = "http://upload"
            resp = messaging.presign_image_upload(
                "c1", messaging.SendImagePresignIn(filename="file.png"), user_id="u1"
            )
        self.assertEqual(resp.upload_url, "http://upload")

    def test_create_image_message(self):
        tbl_msgs = Mock()
        tbl_convos = Mock()
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "now_ts", return_value=10),
            patch.object(messaging, "new_id", return_value="img"),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_convos", tbl_convos),
        ):
            resp = messaging.create_image_message(
                "c1",
                messaging.CreateImageMessageIn(bucket="b", key="k"),
                user_id="u1",
            )
        self.assertEqual(resp.message_id, "m_img")
        tbl_msgs.put_item.assert_called_once()

    def test_mark_read_updates_last_read(self):
        tbl_parts = Mock()
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "get_participant_any", return_value={"last_read_at": 5}),
            patch.object(messaging, "tbl_parts", tbl_parts),
        ):
            resp = messaging.mark_read("c1", messaging.MarkReadIn(last_read_at=7), user_id="u1")
        self.assertEqual(resp["last_read_at"], 7)
        tbl_parts.update_item.assert_called_once()

    def test_delete_message_for_me(self):
        tbl_msgs = Mock()
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
        ):
            resp = messaging.delete_message_for_me("c1", "m1", user_id="u1")
        self.assertTrue(resp["ok"])
        tbl_msgs.update_item.assert_called_once()

    def test_react_to_message(self):
        tbl_msgs = Mock()
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "fanout_event_to_conversation"),
            patch.object(messaging, "now_ts", return_value=10),
        ):
            resp = messaging.react_to_message(
                "c1", "m1", messaging.ReactIn(emoji="👍", action="add"), user_id="u1"
            )
        self.assertTrue(resp["ok"])
        tbl_msgs.update_item.assert_called_once()

    def test_edit_message_updates_and_fanout(self):
        tbl_msgs = Mock()
        tbl_edits = Mock()
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "now_ts", return_value=10),
            patch.object(
                messaging,
                "_get_message_or_404",
                side_effect=[
                    {
                        "conversation_id": "c1",
                        "message_id": "m1",
                        "sender_id": "u1",
                        "created_at": 1,
                        "kind": "text",
                        "text": "old",
                    },
                    {
                        "conversation_id": "c1",
                        "message_id": "m1",
                        "sender_id": "u1",
                        "created_at": 1,
                        "kind": "text",
                        "text": "new",
                    },
                ],
            ),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_edits", tbl_edits),
            patch.object(messaging, "_reaction_summaries", return_value=({}, [])),
            patch.object(messaging, "fanout_event_to_conversation"),
        ):
            resp = messaging.edit_message(
                "c1", "m1", messaging.EditMessageIn(text="new"), user_id="u1"
            )
        self.assertEqual(resp.text, "new")
        tbl_edits.put_item.assert_called_once()
        tbl_msgs.update_item.assert_called_once()

    def test_get_edit_history(self):
        tbl_edits = Mock()
        tbl_edits.query.return_value = {"Items": [{"edited_at": 1, "edited_by": "u1", "old_text": "a", "new_text": "b"}]}
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_get_message_or_404"),
            patch.object(messaging, "tbl_edits", tbl_edits),
        ):
            resp = messaging.get_edit_history("c1", "m1", user_id="u1")
        self.assertEqual(len(resp), 1)
        self.assertEqual(resp[0].edited_by, "u1")

    def test_forward_message(self):
        tbl_msgs = Mock()
        tbl_convos = Mock()
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "now_ts", return_value=10),
            patch.object(messaging, "new_id", return_value="fwd"),
            patch.object(
                messaging,
                "_get_message_or_404",
                return_value={
                    "conversation_id": "c1",
                    "message_id": "m1",
                    "sender_id": "u2",
                    "created_at": 1,
                    "kind": "text",
                    "text": "hello",
                },
            ),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_convos", tbl_convos),
            patch.object(messaging, "fanout_event_to_conversation"),
        ):
            resp = messaging.forward_message(
                "c2",
                messaging.ForwardMessageIn(source_conversation_id="c1", source_message_id="m1"),
                user_id="u1",
            )
        self.assertEqual(resp.message_id, "m_fwd")
        tbl_msgs.put_item.assert_called_once()

    def test_mark_message_viewed(self):
        tbl_views = Mock()
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_get_message_or_404"),
            patch.object(messaging, "tbl_views", tbl_views),
            patch.object(messaging, "fanout_event_to_conversation"),
            patch.object(messaging, "now_ts", return_value=10),
        ):
            resp = messaging.mark_message_viewed(
                "c1", "m1", messaging.ViewMessageIn(), user_id="u1"
            )
        self.assertTrue(resp.ok)
        tbl_views.update_item.assert_called_once()

    def test_get_message_views(self):
        tbl_views = Mock()
        tbl_views.query.return_value = {
            "Items": [{"user_id": "u1", "last_viewed_at": 1, "view_count": 2}]
        }
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_get_message_or_404"),
            patch.object(messaging, "tbl_views", tbl_views),
        ):
            resp = messaging.get_message_views("c1", "m1", user_id="u1")
        self.assertEqual(resp[0].user_id, "u1")

    def test_set_typing(self):
        tbl_typing = Mock()
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "tbl_typing", tbl_typing),
            patch.object(messaging, "fanout_event_to_conversation"),
            patch.object(messaging, "now_ts", return_value=10),
        ):
            resp = messaging.set_typing("c1", messaging.TypingIn(is_typing=True), user_id="u1")
        self.assertTrue(resp["ok"])
        tbl_typing.put_item.assert_called_once()

    def test_get_typing_filters_expired(self):
        tbl_typing = Mock()
        tbl_typing.query.return_value = {
            "Items": [
                {"user_id": "u1", "is_typing": True, "updated_at": 5, "ttl": 20},
                {"user_id": "u2", "is_typing": True, "updated_at": 5, "ttl": 5},
            ]
        }
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "tbl_typing", tbl_typing),
            patch.object(messaging, "now_ts", return_value=10),
        ):
            resp = messaging.get_typing("c1", user_id="u1")
        self.assertEqual(len(resp), 1)
        self.assertEqual(resp[0].user_id, "u1")

    def test_presence_heartbeat(self):
        tbl_presence = Mock()
        with (
            patch.object(messaging, "tbl_presence", tbl_presence),
            patch.object(messaging, "now_ts", return_value=10),
        ):
            resp = messaging.presence_heartbeat(messaging.PresenceHeartbeatIn(), user_id="u1")
        self.assertTrue(resp["ok"])
        tbl_presence.put_item.assert_called_once()

    def test_presence_get(self):
        ddb = SimpleNamespace(
            meta=SimpleNamespace(
                client=SimpleNamespace(
                    batch_get_item=Mock(
                        return_value={"Responses": {messaging.DDB_PRESENCE: [{"user_id": "u1", "last_seen_at": 9}]}}
                    )
                )
            )
        )
        with (
            patch.object(messaging, "ddb", ddb),
            patch.object(messaging, "now_ts", return_value=10),
        ):
            resp = messaging.presence_get("u1", user_id="u1")
        self.assertTrue(resp[0].online)

    def test_fetch_events(self):
        with patch.object(messaging, "_ddb_fetch_events", return_value=[{"event_id": "e1"}]):
            resp = messaging.fetch_events(user_id="u1")
        self.assertEqual(resp["next_after"], "e1")

    def test_events_stream_returns_streaming_response(self):
        resp = asyncio.run(messaging.events_stream(user_id="u1"))
        self.assertIsInstance(resp, StreamingResponse)

    def test_healthz(self):
        with patch.object(messaging, "now_ts", return_value=10):
            resp = messaging.healthz()
        self.assertEqual(resp["ts"], 10)
