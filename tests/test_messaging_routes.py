import asyncio
import os
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from fastapi import HTTPException
from fastapi.responses import StreamingResponse
from pydantic import ValidationError

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
        convo_item = tbl_convos.put_item.call_args.kwargs["Item"]
        self.assertEqual(convo_item["routing_mode"], "standard")
        self.assertEqual(convo_item["routing_state"], "none")
        self.assertEqual(convo_item["assignment_version"], 0)
        self.assertEqual(tbl_parts.put_item.call_count, 2)
        self.assertEqual(resp.conversation_id, "c_abc")
        self.assertEqual(resp.created_at, 123)
        self.assertEqual(resp.participant_count, 2)
        self.assertEqual(resp.status, "active")

    def test_start_conversation_helpdesk_routing_metadata(self):
        with (
            patch.object(messaging, "now_ts", return_value=123),
            patch.object(messaging, "new_id", return_value="abc"),
            patch.object(messaging, "tbl_convos") as tbl_convos,
            patch.object(messaging, "tbl_parts") as tbl_parts,
        ):
            messaging.start_conversation(
                messaging.StartConversationIn(
                    participant_ids=[],
                    type="dm",
                    routing_mode="helpdesk_bridge",
                    helpdesk_group_id="helpdesk-l1",
                ),
                user_id="user-1",
            )

        self.assertEqual(tbl_parts.put_item.call_count, 2)
        participant_items = [c.kwargs["Item"] for c in tbl_parts.put_item.call_args_list]
        self.assertIn("helpdesk_group:helpdesk-l1", {i["user_id"] for i in participant_items})
        convo_item = tbl_convos.put_item.call_args.kwargs["Item"]
        self.assertEqual(convo_item["routing_mode"], "helpdesk_bridge")
        self.assertEqual(convo_item["routing_group_id"], "helpdesk-l1")
        self.assertEqual(convo_item["routing_state"], "awaiting_agent")
        self.assertEqual(convo_item["routing_state_group_pk"], "awaiting_agent#helpdesk-l1")
        self.assertEqual(convo_item["routing_state_group_sk"], "c_abc")


    def test_start_conversation_standard_requires_participant(self):
        with self.assertRaises(ValidationError):
            messaging.StartConversationIn(
                participant_ids=[],
                type="dm",
                routing_mode="standard",
            )

    def test_start_conversation_helpdesk_requires_group(self):
        with self.assertRaises(ValidationError):
            messaging.StartConversationIn(
                participant_ids=["user-2"],
                type="dm",
                routing_mode="helpdesk_bridge",
            )

    def test_helpdesk_bridge_mode_disabled_blocks_start_conversation(self):
        with patch.dict(os.environ, {"HELPDESK_BRIDGE_MODE": "disabled"}, clear=False):
            with self.assertRaises(HTTPException) as ctx:
                messaging.start_conversation(
                    messaging.StartConversationIn(
                        participant_ids=[],
                        type="dm",
                        routing_mode="helpdesk_bridge",
                        helpdesk_group_id="helpdesk-l1",
                    ),
                    user_id="user-1",
                )

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail.get("code"), "helpdesk_bridge_mode_disabled")

    def test_helpdesk_bridge_mode_internal_allows_only_internal_groups(self):
        with patch.dict(
            os.environ,
            {
                "HELPDESK_BRIDGE_MODE": "internal",
                "HELPDESK_BRIDGE_INTERNAL_GROUP_IDS": "helpdesk-internal,helpdesk-l2",
            },
            clear=False,
        ):
            self.assertTrue(
                messaging._is_helpdesk_bridge_mode_enabled_for(user_id="user-1", group_id="helpdesk-internal")
            )
            self.assertFalse(
                messaging._is_helpdesk_bridge_mode_enabled_for(user_id="user-1", group_id="helpdesk-l1")
            )

    def test_helpdesk_bridge_mode_selective_allows_enabled_group(self):
        with patch.dict(
            os.environ,
            {
                "HELPDESK_BRIDGE_MODE": "selective",
                "HELPDESK_BRIDGE_ENABLED_GROUP_IDS": "helpdesk-l1,helpdesk-l3",
                "HELPDESK_BRIDGE_ENABLED_TENANT_IDS": "",
            },
            clear=False,
        ):
            self.assertTrue(messaging._is_helpdesk_bridge_mode_enabled_for(user_id="user-1", group_id="helpdesk-l1"))
            self.assertFalse(messaging._is_helpdesk_bridge_mode_enabled_for(user_id="user-1", group_id="helpdesk-l2"))

    def test_helpdesk_bridge_mode_selective_allows_enabled_tenant(self):
        with patch.dict(
            os.environ,
            {
                "HELPDESK_BRIDGE_MODE": "selective",
                "HELPDESK_BRIDGE_ENABLED_GROUP_IDS": "",
                "HELPDESK_BRIDGE_ENABLED_TENANT_IDS": "tenant-1",
            },
            clear=False,
        ):
            with patch.object(messaging, "tbl_users") as tbl_users:
                tbl_users.get_item.return_value = {"Item": {"tenant_id": "tenant-1"}}
                self.assertTrue(
                    messaging._is_helpdesk_bridge_mode_enabled_for(user_id="user-1", group_id="helpdesk-l9")
                )

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

    def test_list_messages_masks_helpdesk_agent_sender_for_end_users(self):
        tbl_parts = Mock()
        tbl_msgs = Mock()
        tbl_parts.get_item.return_value = {"Item": {"status": "active"}}
        tbl_parts.query.return_value = {"Items": []}
        tbl_msgs.query.return_value = {
            "Items": [
                {
                    "conversation_id": "c1",
                    "message_id": "m1",
                    "sender_id": "agent-1",
                    "created_at": 10,
                    "kind": "text",
                    "text": "hello",
                    "deleted_for": [],
                    "reactions": {},
                }
            ]
        }

        with (
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(
                messaging,
                "_get_conversation_or_404",
                return_value={"routing_mode": "helpdesk_bridge", "routing_group_id": "helpdesk-l1"},
            ),
            patch.object(messaging, "_is_helpdesk_group_member", side_effect=lambda gid, uid: uid == "agent-1"),
        ):
            messages = messaging.list_messages("c1", user_id="customer-1")

        self.assertEqual(messages[0].sender_id, messaging.HELPDESK_MASKED_SENDER_ID)

    def test_list_conversation_gallery_filters_by_type_and_returns_cursor(self):
        tbl_parts = Mock()
        tbl_msgs = Mock()
        tbl_parts.get_item.return_value = {"Item": {"status": "active"}}
        tbl_msgs.query.side_effect = [
            {
                "Items": [
                    {
                        "conversation_id": "c1",
                        "message_id": "m3",
                        "sender_id": "user-2",
                        "created_at": 100,
                        "kind": "image",
                        "image": {"url": "https://cdn.example.com/a.jpg", "content_type": "image/jpeg"},
                    },
                    {
                        "conversation_id": "c1",
                        "message_id": "m2",
                        "sender_id": "user-3",
                        "created_at": 90,
                        "kind": "text",
                        "preview": {"url": "https://example.com", "title": "Example"},
                    },
                ],
                "LastEvaluatedKey": {"conversation_id": "c1", "message_id": "m2"},
            },
            {"Items": []},
        ]

        with (
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
        ):
            page = messaging.list_conversation_gallery("c1", type="image", user_id="user-1")

        self.assertEqual(len(page.items), 1)
        self.assertEqual(page.items[0].type, "image")
        self.assertEqual(page.items[0].message_id, "m3")
        self.assertIsNone(page.next_cursor)

    def test_e2e_mid_thread_assignee_change_keeps_helpdesk_identity_for_end_user(self):
        tbl_parts = Mock()
        tbl_msgs = Mock()
        tbl_parts.get_item.return_value = {"Item": {"status": "active"}}
        tbl_parts.query.return_value = {"Items": []}
        # agent-1 sent early, agent-2 claimed and replied later — end user sees both as "Helpdesk"
        tbl_msgs.query.return_value = {
            "Items": [
                {
                    "conversation_id": "c1",
                    "message_id": "m2",
                    "sender_id": "agent-2",
                    "created_at": 20,
                    "kind": "text",
                    "text": "I can take over from here",
                    "deleted_for": [],
                    "reactions": {},
                },
                {
                    "conversation_id": "c1",
                    "message_id": "m1",
                    "sender_id": "agent-1",
                    "created_at": 10,
                    "kind": "text",
                    "text": "Hi, I will help you",
                    "deleted_for": [],
                    "reactions": {},
                },
            ]
        }

        with (
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(
                messaging,
                "_get_conversation_or_404",
                return_value={
                    "routing_mode": "helpdesk_bridge",
                    "routing_group_id": "helpdesk-l1",
                    "routing_state": "assigned",
                    "active_agent_user_id": "agent-2",
                },
            ),
            patch.object(
                messaging,
                "_is_helpdesk_group_member",
                side_effect=lambda gid, uid: uid in {"agent-1", "agent-2"},
            ),
        ):
            messages = messaging.list_messages("c1", user_id="customer-1")

        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0].sender_id, messaging.HELPDESK_MASKED_SENDER_ID)
        self.assertEqual(messages[1].sender_id, messaging.HELPDESK_MASKED_SENDER_ID)

    def test_list_conversation_gallery_paginates_across_sparse_matches(self):
        tbl_parts = Mock()
        tbl_msgs = Mock()
        tbl_parts.get_item.return_value = {"Item": {"status": "active"}}
        tbl_msgs.query.side_effect = [
            {
                "Items": [
                    {
                        "conversation_id": "c1",
                        "message_id": "m3",
                        "sender_id": "user-2",
                        "created_at": 103,
                        "kind": "text",
                        "text": "hello",
                    },
                    {
                        "conversation_id": "c1",
                        "message_id": "m2",
                        "sender_id": "user-2",
                        "created_at": 102,
                        "kind": "image",
                        "image": {"url": "https://cdn.example.com/2.jpg"},
                    },
                ],
                "LastEvaluatedKey": {"conversation_id": "c1", "message_id": "m2"},
            },
            {
                "Items": [
                    {
                        "conversation_id": "c1",
                        "message_id": "m1",
                        "sender_id": "user-3",
                        "created_at": 101,
                        "kind": "image",
                        "image": {"url": "https://cdn.example.com/1.jpg"},
                    },
                ]
            },
        ]

        with (
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
        ):
            page = messaging.list_conversation_gallery("c1", type="image", limit=2, user_id="user-1")

        self.assertEqual([item.message_id for item in page.items], ["m2", "m1"])
        self.assertIsNone(page.next_cursor)

    def test_list_conversation_gallery_suppresses_revoked_and_deleted(self):
        tbl_msgs = Mock()
        tbl_msgs.query.return_value = {
            "Items": [
                {
                    "conversation_id": "c1",
                    "message_id": "m3",
                    "sender_id": "user-2",
                    "created_at": 103,
                    "kind": "image",
                    "image": {"url": "https://cdn.example.com/3.jpg"},
                    "revoked_at": 101,
                },
                {
                    "conversation_id": "c1",
                    "message_id": "m2",
                    "sender_id": "user-2",
                    "created_at": 102,
                    "kind": "image",
                    "image": {"url": "https://cdn.example.com/2.jpg"},
                    "deleted_for": ["user-1"],
                },
                {
                    "conversation_id": "c1",
                    "message_id": "m1",
                    "sender_id": "user-2",
                    "created_at": 101,
                    "kind": "image",
                    "image": {"url": "https://cdn.example.com/1.jpg"},
                },
            ]
        }

        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
        ):
            page = messaging.list_conversation_gallery("c1", type="image", user_id="user-1")

        self.assertEqual([item.message_id for item in page.items], ["m1"])

    def test_list_messages_masks_helpdesk_agents_for_end_users(self):
        tbl_parts = Mock()
        tbl_msgs = Mock()
        tbl_parts.get_item.return_value = {"Item": {"status": "active"}}
        tbl_parts.query.return_value = {"Items": []}

        tbl_msgs.query.return_value = {
            "Items": [
                {
                    "conversation_id": "c1",
                    "message_id": "m2",
                    "sender_id": "agent-2",
                    "created_at": 20,
                    "kind": "text",
                    "text": "I can take over",
                    "deleted_for": [],
                    "reactions": {},
                },
                {
                    "conversation_id": "c1",
                    "message_id": "m1",
                    "sender_id": "agent-1",
                    "created_at": 10,
                    "kind": "text",
                    "text": "I will help you",
                    "deleted_for": [],
                    "reactions": {},
                },
            ]
        }

        with (
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(
                messaging,
                "_get_conversation_or_404",
                return_value={
                    "routing_mode": "helpdesk_bridge",
                    "routing_group_id": "helpdesk-l1",
                    "routing_state": "assigned",
                },
            ),
            patch.object(messaging, "_is_helpdesk_group_member", side_effect=lambda gid, uid: uid in {"agent-1", "agent-2"}),
        ):
            messages = messaging.list_messages("c1", user_id="customer-1")

        self.assertEqual(
            [m.sender_id for m in messages],
            [messaging.HELPDESK_MASKED_SENDER_ID, messaging.HELPDESK_MASKED_SENDER_ID],
        )

    def test_list_messages_retains_helpdesk_agent_sender_for_helpdesk_agents(self):
        tbl_parts = Mock()
        tbl_msgs = Mock()
        tbl_parts.get_item.return_value = {"Item": {"status": "active"}}
        tbl_parts.query.return_value = {"Items": []}

        tbl_msgs.query.return_value = {
            "Items": [
                {
                    "conversation_id": "c1",
                    "message_id": "m1",
                    "sender_id": "agent-1",
                    "created_at": 10,
                    "kind": "text",
                    "text": "hello",
                    "deleted_for": [],
                    "reactions": {},
                }
            ]
        }

        with (
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(
                messaging,
                "_get_conversation_or_404",
                return_value={"routing_mode": "helpdesk_bridge", "routing_group_id": "helpdesk-l1"},
            ),
            patch.object(messaging, "_is_helpdesk_group_member", side_effect=lambda gid, uid: uid in {"agent-1", "agent-2"}),
        ):
            messages = messaging.list_messages("c1", user_id="agent-2")

        self.assertEqual(messages[0].sender_id, "agent-1")

    def test_fetch_events_projects_helpdesk_sender_for_end_users(self):
        with (
            patch.object(
                messaging,
                "_ddb_fetch_events",
                return_value=[
                    {
                        "event_id": "e1",
                        "type": "message:new",
                        "conversation_id": "c1",
                        "payload": {
                            "message": {
                                "conversation_id": "c1",
                                "message_id": "m1",
                                "sender_id": "agent-1",
                            }
                        },
                    }
                ],
            ),
            patch.object(
                messaging,
                "_get_message_or_404",
                return_value={
                    "conversation_id": "c1",
                    "message_id": "m1",
                    "sender_id": "agent-1",
                    "created_at": 10,
                    "kind": "text",
                    "text": "hello",
                    "reactions": {},
                },
            ),
            patch.object(
                messaging,
                "_get_conversation_or_404",
                return_value={"routing_mode": "helpdesk_bridge", "routing_group_id": "helpdesk-l1"},
            ),
            patch.object(messaging, "_is_helpdesk_group_member", side_effect=lambda gid, uid: uid == "agent-1"),
        ):
            resp = messaging.fetch_events(user_id="customer-1")

        self.assertEqual(
            resp["events"][0]["payload"]["message"]["sender_id"],
            messaging.HELPDESK_MASKED_SENDER_ID,
        )


    def test_send_text_message_success_records_usage_once(self):
        tbl_msgs = Mock()
        tbl_convos = Mock()
        with (
            patch.object(messaging, "S") as settings,
            patch.object(messaging, "ddb") as ddb,
            patch.object(messaging, "record_usage_event_and_aggregates") as record_usage,
            patch.object(messaging, "now_ts", return_value=55),
            patch.object(messaging, "new_id", return_value="xyz"),
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_enforce_message_send_quota_precheck"),
            patch.object(messaging, "fanout_event_to_conversation"),
            patch.object(messaging, "audit_event"),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_convos", tbl_convos),
            patch.object(messaging, "fanout_event_to_conversation"),
        ):
            settings.filemgr_table_name = "FileManager"
            ddb.Table.return_value = Mock()
            messaging.send_text_message(
                "c1",
                messaging.SendTextMessageIn(text="Hello world"),
                user_id="user-1",
            )

        record_usage.assert_called_once()
        event = record_usage.call_args.args[1]
        self.assertEqual(event["source"], "messaging_send")
        self.assertEqual(event["idempotency_key"], "user-1|messaging_send|c1|m_xyz")

    def test_send_text_message_failed_persist_does_not_record_usage(self):
        tbl_msgs = Mock()
        tbl_msgs.put_item.side_effect = RuntimeError("ddb down")
        tbl_convos = Mock()
        with (
            patch.object(messaging, "S") as settings,
            patch.object(messaging, "ddb") as ddb,
            patch.object(messaging, "record_usage_event_and_aggregates") as record_usage,
            patch.object(messaging, "now_ts", return_value=55),
            patch.object(messaging, "new_id", return_value="xyz"),
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_enforce_message_send_quota_precheck"),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_convos", tbl_convos),
        ):
            settings.filemgr_table_name = "FileManager"
            ddb.Table.return_value = Mock()
            with self.assertRaises(RuntimeError):
                messaging.send_text_message(
                    "c1",
                    messaging.SendTextMessageIn(text="Hello world"),
                    user_id="user-1",
                )

        record_usage.assert_not_called()

    def test_send_text_message_updates_conversation_preview(self):
        tbl_msgs = Mock()
        tbl_convos = Mock()
        with (
            patch.object(messaging, "now_ts", return_value=55),
            patch.object(messaging, "new_id", return_value="xyz"),
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_enforce_message_send_quota_precheck"),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_convos", tbl_convos),
            patch.object(messaging, "_meter_message_send") as meter_send,
            patch.object(messaging, "fanout_event_to_conversation") as fanout,
        ):
            resp = messaging.send_text_message(
                "c1",
                messaging.SendTextMessageIn(text="Hello world"),
                user_id="user-1",
            )

        tbl_msgs.put_item.assert_called_once()
        tbl_convos.update_item.assert_called_once()
        meter_send.assert_called_once_with(user_id="user-1", conversation_id="c1", message_id="m_xyz")
        self.assertEqual(resp.message_id, "m_xyz")
        self.assertEqual(resp.text, "Hello world")
        fanout.assert_called_once()
        self.assertEqual(fanout.call_args.kwargs["event_type"], "message:new")
        payload = fanout.call_args.kwargs["payload"]
        self.assertEqual(payload["message"]["message_id"], "m_xyz")
        self.assertEqual(payload["message"]["text"], "Hello world")
        self.assertNotIn("encryption", payload["message"])


    def test_send_text_message_helpdesk_auto_claim_on_first_reply_when_enabled(self):
        tbl_msgs = Mock()
        tbl_convos = Mock()
        with (
            patch.object(messaging, "HELPDESK_AUTO_CLAIM_ON_REPLY_ENABLED", True),
            patch.object(messaging, "now_ts", return_value=55),
            patch.object(messaging, "new_id", return_value="xyz"),
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_enforce_message_send_quota_precheck"),
            patch.object(messaging, "_is_helpdesk_group_member", return_value=True),
            patch.object(
                messaging,
                "_claim_helpdesk_conversation_internal",
                return_value=messaging.HelpdeskClaimOut(
                    ok=True,
                    conversation_id="c1",
                    state="assigned",
                    assigned_agent_user_id="agent-1",
                    assignment_version=1,
                    idempotent=False,
                ),
            ) as claim_internal,
            patch.object(messaging, "_get_conversation_or_404", return_value={"routing_mode": "helpdesk_bridge", "routing_group_id": "helpdesk-l1", "routing_state": "awaiting_agent"}),
            patch.object(messaging, "fanout_event_to_conversation"),
            patch.object(messaging, "_meter_message_send"),
            patch.object(messaging, "audit_event"),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_convos", tbl_convos),
        ):
            messaging.send_text_message("c1", messaging.SendTextMessageIn(text="Hello world"), user_id="agent-1")

        claim_internal.assert_called_once_with(conversation_id="c1", user_id="agent-1", req=None)

    def test_send_text_message_helpdesk_requires_explicit_claim_when_auto_claim_disabled(self):
        with (
            patch.object(messaging, "HELPDESK_AUTO_CLAIM_ON_REPLY_ENABLED", False),
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_is_helpdesk_group_member", return_value=True),
            patch.object(messaging, "_get_conversation_or_404", return_value={"routing_mode": "helpdesk_bridge", "routing_group_id": "helpdesk-l1", "routing_state": "awaiting_agent"}),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.send_text_message("c1", messaging.SendTextMessageIn(text="Hello world"), user_id="agent-1")

        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "helpdesk_claim_required")






    def test_send_text_message_helpdesk_assigned_rejects_non_assignee(self):
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_is_helpdesk_group_member", return_value=True),
            patch.object(
                messaging,
                "_get_conversation_or_404",
                return_value={
                    "routing_mode": "helpdesk_bridge",
                    "routing_group_id": "helpdesk-l1",
                    "routing_state": "assigned",
                    "active_agent_user_id": "agent-1",
                },
            ),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.send_text_message("c1", messaging.SendTextMessageIn(text="Hello world"), user_id="agent-2")

        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "helpdesk_assignee_required")

    def test_send_text_message_helpdesk_assigned_allows_assignee(self):
        tbl_msgs = Mock()
        tbl_convos = Mock()
        with (
            patch.object(messaging, "now_ts", return_value=55),
            patch.object(messaging, "new_id", return_value="xyz"),
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_enforce_message_send_quota_precheck"),
            patch.object(messaging, "_is_helpdesk_group_member", return_value=True),
            patch.object(
                messaging,
                "_get_conversation_or_404",
                return_value={
                    "routing_mode": "helpdesk_bridge",
                    "routing_group_id": "helpdesk-l1",
                    "routing_state": "assigned",
                    "active_agent_user_id": "agent-1",
                },
            ),
            patch.object(messaging, "fanout_event_to_conversation"),
            patch.object(messaging, "_meter_message_send"),
            patch.object(messaging, "audit_event"),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_convos", tbl_convos),
        ):
            messaging.send_text_message("c1", messaging.SendTextMessageIn(text="Hello world"), user_id="agent-1")

        tbl_msgs.put_item.assert_called_once()


    def test_send_encrypted_message_rejected_when_feature_flag_off(self):
        with (
            patch.dict(os.environ, {"MESSAGING_ENCRYPTED_MESSAGES_ENABLED": "0"}, clear=False),
            patch.object(messaging, "require_participant_active"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.send_text_message(
                    "c1",
                    messaging.SendTextMessageIn(
                        encryption={
                            "version": 1,
                            "alg": "AES-256-GCM",
                            "kdf": "PBKDF2-SHA256",
                            "iterations": 600000,
                            "salt_b64": "MTIzNDU2Nzg5MGFiY2RlZg==",
                            "iv_b64": "MTIzNDU2Nzg5MDEy",
                            "ciphertext_b64": "cGF5bG9hZC1ieXRlcy0xMjM0NTY=",
                        }
                    ),
                    user_id="user-1",
                )
        self.assertEqual(ctx.exception.status_code, 403)

    def test_messaging_config_reflects_kill_switch(self):
        with patch.dict(
            os.environ,
            {
                "MESSAGING_ENCRYPTED_MESSAGES_ENABLED": "1",
                "MESSAGING_ENCRYPTED_MESSAGES_KILL_SWITCH": "1",
            },
            clear=False,
        ):
            resp = messaging.messaging_config(user_id="user-1")
        self.assertFalse(resp.messaging_encrypted_messages_enabled)

    def test_messaging_config_reflects_gallery_kill_switch(self):
        with patch.dict(
            os.environ,
            {
                "MESSAGING_GALLERY_ENABLED": "1",
                "MESSAGING_GALLERY_KILL_SWITCH": "1",
            },
            clear=False,
        ):
            resp = messaging.messaging_config(user_id="user-1")
        self.assertFalse(resp.messaging_gallery_enabled)


    def test_plaintext_send_works_when_encryption_feature_flag_off(self):
        tbl_msgs = Mock()
        tbl_convos = Mock()
        with (
            patch.dict(os.environ, {"MESSAGING_ENCRYPTED_MESSAGES_ENABLED": "0"}, clear=False),
            patch.object(messaging, "now_ts", return_value=55),
            patch.object(messaging, "new_id", return_value="xyz"),
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_convos", tbl_convos),
            patch.object(messaging, "fanout_event_to_conversation"),
        ):
            resp = messaging.send_text_message(
                "c1",
                messaging.SendTextMessageIn(text="Hello world"),
                user_id="user-1",
            )

        self.assertEqual(resp.text, "Hello world")
        self.assertFalse(resp.is_encrypted)
        tbl_msgs.put_item.assert_called_once()

    def test_send_encrypted_text_message_skips_search_index(self):
        tbl_msgs = Mock()
        tbl_convos = Mock()
        with (
            patch.dict(os.environ, {"MESSAGING_ENCRYPTED_MESSAGES_ENABLED": "1"}, clear=False),
            patch.object(messaging, "now_ts", return_value=55),
            patch.object(messaging, "new_id", return_value="xyz"),
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_convos", tbl_convos),
            patch.object(messaging, "index_message_search") as index_message_search,
            patch.object(messaging, "fanout_event_to_conversation") as fanout,
        ):
            resp = messaging.send_text_message(
                "c1",
                messaging.SendTextMessageIn(
                    encryption={
                        "version": 1,
                        "alg": "AES-256-GCM",
                        "kdf": "PBKDF2-SHA256",
                        "iterations": 600000,
                        "salt_b64": "MTIzNDU2Nzg5MGFiY2RlZg==",
                        "iv_b64": "MTIzNDU2Nzg5MDEy",
                        "ciphertext_b64": "cGF5bG9hZC1ieXRlcy0xMjM0NTY=",
                    }
                ),
                user_id="user-1",
            )

        index_message_search.assert_not_called()
        self.assertTrue(resp.is_encrypted)
        self.assertIsNotNone(resp.encryption)
        stored_item = tbl_msgs.put_item.call_args.kwargs["Item"]
        self.assertTrue(stored_item["is_encrypted"])
        self.assertIsNone(stored_item["text"])
        self.assertEqual(stored_item["encryption"]["alg"], "AES-256-GCM")
        fanout.assert_called_once()
        self.assertEqual(fanout.call_args.kwargs["event_type"], "message:new")
        payload = fanout.call_args.kwargs["payload"]
        self.assertEqual(payload["message"]["message_id"], "m_xyz")
        self.assertTrue(payload["message"]["is_encrypted"])
        self.assertEqual(payload["message"]["encryption"]["ciphertext_b64"], "cGF5bG9hZC1ieXRlcy0xMjM0NTY=")
        self.assertNotIn("text", payload["message"])

    def test_meter_message_send_builds_deterministic_idempotency_key(self):
        table = Mock()
        with (
            patch.object(messaging, "ddb") as ddb,
            patch.object(messaging, "S") as settings,
            patch.object(messaging, "record_usage_event_and_aggregates") as record_usage,
        ):
            settings.filemgr_table_name = "FileManager"
            ddb.Table.return_value = table
            messaging._meter_message_send(user_id="u1", conversation_id="c1", message_id="m1")

        ddb.Table.assert_called_once_with("FileManager")
        record_usage.assert_called_once()
        event = record_usage.call_args.args[1]
        self.assertEqual(event["source"], "messaging_send")
        self.assertEqual(event["idempotency_key"], "u1|messaging_send|c1|m1")

    def test_send_text_message_failed_persist_does_not_meter(self):
        tbl_msgs = Mock()
        tbl_msgs.put_item.side_effect = RuntimeError("ddb down")
        tbl_convos = Mock()
        with (
            patch.object(messaging, "now_ts", return_value=55),
            patch.object(messaging, "new_id", return_value="xyz"),
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_enforce_message_send_quota_precheck"),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_convos", tbl_convos),
            patch.object(messaging, "_meter_message_send") as meter_send,
        ):
            with self.assertRaises(RuntimeError):
                messaging.send_text_message(
                    "c1",
                    messaging.SendTextMessageIn(text="Hello world"),
                    user_id="user-1",
                )

        meter_send.assert_not_called()

    def test_create_image_message_meters_send_unit(self):
        tbl_msgs = Mock()
        tbl_convos = Mock()
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_enforce_message_send_quota_precheck"),
            patch.object(messaging, "now_ts", return_value=10),
            patch.object(messaging, "new_id", return_value="img"),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_convos", tbl_convos),
            patch.object(messaging, "_meter_message_send") as meter_send,
            patch.object(messaging, "_meter_messaging_attachment_upload") as meter_upload,
        ):
            messaging.create_image_message(
                "c1",
                messaging.CreateImageMessageIn(bucket="b", key="k"),
                user_id="u1",
            )

        meter_send.assert_called_once_with(user_id="u1", conversation_id="c1", message_id="m_img")
        meter_upload.assert_called_once_with(
            user_id="u1",
            bucket="b",
            key="k",
            conversation_id="c1",
            message_id="m_img",
        )

    def test_create_file_message_meters_send_unit(self):
        tbl_msgs = Mock()
        tbl_convos = Mock()
        tbl_parts = Mock()
        tbl_parts.query.return_value = {"Items": [{"user_id": "u1"}, {"user_id": "u2"}]}
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_enforce_message_send_quota_precheck"),
            patch.object(messaging, "now_ts", return_value=10),
            patch.object(messaging, "new_id", return_value="file"),
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_convos", tbl_convos),
            patch.object(messaging, "get_node", return_value={"type": "file", "path": "/a.mp3", "name": "a.mp3", "size": 1, "content_type": "audio/mp3"}),
            patch.object(messaging, "_meter_message_send") as meter_send,
        ):
            messaging.create_file_message(
                "c1",
                messaging.CreateFileMessageIn(path="/a.mp3", kind="audio"),
                user_id="u1",
            )

        meter_send.assert_called_once_with(user_id="u1", conversation_id="c1", message_id="m_file")

    def test_create_image_message_failed_persist_does_not_meter(self):
        tbl_msgs = Mock()
        tbl_msgs.put_item.side_effect = RuntimeError("ddb down")
        tbl_convos = Mock()
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_enforce_message_send_quota_precheck"),
            patch.object(messaging, "now_ts", return_value=10),
            patch.object(messaging, "new_id", return_value="img"),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_convos", tbl_convos),
            patch.object(messaging, "_meter_message_send") as meter_send,
            patch.object(messaging, "_meter_messaging_attachment_upload") as meter_upload,
        ):
            with self.assertRaises(RuntimeError):
                messaging.create_image_message(
                    "c1",
                    messaging.CreateImageMessageIn(bucket="b", key="k"),
                    user_id="u1",
                )

        meter_send.assert_not_called()
        meter_upload.assert_not_called()

    def test_messaging_send_quota_precheck_raises_machine_readable_error(self):
        with (
            patch.object(
                messaging,
                "get_usage_summary",
                return_value={
                    "period_id": "2026-03",
                    "message_send": {"used_count": 10, "limit_count": 10},
                },
            ),
            patch.object(messaging, "S") as settings,
        ):
            settings.filemgr_table_name = "FileManager"
            with self.assertRaises(HTTPException) as ctx:
                messaging._enforce_message_send_quota_precheck(user_id="u1", conversation_id="c1", req=None)

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "messaging_send_quota_exceeded")
        self.assertEqual(ctx.exception.detail["quota_type"], "messaging_send")
        self.assertEqual(ctx.exception.detail["limit_count"], 10)
        self.assertEqual(ctx.exception.detail["used_count"], 10)
        self.assertEqual(ctx.exception.detail["remaining_count"], 0)

    def test_messaging_send_quota_soft_warnings_trigger_at_80_and_95(self):
        with (
            patch.object(
                messaging,
                "get_usage_summary",
                return_value={
                    "period_id": "2026-03",
                    "message_send": {"used_count": 0, "limit_count": 1},
                },
            ),
            patch.object(messaging, "S") as settings,
            patch.object(messaging, "_emit_messaging_quota_warning") as warn,
        ):
            settings.filemgr_table_name = "FileManager"
            settings.messaging_send_quota_soft_warnings_enabled = True
            messaging._enforce_message_send_quota_precheck(user_id="u1", conversation_id="c1", req=None)

        self.assertEqual(warn.call_count, 2)
        first_threshold = warn.call_args_list[0].kwargs["threshold_percent"]
        second_threshold = warn.call_args_list[1].kwargs["threshold_percent"]
        self.assertEqual(first_threshold, 80)
        self.assertEqual(second_threshold, 95)

    def test_messaging_send_quota_soft_warnings_disabled(self):
        with (
            patch.object(
                messaging,
                "get_usage_summary",
                return_value={
                    "period_id": "2026-03",
                    "message_send": {"used_count": 79, "limit_count": 99},
                },
            ),
            patch.object(messaging, "S") as settings,
            patch.object(messaging, "_emit_messaging_quota_warning") as warn,
        ):
            settings.filemgr_table_name = "FileManager"
            settings.messaging_send_quota_soft_warnings_enabled = False
            messaging._enforce_message_send_quota_precheck(user_id="u1", conversation_id="c1", req=None)

        warn.assert_not_called()

    def test_meter_messaging_attachment_upload_uses_head_object_content_length(self):
        table = Mock()
        with (
            patch.object(messaging, "S") as settings,
            patch.object(messaging, "ddb") as ddb,
            patch.object(messaging, "s3") as s3,
            patch.object(messaging, "record_usage_event_and_aggregates") as record_usage,
        ):
            settings.filemgr_table_name = "FileManager"
            ddb.Table.return_value = table
            s3.head_object.return_value = {"ContentLength": 321}

            messaging._meter_messaging_attachment_upload(
                user_id="u1",
                bucket="b",
                key="attachments/a.png",
                conversation_id="c1",
                message_id="m1",
            )

        s3.head_object.assert_called_once_with(Bucket="b", Key="attachments/a.png")
        record_usage.assert_called_once()
        event = record_usage.call_args.args[1]
        self.assertEqual(event["source"], "messaging_attachment_upload")
        self.assertEqual(event["bytes"], 321)
        self.assertEqual(event["idempotency_key"], "u1|messaging_attachment_upload|b/attachments/a.png|m1")

    def test_record_messaging_attachment_download_builds_deterministic_key(self):
        table = Mock()
        with (
            patch.object(messaging, "S") as settings,
            patch.object(messaging, "ddb") as ddb,
            patch.object(messaging, "record_usage_event_and_aggregates") as record_usage,
        ):
            settings.filemgr_table_name = "FileManager"
            ddb.Table.return_value = table
            messaging._record_messaging_attachment_download(
                user_id="u1",
                conversation_id="c1",
                message_id="m1",
                attachment_key="b/k.png",
                bytes_count=77,
                idempotency_operation_id="req-1",
            )

        record_usage.assert_called_once()
        event = record_usage.call_args.args[1]
        self.assertEqual(event["source"], "messaging_attachment_download")
        self.assertEqual(event["bytes"], 77)
        self.assertEqual(event["idempotency_key"], "u1|messaging_attachment_download|b/k.png|req-1")


    def test_create_once_media_attachment_grant_success(self):
        msg = {
            "conversation_id": "c1",
            "message_id": "m1",
            "sender_id": "u2",
            "kind": "image",
            "consumption_policy": "view_once",
            "media_kind": "image",
        }
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_get_message_or_404", return_value=msg),
            patch.object(messaging, "tbl_msg_consumption") as tbl_consumption,
            patch.object(messaging, "now_ts", return_value=100),
            patch.object(messaging, "audit_event"),
        ):
            tbl_consumption.get_item.return_value = {"Item": {"consumption_state": "pending"}}
            out = messaging.create_once_media_attachment_grant("c1", "m1", SimpleNamespace(headers={}), user_id="u1")

        self.assertEqual(out.conversation_id, "c1")
        self.assertEqual(out.message_id, "m1")
        self.assertTrue(out.grant_token)
        self.assertEqual(out.expires_at, 220)

    def test_create_once_media_attachment_grant_rejects_consumed(self):
        msg = {
            "conversation_id": "c1",
            "message_id": "m1",
            "sender_id": "u2",
            "kind": "video",
            "consumption_policy": "view_once",
            "media_kind": "video",
        }
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_get_message_or_404", return_value=msg),
            patch.object(messaging, "tbl_msg_consumption") as tbl_consumption,
        ):
            tbl_consumption.get_item.return_value = {"Item": {"consumption_state": "consumed"}}
            with self.assertRaises(HTTPException) as ctx:
                messaging.create_once_media_attachment_grant("c1", "m1", SimpleNamespace(headers={}), user_id="u1")

        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "already_consumed")


    def test_consume_once_media_attachment_success(self):
        msg = {
            "conversation_id": "c1",
            "message_id": "m1",
            "sender_id": "u2",
            "kind": "image",
            "consumption_policy": "view_once",
            "media_kind": "image",
        }
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_get_message_or_404", return_value=msg),
            patch.object(messaging, "tbl_msg_consumption") as tbl_consumption,
            patch.object(messaging, "now_ts", return_value=100),
            patch.object(messaging, "audit_event"),
        ):
            tbl_consumption.get_item.side_effect = [
                {"Item": {"consumption_state": "pending"}},
                {"Item": {"consumption_state": "consumed", "consumed_at": 100, "last_consumption_attempt_id": "attempt-1"}},
            ]
            grant = messaging._encode_once_media_grant(
                conversation_id="c1", message_id="m1", recipient_id="u1", expires_at=200
            )
            out = messaging.consume_once_media_attachment(
                "c1",
                "m1",
                messaging.ConsumeAttachmentIn(consumption_attempt_id="attempt-1", trigger="open"),
                SimpleNamespace(headers={}),
                grant_token=grant,
                user_id="u1",
            )

        self.assertTrue(out.ok)
        self.assertEqual(out.consumption_state, "consumed")
        self.assertEqual(out.consumed_at, 100)

    def test_consume_once_media_attachment_idempotent_retry(self):
        msg = {
            "conversation_id": "c1",
            "message_id": "m1",
            "sender_id": "u2",
            "kind": "audio",
            "consumption_policy": "listen_once",
            "media_kind": "audio",
        }

        err = messaging.ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "failed"}},
            "UpdateItem",
        )

        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_get_message_or_404", return_value=msg),
            patch.object(messaging, "tbl_msg_consumption") as tbl_consumption,
            patch.object(messaging, "now_ts", return_value=100),
            patch.object(messaging, "audit_event"),
        ):
            tbl_consumption.update_item.side_effect = err
            tbl_consumption.get_item.side_effect = [
                {"Item": {"consumption_state": "pending"}},
                {
                    "Item": {
                        "consumption_state": "consumed",
                        "consumed_at": 101,
                        "last_consumption_attempt_id": "attempt-77",
                    }
                },
            ]
            grant = messaging._encode_once_media_grant(
                conversation_id="c1", message_id="m1", recipient_id="u1", expires_at=200
            )
            out = messaging.consume_once_media_attachment(
                "c1",
                "m1",
                messaging.ConsumeAttachmentIn(consumption_attempt_id="attempt-77", trigger="play", playback_seconds=2.0),
                SimpleNamespace(headers={}),
                grant_token=grant,
                user_id="u1",
            )

        self.assertTrue(out.ok)
        self.assertEqual(out.consumed_at, 101)

    def test_consume_once_media_attachment_rejects_other_attempt_after_consumed(self):
        msg = {
            "conversation_id": "c1",
            "message_id": "m1",
            "sender_id": "u2",
            "kind": "video",
            "consumption_policy": "view_once",
            "media_kind": "video",
        }

        err = messaging.ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "failed"}},
            "UpdateItem",
        )

        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_get_message_or_404", return_value=msg),
            patch.object(messaging, "tbl_msg_consumption") as tbl_consumption,
            patch.object(messaging, "now_ts", return_value=100),
        ):
            tbl_consumption.update_item.side_effect = err
            tbl_consumption.get_item.side_effect = [
                {"Item": {"consumption_state": "pending"}},
                {
                    "Item": {
                        "consumption_state": "consumed",
                        "consumed_at": 101,
                        "last_consumption_attempt_id": "attempt-A",
                    }
                },
            ]
            grant = messaging._encode_once_media_grant(
                conversation_id="c1", message_id="m1", recipient_id="u1", expires_at=200
            )
            with self.assertRaises(HTTPException) as ctx:
                messaging.consume_once_media_attachment(
                    "c1",
                    "m1",
                    messaging.ConsumeAttachmentIn(consumption_attempt_id="attempt-B", trigger="play", playback_seconds=3.0),
                    SimpleNamespace(headers={}),
                    grant_token=grant,
                    user_id="u1",
                )

        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "already_consumed")


    def test_consume_once_media_attachment_video_threshold_not_met_retryable(self):
        msg = {
            "conversation_id": "c1",
            "message_id": "m1",
            "sender_id": "u2",
            "kind": "video",
            "consumption_policy": "view_once",
            "media_kind": "video",
        }
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_get_message_or_404", return_value=msg),
            patch.object(messaging, "tbl_msg_consumption") as tbl_consumption,
            patch.object(messaging, "now_ts", return_value=100),
        ):
            tbl_consumption.get_item.return_value = {"Item": {"consumption_state": "pending"}}
            grant = messaging._encode_once_media_grant(
                conversation_id="c1", message_id="m1", recipient_id="u1", expires_at=200
            )
            with self.assertRaises(HTTPException) as ctx:
                messaging.consume_once_media_attachment(
                    "c1",
                    "m1",
                    messaging.ConsumeAttachmentIn(consumption_attempt_id="attempt-v1", trigger="play", playback_seconds=0.2),
                    SimpleNamespace(headers={}),
                    grant_token=grant,
                    user_id="u1",
                )

        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "consume_threshold_not_met")
        self.assertTrue(ctx.exception.detail["retryable"])

    def test_consume_once_media_attachment_audio_threshold_met_succeeds(self):
        msg = {
            "conversation_id": "c1",
            "message_id": "m1",
            "sender_id": "u2",
            "kind": "audio",
            "consumption_policy": "listen_once",
            "media_kind": "audio",
        }
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_get_message_or_404", return_value=msg),
            patch.object(messaging, "tbl_msg_consumption") as tbl_consumption,
            patch.object(messaging, "now_ts", return_value=100),
            patch.object(messaging, "audit_event"),
        ):
            tbl_consumption.get_item.side_effect = [
                {"Item": {"consumption_state": "pending"}},
                {"Item": {"consumption_state": "consumed", "consumed_at": 100, "last_consumption_attempt_id": "attempt-a1"}},
            ]
            grant = messaging._encode_once_media_grant(
                conversation_id="c1", message_id="m1", recipient_id="u1", expires_at=200
            )
            out = messaging.consume_once_media_attachment(
                "c1",
                "m1",
                messaging.ConsumeAttachmentIn(consumption_attempt_id="attempt-a1", trigger="play", playback_seconds=2.2),
                SimpleNamespace(headers={}),
                grant_token=grant,
                user_id="u1",
            )
        self.assertEqual(out.consumption_state, "consumed")

    def test_download_once_media_attachment_requires_valid_grant_and_no_store_cache(self):
        class _Body:
            def iter_chunks(self, chunk_size=65536):
                yield b"x"

        async def _drain(resp):
            async for _ in resp.body_iterator:
                pass

        msg = {
            "conversation_id": "c1",
            "message_id": "m1",
            "sender_id": "u2",
            "kind": "image",
            "consumption_policy": "view_once",
            "media_kind": "image",
            "image": {"bucket": "b", "key": "img/k.png", "content_type": "image/png"},
        }

        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_get_message_or_404", return_value=msg),
            patch.object(messaging, "tbl_msg_consumption") as tbl_consumption,
            patch.object(messaging, "now_ts", return_value=100),
            patch.object(messaging, "s3") as s3,
            patch.object(messaging, "_record_messaging_attachment_download"),
            patch.object(messaging, "audit_event"),
        ):
            tbl_consumption.get_item.return_value = {"Item": {"consumption_state": "pending"}}
            grant = messaging._encode_once_media_grant(
                conversation_id="c1", message_id="m1", recipient_id="u1", expires_at=200
            )
            s3.get_object.return_value = {"Body": _Body(), "ContentLength": 1}
            resp = messaging.download_message_attachment(
                "c1", "m1", SimpleNamespace(headers={}), grant_token=grant, x_request_id=None, user_id="u1"
            )
            asyncio.run(_drain(resp))

        self.assertEqual(resp.headers["Cache-Control"], "no-store, no-cache, max-age=0, must-revalidate")
        self.assertEqual(resp.headers["Pragma"], "no-cache")
        self.assertEqual(resp.headers["Expires"], "0")

    def test_download_message_attachment_streams_and_records_download_bytes(self):
        class _Body:
            def iter_chunks(self, chunk_size=65536):
                yield b"ab"
                yield b"cde"

        async def _collect_chunks(resp):
            out = []
            async for chunk in resp.body_iterator:
                out.append(chunk)
            return out

        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(
                messaging,
                "_get_message_or_404",
                return_value={
                    "kind": "image",
                    "image": {"bucket": "b", "key": "img/k.png", "content_type": "image/png"},
                },
            ),
            patch.object(messaging, "s3") as s3,
            patch.object(messaging, "_record_messaging_attachment_download") as meter_download,
            patch.object(messaging, "audit_event"),
        ):
            s3.get_object.return_value = {"Body": _Body(), "ContentLength": 5}
            req = SimpleNamespace(headers={})
            resp = messaging.download_message_attachment("c1", "m1", req, x_request_id=None, user_id="u1")

            self.assertIsInstance(resp, StreamingResponse)
            chunks = asyncio.run(_collect_chunks(resp))
            self.assertEqual(chunks, [b"ab", b"cde"])

        meter_download.assert_called_once_with(
            user_id="u1",
            conversation_id="c1",
            message_id="m1",
            attachment_key="b/img/k.png",
            bytes_count=5,
            idempotency_operation_id=None,
        )

    def test_download_message_attachment_uses_request_id_for_idempotency_operation(self):
        class _Body:
            def iter_chunks(self, chunk_size=65536):
                yield b"data"

        async def _drain(resp):
            async for _ in resp.body_iterator:
                pass

        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(
                messaging,
                "_get_message_or_404",
                return_value={
                    "kind": "image",
                    "image": {"bucket": "b", "key": "img/k.png", "content_type": "image/png"},
                },
            ),
            patch.object(messaging, "s3") as s3,
            patch.object(messaging, "_record_messaging_attachment_download") as meter_download,
            patch.object(messaging, "audit_event"),
        ):
            s3.get_object.return_value = {"Body": _Body(), "ContentLength": 4}
            req = SimpleNamespace(headers={})
            resp = messaging.download_message_attachment("c1", "m1", req, x_request_id="req-xyz", user_id="u1")
            asyncio.run(_drain(resp))

        self.assertEqual(meter_download.call_args.kwargs["idempotency_operation_id"], "req-xyz")

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



    def test_fallback_search_messages_skips_encrypted_messages(self):
        tbl_msgs = Mock()
        tbl_msgs.query.return_value = {
            "Items": [
                {
                    "conversation_id": "c1",
                    "message_id": "m1",
                    "sender_id": "u1",
                    "created_at": 20,
                    "kind": "text",
                    "text": None,
                    "is_encrypted": True,
                    "encryption": {
                        "version": 1,
                        "alg": "AES-256-GCM",
                        "kdf": "PBKDF2-SHA256",
                        "iterations": 600000,
                        "salt_b64": "MTIzNDU2Nzg5MGFiY2RlZg==",
                        "iv_b64": "MTIzNDU2Nzg5MDEy",
                        "ciphertext_b64": "cGF5bG9hZC1ieXRlcy0xMjM0NTY=",
                    },
                }
            ]
        }
        with patch.object(messaging, "tbl_msgs", tbl_msgs):
            resp = messaging._fallback_search_messages("c1", "payload", limit=10, user_id="u1")
        self.assertEqual(resp, [])

    def test_search_messages_in_conversation_filters_encrypted_opensearch_hits(self):
        encrypted_item = {
            "conversation_id": "c1",
            "message_id": "m1",
            "sender_id": "u1",
            "created_at": 10,
            "kind": "text",
            "text": None,
            "is_encrypted": True,
            "encryption": {
                "version": 1,
                "alg": "AES-256-GCM",
                "kdf": "PBKDF2-SHA256",
                "iterations": 600000,
                "salt_b64": "MTIzNDU2Nzg5MGFiY2RlZg==",
                "iv_b64": "MTIzNDU2Nzg5MDEy",
                "ciphertext_b64": "cGF5bG9hZC1ieXRlcy0xMjM0NTY=",
            },
            "deleted_for": [],
            "reactions": {},
        }
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_opensearch_search_messages", return_value=["c1#m1"]),
            patch.object(messaging, "_fetch_message_items", return_value=[encrypted_item]),
            patch.object(messaging, "tbl_parts", Mock(query=Mock(return_value={"Items": []}))),
        ):
            resp = messaging.search_messages_in_conversation("c1", q="hello", limit=50, user_id="u1")
        self.assertEqual(resp, [])

    def test_edit_encrypted_message_is_rejected(self):
        encrypted_msg = {
            "conversation_id": "c1",
            "message_id": "m1",
            "sender_id": "u1",
            "created_at": 1,
            "kind": "text",
            "is_encrypted": True,
            "encryption": {
                "version": 1,
                "alg": "AES-256-GCM",
                "kdf": "PBKDF2-SHA256",
                "iterations": 600000,
                "salt_b64": "MTIzNDU2Nzg5MGFiY2RlZg==",
                "iv_b64": "MTIzNDU2Nzg5MDEy",
                "ciphertext_b64": "cGF5bG9hZC1ieXRlcy0xMjM0NTY=",
            },
        }
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_get_message_or_404", return_value=encrypted_msg),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.edit_message("c1", "m1", messaging.EditMessageIn(text="new"), user_id="u1")
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], messaging.ENCRYPTED_EDIT_ERROR_CODE)

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

    def test_list_conversations_includes_helpdesk_assignment_fields_for_agent_view(self):
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
                "routing_mode": "helpdesk_bridge",
                "routing_group_id": "helpdesk-l1",
                "routing_state": "assigned",
                "active_agent_user_id": "agent-1",
                "active_agent_claimed_at": 10,
                "assignment_version": 3,
            }
        }
        with (
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_convos", tbl_convos),
            patch.object(messaging, "_is_helpdesk_group_member", return_value=True),
        ):
            resp = messaging.list_conversations(user_id="agent-1")
        self.assertEqual(resp[0].routing_state, "assigned")
        self.assertEqual(resp[0].active_agent_user_id, "agent-1")
        self.assertEqual(resp[0].assignment_version, 3)

    def test_list_conversations_omits_helpdesk_assignment_fields_for_end_user(self):
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
                "routing_mode": "helpdesk_bridge",
                "routing_group_id": "helpdesk-l1",
                "routing_state": "assigned",
                "active_agent_user_id": "agent-1",
                "assignment_version": 3,
            }
        }
        with (
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_convos", tbl_convos),
            patch.object(messaging, "_is_helpdesk_group_member", return_value=False),
        ):
            resp = messaging.list_conversations(user_id="customer-1")
        self.assertIsNone(resp[0].routing_state)
        self.assertIsNone(resp[0].active_agent_user_id)
        self.assertIsNone(resp[0].assignment_version)

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
            patch.object(messaging, "_get_conversation_or_404", return_value={"routing_mode": "standard"}),
        ):
            resp = messaging.list_participants("c1", user_id="u1")
        self.assertEqual(len(resp), 2)
        self.assertEqual(resp[0].user_id, "u1")

    def test_list_participants_masks_helpdesk_identity_for_end_user_view(self):
        tbl_parts = Mock()
        tbl_parts.query.return_value = {
            "Items": [
                {"user_id": "customer-1", "status": "active", "role": "admin"},
                {"user_id": "helpdesk_group:helpdesk-l1", "status": "pending", "role": "member"},
            ]
        }
        with (
            patch.object(messaging, "get_participant_any", return_value={"status": "active", "user_id": "customer-1", "role": "admin"}),
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "_get_conversation_or_404", return_value={"routing_mode": "helpdesk_bridge", "routing_group_id": "helpdesk-l1", "routing_state": "awaiting_agent"}),
            patch.object(messaging, "_is_helpdesk_group_member", return_value=False),
        ):
            resp = messaging.list_participants("c1", user_id="customer-1")
        self.assertEqual([p.user_id for p in resp], ["customer-1", messaging.HELPDESK_MASKED_SENDER_ID])

    def test_list_participants_includes_assignment_metadata_for_helpdesk_agent_view(self):
        tbl_parts = Mock()
        tbl_parts.query.return_value = {
            "Items": [
                {"user_id": "customer-1", "status": "active", "role": "admin"},
                {"user_id": "helpdesk_group:helpdesk-l1", "status": "pending", "role": "member"},
                {"user_id": "agent-1", "status": "active", "role": "member"},
            ]
        }
        with (
            patch.object(messaging, "get_participant_any", return_value={"status": "active"}),
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(
                messaging,
                "_get_conversation_or_404",
                return_value={
                    "routing_mode": "helpdesk_bridge",
                    "routing_group_id": "helpdesk-l1",
                    "routing_state": "assigned",
                    "active_agent_user_id": "agent-1",
                },
            ),
            patch.object(messaging, "_is_helpdesk_group_member", return_value=True),
        ):
            resp = messaging.list_participants("c1", user_id="agent-1")
        owner = next(p for p in resp if p.user_id == "agent-1")
        other = next(p for p in resp if p.user_id == "customer-1")
        self.assertEqual(owner.assignment_state, "assigned")
        self.assertEqual(owner.assignment_owner_user_id, "agent-1")
        self.assertTrue(owner.is_assignment_owner)
        self.assertFalse(other.is_assignment_owner)

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



    def test_message_out_non_once_omits_consumption_fields(self):
        item = {
            "conversation_id": "c1",
            "message_id": "m1",
            "sender_id": "u2",
            "created_at": 10,
            "kind": "image",
            "image": {"bucket": "b", "key": "k"},
            "consumption_policy": "none",
            "media_kind": "image",
            "reactions": {},
        }
        with patch.object(messaging, "tbl_msg_consumption") as tbl:
            tbl.get_item.return_value = {}
            out = messaging._serialize_message_event_payload(item, "u1")

        self.assertNotIn("consumption_policy", out)
        self.assertNotIn("media_kind", out)
        self.assertNotIn("consumption_state", out)
        self.assertNotIn("consumed_at", out)

    def test_message_out_once_includes_recipient_consumption_state(self):
        item = {
            "conversation_id": "c1",
            "message_id": "m1",
            "sender_id": "u2",
            "created_at": 10,
            "kind": "video",
            "file": {"path": "/v.mp4", "content_type": "video/mp4"},
            "consumption_policy": "view_once",
            "media_kind": "video",
            "reactions": {},
        }
        with patch.object(messaging, "tbl_msg_consumption") as tbl:
            tbl.get_item.return_value = {
                "Item": {
                    "consumption_policy": "view_once",
                    "media_kind": "video",
                    "consumption_state": "pending",
                    "consumed_at": 0,
                }
            }
            out = messaging._serialize_message_event_payload(item, "u1")

        self.assertEqual(out["consumption_policy"], "view_once")
        self.assertEqual(out["media_kind"], "video")
        self.assertEqual(out["consumption_state"], "pending")
        self.assertNotIn("consumed_at", out)

    def test_list_messages_once_state_parity_with_event_serializer(self):
        tbl_parts = Mock()
        tbl_msgs = Mock()
        tbl_parts.get_item.return_value = {"Item": {"status": "active"}}
        msg_item = {
            "conversation_id": "c1",
            "message_id": "m1",
            "sender_id": "u2",
            "created_at": 10,
            "kind": "audio",
            "file": {"path": "/a.mp3", "content_type": "audio/mp3"},
            "consumption_policy": "listen_once",
            "media_kind": "audio",
            "reactions": {},
        }
        tbl_msgs.query.return_value = {"Items": [msg_item]}
        with (
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_msg_consumption") as tbl_consumption,
        ):
            tbl_consumption.get_item.return_value = {
                "Item": {
                    "consumption_policy": "listen_once",
                    "media_kind": "audio",
                    "consumption_state": "pending",
                    "consumed_at": 0,
                }
            }
            listed = messaging.list_messages("c1", user_id="u1")
            event_payload = messaging._serialize_message_event_payload(msg_item, "u1")

        self.assertEqual(listed[0].model_dump(exclude_none=True)["consumption_policy"], event_payload["consumption_policy"])
        self.assertEqual(listed[0].model_dump(exclude_none=True)["media_kind"], event_payload["media_kind"])
        self.assertEqual(listed[0].model_dump(exclude_none=True)["consumption_state"], event_payload["consumption_state"])

    def test_create_image_message_view_once_persists_recipient_consumption(self):
        tbl_msgs = Mock()
        tbl_convos = Mock()
        tbl_parts = Mock()
        tbl_parts.query.return_value = {"Items": [{"user_id": "u1"}, {"user_id": "u2"}]}
        tbl_consumption = Mock()
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_enforce_message_send_quota_precheck"),
            patch.object(messaging, "now_ts", return_value=10),
            patch.object(messaging, "new_id", return_value="img"),
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_convos", tbl_convos),
            patch.object(messaging, "tbl_msg_consumption", tbl_consumption),
            patch.object(messaging, "_meter_message_send"),
            patch.object(messaging, "_meter_messaging_attachment_upload"),
        ):
            resp = messaging.create_image_message(
                "c1",
                messaging.CreateImageMessageIn(bucket="b", key="k", consumption_policy="view_once"),
                user_id="u1",
            )

        self.assertEqual(resp.consumption_policy, "view_once")
        self.assertEqual(resp.media_kind, "image")
        self.assertEqual(resp.consumption_state, "pending")
        tbl_consumption.put_item.assert_called_once()

    def test_create_file_message_audio_listen_once_persists_recipient_consumption(self):
        tbl_msgs = Mock()
        tbl_convos = Mock()
        tbl_parts = Mock()
        tbl_parts.query.return_value = {"Items": [{"user_id": "u1"}, {"user_id": "u2"}]}
        tbl_consumption = Mock()
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_enforce_message_send_quota_precheck"),
            patch.object(messaging, "now_ts", return_value=10),
            patch.object(messaging, "new_id", return_value="file"),
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_convos", tbl_convos),
            patch.object(messaging, "tbl_msg_consumption", tbl_consumption),
            patch.object(
                messaging,
                "get_node",
                return_value={
                    "type": "file",
                    "path": "/a.mp3",
                    "name": "a.mp3",
                    "size": 1,
                    "content_type": "audio/mp3",
                },
            ),
            patch.object(messaging, "_meter_message_send"),
        ):
            resp = messaging.create_file_message(
                "c1",
                messaging.CreateFileMessageIn(path="/a.mp3", kind="audio", consumption_policy="listen_once"),
                user_id="u1",
            )

        self.assertEqual(resp.consumption_policy, "listen_once")
        self.assertEqual(resp.media_kind, "audio")
        self.assertEqual(resp.consumption_state, "pending")
        tbl_consumption.put_item.assert_called_once()

    def test_create_file_message_invalid_policy_for_kind_raises(self):
        with self.assertRaises(Exception):
            messaging.CreateFileMessageIn(path="/doc.pdf", kind="file", consumption_policy="view_once")


    def test_create_image_message_view_once_records_once_media_send_metric(self):
        tbl_parts = Mock()
        tbl_parts.query.return_value = {"Items": [{"user_id": "u1"}, {"user_id": "u2"}]}
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_enforce_message_send_quota_precheck"),
            patch.object(messaging, "now_ts", return_value=10),
            patch.object(messaging, "new_id", return_value="img"),
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_msgs"),
            patch.object(messaging, "tbl_convos"),
            patch.object(messaging, "tbl_msg_consumption"),
            patch.object(messaging, "_meter_message_send"),
            patch.object(messaging, "_meter_messaging_attachment_upload"),
            patch.object(messaging, "audit_event"),
            patch.object(messaging, "record_once_media_send") as record_send,
        ):
            messaging.create_image_message(
                "c1",
                messaging.CreateImageMessageIn(bucket="b", key="k", consumption_policy="view_once"),
                req=SimpleNamespace(headers={"x-once-media-cohort": "beta_a"}),
                user_id="u1",
            )

        record_send.assert_called_once_with(
            media_kind="image",
            consumption_policy="view_once",
            cohort="beta_a",
        )

    def test_create_once_media_attachment_grant_failure_records_metrics(self):
        msg = {
            "conversation_id": "c1",
            "message_id": "m1",
            "sender_id": "u2",
            "kind": "video",
            "consumption_policy": "view_once",
            "media_kind": "video",
        }
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_get_message_or_404", return_value=msg),
            patch.object(messaging, "tbl_msg_consumption") as tbl_consumption,
            patch.object(messaging, "record_once_media_grant") as record_grant,
            patch.object(messaging, "record_once_media_grant_latency") as record_latency,
        ):
            tbl_consumption.get_item.return_value = {"Item": {"consumption_state": "consumed"}}
            with self.assertRaises(HTTPException):
                messaging.create_once_media_attachment_grant(
                    "c1",
                    "m1",
                    SimpleNamespace(headers={"x-once-media-cohort": "rollout-1"}),
                    user_id="u1",
                )

        record_grant.assert_called_once_with(
            media_kind="video",
            outcome="error",
            reason="already_consumed",
            cohort="rollout-1",
        )
        record_latency.assert_called_once()

    def test_consume_once_media_attachment_conflict_records_conflict_metric(self):
        msg = {
            "conversation_id": "c1",
            "message_id": "m1",
            "sender_id": "u2",
            "kind": "video",
            "consumption_policy": "view_once",
            "media_kind": "video",
        }

        err = messaging.ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "failed"}},
            "UpdateItem",
        )

        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_get_message_or_404", return_value=msg),
            patch.object(messaging, "tbl_msg_consumption") as tbl_consumption,
            patch.object(messaging, "now_ts", return_value=100),
            patch.object(messaging, "record_once_media_consume") as record_consume,
            patch.object(messaging, "record_once_media_conflict") as record_conflict,
        ):
            tbl_consumption.update_item.side_effect = err
            tbl_consumption.get_item.side_effect = [
                {"Item": {"consumption_state": "pending"}},
                {
                    "Item": {
                        "consumption_state": "consumed",
                        "consumed_at": 101,
                        "last_consumption_attempt_id": "attempt-abc",
                    }
                },
            ]
            grant = messaging._encode_once_media_grant(
                conversation_id="c1", message_id="m1", recipient_id="u1", expires_at=200
            )
            with self.assertRaises(HTTPException):
                messaging.consume_once_media_attachment(
                    "c1",
                    "m1",
                    messaging.ConsumeAttachmentIn(consumption_attempt_id="attempt-xyz", trigger="play", playback_seconds=2.0),
                    SimpleNamespace(headers={"x-once-media-cohort": "rollout-1"}),
                    grant_token=grant,
                    user_id="u1",
                )

        record_consume.assert_called_once_with(
            media_kind="video",
            outcome="error",
            reason="already_consumed",
            cohort="rollout-1",
        )
        record_conflict.assert_called_once_with(media_kind="video", cohort="rollout-1")

    def test_consume_once_media_state_atomic_success_transition(self):
        with patch.object(messaging, "tbl_msg_consumption") as tbl_consumption:
            tbl_consumption.update_item.return_value = {
                "Attributes": {
                    "consumption_state": "consumed",
                    "consumed_at": 123,
                    "last_consumption_attempt_id": "attempt-1",
                }
            }
            tbl_consumption.get_item.return_value = {
                "Item": {
                    "consumption_state": "consumed",
                    "consumed_at": 123,
                    "last_consumption_attempt_id": "attempt-1",
                }
            }
            out = messaging._consume_once_media_state_atomic(
                conversation_id="c1",
                message_id="m1",
                recipient_id="u1",
                consumption_attempt_id="attempt-1",
                consumed_at=123,
            )

        self.assertEqual(out["consumption_state"], "consumed")
        self.assertEqual(out["consumed_at"], 123)
        self.assertTrue(out["idempotent_replay"])

    def test_consume_once_media_state_atomic_missing_state_raises_404(self):
        err = messaging.ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "failed"}},
            "UpdateItem",
        )
        with patch.object(messaging, "tbl_msg_consumption") as tbl_consumption:
            tbl_consumption.update_item.side_effect = err
            tbl_consumption.get_item.return_value = {}
            with self.assertRaises(HTTPException) as ctx:
                messaging._consume_once_media_state_atomic(
                    conversation_id="c1",
                    message_id="m1",
                    recipient_id="u1",
                    consumption_attempt_id="attempt-1",
                    consumed_at=123,
                )

        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(ctx.exception.detail["code"], "consumption_state_missing")


    def test_group_video_view_once_creates_per_recipient_consumption_rows(self):
        tbl_parts = Mock()
        tbl_parts.query.return_value = {"Items": [{"user_id": "u1"}, {"user_id": "u2"}, {"user_id": "u3"}]}
        tbl_consumption = Mock()
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_enforce_message_send_quota_precheck"),
            patch.object(messaging, "now_ts", return_value=10),
            patch.object(messaging, "new_id", return_value="v1"),
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_msgs"),
            patch.object(messaging, "tbl_convos"),
            patch.object(messaging, "tbl_msg_consumption", tbl_consumption),
            patch.object(messaging, "get_node", return_value={"type": "file", "path": "/a.mp4", "name": "a.mp4", "size": 1, "content_type": "video/mp4"}),
            patch.object(messaging, "_meter_message_send"),
            patch.object(messaging, "audit_event"),
            patch.object(messaging, "require_subscription_access"),
        ):
            resp = messaging.create_file_message(
                "c1",
                messaging.CreateFileMessageIn(path="/a.mp4", kind="video", consumption_policy="view_once"),
                user_id="u1",
            )

        self.assertEqual(resp.consumption_policy, "view_once")
        self.assertEqual(resp.media_kind, "video")
        self.assertEqual(tbl_consumption.put_item.call_count, 2)

    def test_create_file_message_without_once_policy_does_not_create_consumption_rows(self):
        tbl_parts = Mock()
        tbl_parts.query.return_value = {"Items": [{"user_id": "u1"}, {"user_id": "u2"}]}
        tbl_consumption = Mock()
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_enforce_message_send_quota_precheck"),
            patch.object(messaging, "now_ts", return_value=10),
            patch.object(messaging, "new_id", return_value="f1"),
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_msgs"),
            patch.object(messaging, "tbl_convos"),
            patch.object(messaging, "tbl_msg_consumption", tbl_consumption),
            patch.object(messaging, "get_node", return_value={"type": "file", "path": "/doc.pdf", "name": "doc.pdf", "size": 1, "content_type": "application/pdf"}),
            patch.object(messaging, "_meter_message_send"),
            patch.object(messaging, "audit_event"),
            patch.object(messaging, "require_subscription_access"),
        ):
            resp = messaging.create_file_message(
                "c1",
                messaging.CreateFileMessageIn(path="/doc.pdf", kind="file", consumption_policy="none"),
                user_id="u1",
            )

        self.assertIsNone(resp.consumption_policy)
        self.assertIsNone(resp.media_kind)
        self.assertIsNone(resp.consumption_state)
        tbl_consumption.put_item.assert_not_called()

    def test_consume_once_audio_interrupted_then_retry_succeeds(self):
        msg = {
            "conversation_id": "c1",
            "message_id": "m1",
            "sender_id": "u2",
            "kind": "audio",
            "consumption_policy": "listen_once",
            "media_kind": "audio",
        }
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_get_message_or_404", return_value=msg),
            patch.object(messaging, "tbl_msg_consumption") as tbl_consumption,
            patch.object(messaging, "now_ts", return_value=100),
            patch.object(messaging, "audit_event"),
        ):
            tbl_consumption.get_item.side_effect = [
                {"Item": {"consumption_state": "pending"}},
                {"Item": {"consumption_state": "pending"}},
                {"Item": {"consumption_state": "consumed", "consumed_at": 101, "last_consumption_attempt_id": "attempt-1"}},
            ]
            grant = messaging._encode_once_media_grant(conversation_id="c1", message_id="m1", recipient_id="u1", expires_at=200)

            with self.assertRaises(HTTPException) as first:
                messaging.consume_once_media_attachment(
                    "c1",
                    "m1",
                    messaging.ConsumeAttachmentIn(consumption_attempt_id="attempt-1", trigger="play", playback_seconds=0.1),
                    SimpleNamespace(headers={}),
                    grant_token=grant,
                    user_id="u1",
                )
            self.assertEqual(first.exception.detail["code"], "consume_threshold_not_met")

            out = messaging.consume_once_media_attachment(
                "c1",
                "m1",
                messaging.ConsumeAttachmentIn(consumption_attempt_id="attempt-1", trigger="play", playback_seconds=2.0),
                SimpleNamespace(headers={}),
                grant_token=grant,
                user_id="u1",
            )

        self.assertTrue(out.ok)
        self.assertEqual(out.consumption_state, "consumed")


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

    def test_revoke_encrypted_message_for_all_supported(self):
        tbl_msgs = Mock()
        encrypted_msg = {
            "conversation_id": "c1",
            "message_id": "m1",
            "sender_id": "u1",
            "created_at": 1,
            "kind": "text",
            "is_encrypted": True,
            "encryption": {
                "version": 1,
                "alg": "AES-256-GCM",
                "kdf": "PBKDF2-SHA256",
                "iterations": 600000,
                "salt_b64": "MTIzNDU2Nzg5MGFiY2RlZg==",
                "iv_b64": "MTIzNDU2Nzg5MDEy",
                "ciphertext_b64": "cGF5bG9hZC1ieXRlcy0xMjM0NTY=",
            },
        }
        revoked_msg = {**encrypted_msg, "revoked_at": 10, "revoked_by": "u1"}
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_ensure_can_revoke_message"),
            patch.object(messaging, "_get_message_or_404", side_effect=[encrypted_msg, revoked_msg]),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "fanout_event_to_conversation") as fanout,
            patch.object(messaging, "now_ts", return_value=10),
            patch.object(messaging, "remove_message_search") as remove_search,
            patch.object(messaging, "_reaction_summaries", return_value=({}, [])),
        ):
            resp = messaging.revoke_message_for_all("c1", "m1", user_id="u1")

        tbl_msgs.update_item.assert_called_once()
        fanout.assert_called_once()
        self.assertEqual(fanout.call_args.kwargs["event_type"], "message:revoked")
        remove_search.assert_called_once_with("c1", "m1", "")
        self.assertTrue(resp.is_encrypted)
        self.assertEqual(resp.revoked_by, "u1")

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
            patch.object(messaging, "fanout_event_to_conversation") as fanout,
        ):
            resp = messaging.forward_message(
                "c2",
                messaging.ForwardMessageIn(source_conversation_id="c1", source_message_id="m1"),
                user_id="u1",
            )
        self.assertEqual(resp.message_id, "m_fwd")
        self.assertEqual(resp.text, "hello")
        self.assertFalse(resp.is_encrypted)
        tbl_msgs.put_item.assert_called_once()
        fanout.assert_called_once()
        payload = fanout.call_args.kwargs["payload"]
        self.assertEqual(payload["message"]["message_id"], "m_fwd")

    def test_forward_encrypted_message_preserves_encryption_fields(self):
        tbl_msgs = Mock()
        tbl_convos = Mock()
        source = {
            "conversation_id": "c1",
            "message_id": "m1",
            "sender_id": "u2",
            "created_at": 1,
            "kind": "text",
            "text": None,
            "is_encrypted": True,
            "encryption": {
                "version": 1,
                "alg": "AES-256-GCM",
                "kdf": "PBKDF2-SHA256",
                "iterations": 600000,
                "salt_b64": "MTIzNDU2Nzg5MGFiY2RlZg==",
                "iv_b64": "MTIzNDU2Nzg5MDEy",
                "ciphertext_b64": "cGF5bG9hZC1ieXRlcy0xMjM0NTY=",
            },
        }
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "now_ts", return_value=10),
            patch.object(messaging, "new_id", return_value="fwd"),
            patch.object(messaging, "_get_message_or_404", return_value=source),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_convos", tbl_convos),
            patch.object(messaging, "index_message_search") as index_search,
            patch.object(messaging, "fanout_event_to_conversation") as fanout,
        ):
            resp = messaging.forward_message(
                "c2",
                messaging.ForwardMessageIn(source_conversation_id="c1", source_message_id="m1"),
                user_id="u1",
            )

        self.assertTrue(resp.is_encrypted)
        self.assertIsNotNone(resp.encryption)
        self.assertIsNone(resp.text)
        index_search.assert_not_called()
        item = tbl_msgs.put_item.call_args.kwargs["Item"]
        self.assertTrue(item["is_encrypted"])
        self.assertIn("encryption", item)
        payload = fanout.call_args.kwargs["payload"]
        self.assertTrue(payload["message"]["is_encrypted"])

    def test_mark_message_viewed(self):
        tbl_views = Mock()
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(
                messaging,
                "_get_message_or_404",
                return_value={"message_id": "m1", "sender_id": "other-user", "kind": "text"},
            ),
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
            patch.object(messaging, "_handle_helpdesk_presence_event", return_value={"action": "observe_available", "processed": 0, "transitioned": 0, "failed": 0}),
            patch.object(messaging, "audit_event"),
            patch.object(messaging, "now_ts", return_value=10),
        ):
            resp = messaging.presence_heartbeat(messaging.PresenceHeartbeatIn(), user_id="u1")
        self.assertTrue(resp["ok"])
        self.assertEqual(resp["status"], "online")
        tbl_presence.put_item.assert_called_once()

    def test_handle_helpdesk_presence_event_releases_assigned_conversations(self):
        convo = {
            "conversation_id": "c1",
            "routing_group_id": "helpdesk-l1",
            "assignment_version": 4,
        }
        with (
            patch.object(messaging, "_assigned_helpdesk_conversations_for_agent", return_value=[convo]),
            patch.object(
                messaging,
                "_apply_helpdesk_routing_transition",
                side_effect=[
                    {"conversation": {"routing_group_id": "helpdesk-l1", "assignment_version": 5}},
                    {"conversation": {"routing_group_id": "helpdesk-l1", "assignment_version": 5}},
                ],
            ) as apply_transition,
            patch.object(messaging, "fanout_helpdesk_alert", return_value=1),
            patch.object(messaging, "_emit_no_agents_online_notice") as emit_notice,
        ):
            out = messaging._handle_helpdesk_presence_event(user_id="agent-1", status="offline", ts=100)

        self.assertEqual(out["processed"], 1)
        self.assertEqual(out["transitioned"], 1)
        self.assertEqual(apply_transition.call_count, 2)
        self.assertEqual(apply_transition.call_args_list[0].kwargs["cmd"].action, "release_agent")
        self.assertEqual(apply_transition.call_args_list[1].kwargs["cmd"].action, "alert_awaiting")
        emit_notice.assert_not_called()

    def test_handle_helpdesk_presence_event_emits_notice_when_no_agents_online_after_release(self):
        convo = {
            "conversation_id": "c1",
            "routing_group_id": "helpdesk-l1",
            "assignment_version": 2,
        }
        with (
            patch.object(messaging, "_assigned_helpdesk_conversations_for_agent", return_value=[convo]),
            patch.object(messaging, "_apply_helpdesk_routing_transition"),
            patch.object(messaging, "fanout_helpdesk_alert", return_value=0),
            patch.object(messaging, "_emit_no_agents_online_notice") as emit_notice,
            patch.object(messaging, "record_helpdesk_failover") as rec_failover,
        ):
            out = messaging._handle_helpdesk_presence_event(user_id="agent-1", status="unavailable", ts=100)

        self.assertEqual(out["transitioned"], 1)
        emit_notice.assert_called_once_with(conversation_id="c1", user_id="agent-1", now=100)
        rec_failover.assert_called_once_with("assignee_disconnect")

    def test_handle_helpdesk_presence_event_resumes_paused_conversations_when_agent_returns_online(self):
        paused = {
            "conversation_id": "c1",
            "routing_group_id": "helpdesk-l1",
            "assignment_version": 7,
        }
        with (
            patch.object(messaging, "_helpdesk_groups_for_agent", return_value=["helpdesk-l1"]),
            patch.object(messaging, "_paused_helpdesk_conversations_for_groups", return_value=[paused]),
            patch.object(messaging, "_apply_helpdesk_routing_transition") as apply_transition,
            patch.object(messaging, "fanout_helpdesk_alert") as fanout,
        ):
            out = messaging._handle_helpdesk_presence_event(user_id="agent-1", status="online", ts=200)

        self.assertEqual(out["action"], "resume_paused")
        self.assertEqual(out["processed"], 1)
        self.assertEqual(out["transitioned"], 1)
        self.assertEqual(apply_transition.call_args.kwargs["cmd"].action, "resume_awaiting")
        fanout.assert_called_once_with(conversation_id="c1", group_id="helpdesk-l1", created_by="agent-1")

    def test_handle_helpdesk_presence_event_resume_is_retry_safe(self):
        paused = {
            "conversation_id": "c1",
            "routing_group_id": "helpdesk-l1",
            "assignment_version": 7,
        }
        with (
            patch.object(messaging, "_helpdesk_groups_for_agent", return_value=["helpdesk-l1"]),
            patch.object(messaging, "_paused_helpdesk_conversations_for_groups", return_value=[paused]),
            patch.object(
                messaging,
                "_apply_helpdesk_routing_transition",
                side_effect=messaging.RoutingTransitionError(code="routing_assignment_version_conflict", message="stale"),
            ),
            patch.object(messaging, "fanout_helpdesk_alert") as fanout,
        ):
            out = messaging._handle_helpdesk_presence_event(user_id="agent-1", status="available", ts=200)

        self.assertEqual(out["processed"], 1)
        self.assertEqual(out["transitioned"], 0)
        self.assertEqual(out["failed"], 0)
        fanout.assert_not_called()

    def test_integration_helpdesk_create_alert_claim_release_no_agent_flow(self):
        # Integration-style flow: create -> alert -> claim -> release -> no-agent pause/notice
        convo = {
            "conversation_id": "c1",
            "routing_group_id": "helpdesk-l1",
            "assignment_version": 2,
            "routing_state": "assigned",
            "active_agent_user_id": "agent-1",
        }
        with (
            patch.object(messaging, "_assigned_helpdesk_conversations_for_agent", return_value=[convo]),
            patch.object(
                messaging,
                "_apply_helpdesk_routing_transition",
                side_effect=[
                    {"conversation": {"conversation_id": "c1", "routing_group_id": "helpdesk-l1", "assignment_version": 3}},
                ],
            ) as apply_transition,
            patch.object(messaging, "fanout_helpdesk_alert", return_value=0) as fanout,
            patch.object(messaging, "_emit_no_agents_online_notice", return_value=True) as emit_notice,
        ):
            out = messaging._handle_helpdesk_presence_event(user_id="agent-1", status="offline", ts=300)

        self.assertEqual(out["processed"], 1)
        self.assertEqual(out["transitioned"], 1)
        self.assertEqual(apply_transition.call_args.kwargs["cmd"].action, "release_agent")
        fanout.assert_called_once_with(conversation_id="c1", group_id="helpdesk-l1", created_by="agent-1")
        emit_notice.assert_called_once_with(conversation_id="c1", user_id="agent-1", now=300)

    def test_handle_helpdesk_presence_event_is_retry_safe_on_transition_conflict(self):
        convo = {
            "conversation_id": "c1",
            "routing_group_id": "helpdesk-l1",
            "assignment_version": 2,
        }
        with (
            patch.object(messaging, "_assigned_helpdesk_conversations_for_agent", return_value=[convo]),
            patch.object(
                messaging,
                "_apply_helpdesk_routing_transition",
                side_effect=messaging.RoutingTransitionError(code="routing_assignment_version_conflict", message="stale"),
            ),
            patch.object(messaging, "fanout_helpdesk_alert") as fanout,
        ):
            out = messaging._handle_helpdesk_presence_event(user_id="agent-1", status="offline", ts=100)

        self.assertEqual(out["processed"], 1)
        self.assertEqual(out["transitioned"], 0)
        self.assertEqual(out["failed"], 0)
        fanout.assert_not_called()

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

    def test_mark_read_legacy_message_id_resolves_timestamp(self):
        tbl_parts = Mock()
        tbl_msgs = Mock()
        tbl_msgs.get_item.return_value = {
            "Item": {
                "conversation_id": "c1",
                "message_id": "m1",
                "created_at": 77,
            }
        }
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "get_participant_any", return_value={"last_read_at": 5}),
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
        ):
            resp = messaging.mark_read(
                "c1",
                messaging.MarkReadIn(last_read_message_id="m1"),
                user_id="u1",
            )
        self.assertEqual(resp["last_read_at"], 77)
        tbl_parts.update_item.assert_called_once()

    def test_mark_read_legacy_message_id_not_found_returns_422(self):
        tbl_msgs = Mock()
        tbl_msgs.get_item.return_value = {}
        with (
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.mark_read(
                    "c1",
                    messaging.MarkReadIn(last_read_message_id="missing"),
                    user_id="u1",
                )
        self.assertEqual(ctx.exception.status_code, 422)

    def test_mute_conversation_legacy_true_converts_to_window(self):
        tbl_parts = Mock()
        with (
            patch.object(messaging, "get_participant_any", return_value={"status": "active"}),
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "now_ts", return_value=100),
            patch.dict("os.environ", {"LEGACY_MUTE_DEFAULT_WINDOW_SEC": "3600"}, clear=False),
        ):
            resp = messaging.mute_conversation("c1", messaging.MuteIn(muted=True), user_id="u1")
        self.assertEqual(resp["muted_until"], 3700)
        tbl_parts.update_item.assert_called_once()

    def test_mute_conversation_legacy_false_converts_to_zero(self):
        tbl_parts = Mock()
        with (
            patch.object(messaging, "get_participant_any", return_value={"status": "active"}),
            patch.object(messaging, "tbl_parts", tbl_parts),
        ):
            resp = messaging.mute_conversation("c1", messaging.MuteIn(muted=False), user_id="u1")
        self.assertEqual(resp["muted_until"], 0)
        tbl_parts.update_item.assert_called_once()


    def test_list_conversation_routing_events_returns_items(self):
        tbl_events = Mock()
        tbl_events.query.return_value = {
            "Items": [
                {
                    "conversation_id": "c1",
                    "event_id": "00001#e1",
                    "event_type": "helpdesk.conversation.assigned",
                    "actor_user_id": "agent-1",
                    "from_state": "awaiting_agent",
                    "to_state": "assigned",
                    "created_at": 1,
                    "assignment_version": 1,
                    "routing_group_id": "helpdesk-l1",
                    "active_agent_user_id": "agent-1",
                    "metadata": {"source": "claim"},
                }
            ]
        }
        with (
            patch.object(messaging, "require_participant_role"),
            patch.object(messaging, "tbl_routing_events", tbl_events),
        ):
            out = messaging.list_conversation_routing_events("c1", user_id="u1")

        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].event_type, "helpdesk.conversation.assigned")
        self.assertEqual(out[0].metadata["source"], "claim")

    def test_apply_helpdesk_routing_transition_writes_event(self):
        tbl_convos = Mock()
        tbl_routing_events = Mock()
        tbl_user_events = Mock()
        tbl_parts = Mock()
        tbl_convos.get_item.return_value = {
            "Item": {
                "conversation_id": "c1",
                "routing_mode": "helpdesk_bridge",
                "routing_group_id": "helpdesk-l1",
                "routing_state": "awaiting_agent",
                "assignment_version": 0,
            }
        }
        tbl_parts.query.return_value = {"Items": [{"user_id": "u1", "status": "active"}]}
        with (
            patch.object(messaging, "tbl_convos", tbl_convos),
            patch.object(messaging, "tbl_routing_events", tbl_routing_events),
            patch.object(messaging, "tbl_events", tbl_user_events),
            patch.object(messaging, "tbl_parts", tbl_parts),
            patch.object(messaging, "new_id", return_value="evt1"),
        ):
            result = messaging._apply_helpdesk_routing_transition(
                conversation_id="c1",
                cmd=messaging.RoutingTransitionInput(action="assign_agent", now_ts=10, agent_user_id="a1"),
                actor_user_id="a1",
                metadata={"reason": "claim"},
            )

        tbl_convos.update_item.assert_called_once()
        tbl_routing_events.put_item.assert_called_once()
        self.assertGreaterEqual(tbl_user_events.put_item.call_count, 1)
        payload = tbl_user_events.put_item.call_args.kwargs["Item"]["payload"]
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["event_type"], "helpdesk.conversation.assigned")
        self.assertIn("assignment_version", payload)
        self.assertEqual(result["event"]["event_type"], "helpdesk.conversation.assigned")
        self.assertEqual(result["event"]["metadata"]["reason"], "claim")


    def test_project_helpdesk_lifecycle_payload_masks_for_end_user(self):
        payload = {
            "schema_version": 1,
            "conversation_id": "c1",
            "event_id": "e1",
            "event_type": "helpdesk.conversation.assigned",
            "occurred_at": 10,
            "routing_group_id": "helpdesk-l1",
            "from_state": "awaiting_agent",
            "to_state": "assigned",
            "routing_state": "assigned",
            "assignment_version": 2,
            "active_agent_user_id": "agent-1",
            "metadata": {"reason": "claim", "actor": "agent-1"},
        }
        with patch.object(messaging, "_is_helpdesk_group_member", return_value=False):
            out = messaging._project_helpdesk_lifecycle_payload_for_user(
                payload=payload,
                conversation={"routing_mode": "helpdesk_bridge", "routing_group_id": "helpdesk-l1"},
                user_id="customer-1",
            )
        self.assertEqual(out["active_agent_user_id"], "")
        self.assertEqual(out["metadata"], {})

    def test_project_helpdesk_lifecycle_payload_retains_for_helpdesk_agent(self):
        payload = {
            "schema_version": 1,
            "conversation_id": "c1",
            "event_id": "e1",
            "event_type": "helpdesk.conversation.assigned",
            "occurred_at": 10,
            "routing_group_id": "helpdesk-l1",
            "from_state": "awaiting_agent",
            "to_state": "assigned",
            "routing_state": "assigned",
            "assignment_version": 2,
            "active_agent_user_id": "agent-1",
            "metadata": {"reason": "claim"},
        }
        with patch.object(messaging, "_is_helpdesk_group_member", return_value=True):
            out = messaging._project_helpdesk_lifecycle_payload_for_user(
                payload=payload,
                conversation={"routing_mode": "helpdesk_bridge", "routing_group_id": "helpdesk-l1"},
                user_id="agent-2",
            )
        self.assertEqual(out["active_agent_user_id"], "agent-1")
        self.assertEqual(out["metadata"], {"reason": "claim"})

    def test_project_event_for_user_masks_lifecycle_event_for_end_user(self):
        event = {
            "type": "helpdesk.conversation.assigned",
            "conversation_id": "c1",
            "payload": {
                "schema_version": 1,
                "conversation_id": "c1",
                "event_id": "e1",
                "event_type": "helpdesk.conversation.assigned",
                "occurred_at": 10,
                "routing_group_id": "helpdesk-l1",
                "from_state": "awaiting_agent",
                "to_state": "assigned",
                "routing_state": "assigned",
                "assignment_version": 2,
                "active_agent_user_id": "agent-1",
                "metadata": {"reason": "claim"},
            },
        }
        with (
            patch.object(messaging, "_get_conversation_or_404", return_value={"routing_mode": "helpdesk_bridge", "routing_group_id": "helpdesk-l1"}),
            patch.object(messaging, "_is_helpdesk_group_member", return_value=False),
        ):
            out = messaging._project_event_for_user(event, "customer-1")
        self.assertEqual(out["payload"]["active_agent_user_id"], "")

    def test_helpdesk_lifecycle_event_payload_contract(self):
        payload = messaging._helpdesk_lifecycle_event_payload(
            conversation={
                "conversation_id": "c1",
                "routing_group_id": "helpdesk-l1",
                "routing_state": "awaiting_agent",
                "assignment_version": 3,
                "active_agent_user_id": "",
            },
            event_item={
                "event_id": "0001#evt",
                "event_type": "helpdesk.conversation.alerted",
                "created_at": 10,
                "from_state": "awaiting_agent",
                "to_state": "awaiting_agent",
            },
        )
        required = {
            "schema_version",
            "conversation_id",
            "event_id",
            "event_type",
            "occurred_at",
            "routing_group_id",
            "from_state",
            "to_state",
            "routing_state",
            "assignment_version",
            "active_agent_user_id",
            "metadata",
        }
        self.assertEqual(required, set(payload.keys()))

    def test_fanout_helpdesk_alert_targets_online_group_members(self):
        tbl_events = Mock()
        ddb = Mock()
        ddb.meta.client.batch_get_item.return_value = {
            "Responses": {
                messaging.DDB_PRESENCE: [
                    {"user_id": "a1", "last_seen_at": 100, "status": "online"},
                    {"user_id": "a2", "last_seen_at": 20, "status": "online"},
                    {"user_id": "a3", "last_seen_at": 100, "status": "offline"},
                ]
            }
        }
        with (
            patch.object(messaging, "_resolve_helpdesk_group_members", return_value=["a1", "a2", "a3"]),
            patch.object(messaging, "tbl_events", tbl_events),
            patch.object(messaging, "ddb", ddb),
            patch.object(messaging, "now_ts", return_value=110),
            patch.object(messaging, "record_helpdesk_alert_sent") as rec_metric,
        ):
            delivered = messaging.fanout_helpdesk_alert("c1", "helpdesk-l1", "u1")

        self.assertEqual(delivered, 1)
        tbl_events.put_item.assert_called_once()
        payload = tbl_events.put_item.call_args.kwargs["Item"]["payload"]
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["event_type"], "helpdesk.conversation.alerted")
        self.assertIn("assignment_version", payload)
        rec_metric.assert_called_once_with("delivered")

    def test_start_conversation_helpdesk_fanout_called(self):
        with (
            patch.object(messaging, "now_ts", return_value=123),
            patch.object(messaging, "new_id", return_value="abc"),
            patch.object(messaging, "tbl_convos") as tbl_convos,
            patch.object(messaging, "tbl_parts") as tbl_parts,
            patch.object(messaging, "fanout_helpdesk_alert") as fanout,
        ):
            messaging.start_conversation(
                messaging.StartConversationIn(
                    participant_ids=[],
                    type="dm",
                    routing_mode="helpdesk_bridge",
                    helpdesk_group_id="helpdesk-l1",
                ),
                user_id="user-1",
            )

        tbl_convos.put_item.assert_called_once()
        self.assertEqual(tbl_parts.put_item.call_count, 2)
        fanout.assert_called_once_with(conversation_id="c_abc", group_id="helpdesk-l1", created_by="user-1")


    def test_start_conversation_helpdesk_no_agents_emits_notice(self):
        with (
            patch.object(messaging, "now_ts", return_value=123),
            patch.object(messaging, "new_id", return_value="abc"),
            patch.object(messaging, "tbl_convos") as tbl_convos,
            patch.object(messaging, "tbl_parts") as tbl_parts,
            patch.object(messaging, "fanout_helpdesk_alert", return_value=0),
            patch.object(messaging, "_emit_no_agents_online_notice") as emit_notice,
        ):
            messaging.start_conversation(
                messaging.StartConversationIn(
                    participant_ids=[],
                    type="dm",
                    routing_mode="helpdesk_bridge",
                    helpdesk_group_id="helpdesk-l1",
                ),
                user_id="user-1",
            )

        tbl_convos.put_item.assert_called_once()
        self.assertEqual(tbl_parts.put_item.call_count, 2)
        emit_notice.assert_called_once_with(conversation_id="c_abc", user_id="user-1", now=123)

    def test_emit_no_agents_online_notice_throttled(self):
        with (
            patch.object(messaging, "_get_conversation_or_404", return_value={"no_agents_notice_sent_at": 100}),
            patch.object(messaging, "NO_AGENTS_NOTICE_THROTTLE_SEC", 600),
        ):
            out = messaging._emit_no_agents_online_notice(conversation_id="c1", user_id="u1", now=200)
        self.assertFalse(out)

    def test_emit_no_agents_online_notice_records_throttled_metric(self):
        with (
            patch.object(messaging, "_get_conversation_or_404", return_value={"no_agents_notice_sent_at": 100}),
            patch.object(messaging, "NO_AGENTS_NOTICE_THROTTLE_SEC", 600),
            patch.object(messaging, "record_helpdesk_no_agents_notice") as rec_metric,
        ):
            out = messaging._emit_no_agents_online_notice(conversation_id="c1", user_id="u1", now=200)
        self.assertFalse(out)
        rec_metric.assert_called_once_with("throttled")

    def test_emit_no_agents_online_notice_writes_message_and_updates_convo(self):
        tbl_msgs = Mock()
        tbl_convos = Mock()
        with (
            patch.object(messaging, "_get_conversation_or_404", return_value={"no_agents_notice_sent_at": 0}),
            patch.object(messaging, "_apply_helpdesk_routing_transition"),
            patch.object(messaging, "tbl_msgs", tbl_msgs),
            patch.object(messaging, "tbl_convos", tbl_convos),
        ):
            out = messaging._emit_no_agents_online_notice(conversation_id="c1", user_id="u1", now=200)

        self.assertTrue(out)
        tbl_msgs.put_item.assert_called_once()
        tbl_convos.update_item.assert_called_once()


    def test_claim_helpdesk_conversation_success(self):
        with (
            patch.object(messaging, "_get_conversation_or_404", return_value={
                "conversation_id": "c1",
                "routing_mode": "helpdesk_bridge",
                "routing_group_id": "helpdesk-l1",
                "routing_state": "awaiting_agent",
                "assignment_version": 2,
                "created_at": 1,
            }),
            patch.object(messaging, "_is_helpdesk_group_member", return_value=True),
            patch.object(messaging, "_is_user_online_available", return_value=True),
            patch.object(messaging, "now_ts", return_value=50),
            patch.object(messaging, "_apply_helpdesk_routing_transition", return_value={
                "conversation": {"routing_state": "assigned", "active_agent_user_id": "a1", "assignment_version": 3}
            }),
            patch.object(messaging, "audit_event"),
            patch.object(messaging, "record_helpdesk_claim") as record_claim,
            patch.object(messaging, "record_helpdesk_claim_success") as claim_success,
            patch.object(messaging, "record_helpdesk_time_to_first_claim_ms") as claim_latency,
        ):
            out = messaging.claim_helpdesk_conversation("c1", user_id="a1")

        self.assertTrue(out.ok)
        self.assertEqual(out.state, "assigned")
        self.assertEqual(out.assigned_agent_user_id, "a1")
        self.assertEqual(out.assignment_version, 3)
        record_claim.assert_called_once_with("success")
        claim_success.assert_called_once()
        claim_latency.assert_called_once_with(49000.0)

    def test_claim_helpdesk_conversation_rejects_non_member(self):
        with (
            patch.object(messaging, "_get_conversation_or_404", return_value={
                "conversation_id": "c1",
                "routing_mode": "helpdesk_bridge",
                "routing_group_id": "helpdesk-l1",
                "routing_state": "awaiting_agent",
                "assignment_version": 0,
            }),
            patch.object(messaging, "_is_helpdesk_group_member", return_value=False),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.claim_helpdesk_conversation("c1", user_id="a1")
        self.assertEqual(ctx.exception.status_code, 403)

    def test_claim_helpdesk_conversation_rejects_unavailable(self):
        with (
            patch.object(messaging, "_get_conversation_or_404", return_value={
                "conversation_id": "c1",
                "routing_mode": "helpdesk_bridge",
                "routing_group_id": "helpdesk-l1",
                "routing_state": "awaiting_agent",
                "assignment_version": 0,
            }),
            patch.object(messaging, "_is_helpdesk_group_member", return_value=True),
            patch.object(messaging, "now_ts", return_value=50),
            patch.object(messaging, "_is_user_online_available", return_value=False),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.claim_helpdesk_conversation("c1", user_id="a1")
        self.assertEqual(ctx.exception.status_code, 403)

    def test_claim_helpdesk_conversation_conflict_when_assigned_to_other(self):
        with (
            patch.object(messaging, "_get_conversation_or_404", return_value={
                "conversation_id": "c1",
                "routing_mode": "helpdesk_bridge",
                "routing_group_id": "helpdesk-l1",
                "routing_state": "assigned",
                "active_agent_user_id": "a2",
                "assignment_version": 4,
            }),
            patch.object(messaging, "_is_helpdesk_group_member", return_value=True),
            patch.object(messaging, "now_ts", return_value=50),
            patch.object(messaging, "_is_user_online_available", return_value=True),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.claim_helpdesk_conversation("c1", user_id="a1")
        self.assertEqual(ctx.exception.status_code, 409)

    def test_claim_helpdesk_conversation_idempotent_for_same_agent(self):
        with (
            patch.object(messaging, "_get_conversation_or_404", return_value={
                "conversation_id": "c1",
                "routing_mode": "helpdesk_bridge",
                "routing_group_id": "helpdesk-l1",
                "routing_state": "assigned",
                "active_agent_user_id": "a1",
                "assignment_version": 4,
            }),
            patch.object(messaging, "_is_helpdesk_group_member", return_value=True),
            patch.object(messaging, "now_ts", return_value=50),
            patch.object(messaging, "_is_user_online_available", return_value=True),
            patch.object(messaging, "record_helpdesk_claim") as record_claim,
        ):
            out = messaging.claim_helpdesk_conversation("c1", user_id="a1")
        self.assertTrue(out.idempotent)
        self.assertEqual(out.assignment_version, 4)
        record_claim.assert_called_once_with("idempotent")

    def test_claim_helpdesk_conversation_cas_conflict_returns_idempotent_for_winner_retry(self):
        with (
            patch.object(
                messaging,
                "_get_conversation_or_404",
                side_effect=[
                    {
                        "conversation_id": "c1",
                        "routing_mode": "helpdesk_bridge",
                        "routing_group_id": "helpdesk-l1",
                        "routing_state": "awaiting_agent",
                        "assignment_version": 2,
                    },
                    {
                        "conversation_id": "c1",
                        "routing_mode": "helpdesk_bridge",
                        "routing_group_id": "helpdesk-l1",
                        "routing_state": "assigned",
                        "active_agent_user_id": "a1",
                        "assignment_version": 3,
                    },
                ],
            ),
            patch.object(messaging, "_is_helpdesk_group_member", return_value=True),
            patch.object(messaging, "_is_user_online_available", return_value=True),
            patch.object(messaging, "now_ts", return_value=50),
            patch.object(messaging, "_apply_helpdesk_routing_transition", side_effect=messaging.RoutingTransitionError(code="routing_assignment_version_conflict", message="stale")),
            patch.object(messaging, "record_helpdesk_claim") as record_claim,
        ):
            out = messaging.claim_helpdesk_conversation("c1", user_id="a1")

        self.assertTrue(out.ok)
        self.assertTrue(out.idempotent)
        self.assertEqual(out.assignment_version, 3)
        record_claim.assert_called_once_with("idempotent")

    def test_claim_helpdesk_conversation_cas_conflict_records_conflict_metric(self):
        with (
            patch.object(
                messaging,
                "_get_conversation_or_404",
                side_effect=[
                    {
                        "conversation_id": "c1",
                        "routing_mode": "helpdesk_bridge",
                        "routing_group_id": "helpdesk-l1",
                        "routing_state": "awaiting_agent",
                        "assignment_version": 2,
                    },
                    {
                        "conversation_id": "c1",
                        "routing_mode": "helpdesk_bridge",
                        "routing_group_id": "helpdesk-l1",
                        "routing_state": "assigned",
                        "active_agent_user_id": "a2",
                        "assignment_version": 3,
                    },
                ],
            ),
            patch.object(messaging, "_is_helpdesk_group_member", return_value=True),
            patch.object(messaging, "_is_user_online_available", return_value=True),
            patch.object(messaging, "now_ts", return_value=50),
            patch.object(messaging, "_apply_helpdesk_routing_transition", side_effect=messaging.RoutingTransitionError(code="routing_assignment_version_conflict", message="stale")),
            patch.object(messaging, "record_helpdesk_claim") as record_claim,
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.claim_helpdesk_conversation("c1", user_id="a1")

        self.assertEqual(ctx.exception.status_code, 409)
        record_claim.assert_called_once_with("conflict")
