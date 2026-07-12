from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("boto3")
pytest.importorskip("pydantic")

from fastapi import HTTPException

from app.models_mass_message import MassMessageCreateCampaignRequest
from app.routers import messaging
from app.core.cursor import encode_cursor


class TestMassMessageCreateEndpoint(unittest.TestCase):
    def test_create_mass_message_campaign_blocked_when_feature_flag_disabled(self):
        req = MassMessageCreateCampaignRequest(
            conversation_ids=["c1"],
            content={"kind": "text", "text": "hello world"},
            mode="immediate",
        )
        with patch.object(messaging, "_messaging_mass_send_enabled", return_value=False):
            with self.assertRaises(HTTPException) as ctx:
                messaging.create_mass_message_campaign(req, user_id="u1")
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "mass_send_disabled")

    def test_create_mass_message_campaign_persists_records_and_returns_split(self):
        req = MassMessageCreateCampaignRequest(
            conversation_ids=["c1", "c2"],
            content={"kind": "text", "text": "hello world"},
            mode="immediate",
            idempotency_key="idem-12345678",
        )

        convo_table = MagicMock()
        convo_table.get_item.side_effect = [
            {"Item": {"conversation_id": "c1", "type": "dm"}},
            {"Item": None},
        ]

        with (
            patch.object(messaging, "tbl_convos", convo_table),
            patch.object(messaging, "get_participant_any", return_value={"status": "active"}),
            patch.object(
                messaging,
                "create_or_get_mass_campaign_record",
                return_value=(
                    {
                        "campaign_id": "mmc_1",
                        "mode": "immediate",
                        "status": "pending",
                        "created_at": 1760000000,
                        "updated_at": 1760000000,
                    },
                    True,
                ),
            ),
            patch.object(
                messaging,
                "get_mass_campaign_record",
                return_value={
                    "campaign_id": "mmc_1",
                    "mode": "immediate",
                    "status": "pending",
                    "total": 1,
                    "queued": 1,
                    "sent": 0,
                    "failed": 0,
                    "cancelled": 0,
                    "created_at": 1760000000,
                    "updated_at": 1760000001,
                },
            ),
            patch.object(messaging, "upsert_mass_destination") as upsert_mass_destination,
            patch.object(messaging, "apply_destination_counter_delta") as apply_destination_counter_delta,
            patch.object(messaging, "set_campaign_submission_result") as set_campaign_submission_result,
            patch.object(messaging, "audit_event") as audit_event,
            patch.object(messaging, "_kickoff_mass_message_dispatch"),
        ):
            out = messaging.create_mass_message_campaign(req, user_id="u1")

        self.assertEqual(out.campaign_id, "mmc_1")
        self.assertEqual(out.accepted_count, 1)
        self.assertEqual(out.accepted_conversation_ids, ["c1"])
        self.assertEqual(len(out.rejected), 1)
        self.assertEqual(out.rejected[0].conversation_id, "c2")
        self.assertEqual(out.rejected[0].reason, "conversation_not_found")
        upsert_mass_destination.assert_called_once()
        apply_destination_counter_delta.assert_called_once()
        set_campaign_submission_result.assert_called_once()
        audit_event.assert_called_once()
        self.assertEqual(audit_event.call_args.args[0], "messaging_mass_campaign_submitted")

    def test_create_mass_message_campaign_rejects_when_no_eligible_destinations(self):
        req = MassMessageCreateCampaignRequest(
            conversation_ids=["c1"],
            content={"kind": "text", "text": "hello world"},
            mode="immediate",
            idempotency_key="idem-12345678",
        )

        convo_table = MagicMock()
        convo_table.get_item.return_value = {"Item": None}

        with patch.object(messaging, "tbl_convos", convo_table):
            with self.assertRaises(HTTPException) as ctx:
                messaging.create_mass_message_campaign(req, user_id="u1")

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "No eligible destinations")

    def test_create_mass_message_campaign_idempotency_replay_returns_existing_campaign(self):
        req = MassMessageCreateCampaignRequest(
            conversation_ids=["c1"],
            content={"kind": "text", "text": "hello world"},
            mode="immediate",
            idempotency_key="idem-12345678",
        )

        convo_table = MagicMock()
        convo_table.get_item.return_value = {"Item": {"conversation_id": "c1", "type": "dm"}}

        with (
            patch.object(messaging, "tbl_convos", convo_table),
            patch.object(messaging, "get_participant_any", return_value={"status": "active"}),
            patch.object(
                messaging,
                "create_or_get_mass_campaign_record",
                return_value=(
                    {
                        "campaign_id": "mmc_1",
                        "mode": "immediate",
                        "status": "pending",
                        "created_at": 1760000000,
                        "updated_at": 1760000001,
                        "accepted_conversation_ids": ["c1"],
                        "rejected_destinations": [],
                    },
                    False,
                ),
            ),
            patch.object(
                messaging,
                "get_mass_campaign_record",
                return_value={
                    "campaign_id": "mmc_1",
                    "mode": "immediate",
                    "status": "pending",
                    "total": 1,
                    "queued": 1,
                    "sent": 0,
                    "failed": 0,
                    "cancelled": 0,
                    "accepted_conversation_ids": ["c1"],
                    "rejected_destinations": [],
                    "created_at": 1760000000,
                    "updated_at": 1760000001,
                },
            ),
            patch.object(messaging, "upsert_mass_destination") as upsert_mass_destination,
            patch.object(messaging, "apply_destination_counter_delta") as apply_destination_counter_delta,
            patch.object(messaging, "set_campaign_submission_result") as set_campaign_submission_result,
            patch.object(messaging, "audit_event") as audit_event,
            patch.object(messaging, "_kickoff_mass_message_dispatch"),
        ):
            out = messaging.create_mass_message_campaign(req, user_id="u1")

        self.assertEqual(out.campaign_id, "mmc_1")
        self.assertEqual(out.accepted_count, 1)
        self.assertEqual(out.accepted_conversation_ids, ["c1"])
        upsert_mass_destination.assert_not_called()
        apply_destination_counter_delta.assert_not_called()
        set_campaign_submission_result.assert_not_called()
        audit_event.assert_called_once()

    def test_get_mass_message_campaign_returns_details_for_owner(self):
        with (
            patch.object(
                messaging,
                "get_mass_campaign_record",
                return_value={
                    "campaign_id": "mmc_1",
                    "sender_id": "u1",
                    "mode": "immediate",
                    "status": "pending",
                    "total": 2,
                    "queued": 2,
                    "sent": 0,
                    "failed": 0,
                    "cancelled": 0,
                    "created_at": 1760000000,
                    "updated_at": 1760000001,
                },
            ),
            patch.object(
                messaging,
                "list_mass_destinations_page",
                return_value=(
                    [
                        {
                            "campaign_id": "mmc_1",
                            "conversation_id": "c1",
                            "state": "pending",
                            "message_id": None,
                            "error_code": None,
                            "attempt_count": 1,
                            "updated_at": 1760000001,
                            "created_at": 1760000000,
                            "campaign_state": "mmc_1#pending",
                        }
                    ],
                    {"campaign_id": "mmc_1", "conversation_id": "c1"},
                ),
            ),
        ):
            out = messaging.get_mass_message_campaign("mmc_1", limit=100, user_id="u1")

        self.assertEqual(out.campaign_id, "mmc_1")
        self.assertEqual(out.sender_id, "u1")
        self.assertEqual(out.counters.total, 2)
        self.assertEqual(len(out.destinations), 1)
        self.assertEqual(out.next_cursor, encode_cursor({"campaign_id": "mmc_1", "conversation_id": "c1"}))

    def test_get_mass_message_campaign_rejects_invalid_cursor(self):
        with patch.object(
            messaging,
            "get_mass_campaign_record",
            return_value={
                "campaign_id": "mmc_1",
                "sender_id": "u1",
                "mode": "immediate",
                "status": "pending",
            },
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.get_mass_message_campaign("mmc_1", limit=100, cursor="not-base64", user_id="u1")

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "Invalid cursor")

    def test_get_mass_message_campaign_rejects_cursor_for_other_campaign(self):
        with patch.object(
            messaging,
            "get_mass_campaign_record",
            return_value={
                "campaign_id": "mmc_1",
                "sender_id": "u1",
                "mode": "immediate",
                "status": "pending",
            },
        ):
            cursor = encode_cursor({"campaign_id": "mmc_other", "conversation_id": "c9"})
            with self.assertRaises(HTTPException) as ctx:
                messaging.get_mass_message_campaign("mmc_1", limit=100, cursor=cursor, user_id="u1")

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "Invalid cursor")

    def test_get_mass_message_campaign_returns_404_for_non_owner(self):
        with patch.object(
            messaging,
            "get_mass_campaign_record",
            return_value={
                "campaign_id": "mmc_1",
                "sender_id": "other-user",
                "mode": "immediate",
                "status": "pending",
            },
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.get_mass_message_campaign("mmc_1", limit=100, user_id="u1")

        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(ctx.exception.detail, "Campaign not found")

    def test_get_mass_message_campaign_returns_404_when_missing(self):
        with patch.object(messaging, "get_mass_campaign_record", return_value=None):
            with self.assertRaises(HTTPException) as ctx:
                messaging.get_mass_message_campaign("mmc_missing", limit=100, user_id="u1")

        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(ctx.exception.detail, "Campaign not found")

    def test_cancel_mass_message_campaign_transitions_and_cancels_pending_destinations(self):
        with (
            patch.object(
                messaging,
                "get_mass_campaign_record",
                side_effect=[
                    {
                        "campaign_id": "mmc_1",
                        "sender_id": "u1",
                        "mode": "scheduled",
                        "status": "scheduled",
                        "total": 3,
                        "queued": 3,
                        "sent": 0,
                        "failed": 0,
                        "cancelled": 0,
                        "updated_at": 1760000000,
                    },
                    {
                        "campaign_id": "mmc_1",
                        "sender_id": "u1",
                        "mode": "scheduled",
                        "status": "cancelled",
                        "total": 3,
                        "queued": 0,
                        "sent": 1,
                        "failed": 0,
                        "cancelled": 2,
                        "updated_at": 1760000200,
                    },
                ],
            ),
            patch.object(
                messaging,
                "update_mass_campaign_status",
                return_value={
                    "campaign_id": "mmc_1",
                    "sender_id": "u1",
                    "mode": "scheduled",
                    "status": "cancelled",
                    "total": 3,
                    "queued": 1,
                    "sent": 1,
                    "failed": 0,
                    "cancelled": 1,
                    "updated_at": 1760000100,
                },
            ),
            patch.object(messaging, "_cancel_pending_mass_destinations", return_value=2),
            patch.object(messaging, "record_mass_message_campaign_event") as record_event,
            patch.object(messaging, "audit_event") as audit_event,
        ):
            out = messaging.cancel_mass_message_campaign("mmc_1", user_id="u1")

        self.assertEqual(out.status, "cancelled")
        self.assertEqual(out.cancelled_destinations, 2)
        self.assertEqual(out.counters.cancelled, 2)
        record_event.assert_called_once()
        audit_event.assert_called_once()

    def test_cancel_mass_message_campaign_is_idempotent_for_terminal_campaign(self):
        with (
            patch.object(
                messaging,
                "get_mass_campaign_record",
                return_value={
                    "campaign_id": "mmc_1",
                    "sender_id": "u1",
                    "mode": "immediate",
                    "status": "completed",
                    "total": 1,
                    "queued": 0,
                    "sent": 1,
                    "failed": 0,
                    "cancelled": 0,
                    "updated_at": 1760000100,
                },
            ),
            patch.object(messaging, "update_mass_campaign_status") as update_status,
            patch.object(messaging, "_cancel_pending_mass_destinations") as cancel_pending,
            patch.object(messaging, "record_mass_message_campaign_event") as record_event,
        ):
            out = messaging.cancel_mass_message_campaign("mmc_1", user_id="u1")

        self.assertEqual(out.status, "completed")
        self.assertEqual(out.cancelled_destinations, 0)
        update_status.assert_not_called()
        cancel_pending.assert_not_called()
        record_event.assert_called_once_with(event="cancel", mode="immediate", outcome="noop_terminal")

    def test_cancel_mass_message_campaign_records_race_outcome(self):
        with (
            patch.object(
                messaging,
                "get_mass_campaign_record",
                side_effect=[
                    {
                        "campaign_id": "mmc_1",
                        "sender_id": "u1",
                        "mode": "immediate",
                        "status": "processing",
                        "total": 2,
                        "queued": 1,
                        "sent": 1,
                        "failed": 0,
                        "cancelled": 0,
                        "updated_at": 1760000100,
                    },
                    {
                        "campaign_id": "mmc_1",
                        "sender_id": "u1",
                        "mode": "immediate",
                        "status": "completed",
                        "total": 2,
                        "queued": 0,
                        "sent": 2,
                        "failed": 0,
                        "cancelled": 0,
                        "updated_at": 1760000200,
                    },
                ],
            ),
            patch.object(messaging, "update_mass_campaign_status", side_effect=ValueError("campaign status changed")),
            patch.object(messaging, "record_mass_message_campaign_event") as record_event,
        ):
            out = messaging.cancel_mass_message_campaign("mmc_1", user_id="u1")

        self.assertEqual(out.status, "completed")
        record_event.assert_called_once_with(event="cancel", mode="immediate", outcome="race")

    def test_cancel_pending_mass_destinations_marks_pending_only(self):
        with (
            patch.object(
                messaging,
                "list_mass_destinations_page",
                side_effect=[
                    (
                        [
                            {"campaign_id": "mmc_1", "conversation_id": "c1", "state": "pending"},
                            {"campaign_id": "mmc_1", "conversation_id": "c2", "state": "sent"},
                        ],
                        None,
                    )
                ],
            ),
            patch.object(messaging, "upsert_mass_destination") as upsert,
            patch.object(messaging, "apply_destination_counter_delta") as apply_delta,
        ):
            cancelled = messaging._cancel_pending_mass_destinations(campaign_id="mmc_1")

        self.assertEqual(cancelled, 1)
        upsert.assert_called_once_with(
            campaign_id="mmc_1",
            conversation_id="c1",
            state="cancelled",
            message_id=None,
            error_code=None,
        )
        apply_delta.assert_called_once_with(
            campaign_id="mmc_1",
            to_state="cancelled",
            from_state="pending",
        )

    def test_list_mass_message_campaigns_returns_filtered_items_with_next_cursor(self):
        with patch.object(
            messaging,
            "list_campaigns_for_sender",
            return_value=(
                [
                    {
                        "campaign_id": "mmc_1",
                        "mode": "immediate",
                        "status": "completed",
                        "total": 2,
                        "queued": 0,
                        "sent": 2,
                        "failed": 0,
                        "cancelled": 0,
                        "created_at": 1760000000,
                        "updated_at": 1760000100,
                    },
                    {
                        "campaign_id": "mmc_2",
                        "mode": "scheduled",
                        "status": "scheduled",
                        "total": 3,
                        "queued": 3,
                        "sent": 0,
                        "failed": 0,
                        "cancelled": 0,
                        "created_at": 1760000001,
                        "updated_at": 1760000101,
                    },
                ],
                {"campaign_id": "mmc_2", "sender_id": "u1", "created_at": 1760000001},
            ),
        ):
            out = messaging.list_mass_message_campaigns(limit=25, status="completed", user_id="u1")

        self.assertEqual(len(out.items), 1)
        self.assertEqual(out.items[0].campaign_id, "mmc_1")
        self.assertIsNotNone(out.next_cursor)

    def test_list_mass_message_campaigns_rejects_invalid_cursor(self):
        with self.assertRaises(HTTPException) as ctx:
            messaging.list_mass_message_campaigns(limit=25, cursor="invalid", user_id="u1")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "Invalid cursor")

    def test_list_mass_message_campaigns_rejects_malformed_decoded_cursor(self):
        malformed_cursor = encode_cursor({"sender_id": "u1", "campaign_id": "", "created_at": 0})
        with self.assertRaises(HTTPException) as ctx:
            messaging.list_mass_message_campaigns(limit=25, cursor=malformed_cursor, user_id="u1")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "Invalid cursor")

    def test_list_mass_message_campaigns_rejects_non_numeric_created_at_cursor(self):
        malformed_cursor = encode_cursor({"sender_id": "u1", "campaign_id": "mmc_1", "created_at": "abc"})
        with self.assertRaises(HTTPException) as ctx:
            messaging.list_mass_message_campaigns(limit=25, cursor=malformed_cursor, user_id="u1")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "Invalid cursor")

    def test_list_mass_message_campaigns_rejects_invalid_status_filter(self):
        with self.assertRaises(HTTPException) as ctx:
            messaging.list_mass_message_campaigns(limit=25, status="not-a-status", user_id="u1")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "Invalid status filter")

    def test_list_mass_message_campaigns_rejects_invalid_mode_filter(self):
        with self.assertRaises(HTTPException) as ctx:
            messaging.list_mass_message_campaigns(limit=25, mode="batch", user_id="u1")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "Invalid mode filter")

    def test_list_mass_message_campaigns_scans_additional_pages_to_fill_filtered_limit(self):
        with patch.object(
            messaging,
            "list_campaigns_for_sender",
            side_effect=[
                (
                    [
                        {
                            "campaign_id": "mmc_1",
                            "sender_id": "u1",
                            "mode": "scheduled",
                            "status": "scheduled",
                            "total": 2,
                            "queued": 2,
                            "sent": 0,
                            "failed": 0,
                            "cancelled": 0,
                            "created_at": 1760000000,
                            "updated_at": 1760000100,
                        }
                    ],
                    {"campaign_id": "mmc_1", "sender_id": "u1", "created_at": 1760000000},
                ),
                (
                    [
                        {
                            "campaign_id": "mmc_2",
                            "sender_id": "u1",
                            "mode": "immediate",
                            "status": "completed",
                            "total": 1,
                            "queued": 0,
                            "sent": 1,
                            "failed": 0,
                            "cancelled": 0,
                            "created_at": 1760000001,
                            "updated_at": 1760000101,
                        },
                        {
                            "campaign_id": "mmc_3",
                            "sender_id": "u1",
                            "mode": "immediate",
                            "status": "completed",
                            "total": 1,
                            "queued": 0,
                            "sent": 1,
                            "failed": 0,
                            "cancelled": 0,
                            "created_at": 1760000002,
                            "updated_at": 1760000102,
                        },
                    ],
                    None,
                ),
            ],
        ):
            out = messaging.list_mass_message_campaigns(limit=2, status="completed", user_id="u1")

        self.assertEqual([item.campaign_id for item in out.items], ["mmc_2", "mmc_3"])
        self.assertIsNone(out.next_cursor)


if __name__ == "__main__":
    unittest.main()
