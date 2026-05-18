from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from app.services import mass_message_campaigns


class TestMassMessageCampaignsService(unittest.TestCase):
    def test_create_campaign_requires_sender_and_payload_hash(self):
        with self.assertRaises(ValueError) as sender_ctx:
            mass_message_campaigns.create_campaign(sender_id="", mode="immediate", payload_hash="hash")
        self.assertEqual(str(sender_ctx.exception), "sender_id required")

        with self.assertRaises(ValueError) as payload_ctx:
            mass_message_campaigns.create_campaign(sender_id="user-1", mode="immediate", payload_hash="")
        self.assertEqual(str(payload_ctx.exception), "payload_hash required")

    def test_create_campaign_immediate_defaults_pending(self):
        table = MagicMock()
        with patch.object(mass_message_campaigns, "_campaigns_table", return_value=table):
            item = mass_message_campaigns.create_campaign(
                sender_id="user-1",
                mode="immediate",
                payload_hash="abc123",
                created_at=1700000000,
                campaign_id="mmc_test_1",
            )

        self.assertEqual(item["campaign_id"], "mmc_test_1")
        self.assertEqual(item["sender_id"], "user-1")
        self.assertEqual(item["mode"], "immediate")
        self.assertEqual(item["status"], "pending")
        self.assertEqual(item["created_at"], 1700000000)
        self.assertNotIn("send_at", item)
        table.put_item.assert_called_once()

    def test_create_campaign_scheduled_requires_send_at(self):
        with self.assertRaises(ValueError) as ctx:
            mass_message_campaigns.create_campaign(
                sender_id="user-1",
                mode="scheduled",
                payload_hash="abc123",
            )
        self.assertEqual(str(ctx.exception), "scheduled mode requires positive send_at")

    def test_create_campaign_scheduled_sets_scheduled_status(self):
        table = MagicMock()
        with patch.object(mass_message_campaigns, "_campaigns_table", return_value=table):
            item = mass_message_campaigns.create_campaign(
                sender_id="user-1",
                mode="scheduled",
                payload_hash="abc123",
                send_at=1700003600,
                created_at=1700000000,
                campaign_id="mmc_sched_1",
            )

        self.assertEqual(item["mode"], "scheduled")
        self.assertEqual(item["status"], "scheduled")
        self.assertEqual(item["send_at"], 1700003600)
        table.put_item.assert_called_once()

    def test_can_transition_status_contract(self):
        self.assertTrue(mass_message_campaigns.can_transition_status("pending", "processing"))
        self.assertFalse(mass_message_campaigns.can_transition_status("completed", "processing"))

    def test_update_campaign_status_rejects_invalid_transition(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": {"campaign_id": "mmc_1", "status": "completed"}}
        with patch.object(mass_message_campaigns, "_campaigns_table", return_value=table):
            with self.assertRaises(ValueError) as ctx:
                mass_message_campaigns.update_campaign_status(
                    campaign_id="mmc_1",
                    next_status="processing",
                )
        self.assertEqual(str(ctx.exception), "invalid status transition")

    def test_update_campaign_status_happy_path(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": {"campaign_id": "mmc_1", "status": "pending"}}
        table.update_item.return_value = {"Attributes": {"campaign_id": "mmc_1", "status": "processing", "updated_at": 1700000001}}
        with patch.object(mass_message_campaigns, "_campaigns_table", return_value=table):
            out = mass_message_campaigns.update_campaign_status(
                campaign_id="mmc_1",
                next_status="processing",
                now_ts=1700000001,
            )
        self.assertEqual(out["status"], "processing")
        table.update_item.assert_called_once()

    def test_update_campaign_status_rejects_expected_status_mismatch_before_write(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": {"campaign_id": "mmc_1", "status": "processing"}}
        with patch.object(mass_message_campaigns, "_campaigns_table", return_value=table):
            with self.assertRaises(ValueError) as ctx:
                mass_message_campaigns.update_campaign_status(
                    campaign_id="mmc_1",
                    next_status="completed",
                    expected_status="pending",
                )

        self.assertEqual(str(ctx.exception), "campaign status changed")
        table.update_item.assert_not_called()

    def test_get_campaign_requires_campaign_id(self):
        with self.assertRaises(ValueError) as ctx:
            mass_message_campaigns.get_campaign("")
        self.assertEqual(str(ctx.exception), "campaign_id required")

    def test_list_due_scheduled_campaigns_queries_status_send_at_index(self):
        table = MagicMock()
        table.query.return_value = {
            "Items": [
                {"campaign_id": "mmc_1", "status": "scheduled", "send_at": 1700000000},
                {"campaign_id": "mmc_2", "status": "scheduled", "send_at": 1700000010},
            ]
        }
        with patch.object(mass_message_campaigns, "_campaigns_table", return_value=table):
            out = mass_message_campaigns.list_due_scheduled_campaigns(now_ts=1700000100, limit=25)

        self.assertEqual(len(out), 2)
        kwargs = table.query.call_args.kwargs
        self.assertEqual(kwargs["IndexName"], "ByStatusSendAt")
        self.assertEqual(kwargs["ExpressionAttributeValues"][":status"], "scheduled")
        self.assertEqual(kwargs["ExpressionAttributeValues"][":send_at"], 1700000100)
        self.assertEqual(kwargs["Limit"], 25)

    def test_list_due_scheduled_campaigns_bounds_limit(self):
        table = MagicMock()
        table.query.return_value = {"Items": []}
        with patch.object(mass_message_campaigns, "_campaigns_table", return_value=table):
            mass_message_campaigns.list_due_scheduled_campaigns(now_ts=1700000100, limit=0)
        self.assertEqual(table.query.call_args.kwargs["Limit"], 1)

        table.reset_mock()
        table.query.return_value = {"Items": []}
        with patch.object(mass_message_campaigns, "_campaigns_table", return_value=table):
            mass_message_campaigns.list_due_scheduled_campaigns(now_ts=1700000100, limit=9999)
        self.assertEqual(table.query.call_args.kwargs["Limit"], 500)

    def test_update_campaign_status_with_expected_updated_at_applies_optimistic_guard(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": {"campaign_id": "mmc_1", "status": "pending"}}
        table.update_item.return_value = {"Attributes": {"campaign_id": "mmc_1", "status": "processing", "updated_at": 1700000001}}
        with patch.object(mass_message_campaigns, "_campaigns_table", return_value=table):
            mass_message_campaigns.update_campaign_status(
                campaign_id="mmc_1",
                next_status="processing",
                expected_updated_at=1700000000,
                now_ts=1700000001,
            )

        kwargs = table.update_item.call_args.kwargs
        self.assertIn(":expected_updated_at", kwargs["ExpressionAttributeValues"])
        self.assertEqual(kwargs["ExpressionAttributeValues"][":expected_updated_at"], 1700000000)
        self.assertIn("#updated_at = :expected_updated_at", kwargs["ConditionExpression"])

    def test_update_campaign_status_raises_version_changed_on_conditional_conflict(self):
        class ConditionalFailure(Exception):
            def __init__(self):
                super().__init__("conditional failed")
                self.response = {"Error": {"Code": "ConditionalCheckFailedException"}}

        table = MagicMock()
        table.get_item.return_value = {"Item": {"campaign_id": "mmc_1", "status": "pending"}}
        table.update_item.side_effect = ConditionalFailure()
        with patch.object(mass_message_campaigns, "_campaigns_table", return_value=table):
            with self.assertRaises(ValueError) as ctx:
                mass_message_campaigns.update_campaign_status(
                    campaign_id="mmc_1",
                    next_status="processing",
                    expected_updated_at=1700000000,
                )
        self.assertEqual(str(ctx.exception), "campaign version changed")

    def test_update_campaign_status_raises_status_changed_on_conditional_conflict_without_version_guard(self):
        class ConditionalFailure(Exception):
            def __init__(self):
                super().__init__("conditional failed")
                self.response = {"Error": {"Code": "ConditionalCheckFailedException"}}

        table = MagicMock()
        table.get_item.return_value = {"Item": {"campaign_id": "mmc_1", "status": "pending"}}
        table.update_item.side_effect = ConditionalFailure()
        with patch.object(mass_message_campaigns, "_campaigns_table", return_value=table):
            with self.assertRaises(ValueError) as ctx:
                mass_message_campaigns.update_campaign_status(
                    campaign_id="mmc_1",
                    next_status="processing",
                )
        self.assertEqual(str(ctx.exception), "campaign status changed")

    def test_list_campaigns_for_sender_queries_sender_index_with_pagination(self):
        table = MagicMock()
        table.query.return_value = {
            "Items": [{"campaign_id": "mmc_1", "sender_id": "u1", "created_at": 1700000000}],
            "LastEvaluatedKey": {"campaign_id": "mmc_1", "sender_id": "u1", "created_at": 1700000000},
        }
        with patch.object(mass_message_campaigns, "_campaigns_table", return_value=table):
            items, next_key = mass_message_campaigns.list_campaigns_for_sender(
                sender_id="u1",
                limit=20,
                start_key={"campaign_id": "mmc_prev", "sender_id": "u1", "created_at": 1699999999},
            )

        self.assertEqual(len(items), 1)
        self.assertEqual(next_key["campaign_id"], "mmc_1")
        kwargs = table.query.call_args.kwargs
        self.assertEqual(kwargs["IndexName"], "BySenderCreatedAt")
        self.assertEqual(kwargs["ExpressionAttributeValues"][":sender_id"], "u1")
        self.assertEqual(kwargs["Limit"], 20)
        self.assertFalse(kwargs["ScanIndexForward"])

    def test_apply_destination_counter_delta_for_new_destination_is_atomic(self):
        table = MagicMock()
        table.update_item.return_value = {"Attributes": {"campaign_id": "mmc_1", "total": 1, "queued": 1}}
        with patch.object(mass_message_campaigns, "_campaigns_table", return_value=table):
            out = mass_message_campaigns.apply_destination_counter_delta(
                campaign_id="mmc_1",
                to_state="pending",
                from_state=None,
                now_ts=1700000200,
            )
        self.assertEqual(out["total"], 1)
        kwargs = table.update_item.call_args.kwargs
        self.assertIn("#total :delta_total", kwargs["UpdateExpression"])
        self.assertIn("#to_queued :delta_to_queued", kwargs["UpdateExpression"])
        self.assertEqual(kwargs["ExpressionAttributeValues"][":delta_total"], 1)
        self.assertEqual(kwargs["ExpressionAttributeValues"][":delta_to_queued"], 1)

    def test_apply_destination_counter_delta_for_state_transition(self):
        table = MagicMock()
        table.update_item.return_value = {"Attributes": {"campaign_id": "mmc_1", "queued": 0, "sent": 1}}
        with patch.object(mass_message_campaigns, "_campaigns_table", return_value=table):
            out = mass_message_campaigns.apply_destination_counter_delta(
                campaign_id="mmc_1",
                from_state="pending",
                to_state="sent",
                now_ts=1700000300,
            )
        self.assertEqual(out["sent"], 1)
        kwargs = table.update_item.call_args.kwargs
        self.assertIn("#from_queued :delta_from_queued", kwargs["UpdateExpression"])
        self.assertIn("#to_sent :delta_to_sent", kwargs["UpdateExpression"])
        self.assertEqual(kwargs["ExpressionAttributeValues"][":delta_from_queued"], -1)
        self.assertEqual(kwargs["ExpressionAttributeValues"][":delta_to_sent"], 1)

    def test_apply_destination_counter_delta_noop_when_state_unchanged(self):
        table = MagicMock()
        with patch.object(mass_message_campaigns, "_campaigns_table", return_value=table):
            out = mass_message_campaigns.apply_destination_counter_delta(
                campaign_id="mmc_1",
                from_state="sent",
                to_state="sent",
            )
        self.assertEqual(out, {})
        table.update_item.assert_not_called()

    def test_build_counter_totals_from_destinations(self):
        totals = mass_message_campaigns.build_counter_totals_from_destinations(
            [
                {"state": "pending"},
                {"state": "sent"},
                {"state": "failed"},
                {"state": "cancelled"},
                {"state": "skipped"},
            ]
        )
        self.assertEqual(
            totals,
            {
                "total": 5,
                "queued": 1,
                "sent": 1,
                "failed": 1,
                "cancelled": 1,
            },
        )

    def test_create_or_get_campaign_returns_existing_on_idempotent_conflict(self):
        class ConditionalFailure(Exception):
            def __init__(self):
                self.response = {"Error": {"Code": "ConditionalCheckFailedException"}}

        table = MagicMock()
        table.put_item.side_effect = ConditionalFailure()
        table.get_item.return_value = {
            "Item": {"campaign_id": "mmc_idm_abc", "sender_id": "user-1", "mode": "immediate", "status": "pending"}
        }
        with patch.object(mass_message_campaigns, "_campaigns_table", return_value=table), patch.object(
            mass_message_campaigns,
            "campaign_id_from_idempotency",
            return_value="mmc_idm_abc",
        ):
            campaign, created_new = mass_message_campaigns.create_or_get_campaign(
                sender_id="user-1",
                mode="immediate",
                payload_hash="h",
                idempotency_key="idem-1",
            )

        self.assertFalse(created_new)
        self.assertEqual(campaign["campaign_id"], "mmc_idm_abc")

    def test_set_campaign_submission_result_updates_accepted_and_rejected(self):
        table = MagicMock()
        table.update_item.return_value = {
            "Attributes": {
                "campaign_id": "mmc_1",
                "accepted_conversation_ids": ["c1"],
                "rejected_destinations": [{"conversation_id": "c2", "reason": "conversation_not_found"}],
            }
        }
        with patch.object(mass_message_campaigns, "_campaigns_table", return_value=table):
            out = mass_message_campaigns.set_campaign_submission_result(
                campaign_id="mmc_1",
                accepted_conversation_ids=["c1"],
                rejected=[{"conversation_id": "c2", "reason": "conversation_not_found"}],
            )
        self.assertEqual(out["accepted_conversation_ids"], ["c1"])
        self.assertEqual(out["rejected_destinations"][0]["conversation_id"], "c2")


if __name__ == "__main__":
    unittest.main()
