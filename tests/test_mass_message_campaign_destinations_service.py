from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from app.services import mass_message_campaign_destinations


class TestMassMessageCampaignDestinationsService(unittest.TestCase):
    def test_upsert_destination_records_state_and_attempts(self):
        table = MagicMock()
        table.get_item.return_value = {}
        table.update_item.return_value = {
            "Attributes": {
                "campaign_id": "mmc_1",
                "conversation_id": "c_1",
                "state": "pending",
                "attempt_count": 1,
            }
        }
        with patch.object(mass_message_campaign_destinations, "_destinations_table", return_value=table):
            out = mass_message_campaign_destinations.upsert_destination(
                campaign_id="mmc_1",
                conversation_id="c_1",
                state="pending",
                updated_at=1700000100,
            )

        self.assertEqual(out["state"], "pending")
        table.update_item.assert_called_once()
        kwargs = table.update_item.call_args.kwargs
        self.assertEqual(kwargs["Key"], {"campaign_id": "mmc_1", "conversation_id": "c_1"})
        self.assertEqual(kwargs["ExpressionAttributeValues"][":campaign_state"], "mmc_1#pending")
        self.assertEqual(kwargs["ExpressionAttributeValues"][":idempotency_key"], "mmc_1:c_1")
        self.assertIn("created_at", out)
        self.assertIn("updated_at", out)
        self.assertIn("attempt_count", out)
        self.assertIn("message_id", out)
        self.assertIn("error_code", out)
        self.assertIn("idempotency_key", out)

    def test_upsert_destination_rejects_invalid_state(self):
        with self.assertRaises(ValueError) as ctx:
            mass_message_campaign_destinations.upsert_destination(
                campaign_id="mmc_1",
                conversation_id="c_1",
                state="not-a-state",
            )
        self.assertEqual(str(ctx.exception), "invalid destination state")

    def test_get_destination(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": {"campaign_id": "mmc_1", "conversation_id": "c_1", "state": "sent"}}
        with patch.object(mass_message_campaign_destinations, "_destinations_table", return_value=table):
            out = mass_message_campaign_destinations.get_destination(campaign_id="mmc_1", conversation_id="c_1")
        self.assertEqual(out["state"], "sent")
        self.assertIn("campaign_state", out)
        self.assertEqual(out["attempt_count"], 0)
        self.assertEqual(out["idempotency_key"], "mmc_1:c_1")

    def test_list_destinations(self):
        table = MagicMock()
        table.query.return_value = {"Items": [{"campaign_id": "mmc_1", "conversation_id": "c_1", "state": "pending"}]}
        with patch.object(mass_message_campaign_destinations, "_destinations_table", return_value=table):
            out = mass_message_campaign_destinations.list_destinations(campaign_id="mmc_1", limit=50)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["state"], "pending")
        self.assertEqual(out[0]["campaign_state"], "mmc_1#pending")
        self.assertEqual(out[0]["idempotency_key"], "mmc_1:c_1")
        table.query.assert_called_once()
        self.assertTrue(table.query.call_args.kwargs["ScanIndexForward"])
        self.assertEqual(table.query.call_args.kwargs["Limit"], 50)

    def test_list_destinations_bounds_limit(self):
        table = MagicMock()
        table.query.return_value = {"Items": []}
        with patch.object(mass_message_campaign_destinations, "_destinations_table", return_value=table):
            mass_message_campaign_destinations.list_destinations(campaign_id="mmc_1", limit=0)
        self.assertEqual(table.query.call_args.kwargs["Limit"], 1)

        table.reset_mock()
        table.query.return_value = {"Items": []}
        with patch.object(mass_message_campaign_destinations, "_destinations_table", return_value=table):
            mass_message_campaign_destinations.list_destinations(campaign_id="mmc_1", limit=9999)
        self.assertEqual(table.query.call_args.kwargs["Limit"], 500)

    def test_list_destinations_page_returns_last_evaluated_key(self):
        table = MagicMock()
        table.query.return_value = {
            "Items": [{"campaign_id": "mmc_1", "conversation_id": "c_2", "state": "pending"}],
            "LastEvaluatedKey": {"campaign_id": "mmc_1", "conversation_id": "c_2"},
        }
        with patch.object(mass_message_campaign_destinations, "_destinations_table", return_value=table):
            items, next_key = mass_message_campaign_destinations.list_destinations_page(
                campaign_id="mmc_1",
                limit=25,
                start_key={"campaign_id": "mmc_1", "conversation_id": "c_1"},
            )
        self.assertEqual(len(items), 1)
        self.assertEqual(next_key, {"campaign_id": "mmc_1", "conversation_id": "c_2"})
        self.assertEqual(
            table.query.call_args.kwargs["ExclusiveStartKey"],
            {"campaign_id": "mmc_1", "conversation_id": "c_1"},
        )

    def test_upsert_rejects_invalid_transition(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": {"campaign_id": "mmc_1", "conversation_id": "c_1", "state": "sent"}}
        with patch.object(mass_message_campaign_destinations, "_destinations_table", return_value=table):
            with self.assertRaises(ValueError) as ctx:
                mass_message_campaign_destinations.upsert_destination(
                    campaign_id="mmc_1",
                    conversation_id="c_1",
                    state="pending",
                )
        self.assertEqual(str(ctx.exception), "invalid destination state transition")

    def test_upsert_is_idempotent_for_same_payload(self):
        table = MagicMock()
        existing = {
            "campaign_id": "mmc_1",
            "conversation_id": "c_1",
            "state": "pending",
            "message_id": None,
            "error_code": None,
            "attempt_count": 1,
            "updated_at": 1700000100,
            "created_at": 1700000000,
            "campaign_state": "mmc_1#pending",
            "idempotency_key": "mmc_1:c_1",
        }
        table.get_item.return_value = {"Item": existing}
        with patch.object(mass_message_campaign_destinations, "_destinations_table", return_value=table):
            out = mass_message_campaign_destinations.upsert_destination(
                campaign_id="mmc_1",
                conversation_id="c_1",
                state="pending",
                message_id=None,
                error_code=None,
            )

        self.assertEqual(out["attempt_count"], 1)
        table.update_item.assert_not_called()

    def test_upsert_sent_destination_is_idempotent_for_replayed_success(self):
        table = MagicMock()
        existing = {
            "campaign_id": "mmc_1",
            "conversation_id": "c_1",
            "state": "sent",
            "message_id": "m_1",
            "error_code": None,
            "attempt_count": 2,
            "updated_at": 1700000200,
            "created_at": 1700000000,
            "campaign_state": "mmc_1#sent",
            "idempotency_key": "mmc_1:c_1",
        }
        table.get_item.return_value = {"Item": existing}
        with patch.object(mass_message_campaign_destinations, "_destinations_table", return_value=table):
            out = mass_message_campaign_destinations.upsert_destination(
                campaign_id="mmc_1",
                conversation_id="c_1",
                state="sent",
                message_id="m_1",
                error_code=None,
            )

        self.assertEqual(out["state"], "sent")
        self.assertEqual(out["attempt_count"], 2)
        table.update_item.assert_not_called()

    def test_upsert_failed_to_pending_retry_bumps_attempt_count_once(self):
        table = MagicMock()
        table.get_item.return_value = {
            "Item": {
                "campaign_id": "mmc_1",
                "conversation_id": "c_1",
                "state": "failed",
                "message_id": None,
                "error_code": "transient_infra",
                "attempt_count": 1,
                "updated_at": 1700000100,
                "created_at": 1700000000,
                "campaign_state": "mmc_1#failed",
                "idempotency_key": "mmc_1:c_1",
            }
        }
        table.update_item.return_value = {
            "Attributes": {
                "campaign_id": "mmc_1",
                "conversation_id": "c_1",
                "state": "pending",
                "message_id": None,
                "error_code": None,
                "attempt_count": 2,
                "updated_at": 1700000200,
                "created_at": 1700000000,
                "campaign_state": "mmc_1#pending",
                "idempotency_key": "mmc_1:c_1",
            }
        }
        with patch.object(mass_message_campaign_destinations, "_destinations_table", return_value=table):
            out = mass_message_campaign_destinations.upsert_destination(
                campaign_id="mmc_1",
                conversation_id="c_1",
                state="pending",
                updated_at=1700000200,
            )

        self.assertEqual(out["state"], "pending")
        self.assertEqual(out["attempt_count"], 2)
        kwargs = table.update_item.call_args.kwargs
        self.assertEqual(kwargs["ExpressionAttributeValues"][":attempt_count_inc"], 1)
        self.assertEqual(kwargs["ExpressionAttributeValues"][":idempotency_key"], "mmc_1:c_1")

    def test_upsert_failed_destination_normalizes_error_code_to_taxonomy(self):
        table = MagicMock()
        table.get_item.return_value = {}
        table.update_item.return_value = {
            "Attributes": {
                "campaign_id": "mmc_1",
                "conversation_id": "c_1",
                "state": "failed",
                "error_code": "authorization",
                "attempt_count": 1,
            }
        }
        with patch.object(mass_message_campaign_destinations, "_destinations_table", return_value=table):
            out = mass_message_campaign_destinations.upsert_destination(
                campaign_id="mmc_1",
                conversation_id="c_1",
                state="failed",
                error_code="authorization_denied",
            )

        kwargs = table.update_item.call_args.kwargs
        self.assertEqual(kwargs["ExpressionAttributeValues"][":error_code"], "authorization")
        self.assertEqual(out["error_code"], "authorization")


if __name__ == "__main__":
    unittest.main()
