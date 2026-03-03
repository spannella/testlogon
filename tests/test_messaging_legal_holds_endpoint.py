from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app.routers import messaging


class TestMessagingLegalHoldsEndpoint(unittest.TestCase):
    def test_create_legal_hold_persists_and_audits(self):
        actor = SimpleNamespace(sub="admin-1")
        with (
            patch.object(messaging, "_messaging_compliance_legal_hold_enabled", return_value=True),
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_get_message_or_404", return_value={"message_id": "m1"}),
            patch.object(messaging, "now_ts", return_value=100),
            patch.object(messaging, "new_id", return_value="h1"),
            patch.object(messaging.T.message_legal_holds, "put_item") as put_mock,
            patch.object(messaging, "audit_event") as audit_mock,
        ):
            out = messaging.create_message_legal_hold(
                "c1",
                messaging.LegalHoldCreateIn(case_id="CASE-1", reason="Preserve for litigation", message_id="m1"),
                actor=actor,
            )

        self.assertEqual(out.hold_id, "lh_h1")
        self.assertEqual(out.status, "active")
        put_mock.assert_called_once()
        audit_mock.assert_called_once()


    def test_create_legal_hold_rejects_when_feature_disabled(self):
        actor = SimpleNamespace(sub="admin-1")
        with patch.object(messaging, "_messaging_compliance_legal_hold_enabled", return_value=False):
            with self.assertRaises(HTTPException) as ctx:
                messaging.create_message_legal_hold(
                    "c1",
                    messaging.LegalHoldCreateIn(case_id="CASE-1", reason="Preserve for litigation", message_id="m1"),
                    actor=actor,
                )
        self.assertEqual(ctx.exception.status_code, 403)

    def test_release_legal_hold_updates_status_and_audits(self):
        actor = SimpleNamespace(sub="admin-1")
        hold_item = {
            "hold_id": "lh_h1",
            "conversation_id": "c1",
            "tenant_id": "default",
            "message_id": "m1",
            "case_id": "CASE-1",
            "reason": "x",
            "created_at": 50,
            "created_by_user_id": "admin-0",
        }
        with (
            patch.object(messaging, "_messaging_compliance_legal_hold_enabled", return_value=True),
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "now_ts", return_value=120),
            patch.object(messaging.T.message_legal_holds, "get_item", return_value={"Item": hold_item}),
            patch.object(messaging.T.message_legal_holds, "update_item") as update_mock,
            patch.object(messaging, "audit_event") as audit_mock,
        ):
            out = messaging.release_message_legal_hold(
                "c1",
                "lh_h1",
                messaging.LegalHoldReleaseIn(reason="Case closed"),
                actor=actor,
            )

        self.assertEqual(out.status, "released")
        update_mock.assert_called_once()
        audit_mock.assert_called_once()

    def test_list_legal_holds_active(self):
        actor = SimpleNamespace(sub="admin-1")
        with (
            patch.object(messaging, "_messaging_compliance_legal_hold_enabled", return_value=True),
            patch.object(messaging, "require_participant_active"),
            patch.object(
                messaging.T.message_legal_holds,
                "query",
                return_value={
                    "Items": [
                        {
                            "hold_id": "lh_h1",
                            "tenant_id": "default",
                            "conversation_id": "c1",
                            "message_id": "m1",
                            "case_id": "CASE-1",
                            "reason": "reason",
                            "status": "active",
                            "created_at": 1,
                            "created_by_user_id": "admin-1",
                        }
                    ]
                },
            ),
        ):
            out = messaging.list_message_legal_holds("c1", status="active", actor=actor)

        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].hold_id, "lh_h1")

    def test_release_legal_hold_404_when_missing(self):
        actor = SimpleNamespace(sub="admin-1")
        with (
            patch.object(messaging, "_messaging_compliance_legal_hold_enabled", return_value=True),
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging.T.message_legal_holds, "get_item", return_value={}),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.release_message_legal_hold(
                    "c1",
                    "missing",
                    messaging.LegalHoldReleaseIn(reason="Case closed"),
                    actor=actor,
                )

        self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
