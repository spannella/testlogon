from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app.services import google_calendar_connections as svc


class _FakeTable:
    def __init__(self):
        self.items = {}

    def put_item(self, Item):
        self.items[(Item["calendar_id"], Item["sk"])] = dict(Item)

    def get_item(self, Key):
        item = self.items.get((Key["calendar_id"], Key["sk"]))
        return {"Item": dict(item)} if item else {}

    def query(self, KeyConditionExpression):
        # parse string repr is overkill; just return all and service filters by pk through Key expr in real env
        return {"Items": [dict(v) for v in self.items.values()]}


class TestGoogleCalendarConnections(unittest.TestCase):
    def test_upsert_stores_only_encrypted_token_fields(self):
        table = _FakeTable()
        token_payload = {
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "expiry": "2026-03-25T00:00:00Z",
        }

        with (
            patch.object(svc, "T", SimpleNamespace(calendar=table)),
            patch.object(
                svc,
                "encrypt_token_payload",
                return_value={
                    "key_encrypted_b64": "key-ct",
                    "secret_ciphertext_b64": "ciphertext",
                    "nonce_b64": "nonce",
                    "aad_b64": "aad",
                    "kms_key_id": "alias/google-calendar",
                    "encrypted_at_utc": "2026-03-25T00:00:00Z",
                },
            ),
            patch.object(svc, "emit_google_calendar_audit_event") as audit,
        ):
            out = svc.upsert_calendar_provider_connection(
                user_sub="user-1",
                connection_id="conn-1",
                account_email="user@example.com",
                token_payload=token_payload,
            )

        stored = table.items[("gcal_conn#user-1", "meta#conn-1")]
        self.assertEqual(out["connection_id"], "conn-1")
        self.assertEqual(stored["type"], "calendar_provider_connection")
        self.assertNotIn("refresh_token", stored)
        self.assertNotIn("access_token", stored)
        self.assertEqual(stored["secret_ciphertext_b64"], "ciphertext")
        self.assertEqual(stored["token_payload_redacted"]["refresh_token"], "[REDACTED]")
        self.assertEqual(stored["sync_health"], "unknown")
        audit.assert_called_once()

    def test_model_supports_multiple_connections_per_user(self):
        table = _FakeTable()
        base = {
            "calendar_id": "gcal_conn#user-1",
            "type": "calendar_provider_connection",
            "provider": "google",
            "user_sub": "user-1",
            "active": True,
            "token_payload_redacted": {},
        }
        table.put_item(Item={**base, "sk": "meta#conn-1", "connection_id": "conn-1"})
        table.put_item(Item={**base, "sk": "meta#conn-2", "connection_id": "conn-2"})

        with patch.object(svc, "T", SimpleNamespace(calendar=table)):
            items = svc.list_calendar_provider_connections(user_sub="user-1")

        ids = sorted(i["connection_id"] for i in items)
        self.assertEqual(ids, ["conn-1", "conn-2"])

    def test_sync_status_updates_are_idempotent(self):
        table = _FakeTable()
        table.put_item(
            Item={
                "calendar_id": "gcal_conn#user-1",
                "sk": "meta#conn-1",
                "type": "calendar_provider_connection",
                "provider": "google",
                "connection_id": "conn-1",
                "user_sub": "user-1",
                "active": True,
                "sync_health": "healthy",
                "last_sync_status": "success",
                "last_sync_error": "",
                "sync_cursor": "cursor-1",
                "reauth_required": False,
                "last_sync_at_utc": "2099-01-01T00:00:00Z",
                "updated_at_utc": "2099-01-01T00:00:00Z",
                "token_payload_redacted": {},
            }
        )

        with patch.object(svc, "T", SimpleNamespace(calendar=table)):
            out = svc.update_calendar_provider_connection_sync_status(
                user_sub="user-1",
                connection_id="conn-1",
                sync_health="healthy",
                last_sync_status="success",
                last_sync_error="",
                sync_cursor="cursor-1",
                reauth_required=False,
                last_sync_at_utc="2099-01-01T00:00:00Z",
            )

        self.assertEqual(out["sync_health"], "healthy")
        self.assertEqual(out["last_sync_status"], "success")

    def test_disconnect_marks_connection_inactive_and_audits(self):
        table = _FakeTable()
        table.put_item(
            Item={
                "calendar_id": "gcal_conn#user-1",
                "sk": "meta#google-primary",
                "type": "calendar_provider_connection",
                "provider": "google",
                "connection_id": "google-primary",
                "user_sub": "user-1",
                "account_email": "user@example.com",
                "active": True,
                "token_payload_redacted": {},
            }
        )

        with (
            patch.object(svc, "T", SimpleNamespace(calendar=table)),
            patch.object(svc, "emit_google_calendar_audit_event") as audit,
        ):
            out = svc.disconnect_calendar_provider_connection(
                user_sub="user-1",
                connection_id="google-primary",
                revoked=True,
                revoke_status="revoked",
            )

        stored = table.items[("gcal_conn#user-1", "meta#google-primary")]
        self.assertFalse(stored["active"])
        self.assertEqual(stored["revoke_status"], "revoked")
        self.assertFalse(out["active"])
        audit.assert_called_once()

    def test_missing_connection_returns_404(self):
        table = _FakeTable()
        with patch.object(svc, "T", SimpleNamespace(calendar=table)):
            with self.assertRaises(HTTPException):
                svc.get_calendar_provider_connection(user_sub="user-1", connection_id="missing", include_tokens=False)


if __name__ == "__main__":
    unittest.main()
