from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from app.services.calendar_integrations import credentials, logging_safety, secret_adapter


class TestCalendarLoggingSafety(unittest.TestCase):
    def test_redact_sensitive_masks_nested_sensitive_keys(self):
        payload = {
            "user": "u",
            "auth_header": "Basic abc",
            "nested": {
                "app_specific_password": "pw",
                "token": "tok",
                "ok": "value",
            },
        }

        redacted = logging_safety.redact_sensitive(payload)
        self.assertEqual(redacted["auth_header"], logging_safety.REDACTED)
        self.assertEqual(redacted["nested"]["app_specific_password"], logging_safety.REDACTED)
        self.assertEqual(redacted["nested"]["token"], logging_safety.REDACTED)
        self.assertEqual(redacted["nested"]["ok"], "value")

    def test_credentials_logging_never_emits_plaintext_password(self):
        connections = MagicMock()
        connections.get_item.return_value = {}

        adapter = MagicMock()
        adapter.put_secret.return_value = {
            "credential_ref": "cred_fixed",
            "version": 1,
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        }

        with (
            patch.object(credentials, "_connections_table", return_value=connections),
            patch.object(credentials, "get_calendar_secret_adapter", return_value=adapter),
            self.assertLogs("app.services.calendar_integrations.credentials", level="INFO") as cm,
        ):
            credentials.upsert_apple_caldav_credential(
                user_sub="user-1",
                username="user@example.com",
                app_specific_password="super-secret",
                credential_validation_status="valid",
            )

        logged = [getattr(record, "calendar", {}) for record in cm.records]
        self.assertTrue(logged)
        flat = str(logged)
        self.assertNotIn("super-secret", flat)
        self.assertNotIn("Basic ...", flat)
        self.assertIn(logging_safety.REDACTED, flat)

    def test_secret_adapter_logging_never_emits_plaintext_secret_payload(self):
        table = MagicMock()
        table.get_item.return_value = {}

        adapter = secret_adapter.DynamoCalendarSecretAdapter()
        with (
            patch.object(secret_adapter, "_secrets_table", return_value=table),
            patch.object(secret_adapter, "_encrypt", return_value="ciphertext"),
            self.assertLogs("app.services.calendar_integrations.secret_adapter", level="INFO") as cm,
        ):
            adapter.put_secret(
                provider="apple_caldav",
                secret_payload={"username": "user@example.com", "app_specific_password": "super-secret"},
                tags={"integration": "calendar"},
            )

        logged = [getattr(record, "calendar", {}) for record in cm.records]
        self.assertTrue(logged)
        flat = str(logged)
        self.assertNotIn("super-secret", flat)
        self.assertIn(logging_safety.REDACTED, flat)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
