from __future__ import annotations

import unittest
from unittest.mock import patch

from app.services import google_calendar_audit as svc


class TestGoogleCalendarAudit(unittest.TestCase):
    def test_sanitize_redacts_sensitive_keys(self):
        payload = svc.sanitize_audit_payload(
            {
                "access_token": "abc",
                "client_secret": "def",
                "nested": {"authorization": "Bearer xyz", "ok": "value"},
                "kms_key_id": "alias/something",
            }
        )
        self.assertEqual(payload["access_token"], "[REDACTED]")
        self.assertEqual(payload["client_secret"], "[REDACTED]")
        self.assertEqual(payload["nested"]["authorization"], "[REDACTED]")
        self.assertEqual(payload["nested"]["ok"], "value")
        self.assertEqual(payload["kms_key_id"], "[REDACTED]")

    def test_emit_uses_sanitized_fields_and_context(self):
        with patch.object(svc, "audit_event") as audit:
            svc.emit_google_calendar_audit_event(
                event="google_calendar_connected",
                actor_user_sub="user-1",
                outcome="success",
                target_type="connection",
                target_id="conn-1",
                refresh_token="secret-token",
            )

        args, kwargs = audit.call_args
        self.assertEqual(args[0], "google_calendar_connected")
        self.assertEqual(args[1], "user-1")
        self.assertEqual(kwargs["actor_sub"], "user-1")
        self.assertEqual(kwargs["target_type"], "connection")
        self.assertEqual(kwargs["target_id"], "conn-1")
        self.assertEqual(kwargs["refresh_token"], "[REDACTED]")

    def test_sanitize_redacts_sensitive_values_for_non_sensitive_keys(self):
        payload = svc.sanitize_audit_payload(
            {
                "context": "Authorization: Bearer abc123.token.value",
                "error": "refresh_token=def456",
                "provider_message": "google says token ya29.a0ARrdaMEXAMPLE expired",
            }
        )
        self.assertIn("[REDACTED]", payload["context"])
        self.assertIn("[REDACTED]", payload["error"])
        self.assertIn("[REDACTED]", payload["provider_message"])

    def test_sanitize_applies_value_redaction_in_nested_lists(self):
        payload = svc.sanitize_audit_payload(
            {
                "events": [
                    {"message": "Bearer nested-token-value"},
                    {"message": "safe message"},
                ]
            }
        )
        self.assertEqual(payload["events"][0]["message"], "[REDACTED]")
        self.assertEqual(payload["events"][1]["message"], "safe message")


if __name__ == "__main__":
    unittest.main()
