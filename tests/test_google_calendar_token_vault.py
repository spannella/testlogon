from __future__ import annotations

import base64
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.services import google_calendar_token_vault as vault


class _FakeKms:
    def __init__(self):
        self._data_key = b"k" * 32

    def generate_data_key(self, KeyId, KeySpec, EncryptionContext):
        assert KeySpec == "AES_256"
        assert EncryptionContext["service"] == "google_calendar"
        return {
            "Plaintext": self._data_key,
            "CiphertextBlob": b"encrypted-data-key",
        }

    def decrypt(self, CiphertextBlob, EncryptionContext):
        assert EncryptionContext["scope"] == "oauth_tokens"
        if CiphertextBlob != b"encrypted-data-key":
            raise ValueError("invalid key blob")
        return {"Plaintext": self._data_key}


class TestGoogleCalendarTokenVault(unittest.TestCase):
    def test_encrypt_decrypt_round_trip(self):
        fake_kms = _FakeKms()
        payload = {
            "access_token": "access-1",
            "refresh_token": "refresh-1",
            "expiry": "2026-01-01T00:00:00Z",
            "scope": "calendar.events",
        }

        with (
            patch.object(vault, "kms_client", return_value=fake_kms),
            patch.object(vault, "S") as settings,
        ):
            settings.google_calendar_tokens_kms_key_id = "alias/google-calendar"
            settings.kms_key_id = ""

            encrypted = vault.encrypt_token_payload(payload=payload, user_sub="user-1", connection_id="conn-1")
            decrypted = vault.decrypt_token_payload(
                encrypted=encrypted,
                user_sub="user-1",
                connection_id="conn-1",
            )

        self.assertEqual(decrypted, payload)
        self.assertEqual(encrypted["kms_key_id"], "alias/google-calendar")
        self.assertTrue(encrypted["encrypted_at_utc"].endswith("Z"))
        base64.b64decode(encrypted["secret_ciphertext_b64"])

    def test_kms_key_falls_back_to_global_kms_key_id(self):
        with patch.object(vault, "S") as settings:
            settings.google_calendar_tokens_kms_key_id = ""
            settings.kms_key_id = "alias/global-default"
            self.assertEqual(vault._kms_key_id(), "alias/global-default")

    def test_kms_key_missing_fails_closed(self):
        with patch.object(vault, "S") as settings:
            settings.google_calendar_tokens_kms_key_id = ""
            settings.kms_key_id = ""
            with self.assertRaises(HTTPException):
                vault._kms_key_id()

    def test_redact_token_payload_masks_sensitive_fields(self):
        payload = {
            "access_token": "a",
            "refresh_token": "b",
            "id_token": "c",
            "scope": "calendar.events",
            "expiry": "2026-01-01T00:00:00Z",
        }
        redacted = vault.redact_token_payload(payload)
        self.assertEqual(redacted["access_token"], "[REDACTED]")
        self.assertEqual(redacted["refresh_token"], "[REDACTED]")
        self.assertEqual(redacted["id_token"], "[REDACTED]")
        self.assertEqual(redacted["scope"], "calendar.events")

    def test_rotate_payload_reencrypts_and_preserves_content(self):
        fake_kms = _FakeKms()
        payload = {"access_token": "access", "refresh_token": "refresh"}

        with (
            patch.object(vault, "kms_client", return_value=fake_kms),
            patch.object(vault, "S") as settings,
        ):
            settings.google_calendar_tokens_kms_key_id = "alias/google-calendar-v1"
            settings.kms_key_id = ""
            encrypted_v1 = vault.encrypt_token_payload(payload=payload, user_sub="user-1", connection_id="conn-1")

            settings.google_calendar_tokens_kms_key_id = "alias/google-calendar-v2"
            encrypted_v2 = vault.rotate_encrypted_token_payload(
                encrypted=encrypted_v1,
                user_sub="user-1",
                connection_id="conn-1",
            )
            decrypted_v2 = vault.decrypt_token_payload(encrypted=encrypted_v2, user_sub="user-1", connection_id="conn-1")

        self.assertEqual(decrypted_v2, payload)
        self.assertEqual(encrypted_v2["kms_key_id"], "alias/google-calendar-v2")


if __name__ == "__main__":
    unittest.main()
