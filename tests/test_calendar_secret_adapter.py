from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from app.services.calendar_integrations import secret_adapter


class TestCalendarSecretAdapter(unittest.TestCase):
    def test_put_secret_create_returns_stable_reference(self):
        table = MagicMock()
        table.get_item.return_value = {}

        adapter = secret_adapter.DynamoCalendarSecretAdapter()
        with (
            patch.object(secret_adapter, "_secrets_table", return_value=table),
            patch.object(secret_adapter, "_encrypt", return_value="ciphertext"),
            patch.object(secret_adapter.uuid, "uuid4") as uuid4,
        ):
            uuid4.return_value.hex = "abc123"
            out = adapter.put_secret(
                provider="apple_caldav",
                secret_payload={"username": "u", "app_specific_password": "p"},
                tags={"integration": "calendar"},
            )

        self.assertEqual(out["credential_ref"], "cred_abc123")
        self.assertEqual(out["version"], 1)
        table.put_item.assert_called_once()

    def test_put_secret_update_keeps_same_reference_and_increments_version(self):
        table = MagicMock()
        table.get_item.return_value = {
            "Item": {
                "credential_ref": "cred_fixed",
                "version": 1,
                "created_at": "2026-01-01T00:00:00+00:00",
            }
        }

        adapter = secret_adapter.DynamoCalendarSecretAdapter()
        with (
            patch.object(secret_adapter, "_secrets_table", return_value=table),
            patch.object(secret_adapter, "_encrypt", return_value="ciphertext"),
        ):
            out = adapter.put_secret(
                provider="apple_caldav",
                credential_ref="cred_fixed",
                secret_payload={"username": "u2", "app_specific_password": "p2"},
                tags={"integration": "calendar"},
            )

        self.assertEqual(out["credential_ref"], "cred_fixed")
        self.assertEqual(out["version"], 2)

    def test_delete_secret_removes_reference(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": {"credential_ref": "cred_fixed"}}

        adapter = secret_adapter.DynamoCalendarSecretAdapter()
        with patch.object(secret_adapter, "_secrets_table", return_value=table):
            deleted = adapter.delete_secret(credential_ref="cred_fixed")

        self.assertTrue(deleted)
        table.delete_item.assert_called_once_with(Key={"credential_ref": "cred_fixed"})

    def test_get_secret_returns_decrypted_payload_and_metadata(self):
        table = MagicMock()
        table.get_item.return_value = {
            "Item": {
                "credential_ref": "cred_fixed",
                "provider": "apple_caldav",
                "tags": {"integration": "calendar"},
                "version": 3,
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-02T00:00:00+00:00",
                "secret_ct_b64": "ciphertext",
            }
        }

        adapter = secret_adapter.DynamoCalendarSecretAdapter()
        with (
            patch.object(secret_adapter, "_secrets_table", return_value=table),
            patch.object(secret_adapter, "_decrypt", return_value=b'{"username":"u","app_specific_password":"p"}'),
        ):
            out = adapter.get_secret(credential_ref="cred_fixed")

        self.assertIsNotNone(out)
        self.assertEqual(out["credential_ref"], "cred_fixed")
        self.assertEqual(out["version"], 3)
        self.assertEqual(out["secret_payload"]["username"], "u")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
