import base64
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.services import sftp_credentials


class _FakeTable:
    def __init__(self):
        self.items = {}

    def get_item(self, Key, ConsistentRead=False):
        item = self.items.get((Key["PK"], Key["SK"]))
        return {"Item": dict(item)} if item else {}

    def put_item(self, Item):
        self.items[(Item["PK"], Item["SK"])] = dict(Item)

    def delete_item(self, Key):
        self.items.pop((Key["PK"], Key["SK"]), None)


class _FakeDdb:
    def __init__(self, table):
        self._table = table

    def Table(self, name):
        return self._table


class _FakeKms:
    def __init__(self):
        self._data_key = b"k" * 32

    def generate_data_key(self, KeyId, KeySpec, EncryptionContext):
        assert KeySpec == "AES_256"
        return {
            "Plaintext": self._data_key,
            "CiphertextBlob": b"encrypted-data-key",
        }

    def decrypt(self, CiphertextBlob, EncryptionContext):
        if CiphertextBlob != b"encrypted-data-key":
            raise ValueError("bad ciphertext blob")
        return {"Plaintext": self._data_key}


class TestSftpCredentialsService(unittest.TestCase):
    def test_upsert_password_auth_stores_only_ciphertext_fields(self):
        table = _FakeTable()
        fake_ddb = _FakeDdb(table)
        fake_kms = _FakeKms()

        with (
            patch.object(sftp_credentials, "ddb", fake_ddb),
            patch.object(sftp_credentials, "kms_client", return_value=fake_kms),
            patch.object(sftp_credentials, "audit_event") as audit,
            patch.object(sftp_credentials, "S") as settings,
        ):
            settings.filemgr_sftp_credentials_table_name = "sftp_credentials"
            settings.filemgr_sftp_credentials_kms_key_id = "alias/sftp-creds"
            settings.kms_key_id = ""

            out = sftp_credentials.upsert_sftp_credential(
                owner="user-1",
                mount_id="mnt-1",
                auth_mode="password",
                username="alice",
                password="super-secret",
            )

        key = ("OWNER#user-1", "SFTP_CRED#mnt-1")
        stored = table.items[key]
        self.assertEqual(out["auth_mode"], "password")
        self.assertNotIn("password", stored)
        self.assertIn("secret_ciphertext_b64", stored)
        self.assertIn("key_encrypted_b64", stored)
        self.assertIn("nonce_b64", stored)
        self.assertIn("aad_b64", stored)
        self.assertEqual(stored["kms_key_id"], "alias/sftp-creds")
        self.assertNotEqual(stored["secret_ciphertext_b64"], "super-secret")
        base64.b64decode(stored["secret_ciphertext_b64"])
        audit.assert_called_once()
        self.assertEqual(audit.call_args.args[0], "filemgr_sftp_credential_upserted")
        self.assertTrue(audit.call_args.kwargs.get("secret_redacted"))

    def test_private_key_auth_round_trip_decrypts_secret(self):
        table = _FakeTable()
        fake_ddb = _FakeDdb(table)
        fake_kms = _FakeKms()

        with (
            patch.object(sftp_credentials, "ddb", fake_ddb),
            patch.object(sftp_credentials, "kms_client", return_value=fake_kms),
            patch.object(sftp_credentials, "audit_event"),
            patch.object(sftp_credentials, "S") as settings,
        ):
            settings.filemgr_sftp_credentials_table_name = "sftp_credentials"
            settings.filemgr_sftp_credentials_kms_key_id = "alias/sftp-creds"
            settings.kms_key_id = ""

            sftp_credentials.upsert_sftp_credential(
                owner="user-1",
                mount_id="mnt-2",
                auth_mode="private_key",
                username="alice",
                private_key="---BEGIN---\nabc\n---END---",
                private_key_passphrase="open-sesame",
            )
            loaded = sftp_credentials.get_sftp_credential(owner="user-1", mount_id="mnt-2", include_secret=True)

        self.assertEqual(loaded["auth_mode"], "private_key")
        self.assertEqual(loaded["secret"]["private_key"], "---BEGIN---\nabc\n---END---")
        self.assertEqual(loaded["secret"]["private_key_passphrase"], "open-sesame")

    def test_missing_table_or_key_configuration_fails_closed(self):
        with patch.object(sftp_credentials, "S") as settings:
            settings.filemgr_sftp_credentials_table_name = ""
            settings.filemgr_sftp_credentials_kms_key_id = ""
            settings.kms_key_id = ""
            with self.assertRaises(HTTPException):
                sftp_credentials._table()
            with self.assertRaises(HTTPException):
                sftp_credentials._kms_key_id()

    def test_credential_audit_events_are_redacted(self):
        table = _FakeTable()
        fake_ddb = _FakeDdb(table)
        fake_kms = _FakeKms()

        with (
            patch.object(sftp_credentials, "ddb", fake_ddb),
            patch.object(sftp_credentials, "kms_client", return_value=fake_kms),
            patch.object(sftp_credentials, "audit_event") as audit,
            patch.object(sftp_credentials, "S") as settings,
        ):
            settings.filemgr_sftp_credentials_table_name = "sftp_credentials"
            settings.filemgr_sftp_credentials_kms_key_id = "alias/sftp-creds"
            settings.kms_key_id = ""

            sftp_credentials.upsert_sftp_credential(owner="user-1", mount_id="mnt-3", auth_mode="password", username="alice", password="pw")
            sftp_credentials.get_sftp_credential(owner="user-1", mount_id="mnt-3", include_secret=True)
            sftp_credentials.delete_sftp_credential(owner="user-1", mount_id="mnt-3")

        event_names = [c.args[0] for c in audit.call_args_list]
        self.assertIn("filemgr_sftp_credential_upserted", event_names)
        self.assertIn("filemgr_sftp_credential_accessed", event_names)
        self.assertIn("filemgr_sftp_credential_deleted", event_names)
        self.assertTrue(all(c.kwargs.get("secret_redacted") is True for c in audit.call_args_list))


if __name__ == "__main__":
    unittest.main()
