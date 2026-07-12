"""Hermetic offline tests for app/services/kyc_encryption.py.

Covers:
1. encrypt_fields happy path — encrypted value stored in DDB
2. decrypt_fields round-trip — encrypt then decrypt, verify original value
3. decrypt_fields writes audit log entry to DDB
4. mask_fields for document_number, date_of_birth, tax_id (pure function)
5. get_access_log returns list of audit entries for case
6. get_access_log by accessor_sub returns decrypts by actor
7. Attempting to decrypt when no DEK (keys destroyed) raises KycKeysDestroyedError
8. DEK caching: second call to encrypt_fields reuses the wrapped DEK (no re-generation)
9. Flag-off: when S.kyc_encryption_enabled is False, encrypt_fields still works
   (kyc_encryption_enabled gates the router, not the service directly); verify
   kyc_encryption_audit_enabled=False suppresses the audit write.

Test isolation:
* Real in-memory DynamoDB ``kyc_cases`` table via moto, bound to the frozen
  ``T.kyc_cases`` handle via ``object.__setattr__``.
* ``ENCRYPTION`` singleton's ``_table`` repointed to the same moto table.
* ``app.core.aws.kms`` patched with ``unittest.mock.patch`` to avoid real AWS calls.
* A real 32-byte DEK is used for AESGCM so crypto actually executes.
* ``S.kms_key_id`` set to a fake ARN; ``S.kyc_encryption_audit_enabled`` toggled
  per-test where needed.
"""
from __future__ import annotations

import base64
import os
import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import boto3

try:
    from moto import mock_aws
except ImportError:  # pragma: no cover
    mock_aws = None

from app.core.settings import S
from app.core.tables import T
import app.services.kyc_encryption as enc_mod
from app.services.kyc_encryption import (
    ENCRYPTION,
    KycEncryptionService,
    KycKeysDestroyedError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_KMS_KEY_ID = "arn:aws:kms:us-east-1:123456789012:key/fake-key-id"

# A real 32-byte key so AESGCM operations actually work.
_PLAINTEXT_DEK = os.urandom(32)
# Fake "ciphertext blob" (KMS wraps it in practice; here it's just opaque bytes).
_CIPHERTEXT_BLOB = os.urandom(32)


def _make_kms_mock() -> MagicMock:
    """Return a MagicMock that mimics the two KMS calls the service makes."""
    kms_mock = MagicMock()
    kms_mock.generate_data_key.return_value = {
        "Plaintext": _PLAINTEXT_DEK,
        "CiphertextBlob": _CIPHERTEXT_BLOB,
    }
    kms_mock.decrypt.return_value = {
        "Plaintext": _PLAINTEXT_DEK,
    }
    return kms_mock


def _make_kyc_cases_table(ddb):
    """Create a minimal kyc_cases table with the GSIs the service queries."""
    return ddb.create_table(
        TableName="kyc_cases",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gsi_owner_pk", "AttributeType": "S"},
            {"AttributeName": "gsi_owner_sk", "AttributeType": "S"},
            {"AttributeName": "gsi_pii_accessor_pk", "AttributeType": "S"},
            {"AttributeName": "gsi_pii_accessor_sk", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "owner-updated-index",
                "KeySchema": [
                    {"AttributeName": "gsi_owner_pk", "KeyType": "HASH"},
                    {"AttributeName": "gsi_owner_sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "pii-audit-accessor-index",
                "KeySchema": [
                    {"AttributeName": "gsi_pii_accessor_pk", "KeyType": "HASH"},
                    {"AttributeName": "gsi_pii_accessor_sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


# ---------------------------------------------------------------------------
# Base test class
# ---------------------------------------------------------------------------

class _KycEncryptionBase(unittest.TestCase):
    """Common setUp/tearDown: moto DDB + KMS patch + Settings fixup."""

    def setUp(self):
        if mock_aws is None:
            self.skipTest("moto not available")

        self._stack = ExitStack()
        self._stack.enter_context(mock_aws())

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_kyc_cases_table(ddb)

        # Patch T.kyc_cases → moto table
        self._orig_t_kyc = T.kyc_cases
        object.__setattr__(T, "kyc_cases", self.table)

        # Patch ENCRYPTION singleton's _table
        self._orig_enc_table = ENCRYPTION._table
        object.__setattr__(ENCRYPTION, "_table", self.table)

        # Settings: provide a fake KMS key id and enable audit
        self._orig_kms_key_id = S.kms_key_id
        self._orig_audit_enabled = S.kyc_encryption_audit_enabled
        self._orig_enc_enabled = S.kyc_encryption_enabled
        object.__setattr__(S, "kms_key_id", _FAKE_KMS_KEY_ID)
        object.__setattr__(S, "kyc_encryption_audit_enabled", True)
        object.__setattr__(S, "kyc_encryption_enabled", True)

        # Patch app.core.aws.kms
        self.kms_mock = _make_kms_mock()
        self._kms_patch = patch.object(enc_mod, "kms", self.kms_mock)
        self._kms_patch.start()

    def tearDown(self):
        self._kms_patch.stop()
        object.__setattr__(T, "kyc_cases", self._orig_t_kyc)
        object.__setattr__(ENCRYPTION, "_table", self._orig_enc_table)
        object.__setattr__(S, "kms_key_id", self._orig_kms_key_id)
        object.__setattr__(S, "kyc_encryption_audit_enabled", self._orig_audit_enabled)
        object.__setattr__(S, "kyc_encryption_enabled", self._orig_enc_enabled)
        self._stack.close()

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def _seed_case(self, user_sub: str, case_id: str) -> None:
        """Write a minimal KYC case META item so _iter_user_cases can find it."""
        self.table.put_item(Item={
            "pk": case_id,
            "sk": "META",
            "entity_type": "kyc_case",
            "case_id": case_id,
            "user_sub": user_sub,
            "gsi_owner_pk": f"OWNER#{user_sub}",
            "gsi_owner_sk": "0",
        })

    def _do_encrypt(
        self,
        user_sub: str = "user-alice",
        data: dict | None = None,
    ) -> tuple[dict, dict]:
        """Encrypt fields and return (encrypted_pii, hints)."""
        data = data or {"document_number": "AB1234567", "date_of_birth": "1990-04-15"}
        return ENCRYPTION.encrypt_fields(data=data, user_sub=user_sub)


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestEncryptFieldsHappyPath(_KycEncryptionBase):
    """Test 1: encrypt_fields stores the encrypted value in DDB."""

    def test_dek_written_to_ddb(self):
        user_sub = "user-test-enc"
        self._do_encrypt(user_sub=user_sub)

        # The DEK record should have been written under pk=USER_DEK#{sub}, sk=ACTIVE
        resp = self.table.get_item(Key={"pk": f"USER_DEK#{user_sub}", "sk": "ACTIVE"})
        item = resp.get("Item")
        self.assertIsNotNone(item)
        self.assertEqual(item["user_sub"], user_sub)
        self.assertIn("wrapped_dek", item)
        self.assertEqual(item["key_id"], _FAKE_KMS_KEY_ID)

    def test_encrypted_pii_dict_structure(self):
        encrypted_pii, hints = self._do_encrypt()

        self.assertIn("document_number", encrypted_pii)
        ef = encrypted_pii["document_number"]
        self.assertIn("ciphertext_b64", ef)
        self.assertEqual(ef["algorithm"], "AES-256-GCM")
        self.assertEqual(ef["field_name"], "document_number")
        self.assertIsInstance(ef["encrypted_at"], int)

    def test_hints_populated(self):
        encrypted_pii, hints = self._do_encrypt(
            data={"document_number": "AB1234567"}
        )
        self.assertIn("document_number", hints)
        # Masking rule for document_number: _mask_last4("****", v) → "****4567"
        self.assertEqual(hints["document_number"], "****4567")

    def test_kms_generate_data_key_called(self):
        self._do_encrypt()
        self.kms_mock.generate_data_key.assert_called_once_with(
            KeyId=_FAKE_KMS_KEY_ID, KeySpec="AES_256"
        )

    def test_empty_data_returns_empty_dicts(self):
        encrypted_pii, hints = ENCRYPTION.encrypt_fields(data={}, user_sub="user-x")
        self.assertEqual(encrypted_pii, {})
        self.assertEqual(hints, {})


class TestDecryptFieldsRoundTrip(_KycEncryptionBase):
    """Test 2: encrypt then decrypt yields the original plaintext value."""

    def test_round_trip_document_number(self):
        user_sub = "user-rt"
        plaintext_value = "AB1234567"
        encrypted_pii, _ = ENCRYPTION.encrypt_fields(
            data={"document_number": plaintext_value},
            user_sub=user_sub,
        )

        decrypted = ENCRYPTION.decrypt_fields(
            encrypted_data=encrypted_pii,
            accessor_sub="admin-sub",
            access_reason="compliance review",
            case_id="case-001",
            user_sub=user_sub,
            audit=False,  # skip audit for pure round-trip test
        )
        self.assertEqual(decrypted["document_number"], plaintext_value)

    def test_round_trip_multiple_fields(self):
        user_sub = "user-rt2"
        original = {
            "document_number": "XZ9876543",
            "date_of_birth": "1985-12-01",
            "tax_id": "123-45-6789",
        }
        encrypted_pii, _ = ENCRYPTION.encrypt_fields(data=original, user_sub=user_sub)

        decrypted = ENCRYPTION.decrypt_fields(
            encrypted_data=encrypted_pii,
            accessor_sub="admin-sub",
            access_reason="review",
            case_id="case-002",
            user_sub=user_sub,
            audit=False,
        )
        self.assertEqual(decrypted["document_number"], original["document_number"])
        self.assertEqual(decrypted["date_of_birth"], original["date_of_birth"])
        self.assertEqual(decrypted["tax_id"], original["tax_id"])

    def test_fields_filter_restricts_output(self):
        user_sub = "user-filt"
        encrypted_pii, _ = ENCRYPTION.encrypt_fields(
            data={"document_number": "AA1111111", "date_of_birth": "2000-01-01"},
            user_sub=user_sub,
        )
        decrypted = ENCRYPTION.decrypt_fields(
            encrypted_data=encrypted_pii,
            accessor_sub="admin-sub",
            access_reason="partial",
            case_id="case-003",
            user_sub=user_sub,
            fields=["document_number"],
            audit=False,
        )
        self.assertIn("document_number", decrypted)
        self.assertNotIn("date_of_birth", decrypted)

    def test_decrypt_empty_encrypted_data_returns_empty(self):
        decrypted = ENCRYPTION.decrypt_fields(
            encrypted_data={},
            accessor_sub="admin",
            access_reason="test",
            case_id="case-empty",
            user_sub="user-empty",
            audit=False,
        )
        self.assertEqual(decrypted, {})


class TestDecryptFieldsAuditLog(_KycEncryptionBase):
    """Test 3: decrypt_fields writes an audit log entry to DDB."""

    def test_audit_entry_written(self):
        user_sub = "user-audit"
        case_id = "case-audit-001"
        accessor = "admin-007"

        encrypted_pii, _ = ENCRYPTION.encrypt_fields(
            data={"document_number": "BB2222222"},
            user_sub=user_sub,
        )

        ENCRYPTION.decrypt_fields(
            encrypted_data=encrypted_pii,
            accessor_sub=accessor,
            access_reason="fraud investigation",
            case_id=case_id,
            user_sub=user_sub,
            ip_address="10.0.0.1",
            audit=True,
        )

        # Audit entry lives under pk=PII_AUDIT#{case_id}
        resp = self.table.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": f"PII_AUDIT#{case_id}"},
        )
        items = resp.get("Items", [])
        self.assertEqual(len(items), 1)
        entry = items[0]
        self.assertEqual(entry["accessor_sub"], accessor)
        self.assertEqual(entry["action"], "decrypt")
        self.assertIn("document_number", entry["fields"])
        self.assertEqual(entry["reason"], "fraud investigation")
        self.assertEqual(entry["ip_address"], "10.0.0.1")
        self.assertEqual(entry["case_id"], case_id)
        self.assertIsInstance(int(entry["created_at"]), int)

    def test_audit_suppressed_when_flag_off(self):
        """When kyc_encryption_audit_enabled=False, no audit row is written."""
        object.__setattr__(S, "kyc_encryption_audit_enabled", False)
        user_sub = "user-noaudit"
        case_id = "case-noaudit"

        encrypted_pii, _ = ENCRYPTION.encrypt_fields(
            data={"document_number": "CC3333333"},
            user_sub=user_sub,
        )
        ENCRYPTION.decrypt_fields(
            encrypted_data=encrypted_pii,
            accessor_sub="admin-x",
            access_reason="test",
            case_id=case_id,
            user_sub=user_sub,
            audit=True,
        )

        resp = self.table.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": f"PII_AUDIT#{case_id}"},
        )
        self.assertEqual(resp.get("Items", []), [])

    def test_audit_audit_false_suppresses_regardless_of_flag(self):
        """audit=False parameter always skips writing the audit row."""
        user_sub = "user-noaudit2"
        case_id = "case-noaudit2"

        encrypted_pii, _ = ENCRYPTION.encrypt_fields(
            data={"document_number": "DD4444444"},
            user_sub=user_sub,
        )
        ENCRYPTION.decrypt_fields(
            encrypted_data=encrypted_pii,
            accessor_sub="admin-y",
            access_reason="test",
            case_id=case_id,
            user_sub=user_sub,
            audit=False,
        )

        resp = self.table.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": f"PII_AUDIT#{case_id}"},
        )
        self.assertEqual(resp.get("Items", []), [])


class TestMaskFields(_KycEncryptionBase):
    """Test 4: mask_fields is pure (no KMS/DDB) and applies correct rules."""

    def _make_fake_encrypted_pii(self, *field_names):
        """Build a minimal encrypted_pii structure (ciphertext is fake; masking
        never reads ciphertext directly)."""
        return {
            fn: {
                "ciphertext_b64": base64.b64encode(b"fake").decode(),
                "key_id": _FAKE_KMS_KEY_ID,
                "algorithm": "AES-256-GCM",
                "encrypted_at": 0,
                "field_name": fn,
            }
            for fn in field_names
        }

    def test_document_number_masked_last4(self):
        enc_data = self._make_fake_encrypted_pii("document_number")
        hints = {"document_number": "****4567"}
        masked = ENCRYPTION.mask_fields(encrypted_data=enc_data, hints=hints)
        self.assertEqual(masked["document_number"], "****4567")

    def test_date_of_birth_masked_year_only(self):
        enc_data = self._make_fake_encrypted_pii("date_of_birth")
        hints = {"date_of_birth": "1990-**-**"}
        masked = ENCRYPTION.mask_fields(encrypted_data=enc_data, hints=hints)
        self.assertEqual(masked["date_of_birth"], "1990-**-**")

    def test_tax_id_masked_last4(self):
        enc_data = self._make_fake_encrypted_pii("tax_id")
        hints = {"tax_id": "***-**-6789"}
        masked = ENCRYPTION.mask_fields(encrypted_data=enc_data, hints=hints)
        self.assertEqual(masked["tax_id"], "***-**-6789")

    def test_mask_uses_hint_when_present(self):
        enc_data = self._make_fake_encrypted_pii("document_number")
        hints = {"document_number": "precomputed-hint"}
        masked = ENCRYPTION.mask_fields(encrypted_data=enc_data, hints=hints)
        self.assertEqual(masked["document_number"], "precomputed-hint")

    def test_mask_falls_back_when_hint_missing(self):
        """Without a hint, mask_fields calls the rule with empty string."""
        enc_data = self._make_fake_encrypted_pii("bank_routing_number")
        # bank_routing_number rule always returns "*********" regardless of value
        masked = ENCRYPTION.mask_fields(encrypted_data=enc_data, hints={})
        self.assertEqual(masked["bank_routing_number"], "*********")

    def test_mask_no_kms_call(self):
        enc_data = self._make_fake_encrypted_pii("document_number", "tax_id")
        ENCRYPTION.mask_fields(encrypted_data=enc_data, hints={})
        self.kms_mock.generate_data_key.assert_not_called()
        self.kms_mock.decrypt.assert_not_called()

    def test_mask_hint_computed_correctly_at_write_time(self):
        """Verify _make_hint produces the right values for known inputs."""
        from app.services.kyc_encryption import _make_hint
        self.assertEqual(_make_hint("document_number", "AB1234567"), "****4567")
        self.assertEqual(_make_hint("date_of_birth", "1990-04-15"), "1990-**-**")
        self.assertEqual(_make_hint("tax_id", "123-45-6789"), "***-**-6789")
        self.assertEqual(_make_hint("bank_routing_number", "anything"), "*********")
        self.assertEqual(_make_hint("full_ssn", "123456789"), "***-**-6789")
        self.assertEqual(_make_hint("passport_mrz", "xyz"), "***...***")


class TestGetAccessLogByCase(_KycEncryptionBase):
    """Test 5: get_access_log returns audit entries for a given case."""

    def test_returns_entries_for_case(self):
        case_id = "case-log-001"
        accessor = "admin-log"

        ENCRYPTION.log_access(
            accessor_sub=accessor,
            case_id=case_id,
            fields_accessed=["document_number"],
            reason="routine check",
            action="decrypt",
        )
        ENCRYPTION.log_access(
            accessor_sub=accessor,
            case_id=case_id,
            fields_accessed=["tax_id"],
            reason="audit",
            action="decrypt",
        )

        result = ENCRYPTION.get_access_log(case_id=case_id)
        events = result["events"]
        self.assertEqual(len(events), 2)
        field_sets = [set(e["fields"]) for e in events]
        self.assertIn({"document_number"}, field_sets)
        self.assertIn({"tax_id"}, field_sets)

    def test_returns_empty_for_nonexistent_case(self):
        result = ENCRYPTION.get_access_log(case_id="case-does-not-exist")
        self.assertEqual(result["events"], [])

    def test_event_shape(self):
        case_id = "case-shape"
        ENCRYPTION.log_access(
            accessor_sub="admin-shape",
            case_id=case_id,
            fields_accessed=["document_number", "date_of_birth"],
            reason="test-reason",
            action="decrypt",
            ip_address="192.168.1.1",
        )
        result = ENCRYPTION.get_access_log(case_id=case_id)
        ev = result["events"][0]
        self.assertIn("event_id", ev)
        self.assertEqual(ev["accessor_sub"], "admin-shape")
        self.assertEqual(ev["action"], "decrypt")
        self.assertEqual(set(ev["fields"]), {"document_number", "date_of_birth"})
        self.assertEqual(ev["reason"], "test-reason")
        self.assertEqual(ev["ip_address"], "192.168.1.1")
        self.assertIsInstance(ev["created_at"], int)

    def test_no_filter_returns_empty(self):
        result = ENCRYPTION.get_access_log()
        self.assertEqual(result["events"], [])


class TestGetAccessLogByAccessor(_KycEncryptionBase):
    """Test 6: get_access_log(accessor_sub=...) returns decrypts by that actor."""

    def test_returns_entries_for_accessor(self):
        accessor = "admin-accessor-001"
        ENCRYPTION.log_access(
            accessor_sub=accessor,
            case_id="case-A",
            fields_accessed=["document_number"],
            reason="review",
            action="decrypt",
        )
        ENCRYPTION.log_access(
            accessor_sub=accessor,
            case_id="case-B",
            fields_accessed=["tax_id"],
            reason="audit",
            action="decrypt",
        )
        # Unrelated accessor — should NOT appear
        ENCRYPTION.log_access(
            accessor_sub="admin-other",
            case_id="case-C",
            fields_accessed=["full_ssn"],
            reason="other",
            action="decrypt",
        )

        result = ENCRYPTION.get_access_log(accessor_sub=accessor)
        events = result["events"]
        self.assertEqual(len(events), 2)
        for ev in events:
            self.assertEqual(ev["accessor_sub"], accessor)

    def test_empty_for_unknown_accessor(self):
        result = ENCRYPTION.get_access_log(accessor_sub="nobody")
        self.assertEqual(result["events"], [])


class TestDecryptWithNoKeys(_KycEncryptionBase):
    """Test 7: decrypt_fields raises KycKeysDestroyedError when the DEK is gone."""

    def test_raises_when_no_dek(self):
        user_sub = "user-no-dek"
        # Build a plausible (but fake) encrypted_pii without writing a DEK
        fake_enc = {
            "document_number": {
                "ciphertext_b64": base64.b64encode(b"x" * 40).decode(),
                "key_id": _FAKE_KMS_KEY_ID,
                "algorithm": "AES-256-GCM",
                "encrypted_at": 1000,
                "field_name": "document_number",
            }
        }
        with self.assertRaises(KycKeysDestroyedError):
            ENCRYPTION.decrypt_fields(
                encrypted_data=fake_enc,
                accessor_sub="admin",
                access_reason="test",
                case_id="case-nodek",
                user_sub=user_sub,
                audit=False,
            )

    def test_raises_after_destroy_user_keys(self):
        """encrypt then destroy DEK then decrypt raises KycKeysDestroyedError."""
        user_sub = "user-destroyed"
        encrypted_pii, _ = ENCRYPTION.encrypt_fields(
            data={"document_number": "EE5555555"},
            user_sub=user_sub,
        )
        ENCRYPTION.destroy_user_keys(user_sub=user_sub)

        with self.assertRaises(KycKeysDestroyedError):
            ENCRYPTION.decrypt_fields(
                encrypted_data=encrypted_pii,
                accessor_sub="admin",
                access_reason="should-fail",
                case_id="case-destroyed",
                user_sub=user_sub,
                audit=False,
            )


class TestDekCaching(_KycEncryptionBase):
    """Test 8: second call to encrypt_fields reuses the existing wrapped DEK."""

    def test_generate_data_key_called_only_once(self):
        user_sub = "user-dek-cache"

        # First encrypt — should call generate_data_key once
        ENCRYPTION.encrypt_fields(
            data={"document_number": "FF6666666"},
            user_sub=user_sub,
        )
        first_call_count = self.kms_mock.generate_data_key.call_count
        self.assertEqual(first_call_count, 1)

        # Second encrypt for the same user — DEK already exists in DDB, so
        # generate_data_key should NOT be called again
        ENCRYPTION.encrypt_fields(
            data={"tax_id": "111-22-3333"},
            user_sub=user_sub,
        )
        # Still only one call to generate_data_key
        self.assertEqual(self.kms_mock.generate_data_key.call_count, 1)
        # But kms.decrypt is called each time to unwrap (no in-memory cache)
        self.assertGreaterEqual(self.kms_mock.decrypt.call_count, 1)

    def test_dek_record_present_after_first_encrypt(self):
        user_sub = "user-dek-cache2"
        ENCRYPTION.encrypt_fields(
            data={"document_number": "GG7777777"},
            user_sub=user_sub,
        )
        # Confirm exactly one ACTIVE DEK record exists
        rec = self.table.get_item(
            Key={"pk": f"USER_DEK#{user_sub}", "sk": "ACTIVE"}
        ).get("Item")
        self.assertIsNotNone(rec)
        # Second encrypt doesn't create a duplicate
        ENCRYPTION.encrypt_fields(
            data={"tax_id": "444-55-6666"},
            user_sub=user_sub,
        )
        rec2 = self.table.get_item(
            Key={"pk": f"USER_DEK#{user_sub}", "sk": "ACTIVE"}
        ).get("Item")
        # Same wrapped_dek (not regenerated)
        self.assertEqual(rec["wrapped_dek"], rec2["wrapped_dek"])


class TestAuditEnabledFlag(_KycEncryptionBase):
    """Test 9: kyc_encryption_audit_enabled flag controls audit writes."""

    def test_audit_written_when_enabled(self):
        object.__setattr__(S, "kyc_encryption_audit_enabled", True)
        user_sub = "user-flag-on"
        case_id = "case-flag-on"

        encrypted_pii, _ = ENCRYPTION.encrypt_fields(
            data={"document_number": "HH8888888"},
            user_sub=user_sub,
        )
        ENCRYPTION.decrypt_fields(
            encrypted_data=encrypted_pii,
            accessor_sub="admin-flag-on",
            access_reason="review",
            case_id=case_id,
            user_sub=user_sub,
            audit=True,
        )

        resp = self.table.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": f"PII_AUDIT#{case_id}"},
        )
        self.assertGreater(len(resp.get("Items", [])), 0)

    def test_audit_NOT_written_when_flag_off(self):
        object.__setattr__(S, "kyc_encryption_audit_enabled", False)
        user_sub = "user-flag-off"
        case_id = "case-flag-off"

        encrypted_pii, _ = ENCRYPTION.encrypt_fields(
            data={"document_number": "II9999999"},
            user_sub=user_sub,
        )
        ENCRYPTION.decrypt_fields(
            encrypted_data=encrypted_pii,
            accessor_sub="admin-flag-off",
            access_reason="review",
            case_id=case_id,
            user_sub=user_sub,
            audit=True,  # requested, but flag overrides
        )

        resp = self.table.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": f"PII_AUDIT#{case_id}"},
        )
        self.assertEqual(resp.get("Items", []), [])


class TestGenerateUserDekAndRotation(_KycEncryptionBase):
    """Additional coverage: generate_user_dek, rotate_user_dek, destroy_user_keys."""

    def test_generate_user_dek_stores_item(self):
        user_sub = "user-gen-dek"
        rec = ENCRYPTION.generate_user_dek(user_sub=user_sub)
        self.assertEqual(rec["sk"], "ACTIVE")
        self.assertEqual(rec["entity_type"], "kyc_user_dek")
        stored = self.table.get_item(
            Key={"pk": f"USER_DEK#{user_sub}", "sk": "ACTIVE"}
        ).get("Item")
        self.assertIsNotNone(stored)
        # wrapped_dek is base64 of the fake ciphertext blob
        self.assertEqual(
            stored["wrapped_dek"],
            base64.b64encode(_CIPHERTEXT_BLOB).decode("ascii"),
        )

    def test_rotate_user_dek_archives_old(self):
        user_sub = "user-rotate"
        # First generate a DEK
        ENCRYPTION.generate_user_dek(user_sub=user_sub)
        old_wrapped = self.table.get_item(
            Key={"pk": f"USER_DEK#{user_sub}", "sk": "ACTIVE"}
        )["Item"]["wrapped_dek"]

        # Rotate
        result = ENCRYPTION.rotate_user_dek(user_sub=user_sub)
        self.assertEqual(result["new_version"], 2)

        # Old DEK should be archived under ROTATED#000001
        archived = self.table.get_item(
            Key={"pk": f"USER_DEK#{user_sub}", "sk": "ROTATED#000001"}
        ).get("Item")
        self.assertIsNotNone(archived)
        self.assertEqual(archived["wrapped_dek"], old_wrapped)
        self.assertEqual(archived["version"], 1)

        # New ACTIVE should have version=2
        new_active = self.table.get_item(
            Key={"pk": f"USER_DEK#{user_sub}", "sk": "ACTIVE"}
        ).get("Item")
        self.assertEqual(new_active["version"], 2)

    def test_destroy_user_keys_removes_dek(self):
        user_sub = "user-destroy"
        ENCRYPTION.generate_user_dek(user_sub=user_sub)
        result = ENCRYPTION.destroy_user_keys(user_sub=user_sub)
        self.assertEqual(result["keys_destroyed"], 1)

        # ACTIVE record should be gone
        item = self.table.get_item(
            Key={"pk": f"USER_DEK#{user_sub}", "sk": "ACTIVE"}
        ).get("Item")
        self.assertIsNone(item)

    def test_destroy_user_keys_idempotent(self):
        user_sub = "user-destroy2"
        ENCRYPTION.generate_user_dek(user_sub=user_sub)
        ENCRYPTION.destroy_user_keys(user_sub=user_sub)
        # Second destroy should return 0
        result = ENCRYPTION.destroy_user_keys(user_sub=user_sub)
        self.assertEqual(result["keys_destroyed"], 0)

    def test_generate_dek_raises_without_kms_key_id(self):
        object.__setattr__(S, "kms_key_id", "")
        from app.services.kyc_encryption import KycEncryptionError
        with self.assertRaises(KycEncryptionError) as ctx:
            ENCRYPTION.generate_user_dek(user_sub="user-no-key")
        self.assertIn("kms_key_id_not_set", str(ctx.exception))


class TestLogAccessDirect(_KycEncryptionBase):
    """Direct test of log_access and _audit_item_to_event."""

    def test_log_access_writes_complete_item(self):
        entry = ENCRYPTION.log_access(
            accessor_sub="admin-direct",
            case_id="case-direct",
            fields_accessed=["document_number", "tax_id"],
            reason="compliance",
            action="decrypt",
            ip_address="10.1.2.3",
        )
        self.assertIn("event_id", entry)
        self.assertTrue(entry["event_id"].startswith("evt_"))
        self.assertEqual(entry["case_id"], "case-direct")
        self.assertEqual(entry["action"], "decrypt")
        self.assertIn("document_number", entry["fields"])
        self.assertEqual(entry["gsi_pii_accessor_pk"], "admin-direct")
        self.assertIsInstance(entry["gsi_pii_accessor_sk"], int)

    def test_audit_item_to_event_shape(self):
        raw = {
            "event_id": "evt_abc123",
            "accessor_sub": "admin1",
            "accessor_display_name": "Admin One",
            "action": "decrypt",
            "fields": ["tax_id"],
            "reason": "legal hold",
            "ip_address": "1.2.3.4",
            "created_at": 1700000000,
        }
        ev = KycEncryptionService._audit_item_to_event(raw)
        self.assertEqual(ev["event_id"], "evt_abc123")
        self.assertEqual(ev["accessor_sub"], "admin1")
        self.assertEqual(ev["action"], "decrypt")
        self.assertEqual(ev["fields"], ["tax_id"])
        self.assertEqual(ev["created_at"], 1700000000)


if __name__ == "__main__":
    unittest.main()
