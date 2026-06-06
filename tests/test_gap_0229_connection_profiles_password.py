"""Offline regression tests for GAP-0229 (INFRA-006 / SEC-022 surface).

The Connection Profiles service (``app/services/connection_profiles.py``)
accepts ``auth_method="password"`` but historically had no way to store a
password, and any naive future implementation risked returning plaintext or the
ciphertext blob in API output. The fix:

  * accepts optional ``vnc_password`` / ``ssh_password`` on create and
    ``password`` / ``clear_password`` on update;
  * KMS-encrypts the plaintext before writing it to DynamoDB as ``password_enc``
    (using ``app.core.crypto.kms_encrypt``);
  * never returns the plaintext or the ciphertext from ``_item_to_profile`` —
    only a ``has_password: bool`` flag;
  * decrypts the password in ``quick_connect`` for the in-process terminal layer
    as ``password_resolved`` (which the router strips before serialization).

TEST ISOLATION
--------------
Fully offline and hermetic. There is **no** moto / ``@mock_aws`` interception
(which can leak to real AWS) and **no** real KMS:

  * DynamoDB is replaced by a tiny in-memory fake table object, patched onto the
    frozen ``T`` dataclass via ``object.__setattr__`` (``T`` is frozen).
  * ``kms_encrypt`` / ``kms_decrypt`` are monkeypatched on the
    ``connection_profiles`` module with deterministic fakes — the real KMS
    client is never touched.
  * The frozen ``S`` settings dataclass gets a fake ``kms_key_id`` via
    ``object.__setattr__`` so the KMS-configured guard passes.

Each test is self-contained (it builds its own service handle + fake table) so
it passes both alone and interleaved with other gap test files.
"""
from __future__ import annotations

import unittest
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Minimal in-memory DynamoDB table fake (no moto / no AWS)
# ---------------------------------------------------------------------------

class _FakeTable:
    """In-memory stand-in for a boto3 DynamoDB Table.

    Implements only the operations exercised by connection_profiles:
    get_item, put_item, query (PK eq + sk begins_with), update_item (simple
    ``SET a = :v`` expressions with optional ExpressionAttributeNames).
    Keyed on (user_sub, sk).
    """

    def __init__(self) -> None:
        self.items: Dict[tuple, Dict[str, Any]] = {}

    @staticmethod
    def _k(key: Dict[str, Any]) -> tuple:
        return (key["user_sub"], key["sk"])

    def get_item(self, Key: Dict[str, Any]) -> Dict[str, Any]:
        item = self.items.get(self._k(Key))
        return {"Item": dict(item)} if item is not None else {}

    def put_item(self, Item: Dict[str, Any]) -> Dict[str, Any]:
        self.items[(Item["user_sub"], Item["sk"])] = dict(Item)
        return {}

    def delete_item(self, Key: Dict[str, Any]) -> Dict[str, Any]:
        self.items.pop(self._k(Key), None)
        return {}

    def query(self, KeyConditionExpression: Any = None, **_: Any) -> Dict[str, Any]:
        # connection_profiles always queries: user_sub eq & sk begins_with
        # "PROFILE#". Return every PROFILE# item (single test user per case).
        out: List[Dict[str, Any]] = [
            dict(v) for v in self.items.values() if str(v.get("sk", "")).startswith("PROFILE#")
        ]
        return {"Items": out}

    def update_item(
        self,
        Key: Dict[str, Any],
        UpdateExpression: str = "",
        ExpressionAttributeValues: Optional[Dict[str, Any]] = None,
        ExpressionAttributeNames: Optional[Dict[str, str]] = None,
        ReturnValues: str = "NONE",
        **_: Any,
    ) -> Dict[str, Any]:
        item = self.items.setdefault(self._k(Key), dict(Key))
        names = ExpressionAttributeNames or {}
        values = ExpressionAttributeValues or {}
        expr = UpdateExpression.strip()
        assert expr.upper().startswith("SET "), f"unsupported expr: {expr!r}"
        for assignment in expr[4:].split(","):
            lhs, rhs = assignment.split("=")
            field = lhs.strip()
            field = names.get(field, field)
            item[field] = values[rhs.strip()]
        out = dict(item)
        return {"Attributes": out} if ReturnValues == "ALL_NEW" else {}


class _FakeKMS:
    """Deterministic, reversible fake for kms_encrypt / kms_decrypt."""

    _PREFIX = "ENC::"

    def __init__(self) -> None:
        self.encrypt_calls: List[str] = []
        self.decrypt_calls: List[str] = []

    def encrypt(self, plaintext: str) -> str:
        self.encrypt_calls.append(plaintext)
        return f"{self._PREFIX}{plaintext}"

    def decrypt(self, ct_b64: str) -> bytes:
        self.decrypt_calls.append(ct_b64)
        assert ct_b64.startswith(self._PREFIX), f"not fake-encrypted: {ct_b64!r}"
        return ct_b64[len(self._PREFIX):].encode("utf-8")


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        from app.services import connection_profiles as svc
        from app.core.settings import S

        self.svc = svc
        self.table = _FakeTable()
        self.kms = _FakeKMS()

        # Patch the frozen T dataclass handle -> fake table (object.__setattr__).
        self._orig_table = svc.T.connection_profiles
        object.__setattr__(svc.T, "connection_profiles", self.table)
        self.addCleanup(
            lambda: object.__setattr__(svc.T, "connection_profiles", self._orig_table)
        )

        # Patch crypto fns on the service module (real KMS never touched).
        self._orig_encrypt = svc.kms_encrypt
        self._orig_decrypt = svc.kms_decrypt
        svc.kms_encrypt = self.kms.encrypt
        svc.kms_decrypt = self.kms.decrypt

        def _restore_crypto() -> None:
            svc.kms_encrypt = self._orig_encrypt
            svc.kms_decrypt = self._orig_decrypt

        self.addCleanup(_restore_crypto)

        # Frozen S settings: ensure kms_key_id is set so the guard passes.
        self._orig_kms_key = S.kms_key_id
        object.__setattr__(S, "kms_key_id", "test-cmk-id")
        self.addCleanup(lambda: object.__setattr__(S, "kms_key_id", self._orig_kms_key))
        self.S = S


class TestPasswordStoredAndEncrypted(_Base):
    def test_create_vnc_profile_password_is_kms_encrypted(self) -> None:
        """GAP-0229: VNC password must be KMS-encrypted before storage.

        FAILS BEFORE FIX: create_profile takes no vnc_password; nothing is
        encrypted and the returned profile has no has_password field.
        PASSES AFTER FIX: kms_encrypt is called with the plaintext; the stored
        item holds the ciphertext; has_password is True.
        """
        profile = self.svc.create_profile(
            "alice",
            label="My VNC",
            protocol="vnc",
            hostname="vnc.example.com",
            port=5900,
            auth_method="password",
            vnc_password="s3cr3t-vnc",
        )

        self.assertIn("s3cr3t-vnc", self.kms.encrypt_calls,
                      "kms_encrypt must be called with the plaintext password")
        self.assertTrue(profile.get("has_password"),
                        "has_password must be True after storing a password")

        # The persisted DynamoDB item holds the ciphertext, not the plaintext.
        stored = self.table.items[("alice", f"PROFILE#{profile['profile_id']}")]
        self.assertEqual(stored["password_enc"], "ENC::s3cr3t-vnc")
        self.assertNotIn("s3cr3t-vnc", str({k: v for k, v in stored.items()
                                            if k != "password_enc"}))

    def test_create_ssh_profile_password_is_kms_encrypted(self) -> None:
        profile = self.svc.create_profile(
            "alice",
            label="My SSH",
            protocol="ssh",
            hostname="ssh.example.com",
            port=22,
            username="root",
            auth_method="password",
            ssh_password="hunter2pw",
        )
        self.assertIn("hunter2pw", self.kms.encrypt_calls)
        self.assertTrue(profile.get("has_password"))

    def test_returned_profile_never_exposes_password(self) -> None:
        """GAP-0229: plaintext and ciphertext must never appear in output."""
        profile = self.svc.create_profile(
            "alice",
            label="Secret",
            protocol="vnc",
            hostname="vnc.example.com",
            port=5900,
            auth_method="password",
            vnc_password="topsecret",
        )
        self.assertNotIn("topsecret", str(profile),
                         "plaintext password must not appear in the profile output")
        self.assertNotIn("password_enc", profile,
                         "encrypted blob must not appear in the profile output")
        self.assertNotIn("ENC::topsecret", str(profile),
                         "ciphertext must not appear in the profile output")

    def test_item_to_profile_scrubs_password_enc(self) -> None:
        """GAP-0229: _item_to_profile exposes has_password, never password_enc."""
        item = {
            "user_sub": "alice",
            "profile_id": "cp_test",
            "sk": "PROFILE#cp_test",
            "label": "Test",
            "protocol": "ssh",
            "hostname": "example.com",
            "auth_method": "password",
            "password_enc": "ENC::SOME_CIPHERTEXT",
            "port": 22,
            "username": "alice",
            "created_at": 1000000,
            "updated_at": 1000000,
            "last_used_at": 0,
        }
        out = self.svc._item_to_profile(item)
        self.assertNotIn("password_enc", out)
        self.assertNotIn("SOME_CIPHERTEXT", str(out))
        self.assertTrue(out.get("has_password"))

    def test_password_auth_without_password_is_allowed(self) -> None:
        """Password-auth profile with no password supplied -> has_password False."""
        profile = self.svc.create_profile(
            "alice",
            label="Deferred",
            protocol="ssh",
            hostname="deferred.example.com",
            port=22,
            username="root",
            auth_method="password",
        )
        self.assertFalse(profile.get("has_password"))
        self.assertEqual(self.kms.encrypt_calls, [])


class TestUpdateRotation(_Base):
    def _make(self, **kw: Any) -> Dict[str, Any]:
        base = dict(
            label="P",
            protocol="vnc",
            hostname="vnc.example.com",
            port=5900,
            auth_method="password",
        )
        base.update(kw)
        return self.svc.create_profile("alice", **base)

    def test_update_rotates_password_encrypted(self) -> None:
        p = self._make(vnc_password="old-pw")
        self.kms.encrypt_calls.clear()
        out = self.svc.update_profile("alice", p["profile_id"], password="new-pw")
        self.assertIn("new-pw", self.kms.encrypt_calls)
        self.assertTrue(out.get("has_password"))
        stored = self.table.items[("alice", f"PROFILE#{p['profile_id']}")]
        self.assertEqual(stored["password_enc"], "ENC::new-pw")

    def test_update_clear_password(self) -> None:
        p = self._make(vnc_password="old-pw")
        out = self.svc.update_profile("alice", p["profile_id"], clear_password=True)
        self.assertFalse(out.get("has_password"))
        stored = self.table.items[("alice", f"PROFILE#{p['profile_id']}")]
        self.assertEqual(stored["password_enc"], "")


class TestQuickConnectDecrypt(_Base):
    def test_quick_connect_resolves_password_but_not_exposed_by_has_password(self) -> None:
        """quick_connect decrypts for the terminal layer (password_resolved).

        The HTTP-facing has_password is True; password_resolved carries the
        plaintext for in-process use (the router strips it).
        """
        p = self.svc.create_profile(
            "alice",
            label="QC",
            protocol="vnc",
            hostname="vnc.example.com",
            port=5900,
            auth_method="password",
            vnc_password="qc-secret",
        )
        result = self.svc.quick_connect("alice", p["profile_id"])
        self.assertTrue(result.get("has_password"))
        self.assertEqual(result.get("password_resolved"), "qc-secret")
        self.assertIn("ENC::qc-secret", self.kms.decrypt_calls)

    def test_quick_connect_no_password_returns_empty_resolved(self) -> None:
        p = self.svc.create_profile(
            "alice",
            label="QC2",
            protocol="ssh",
            hostname="qc2.example.com",
            port=22,
            username="root",
            auth_method="key_ref",
            ssh_key_id="",
        )
        result = self.svc.quick_connect("alice", p["profile_id"])
        self.assertFalse(result.get("has_password"))
        self.assertEqual(result.get("password_resolved"), "")
        self.assertEqual(self.kms.decrypt_calls, [])


class TestKmsGuard(_Base):
    def test_password_requires_kms_configured(self) -> None:
        """When KMS_KEY_ID is unset, storing a password fails with a 4xx-style
        ProfileValidationError instead of silently storing plaintext."""
        from app.core.settings import S

        object.__setattr__(S, "kms_key_id", "")
        with self.assertRaises(self.svc.ProfileValidationError):
            self.svc.create_profile(
                "alice",
                label="NoKMS",
                protocol="vnc",
                hostname="vnc.example.com",
                port=5900,
                auth_method="password",
                vnc_password="x",
            )

    def test_password_too_long_rejected(self) -> None:
        with self.assertRaises(self.svc.ProfileValidationError):
            self.svc.create_profile(
                "alice",
                label="TooLong",
                protocol="vnc",
                hostname="vnc.example.com",
                port=5900,
                auth_method="password",
                vnc_password="x" * 257,
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
