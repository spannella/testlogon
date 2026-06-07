"""Offline hermetic regression tests for GAP-0220 and GAP-0221 (INFRA-002).

Both gaps live in the SSH "stored key" path.

GAP-0220 — ``stored_key`` auth type was not wired into the Browser SSH terminal
(``app/routers/browser_ssh_terminal.py``). The connect validator's allowlist was
``{"password", "private_key"}``, so ``stored_key`` was rejected before any
handler ran. The fix adds ``stored_key`` to the allowlist, validates ``keyId``,
resolves the KMS-encrypted private key server-side via
``ssh_key_manager.get_decrypted_private_key`` (so the PEM never reaches the
browser), injects it as ``privateKey`` into the existing ``private_key`` bridge
path, and calls ``host_inventory.record_connection`` for associated hosts.

GAP-0221 — ``app/services/ssh_key_manager.py`` performed six security-sensitive
operations (generate / upload / delete / decrypt / associate / disassociate) but
emitted only ``logger.info`` and never wrote to the platform audit trail. The fix
adds a ``_audit`` wrapper (mirroring ``host_inventory.py``) that delegates to
``app.services.alerts.audit_event`` for each operation.

Isolation rules (per repo TEST ISOLATION guidance):
- NO global ``mock_aws``/botocore interception that could leak to real AWS. We
  create a single in-memory moto DynamoDB resource inside an explicit context
  and patch the *exact* frozen table handles (``T.ssh_keys`` / ``T.host_inventory``)
  via ``object.__setattr__``.
- KMS is stubbed at the module boundary (``ssh_key_manager.kms_encrypt`` /
  ``kms_decrypt``) with identity transforms — no KMS server, no real KMS, dev/prod
  parity preserved because the production code path is unchanged.
- The websocket connect handler is exercised by running the async coroutine on a
  FRESH event loop (``asyncio.new_event_loop()``), never ``get_event_loop()``,
  via a fake WebSocket that scripts the client messages.
- ``ParamikoSshBridge`` is stubbed so no network connection is attempted.
- Settings ``S`` is frozen; any mutation uses ``object.__setattr__``.
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


FAKE_PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEFAKEFAKEFAKE\n"
    "-----END OPENSSH PRIVATE KEY-----"
)


def _make_ssh_keys_table(ddb):
    return ddb.create_table(
        TableName="ssh_keys_test",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_host_inventory_table(ddb):
    return ddb.create_table(
        TableName="host_inventory_test",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


# ---------------------------------------------------------------------------
# GAP-0221: audit events emitted by ssh_key_manager
# ---------------------------------------------------------------------------

@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestSshKeyManagerAuditGap0221(unittest.TestCase):
    USER = "test-user-sub-0221"

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.ssh_table = _make_ssh_keys_table(ddb)

        from app.core.tables import T
        from app.services import ssh_key_manager as skm

        self.skm = skm

        # Patch the EXACT frozen table handle (T is frozen → object.__setattr__).
        prev = T.ssh_keys
        object.__setattr__(T, "ssh_keys", self.ssh_table)
        self.addCleanup(lambda: object.__setattr__(T, "ssh_keys", prev))

        # Stub KMS so no KMS server / real AWS is needed. Identity transforms.
        self.stack.enter_context(
            patch.object(skm, "kms_encrypt", lambda pem: pem)
        )
        self.stack.enter_context(
            patch.object(skm, "kms_decrypt", lambda blob: blob.encode("utf-8") if isinstance(blob, str) else blob)
        )

        # Capture audit events. The fix uses a *local* import of audit_event
        # inside ssh_key_manager._audit, so we patch the source symbol in alerts.
        self.audit_calls = []
        self.stack.enter_context(
            patch(
                "app.services.alerts.audit_event",
                lambda event, user_sub, *a, **fields: self.audit_calls.append((event, user_sub, fields)),
            )
        )

    def _events(self):
        return [e for e, *_ in self.audit_calls]

    def test_generate_key_emits_audit(self):
        self.skm.generate_key(self.USER, label="gen", key_type="ed25519")
        self.assertIn(
            "ssh_key.generate", self._events(),
            "GAP-0221: generate_key must emit an ssh_key.generate audit event",
        )

    def test_upload_key_emits_audit(self):
        # Generate a real key elsewhere, serialize, re-upload.
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization

        obj = ed25519.Ed25519PrivateKey.generate()
        pem = obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        self.skm.upload_key(self.USER, label="up", private_key_pem=pem)
        self.assertIn("ssh_key.upload", self._events())

    def test_delete_key_emits_audit(self):
        meta = self.skm.generate_key(self.USER, label="del")
        self.audit_calls.clear()
        self.skm.delete_key(self.USER, meta["key_id"])
        self.assertIn("ssh_key.delete", self._events())

    def test_decrypt_key_emits_audit(self):
        meta = self.skm.generate_key(self.USER, label="dec")
        self.audit_calls.clear()
        pem = self.skm.get_decrypted_private_key(self.USER, meta["key_id"])
        self.assertIsNotNone(pem)
        self.assertIn("ssh_key.decrypt", self._events())

    def test_associate_emits_audit(self):
        meta = self.skm.generate_key(self.USER, label="assoc")
        self.audit_calls.clear()
        self.skm.associate_key_with_host(self.USER, meta["key_id"], "h_abc123")
        self.assertIn("ssh_key.associate", self._events())

    def test_disassociate_emits_audit(self):
        meta = self.skm.generate_key(self.USER, label="disassoc")
        self.skm.associate_key_with_host(self.USER, meta["key_id"], "h_abc123")
        self.audit_calls.clear()
        self.skm.disassociate_key_from_host(self.USER, meta["key_id"], "h_abc123")
        self.assertIn("ssh_key.disassociate", self._events())


# ---------------------------------------------------------------------------
# GAP-0220: stored_key wired into the SSH terminal validator
# ---------------------------------------------------------------------------

class TestStoredKeyValidatorGap0220(unittest.TestCase):
    def test_stored_key_accepted_by_validator(self):
        """FAILS BEFORE FIX: rejected with invalid_auth_type.
        PASSES AFTER FIX: accepted, keyId carried through normalized payload."""
        from app.routers.browser_ssh_terminal import _validate_connect_payload

        valid, info, err = _validate_connect_payload({
            "host": "10.0.0.1",
            "port": 22,
            "username": "alice",
            "authType": "stored_key",
            "keyId": "key_abc123",
        })
        self.assertTrue(valid, f"stored_key must validate; err={err}")
        self.assertIsNone(err)
        self.assertEqual(info["authType"], "stored_key")
        self.assertEqual(info["keyId"], "key_abc123")

    def test_stored_key_missing_key_id_rejected(self):
        from app.routers.browser_ssh_terminal import _validate_connect_payload

        valid, _, err = _validate_connect_payload({
            "host": "10.0.0.1", "port": 22, "username": "alice",
            "authType": "stored_key",
        })
        self.assertFalse(valid)
        self.assertEqual(err["code"], "invalid_key_id")

    def test_keyid_redacted(self):
        from app.routers.browser_ssh_terminal import _redact_connect_payload

        redacted = _redact_connect_payload({"keyId": "key_abc123", "host": "h"})
        self.assertNotIn("key_abc123", str(redacted["keyId"]))
        self.assertIn("REDACTED", redacted["keyId"])

    def test_protocol_lists_stored_key(self):
        from app.routers.browser_ssh_terminal import browser_ssh_terminal_protocol

        proto = browser_ssh_terminal_protocol()
        auth_types = proto["client_messages"]["connect"]["authType"]
        self.assertIn("stored_key", auth_types)


# ---------------------------------------------------------------------------
# GAP-0220: stored_key resolved server-side in the websocket connect handler
# ---------------------------------------------------------------------------

class _FakeWebSocket:
    """Scripts a sequence of client messages then raises WebSocketDisconnect.

    Records all server->client JSON frames in ``self.sent``.
    """

    def __init__(self, messages):
        self._messages = list(messages)
        self.sent = []
        self.closed_code = None
        self.headers = {}
        self.cookies = {}
        self.client = None

    async def accept(self):
        return None

    async def receive_text(self):
        from fastapi import WebSocketDisconnect

        if not self._messages:
            raise WebSocketDisconnect(code=1000)
        return self._messages.pop(0)

    async def send_json(self, data):
        self.sent.append(data)

    async def close(self, code=1000):
        self.closed_code = code


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestStoredKeyConnectHandlerGap0220(unittest.TestCase):
    USER = "stored-key-user-0220"

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.ssh_table = _make_ssh_keys_table(ddb)
        self.host_table = _make_host_inventory_table(ddb)

        from app.core.tables import T
        from app.services import ssh_key_manager as skm
        import app.routers.browser_ssh_terminal as bst

        self.skm = skm
        self.bst = bst

        prev_ssh = T.ssh_keys
        prev_host = T.host_inventory
        object.__setattr__(T, "ssh_keys", self.ssh_table)
        object.__setattr__(T, "host_inventory", self.host_table)
        self.addCleanup(lambda: object.__setattr__(T, "ssh_keys", prev_ssh))
        self.addCleanup(lambda: object.__setattr__(T, "host_inventory", prev_host))

        # Stub KMS (identity).
        self.stack.enter_context(patch.object(skm, "kms_encrypt", lambda pem: pem))
        self.stack.enter_context(
            patch.object(skm, "kms_decrypt", lambda blob: blob.encode("utf-8") if isinstance(blob, str) else blob)
        )
        # Silence audit_event (write path uses local import).
        self.stack.enter_context(
            patch("app.services.alerts.audit_event", lambda *a, **k: None)
        )

        # Allow this user's role through the terminal authorization gate.
        # The handler reads auth_ctx.get("user_sub").
        async def _authorize(ws):
            return {"user_sub": self.USER, "role": "admin"}, None

        self.stack.enter_context(patch.object(bst, "_authorize_terminal_access", _authorize))
        # session-slot + rate-limit + policy must not block.
        self.stack.enter_context(patch.object(bst, "browser_ssh_terminal_enabled", lambda: True))
        self.stack.enter_context(patch.object(bst, "_consume_connect_rate_limit", lambda *a, **k: True))
        self.stack.enter_context(patch.object(bst, "_try_acquire_user_session_slot", lambda *a, **k: True))
        self.stack.enter_context(patch.object(bst, "_release_user_session_slot", lambda *a, **k: None))
        self.stack.enter_context(patch.object(bst, "_enforce_destination_policy", lambda *a, **k: None))

    def _run_connect(self, payload):
        """Drive the websocket handler on a FRESH event loop with one connect msg."""
        import json

        ws = _FakeWebSocket([json.dumps({"type": "connect", "payload": payload})])
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.bst.browser_ssh_terminal_ws(ws))
        finally:
            loop.close()
            asyncio.set_event_loop(None)
        return ws

    def _seed_key(self, key_id="k_stored_1", associated_hosts=None):
        self.ssh_table.put_item(Item={
            "user_sub": self.USER,
            "sk": f"KEY#{key_id}",
            "key_id": key_id,
            "label": "stored",
            "key_type": "ed25519",
            "key_bits": 256,
            "encrypted_private_key_blob": FAKE_PEM,
            "associated_hosts": associated_hosts or [],
            "use_count": 0,
            "last_used_at": 0,
        })

    def _bridge_codes(self, ws):
        return [m["payload"].get("code") for m in ws.sent if m.get("type") == "error"]

    def test_unknown_stored_key_returns_key_not_found(self):
        """FAILS BEFORE FIX: validator rejects stored_key (invalid_auth_type).
        PASSES AFTER FIX: handler resolves key, gets None → key_not_found."""
        bst = self.bst
        captured = {}

        class _StubBridge:
            def __init__(self, **kwargs):
                captured.update(kwargs)

            def connect(self):
                raise AssertionError("connect must not be reached for unknown key")

            def poll_output(self):
                return ""

            def close(self):
                pass

        with patch.object(bst, "ParamikoSshBridge", _StubBridge):
            ws = self._run_connect({
                "host": "10.0.0.1", "port": 22, "username": "alice",
                "authType": "stored_key", "keyId": "does_not_exist",
            })
        self.assertIn("key_not_found", self._bridge_codes(ws))
        self.assertNotIn("invalid_auth_type", self._bridge_codes(ws))

    def test_successful_stored_key_injects_pem_into_bridge(self):
        """The decrypted PEM must reach ParamikoSshBridge as private_key with
        auth_type normalized to private_key — never sent back to the browser."""
        self._seed_key(key_id="k_ok")
        bst = self.bst
        captured = {}

        class _StubBridge:
            def __init__(self, **kwargs):
                captured.update(kwargs)

            def connect(self):
                return None

            def poll_output(self):
                return ""

            def close(self):
                pass

        with patch.object(bst, "ParamikoSshBridge", _StubBridge):
            ws = self._run_connect({
                "host": "10.0.0.1", "port": 22, "username": "alice",
                "authType": "stored_key", "keyId": "k_ok",
            })

        # PEM resolved server-side and injected into the bridge.
        self.assertEqual(captured.get("private_key"), FAKE_PEM)
        self.assertEqual(captured.get("auth_type"), "private_key")
        # A connected status was sent.
        statuses = [m for m in ws.sent if m.get("type") == "status"]
        self.assertTrue(any(s["payload"].get("connected") for s in statuses))
        # The PEM must NEVER appear in any server->client frame.
        for frame in ws.sent:
            self.assertNotIn(FAKE_PEM, str(frame))

    def test_stored_key_records_connection_for_associated_host(self):
        """When the key is associated with a managed host, record_connection
        must update the host inventory after a successful connect."""
        self._seed_key(key_id="k_host", associated_hosts=["h_managed_1"])
        # Seed the managed host so record_connection has something to update.
        self.host_table.put_item(Item={
            "user_sub": self.USER,
            "sk": "HOST#h_managed_1",
            "host_id": "h_managed_1",
            "label": "managed",
            "protocol": "ssh",
            "status": "offline",
            "connection_count": 0,
        })
        bst = self.bst

        class _StubBridge:
            def __init__(self, **kwargs):
                pass

            def connect(self):
                return None

            def poll_output(self):
                return ""

            def close(self):
                pass

        with patch.object(bst, "ParamikoSshBridge", _StubBridge):
            self._run_connect({
                "host": "10.0.0.1", "port": 22, "username": "alice",
                "authType": "stored_key", "keyId": "k_host",
            })

        resp = self.host_table.get_item(Key={"user_sub": self.USER, "sk": "HOST#h_managed_1"})
        host = resp.get("Item", {})
        self.assertEqual(int(host.get("connection_count", 0)), 1,
                         "record_connection must increment connection_count for the associated host")
        self.assertGreaterEqual(int(host.get("last_connected_at", 0)), 1)


if __name__ == "__main__":
    unittest.main()
