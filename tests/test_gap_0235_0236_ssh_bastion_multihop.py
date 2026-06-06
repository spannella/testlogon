"""Offline regression tests for GAP-0235 and GAP-0236 (INFRA-011 multi-hop SSH).

Both gaps live in ``app/services/ssh_bastion.py``:

GAP-0236 — ``resolve_connection_chain(user_sub, path_id)`` did not exist. The
service only produced a ProxyJump / ssh_config text representation
(``resolve_path``); there was no programmatic resolver that augments each hop
with its decrypted SSH private key (via
``ssh_key_manager.get_decrypted_private_key``). The fix adds
``resolve_connection_chain`` which returns a ready-to-connect hop list with a
``private_key_pem`` per keyed hop.

GAP-0235 — ``MultiHopSshBridge`` did not exist. The browser SSH terminal could
only ever build a single-hop ``ParamikoSshBridge``; multi-hop bastion chains
configured in the UI could not actually be connected. The fix adds
``MultiHopSshBridge`` (Paramiko ``direct-tcpip`` channel forwarding) plus a
``build_multihop_bridge`` factory that consumes ``resolve_connection_chain``.

TEST ISOLATION (per repo rules):
  * No global ``@mock_aws`` interception that could leak to real AWS. The bastion
    table is created with moto inside an ``ExitStack`` and the *exact* frozen
    handle ``app.core.tables.T.ssh_bastion_paths`` is monkeypatched via
    ``object.__setattr__`` (T is a frozen dataclass).
  * ``ssh_key_manager.get_decrypted_private_key`` is patched -- no real KMS.
  * ``paramiko`` is fully stubbed -- NEVER a real SSH connection / socket. The
    stub records ``open_channel`` / auth / shell calls so the multi-hop tunnel
    wiring can be asserted offline.
  * Settings ``S`` is frozen; not mutated here (defaults suffice). If needed it
    would be via ``object.__setattr__``.
"""
from __future__ import annotations

import sys
import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


# ---------------------------------------------------------------------------
# moto table mirroring scripts/local-ddb-init.py (ssh_bastion_paths)
# ---------------------------------------------------------------------------

def _make_bastion_table(ddb):
    return ddb.create_table(
        TableName="ssh_bastion_paths",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByCreatedAt",
                "KeySchema": [
                    {"AttributeName": "user_sub", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


# ---------------------------------------------------------------------------
# Paramiko stub -- records the wiring; performs NO real network I/O.
# ---------------------------------------------------------------------------

class _StubChannel:
    """Stands in for both a direct-tcpip channel and a shell session channel."""

    def __init__(self, registry):
        self._registry = registry
        self._pty = None
        self._shell_invoked = False

    def get_pty(self, **kw):
        self._pty = kw

    def invoke_shell(self):
        self._shell_invoked = True

    def settimeout(self, _):
        pass

    def recv_ready(self):
        return False

    def close(self):
        pass


class _StubTransport:
    def __init__(self, registry):
        self._registry = registry

    def open_channel(self, kind, dest_addr, local_addr, timeout=None):
        self._registry["open_channel_calls"].append(
            {"kind": kind, "dest": tuple(dest_addr), "local": tuple(local_addr)}
        )
        return _StubChannel(self._registry)

    def open_session(self, timeout=None):
        return _StubChannel(self._registry)

    def start_client(self, timeout=None):
        self._registry["start_client_calls"] += 1

    def auth_publickey(self, username, key):
        self._registry["auth"].append(("publickey", username))

    def auth_password(self, username, password):
        self._registry["auth"].append(("password", username))

    def close(self):
        pass


class _StubSSHClient:
    def __init__(self, registry):
        self._registry = registry
        self._transport = _StubTransport(registry)

    def set_missing_host_key_policy(self, _):
        pass

    def connect(self, **kw):
        self._registry["connect_calls"].append(kw)

    def get_transport(self):
        return self._transport

    def close(self):
        pass


def _make_stub_paramiko():
    registry = {
        "open_channel_calls": [],
        "connect_calls": [],
        "auth": [],
        "start_client_calls": 0,
        "transports": [],
    }

    mod = MagicMock(name="paramiko_stub")

    def _make_client():
        return _StubSSHClient(registry)

    def _make_transport(channel):
        t = _StubTransport(registry)
        registry["transports"].append(t)
        return t

    mod.SSHClient.side_effect = _make_client
    mod.Transport.side_effect = _make_transport
    mod.AutoAddPolicy.return_value = object()

    # Key loaders -- return a sentinel; the bridge only passes them through.
    for name in ("RSAKey", "Ed25519Key", "ECDSAKey", "DSSKey"):
        getattr(mod, name).from_private_key.return_value = f"PKEY::{name}"

    # AuthenticationException must be a real exception class for `except`.
    mod.AuthenticationException = type("AuthenticationException", (Exception,), {})
    mod.SSHException = type("SSHException", (Exception,), {})

    return mod, registry


@unittest.skipIf(mock_aws is None, "moto is not installed")
class _BastionTestBase(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_bastion_table(ddb)

        from app.core.tables import T

        self.T = T
        # T is a frozen dataclass -> patch the exact handle via object.__setattr__.
        original = T.ssh_bastion_paths
        object.__setattr__(T, "ssh_bastion_paths", self.table)
        self.addCleanup(
            lambda: object.__setattr__(T, "ssh_bastion_paths", original)
        )

        from app.services import ssh_bastion

        self.svc = ssh_bastion


class TestResolveConnectionChainGap0236(_BastionTestBase):
    def _create_two_hop_path(self, user, *, jump_key_id="key_jump"):
        return self.svc.create_path(
            user,
            label="prod-chain",
            jump_hops=[
                {
                    "hostname": "bastion.example.com",
                    "port": 22,
                    "username": "ec2-user",
                    "ssh_key_id": jump_key_id,
                }
            ],
            target={"hostname": "host.example.org", "port": 22, "username": "ubuntu"},
        )

    def test_function_exists(self):
        """GAP-0236: resolve_connection_chain must be importable (was absent)."""
        from app.services.ssh_bastion import resolve_connection_chain  # noqa: F401

    def test_returns_decrypted_key_per_keyed_hop(self):
        """resolve_connection_chain returns private_key_pem for keyed hops only.

        FAILS BEFORE FIX: function does not exist (ImportError/AttributeError).
        PASSES AFTER FIX: jump hop (has ssh_key_id) gets decrypted PEM; the
        target (no key) gets None.
        """
        user = "u_chain"
        path = self._create_two_hop_path(user)

        fake_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIITEST==\n-----END RSA PRIVATE KEY-----\n"
        with patch(
            "app.services.ssh_key_manager.get_decrypted_private_key",
            return_value=fake_pem,
        ) as get_key:
            chain = self.svc.resolve_connection_chain(user, path["path_id"])

        self.assertEqual(len(chain), 2)
        self.assertEqual(chain[0]["hostname"], "bastion.example.com")
        self.assertEqual(chain[0]["private_key_pem"], fake_pem)
        self.assertTrue(chain[0]["is_bastion"])
        # Target hop has no ssh_key_id -> no decrypt call, pem is None.
        self.assertEqual(chain[1]["hostname"], "host.example.org")
        self.assertIsNone(chain[1]["private_key_pem"])
        # Decrypt called exactly once (only for the keyed hop).
        get_key.assert_called_once_with(user, "key_jump")

    def test_include_keys_false_skips_kms(self):
        """include_keys=False resolves topology without any KMS decrypt call."""
        user = "u_topo"
        path = self._create_two_hop_path(user)

        with patch(
            "app.services.ssh_key_manager.get_decrypted_private_key"
        ) as get_key:
            chain = self.svc.resolve_connection_chain(
                user, path["path_id"], include_keys=False
            )

        get_key.assert_not_called()
        self.assertEqual(len(chain), 2)
        self.assertIsNone(chain[0]["private_key_pem"])

    def test_not_found_raises(self):
        from app.services.ssh_bastion import BastionPathNotFound

        with self.assertRaises(BastionPathNotFound):
            self.svc.resolve_connection_chain("u_nobody", "bp_missing")


class TestMultiHopSshBridgeGap0235(_BastionTestBase):
    def test_class_exists(self):
        """GAP-0235: MultiHopSshBridge must be importable (was absent)."""
        from app.services.ssh_bastion import MultiHopSshBridge  # noqa: F401

    def test_requires_at_least_two_hops(self):
        from app.services.ssh_bastion import MultiHopSshBridge, BastionConnectError

        with self.assertRaises(BastionConnectError):
            MultiHopSshBridge(
                hops=[{"hostname": "h", "port": 22, "username": "u", "password": "p"}],
                cols=80,
                rows=24,
            )

    def test_connect_opens_direct_tcpip_to_each_subsequent_hop(self):
        """Two-hop connect: a direct-tcpip channel is opened to the target.

        FAILS BEFORE FIX: MultiHopSshBridge does not exist.
        PASSES AFTER FIX: hop 0 is a direct client.connect; hop 1 is reached via
        an open_channel('direct-tcpip', (target, 22), ...) through hop 0.
        """
        from app.services.ssh_bastion import MultiHopSshBridge

        stub_paramiko, registry = _make_stub_paramiko()
        bridge = MultiHopSshBridge(
            hops=[
                {"hostname": "bastion", "port": 22, "username": "ops", "password": "pw1"},
                {"hostname": "target", "port": 2222, "username": "app", "password": "pw2"},
            ],
            cols=80,
            rows=24,
        )
        with patch.dict(sys.modules, {"paramiko": stub_paramiko}):
            bridge.connect()

        # Hop 0 connected directly.
        self.assertEqual(len(registry["connect_calls"]), 1)
        self.assertEqual(registry["connect_calls"][0]["hostname"], "bastion")
        # Hop 1 reached via a direct-tcpip channel to the target's address.
        dests = [c["dest"] for c in registry["open_channel_calls"] if c["kind"] == "direct-tcpip"]
        self.assertIn(("target", 2222), dests)
        # Password auth used on the tunnelled transport.
        self.assertIn(("password", "app"), registry["auth"])
        bridge.close()

    def test_connect_uses_publickey_when_pem_present(self):
        """A hop carrying private_key_pem authenticates via publickey."""
        from app.services.ssh_bastion import MultiHopSshBridge

        stub_paramiko, registry = _make_stub_paramiko()
        bridge = MultiHopSshBridge(
            hops=[
                {"hostname": "bastion", "port": 22, "username": "ops",
                 "private_key_pem": "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----\n"},
                {"hostname": "target", "port": 22, "username": "app", "password": "pw"},
            ],
            cols=80,
            rows=24,
        )
        with patch.dict(sys.modules, {"paramiko": stub_paramiko}):
            bridge.connect()

        # Hop 0 connected with a pkey (publickey), not a password.
        self.assertIn("pkey", registry["connect_calls"][0])
        self.assertNotIn("password", registry["connect_calls"][0])
        bridge.close()

    def test_build_multihop_bridge_consumes_resolved_chain(self):
        """build_multihop_bridge resolves a stored path into a bridge.

        End-to-end across both gaps: create a 2-hop path, build the bridge via
        the factory (which calls resolve_connection_chain -> decrypted keys),
        and connect through the stub paramiko.
        """
        from app.services.ssh_bastion import build_multihop_bridge

        user = "u_e2e"
        path = self.svc.create_path(
            user,
            label="e2e-chain",
            jump_hops=[
                {"hostname": "jump1.example.com", "port": 22, "username": "ops",
                 "ssh_key_id": "k1"},
            ],
            target={"hostname": "final.example.net", "port": 22, "username": "deploy"},
        )

        fake_pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nz\n-----END OPENSSH PRIVATE KEY-----\n"
        stub_paramiko, registry = _make_stub_paramiko()
        with patch(
            "app.services.ssh_key_manager.get_decrypted_private_key",
            return_value=fake_pem,
        ):
            bridge = build_multihop_bridge(user, path["path_id"], cols=120, rows=40)

        with patch.dict(sys.modules, {"paramiko": stub_paramiko}):
            bridge.connect()

        # First hop connected directly with the resolved key (publickey).
        self.assertEqual(registry["connect_calls"][0]["hostname"], "jump1.example.com")
        self.assertIn("pkey", registry["connect_calls"][0])
        # Final hop reached via direct-tcpip tunnel.
        dests = [c["dest"] for c in registry["open_channel_calls"]]
        self.assertIn(("final.example.net", 22), dests)
        bridge.close()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
