"""Offline hermetic tests for the next-phase multi-hop agent SSH QA exec.

Extends the AQA foundation (ADR-003) so an agent QA action can run a command
*through a stored bastion path* (path_id) in addition to a single host_id.

Two new code units are covered:
  * ``ssh_bastion.exec_via_chain`` / ``exec_command_multihop`` (AQA-005) — build
    the direct-tcpip transport tunnel hop-by-hop and run ``exec_command`` on the
    final transport to capture a discrete exit code + clean stdout/stderr (vs.
    the existing interactive ``MultiHopSshBridge``).
  * ``agent_ssh_exec._execute_multihop`` — now dials through the chain instead of
    raising ``multihop_not_implemented``; applies the destination policy to the
    final target and normalises errors to the AgentSshExecError contract.

ISOLATION (per repo TEST ISOLATION guidance):
  * moto in-memory DynamoDB tables bound onto the EXACT frozen ``T`` handles via
    ``object.__setattr__`` (restored on cleanup). No real AWS.
  * ``paramiko`` fully stubbed via ``patch.dict(sys.modules, ...)`` — records the
    open_channel/auth/exec wiring; performs NO real SSH/network I/O.
  * ``get_decrypted_private_key`` patched at the source module — no KMS.
  * Frozen ``S`` flags toggled via ``object.__setattr__`` (restored on cleanup).
  * The plaintext PEM resolved into the chain must NEVER appear on the persisted
    action record — asserted explicitly.
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


FAKE_PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEMULTIHOPFAKE\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)


def _make_actions_table(ddb):
    return ddb.create_table(
        TableName="agent_actions_mh",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByStatus",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_bastion_table(ddb):
    return ddb.create_table(
        TableName="ssh_bastion_paths_mh",
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
# Paramiko stub with exec_command session semantics.
# ---------------------------------------------------------------------------

class _StubSession:
    def __init__(self, registry, stdout=b"", stderr=b"", exit_status=0, ready=True):
        self._registry = registry
        self._stdout = stdout
        self._stderr = stderr
        self._exit = exit_status
        self._ready = ready
        self._out_done = False
        self._err_done = False

    def settimeout(self, _):
        pass

    def exec_command(self, command):
        self._registry["exec_calls"].append(command)

    def exit_status_ready(self):
        return self._ready

    def recv_exit_status(self):
        return self._exit

    def recv(self, _n):
        if self._out_done:
            return b""
        self._out_done = True
        return self._stdout

    def recv_stderr(self, _n):
        if self._err_done:
            return b""
        self._err_done = True
        return self._stderr

    def close(self):
        self._registry["closed_sessions"] += 1


class _StubTransport:
    def __init__(self, registry):
        self._registry = registry

    def open_channel(self, kind, dest_addr, local_addr, timeout=None):
        self._registry["open_channel_calls"].append(
            {"kind": kind, "dest": tuple(dest_addr)}
        )
        return MagicMock(name="tcp_channel")

    def open_session(self, timeout=None):
        return _StubSession(
            self._registry,
            stdout=self._registry["stdout"],
            stderr=self._registry["stderr"],
            exit_status=self._registry["exit_status"],
            ready=self._registry["ready"],
        )

    def start_client(self, timeout=None):
        self._registry["start_client_calls"] += 1

    def auth_publickey(self, username, key):
        self._registry["auth"].append(("publickey", username))

    def auth_password(self, username, password):
        self._registry["auth"].append(("password", username))

    def close(self):
        self._registry["closed_transports"] += 1


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
        self._registry["closed_clients"] += 1


def _make_stub_paramiko(*, stdout=b"hello\n", stderr=b"", exit_status=0, ready=True):
    registry = {
        "open_channel_calls": [],
        "connect_calls": [],
        "auth": [],
        "exec_calls": [],
        "start_client_calls": 0,
        "closed_sessions": 0,
        "closed_transports": 0,
        "closed_clients": 0,
        "stdout": stdout,
        "stderr": stderr,
        "exit_status": exit_status,
        "ready": ready,
    }
    mod = MagicMock(name="paramiko_stub")
    mod.SSHClient.side_effect = lambda: _StubSSHClient(registry)
    mod.Transport.side_effect = lambda channel: _StubTransport(registry)
    mod.AutoAddPolicy.return_value = object()
    for name in ("RSAKey", "Ed25519Key", "ECDSAKey", "DSSKey"):
        getattr(mod, name).from_private_key.return_value = f"PKEY::{name}"
    mod.AuthenticationException = type("AuthenticationException", (Exception,), {})
    mod.SSHException = type("SSHException", (Exception,), {})
    return mod, registry


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestMultiHopExec(unittest.TestCase):
    USER = "user-mh"
    WORKER = "w_mh1"

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.actions = _make_actions_table(ddb)
        self.bastion = _make_bastion_table(ddb)

        from app.core.tables import T
        from app.core.settings import S
        from app.services import agent_ssh_exec as eng
        from app.services import ssh_bastion

        self.eng = eng
        self.bastion_svc = ssh_bastion
        self.S = S

        for name, tbl in (
            ("agent_actions", self.actions),
            ("ssh_bastion_paths", self.bastion),
        ):
            prev = getattr(T, name)
            object.__setattr__(T, name, tbl)
            self.addCleanup(lambda n=name, p=prev: object.__setattr__(T, n, p))

        self._set_flag("agent_ssh_qa_enabled", True)
        self._set_flag("agent_qa_execute_commands", True)  # real-dial path (stubbed)
        self._set_flag("agent_ssh_qa_command_denylist", "")
        self._set_flag("agent_ssh_qa_max_concurrent_per_worker", 5)
        self._set_flag("agent_ssh_qa_rate_limit_count", 50)
        eng._RATE_BUCKETS.clear()

        # A 2-hop bastion path owned by USER (jump keyed, target uses jump key too).
        self.path = ssh_bastion.create_path(
            self.USER,
            label="qa-chain",
            jump_hops=[
                {"hostname": "bastion.internal", "port": 22,
                 "username": "ops", "ssh_key_id": "k_jump"},
            ],
            target={"hostname": "target.internal", "port": 22,
                    "username": "deploy", "ssh_key_id": "k_target"},
        )
        self.PATH_ID = self.path["path_id"]

        # Worker resolution stub (avoid seeding agent_workers).
        self._worker = {
            "worker_id": self.WORKER, "user_id": self.USER,
            "host_id": "", "ssh_key_id": "",
        }
        self.stack.enter_context(
            patch(
                "app.services.agent_worker_provisioner.get_worker",
                lambda u, w: (self._worker if (u == self.USER and w == self.WORKER) else None),
            )
        )

        # Credential injection for chain hops.
        self.stack.enter_context(
            patch(
                "app.services.ssh_key_manager.get_decrypted_private_key",
                lambda user_sub, key_id: (FAKE_PEM if user_sub == self.USER else None),
            )
        )

        # Audit capture.
        self.audit = []
        self.stack.enter_context(
            patch(
                "app.services.alerts.audit_event",
                lambda event, user_sub, *a, **f: self.audit.append((event, f)),
            )
        )

    def _set_flag(self, name, value):
        prev = getattr(self.S, name)
        object.__setattr__(self.S, name, value)
        self.addCleanup(lambda n=name, p=prev: object.__setattr__(self.S, n, p))

    def _events(self):
        return [e for e, _ in self.audit]

    def _submit_and_run(self, *, stub):
        action = self.eng.submit_action(
            self.USER, self.WORKER,
            action_type="run_command", command="echo hi", path_id=self.PATH_ID,
        )
        raw = self.actions.get_item(
            Key={"pk": f"WORKER#{self.WORKER}", "sk": f"ACTION#{action['action_id']}"}
        )["Item"]
        with patch.dict(sys.modules, {"paramiko": stub}):
            return self.eng.execute_action(raw)

    # -- happy path --------------------------------------------------------

    def test_multihop_exec_happy_path(self):
        stub, registry = _make_stub_paramiko(stdout=b"hello from target\n", exit_status=0)
        result = self._submit_and_run(stub=stub)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("hello from target", result["stdout_tail"])
        # Hop 0 dialed directly; the target reached via a direct-tcpip tunnel.
        self.assertEqual(registry["connect_calls"][0]["hostname"], "bastion.internal")
        dests = [c["dest"] for c in registry["open_channel_calls"]]
        self.assertIn(("target.internal", 22), dests)
        # exec_command ran on the final transport.
        self.assertIn("echo hi", registry["exec_calls"])
        # Transports/clients torn down.
        self.assertGreaterEqual(registry["closed_transports"], 1)
        self.assertGreaterEqual(registry["closed_clients"], 1)
        self.assertIn("agent_action.connect", self._events())
        self.assertIn("agent_action.complete", self._events())

    def test_multihop_nonzero_exit_is_failed(self):
        stub, _ = _make_stub_paramiko(stdout=b"", stderr=b"boom", exit_status=3)
        result = self._submit_and_run(stub=stub)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["exit_code"], 3)
        self.assertIn("boom", result["stderr_tail"])

    def test_multihop_timeout(self):
        self._set_flag("agent_ssh_qa_action_timeout_seconds", 1)
        stub, registry = _make_stub_paramiko(ready=False)  # exit never ready
        result = self._submit_and_run(stub=stub)
        self.assertEqual(result["status"], "timed_out")
        self.assertIn("agent_action.timeout", self._events())
        # Session closed on timeout.
        self.assertGreaterEqual(registry["closed_sessions"], 1)

    # -- credential boundary ----------------------------------------------

    def test_pem_never_persisted_for_multihop(self):
        stub, _ = _make_stub_paramiko()
        self._submit_and_run(stub=stub)
        for item in self.actions.scan().get("Items", []):
            for v in item.values():
                self.assertNotIn("PRIVATE KEY", str(v))

    # -- error normalisation ----------------------------------------------

    def test_unknown_path_fails_cleanly(self):
        action = self.eng.submit_action(
            self.USER, self.WORKER,
            action_type="run_command", command="echo hi", path_id="bp_missing",
        )
        raw = self.actions.get_item(
            Key={"pk": f"WORKER#{self.WORKER}", "sk": f"ACTION#{action['action_id']}"}
        )["Item"]
        result = self.eng.execute_action(raw)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "path_not_found")

    def test_auth_failure_is_normalised(self):
        stub, _ = _make_stub_paramiko()
        # Make the direct connect raise an auth failure on hop 0.
        def _bad_client():
            c = _StubSSHClient({
                "open_channel_calls": [], "connect_calls": [], "auth": [],
                "exec_calls": [], "start_client_calls": 0, "closed_sessions": 0,
                "closed_transports": 0, "closed_clients": 0,
                "stdout": b"", "stderr": b"", "exit_status": 0, "ready": True,
            })
            def _raise(**kw):
                raise stub.AuthenticationException("nope")
            c.connect = _raise
            return c
        stub.SSHClient.side_effect = _bad_client
        action = self.eng.submit_action(
            self.USER, self.WORKER,
            action_type="run_command", command="echo hi", path_id=self.PATH_ID,
        )
        raw = self.actions.get_item(
            Key={"pk": f"WORKER#{self.WORKER}", "sk": f"ACTION#{action['action_id']}"}
        )["Item"]
        with patch.dict(sys.modules, {"paramiko": stub}):
            result = self.eng.execute_action(raw)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "auth_failed")

    # -- direct exec_via_chain unit (guard) -------------------------------

    def test_exec_via_chain_requires_two_hops(self):
        with self.assertRaises(self.bastion_svc.BastionConnectError) as cm:
            self.bastion_svc.exec_via_chain(
                [{"hostname": "h", "port": 22, "username": "u", "password": "p"}],
                "echo x", timeout_seconds=5,
            )
        self.assertEqual(cm.exception.code, "invalid_chain")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
