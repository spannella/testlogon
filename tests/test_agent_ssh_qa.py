"""Offline hermetic tests for the Agent SSH QA foundation (ADR-003 / AQA).

Covers the Option-B foundation:
  * AQA-003 agent_actions persistence round-trip + output truncation
  * AQA-004 exec engine happy path / non-zero exit / timeout (paramiko stubbed)
  * AQA-005 server-side credential injection: foreign/missing key -> key_not_found,
    PEM never persisted/logged
  * AQA-009 guardrails: agent_qa_allowed host gate, command denylist/length cap,
    per-worker concurrency + rate limit
  * AQA-010 audit emission for submit/connect/complete/failed/denied
  * AQA-007 terminal_monitor signal routing

Isolation (per repo TEST ISOLATION guidance):
  * moto in-memory DynamoDB tables bound onto the EXACT frozen ``T`` handles via
    ``object.__setattr__`` (restored on cleanup). No global botocore interception
    that could leak to real AWS.
  * ``paramiko`` is fully stubbed via ``patch.dict(sys.modules, ...)`` so no real
    SSH/network is attempted.
  * ``get_decrypted_private_key`` is patched at the source module so no KMS server
    is needed.
  * Frozen ``S`` flags toggled via ``object.__setattr__`` (restored on cleanup).
  * ``audit_event`` patched at ``app.services.alerts`` (the _audit wrapper imports
    it locally).
"""

from __future__ import annotations

import sys
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None


FAKE_PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEFAKEFAKEFAKE\n"
    "-----END OPENSSH PRIVATE KEY-----"
)


def _make_actions_table(ddb):
    return ddb.create_table(
        TableName="agent_actions_test",
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


def _make_host_table(ddb):
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


def _fake_channel(exit_status: int, ready: bool = True):
    chan = MagicMock()
    chan.exit_status_ready.return_value = ready
    chan.recv_exit_status.return_value = exit_status
    return chan


def _fake_stdout(text: str, exit_status: int, ready: bool = True):
    s = MagicMock()
    s.channel = _fake_channel(exit_status, ready)
    s.read.return_value = text.encode("utf-8")
    return s


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestAgentSshQa(unittest.TestCase):
    USER = "user-aqa"
    WORKER = "w_aqa1"
    HOST_ID = "h_allowed"
    KEY_ID = "k_known"

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.actions = _make_actions_table(ddb)
        self.hosts = _make_host_table(ddb)

        from app.core.tables import T
        from app.core.settings import S
        from app.services import agent_ssh_exec as eng
        from app.services import host_inventory

        self.eng = eng
        self.host_inventory = host_inventory
        self.S = S

        for name, tbl in (("agent_actions", self.actions), ("host_inventory", self.hosts)):
            prev = getattr(T, name)
            object.__setattr__(T, name, tbl)
            self.addCleanup(lambda n=name, p=prev: object.__setattr__(T, n, p))

        # Frozen S flags. Default: simulate (execute off). Generous guardrails.
        self._set_flag("agent_ssh_qa_enabled", True)
        self._set_flag("agent_qa_execute_commands", False)
        self._set_flag("agent_ssh_qa_command_denylist", "rm -rf,shutdown")
        self._set_flag("agent_ssh_qa_max_concurrent_per_worker", 5)
        self._set_flag("agent_ssh_qa_rate_limit_count", 50)

        # Reset the module-level rate-limit deque between tests.
        eng._RATE_BUCKETS.clear()

        # Seed an allowed host owned by USER.
        self.host_inventory.create_host(
            self.USER, label="qa host", hostname="qa.internal", port=22,
            protocol="ssh", username="ubuntu", agent_qa_allowed=True,
        )
        # Override host_id so tests can reference a known id.
        items = self.hosts.scan().get("Items", [])
        real_id = items[0]["host_id"]
        self.HOST_ID = real_id

        # A worker owned by USER pointing at the host + key.
        self.actions  # noqa
        from app.core.tables import T as _T
        # Stub worker resolution rather than seeding the agent_workers table.
        self._worker = {
            "worker_id": self.WORKER, "user_id": self.USER,
            "host_id": self.HOST_ID, "ssh_key_id": self.KEY_ID,
        }
        self.stack.enter_context(
            patch(
                "app.services.agent_worker_provisioner.get_worker",
                lambda u, w: (self._worker if (u == self.USER and w == self.WORKER) else None),
            )
        )

        # Credential injection: known key -> PEM, anything else -> None.
        self.decrypt_calls = []

        def _fake_decrypt(user_sub, key_id):
            self.decrypt_calls.append((user_sub, key_id))
            return FAKE_PEM if (user_sub == self.USER and key_id == self.KEY_ID) else None

        self.stack.enter_context(
            patch("app.services.ssh_key_manager.get_decrypted_private_key", _fake_decrypt)
        )

        # Capture audit events.
        self.audit = []
        self.stack.enter_context(
            patch(
                "app.services.alerts.audit_event",
                lambda event, user_sub, *a, **f: self.audit.append((event, f)),
            )
        )

        # Stub paramiko at the module boundary so a real dial never happens.
        self._install_paramiko_stub(stdout_text="hello\n", exit_status=0)

    def _set_flag(self, name, value):
        prev = getattr(self.S, name)
        object.__setattr__(self.S, name, value)
        self.addCleanup(lambda n=name, p=prev: object.__setattr__(self.S, n, p))

    def _install_paramiko_stub(self, *, stdout_text, exit_status, ready=True, stderr_text=""):
        client = MagicMock()
        client.connect.return_value = None
        client.exec_command.return_value = (
            MagicMock(),  # stdin
            _fake_stdout(stdout_text, exit_status, ready),
            _fake_stdout(stderr_text, exit_status, ready),
        )

        key_cls = MagicMock()
        key_cls.from_private_key.return_value = MagicMock()

        paramiko_stub = SimpleNamespace(
            SSHClient=lambda: client,
            AutoAddPolicy=lambda: object(),
            Ed25519Key=key_cls,
            ECDSAKey=key_cls,
            RSAKey=key_cls,
            DSSKey=key_cls,
        )
        self._paramiko_client = client
        self.stack.enter_context(patch.dict(sys.modules, {"paramiko": paramiko_stub}))
        # _load_private_key also runs; stub it so we don't need a real PEM.
        self.stack.enter_context(
            patch("app.services.ssh_key_manager._load_private_key", lambda pem, passphrase=None: object())
        )

    def _events(self):
        return [e for e, _ in self.audit]

    # -- AQA-003 persistence + AQA-007 simulate path ----------------------

    def test_submit_creates_pending_record(self):
        action = self.eng.submit_action(
            self.USER, self.WORKER, action_type="run_command", command="echo hello",
        )
        self.assertEqual(action["status"], "pending")
        self.assertTrue(action["action_id"].startswith("a_"))
        self.assertIn("agent_action.submit", self._events())
        got = self.eng.get_action(self.WORKER, action["action_id"])
        self.assertEqual(got["command"], "echo hello")

    def test_simulate_run_completes_with_completion_signal(self):
        # execute off -> in-memory simulation; test suite output -> completion.
        action = self.eng.submit_action(
            self.USER, self.WORKER, action_type="run_test_suite", command="pytest -q",
        )
        raw = self.actions.get_item(
            Key={"pk": f"WORKER#{self.WORKER}", "sk": f"ACTION#{action['action_id']}"}
        )["Item"]
        signals = []
        with patch(
            "app.services.terminal_monitor.process_terminal_output",
            lambda w, c: {"signal": "completion", "pattern": "p", "match": "m"},
        ) as _:
            signals.append("ok")
            result = self.eng.execute_action(raw)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("All tests passed", result["stdout_tail"])
        self.assertIn("agent_action.complete", self._events())

    # -- AQA-004 real exec (execute on, paramiko stubbed) -----------------

    def _run_with_exec(self, command="echo hello"):
        self._set_flag("agent_qa_execute_commands", True)
        action = self.eng.submit_action(self.USER, self.WORKER, action_type="run_command", command=command)
        raw = self.actions.get_item(
            Key={"pk": f"WORKER#{self.WORKER}", "sk": f"ACTION#{action['action_id']}"}
        )["Item"]
        return self.eng.execute_action(raw)

    def test_exec_happy_path(self):
        result = self._run_with_exec()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("hello", result["stdout_tail"])
        # Connect audit fired and channel client closed.
        self.assertIn("agent_action.connect", self._events())
        self.assertTrue(self._paramiko_client.close.called)

    def test_exec_nonzero_exit_is_failed(self):
        self.stack.close()  # rebuild with exit 3 stub
        self.setUp()
        self._install_paramiko_stub(stdout_text="", exit_status=3, stderr_text="boom")
        result = self._run_with_exec(command="exit 3")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["exit_code"], 3)

    def test_exec_timeout(self):
        # exit_status_ready always False -> wall-clock timeout.
        self._set_flag("agent_ssh_qa_action_timeout_seconds", 1)
        self._install_paramiko_stub(stdout_text="partial", exit_status=0, ready=False)
        result = self._run_with_exec(command="sleep 999")
        self.assertEqual(result["status"], "timed_out")
        self.assertIn("agent_action.timeout", self._events())
        self.assertTrue(self._paramiko_client.close.called)

    # -- AQA-005 credential injection -------------------------------------

    def test_foreign_key_returns_key_not_found(self):
        self._set_flag("agent_qa_execute_commands", True)
        self._worker["ssh_key_id"] = "k_foreign"
        action = self.eng.submit_action(self.USER, self.WORKER, action_type="run_command", command="echo x")
        raw = self.actions.get_item(
            Key={"pk": f"WORKER#{self.WORKER}", "sk": f"ACTION#{action['action_id']}"}
        )["Item"]
        result = self.eng.execute_action(raw)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "key_not_found")
        self.assertFalse(self._paramiko_client.connect.called)

    def test_pem_never_persisted(self):
        self._run_with_exec()
        # No stored action item should contain the PEM material.
        for item in self.actions.scan().get("Items", []):
            for v in item.values():
                self.assertNotIn("PRIVATE KEY", str(v))

    # -- AQA-009 guardrails -----------------------------------------------

    def test_host_not_allowed_is_denied(self):
        self._set_flag("agent_qa_execute_commands", True)
        # Flip the host flag off.
        self.host_inventory.update_host(self.USER, self.HOST_ID, agent_qa_allowed=False)
        action = self.eng.submit_action(self.USER, self.WORKER, action_type="run_command", command="echo x")
        raw = self.actions.get_item(
            Key={"pk": f"WORKER#{self.WORKER}", "sk": f"ACTION#{action['action_id']}"}
        )["Item"]
        result = self.eng.execute_action(raw)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "policy_denied_host")
        self.assertFalse(self._paramiko_client.connect.called)

    def test_command_denylist_rejected_at_submit(self):
        with self.assertRaises(self.eng.AgentSshExecError) as cm:
            self.eng.submit_action(self.USER, self.WORKER, action_type="run_command", command="rm -rf /")
        self.assertEqual(cm.exception.code, "command_denied")
        self.assertIn("agent_action.denied", self._events())

    def test_command_length_cap(self):
        self._set_flag("agent_ssh_qa_command_max_length", 10)
        with self.assertRaises(self.eng.AgentSshExecError) as cm:
            self.eng.submit_action(self.USER, self.WORKER, action_type="run_command", command="x" * 50)
        self.assertEqual(cm.exception.code, "command_too_long")

    def test_rate_limit(self):
        self._set_flag("agent_ssh_qa_rate_limit_count", 2)
        self.eng.submit_action(self.USER, self.WORKER, action_type="run_command", command="echo 1")
        self.eng.submit_action(self.USER, self.WORKER, action_type="run_command", command="echo 2")
        with self.assertRaises(self.eng.AgentSshExecError) as cm:
            self.eng.submit_action(self.USER, self.WORKER, action_type="run_command", command="echo 3")
        self.assertEqual(cm.exception.code, "rate_limited")

    def test_concurrency_limit(self):
        self._set_flag("agent_ssh_qa_max_concurrent_per_worker", 1)
        self.eng.submit_action(self.USER, self.WORKER, action_type="run_command", command="echo 1")
        with self.assertRaises(self.eng.AgentSshExecError) as cm:
            self.eng.submit_action(self.USER, self.WORKER, action_type="run_command", command="echo 2")
        self.assertEqual(cm.exception.code, "rate_limited")

    def test_unknown_worker_rejected(self):
        with self.assertRaises(self.eng.AgentSshExecError) as cm:
            self.eng.submit_action(self.USER, "w_nope", action_type="run_command", command="echo x")
        self.assertEqual(cm.exception.code, "worker_not_found")

    # -- output truncation -------------------------------------------------

    def test_output_truncated_before_persist(self):
        big = "A" * (self.eng._OUTPUT_TAIL_MAX + 500)
        self._set_flag("agent_qa_execute_commands", True)
        self._install_paramiko_stub(stdout_text=big, exit_status=0)
        result = self._run_with_exec()
        self.assertEqual(len(result["stdout_tail"]), self.eng._OUTPUT_TAIL_MAX)

    # -- runner CAS --------------------------------------------------------

    def test_runner_claims_and_executes(self):
        self.eng.submit_action(self.USER, self.WORKER, action_type="run_test_suite", command="pytest")
        processed = self.eng.run_one_batch(5)
        self.assertGreaterEqual(processed, 1)
        # Action reached a terminal state.
        actions = self.eng.list_actions(self.WORKER)
        self.assertTrue(any(a["status"] in self.eng.TERMINAL_STATUSES for a in actions))

    def test_cancel(self):
        action = self.eng.submit_action(self.USER, self.WORKER, action_type="run_command", command="echo x")
        cancelled = self.eng.cancel_action(self.USER, self.WORKER, action["action_id"])
        self.assertEqual(cancelled["status"], "cancelled")


if __name__ == "__main__":
    unittest.main()
