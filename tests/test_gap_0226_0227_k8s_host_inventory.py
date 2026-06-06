"""Offline regression tests for GAP-0226 + GAP-0227 (INFRA-004).

Both bugs live in ``app/services/k8s_launcher.py`` and concern the Host
Inventory integration:

* GAP-0226 — ``launch_pod()`` never auto-registered the pod in the host
  inventory: ``host_id`` was initialised to ``""`` and never backfilled, so the
  pod was unreachable via Quick Connect / connection profiles.
* GAP-0227 — ``terminate_pod()`` never deleted the auto-registered host
  inventory entry, leaving "ghost" hosts that accumulate forever.

Fix:
* ``launch_pod()`` now calls ``host_inventory.create_host(... source="k8s_auto",
  group="K8s Containers")`` after persisting the pod, and writes the returned
  ``host_id`` back into the pod record.
* ``terminate_pod()`` now calls ``host_inventory.delete_host(user_sub, host_id)``
  when ``host_id`` is non-empty (a no-op for pre-GAP-0226 pods).

Both code paths are pure DynamoDB operations with no dev/prod fork — the dev
mock K8s path (``S.k8s_mock_enabled is True``) is unchanged (SECOPS-007).

Test isolation (mirrors tests/test_gap_0225_k8s_real_path.py):
 * Real in-memory moto DynamoDB tables back the ``k8s_pods`` AND
   ``host_inventory`` tables — the launcher's ``T`` handle is monkeypatched to
   point at both via ``patch.object`` (no global moto interception leaking to
   real AWS).
 * ``Settings`` is frozen, so flags are flipped with ``object.__setattr__``.
 * The ``kubernetes`` package is NOT touched: every test stays on the dev mock
   K8s path (``k8s_mock_enabled=True``), so no fake kubernetes module is needed.
   The host-inventory integration is environment-agnostic and is exercised on
   the mock path exactly as it would run in prod.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_k8s_pods_table(ddb):
    return ddb.create_table(
        TableName="k8s_pods",
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
        TableName="host_inventory",
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


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestK8sHostInventoryGap0226And0227(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.pods_table = _make_k8s_pods_table(ddb)
        self.hosts_table = _make_host_inventory_table(ddb)

        from app.services import k8s_launcher
        from app.services import host_inventory

        self.k8s = k8s_launcher
        self.host_inv = host_inventory
        self.S = k8s_launcher.S

        # Point BOTH services' table handles at the in-memory tables. The k8s
        # launcher uses T.k8s_pods; host_inventory uses T.host_inventory.
        fake_T = SimpleNamespace(
            k8s_pods=self.pods_table,
            host_inventory=self.hosts_table,
        )
        self.stack.enter_context(patch.object(k8s_launcher, "T", fake_T))
        self.stack.enter_context(patch.object(host_inventory, "T", fake_T))

        # Stay on the dev mock K8s path; disable the admin quota path so the
        # launch path stays focused on the host-inventory integration.
        self._orig = {
            "k8s_mock_enabled": self.S.k8s_mock_enabled,
            "admin_compute_dashboard_enabled": self.S.admin_compute_dashboard_enabled,
        }
        object.__setattr__(self.S, "k8s_mock_enabled", True)
        object.__setattr__(self.S, "admin_compute_dashboard_enabled", False)
        self.addCleanup(self._restore_settings)

    def _restore_settings(self):
        for k, v in self._orig.items():
            object.__setattr__(self.S, k, v)

    # -- GAP-0226: auto-registration --------------------------------------

    def test_launch_pod_auto_registers_host_inventory(self):
        """GAP-0226: launch_pod must create a host entry and store host_id."""
        item = self.k8s.launch_pod(
            "user_alice", label="My Pod", image="ubuntu-ssh", preset="small"
        )

        # Pod record carries a non-empty host_id (was always "" before the fix).
        self.assertTrue(item["host_id"], "pod record must carry a host_id")

        # host_id is persisted back into the DDB pod record.
        stored = self.pods_table.get_item(
            Key={"user_sub": "user_alice", "sk": item["sk"]}
        ).get("Item")
        self.assertEqual(stored["host_id"], item["host_id"])

        # The host inventory entry actually exists and has the expected shape.
        host = self.host_inv.get_host("user_alice", item["host_id"])
        self.assertIsNotNone(host, "host inventory entry must exist")
        self.assertEqual(host["source"], "k8s_auto")
        self.assertEqual(host["protocol"], "ssh")
        self.assertEqual(host["port"], 22)
        self.assertTrue(host["hostname"].endswith(".svc.cluster.local"))
        self.assertEqual(host["label"], "My Pod (K8s)")

    def test_launch_pod_register_failure_does_not_fail_launch(self):
        """GAP-0226: a create_host failure must not break the pod launch."""
        with patch.object(
            self.k8s, "create_host", side_effect=RuntimeError("boom")
        ):
            item = self.k8s.launch_pod(
                "user_bob", label="Resilient", image="ubuntu-ssh", preset="small"
            )
        # Launch still succeeded; host_id simply stays empty.
        self.assertEqual(item["status"], "running")
        self.assertEqual(item["host_id"], "")

    # -- GAP-0227: cleanup on termination ---------------------------------

    def test_terminate_pod_removes_host_inventory(self):
        """GAP-0227: terminate_pod must delete the auto-registered host entry."""
        item = self.k8s.launch_pod(
            "user_carol", label="Disposable", image="ubuntu-ssh", preset="small"
        )
        host_id = item["host_id"]
        self.assertTrue(host_id)
        self.assertIsNotNone(self.host_inv.get_host("user_carol", host_id))

        self.k8s.terminate_pod("user_carol", item["pod_id"])

        # Host inventory entry is gone (was left behind before the fix).
        self.assertIsNone(
            self.host_inv.get_host("user_carol", host_id),
            "host inventory entry must be deleted on termination",
        )
        # Pod record flips to terminated regardless.
        stored = self.pods_table.get_item(
            Key={"user_sub": "user_carol", "sk": item["sk"]}
        ).get("Item")
        self.assertEqual(stored["status"], "terminated")

    def test_terminate_pod_calls_delete_host_once(self):
        """GAP-0227: delete_host is invoked exactly once with the stored host_id."""
        item = self.k8s.launch_pod(
            "user_dave", label="x", image="ubuntu-ssh", preset="small"
        )
        host_id = item["host_id"]

        with patch.object(self.k8s, "delete_host") as mock_del:
            self.k8s.terminate_pod("user_dave", item["pod_id"])
        mock_del.assert_called_once_with("user_dave", host_id)

    def test_terminate_pod_no_host_id_skips_cleanup(self):
        """GAP-0227: pre-GAP-0226 pods (host_id == "") must not call delete_host."""
        from app.core.time import now_ts

        self.pods_table.put_item(Item={
            "user_sub": "user_eve",
            "sk": "POD#p_legacy",
            "pod_id": "p_legacy",
            "k8s_pod_name": "ws-eve-legacy",
            "namespace": "user-eve",
            "status": "running",
            "host_id": "",  # legacy pod, pre-GAP-0226
            "created_at": now_ts(),
            "expires_at": now_ts() + 3600,
        })

        with patch.object(self.k8s, "delete_host") as mock_del:
            self.k8s.terminate_pod("user_eve", "p_legacy")
        mock_del.assert_not_called()

    def test_ttl_checker_cleans_up_host_inventory(self):
        """GAP-0227: TTL expiry path (delegates to terminate_pod) also cleans up."""
        item = self.k8s.launch_pod(
            "user_frank", label="x", image="ubuntu-ssh", preset="small"
        )
        host_id = item["host_id"]
        self.assertTrue(host_id)

        # Back-date expiry so the TTL checker terminates it.
        self.pods_table.update_item(
            Key={"user_sub": "user_frank", "sk": item["sk"]},
            UpdateExpression="SET expires_at = :old",
            ExpressionAttributeValues={":old": 1},
        )
        count = self.k8s.check_expired_pods()
        self.assertGreaterEqual(count, 1)
        self.assertIsNone(
            self.host_inv.get_host("user_frank", host_id),
            "TTL expiry must also remove the host inventory entry",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
