"""Offline regression tests for GAP-0223 and GAP-0224 (INFRA-003).

GAP-0223 — Auto-registration in host inventory never happens.
    After ``launch_instance()`` stored the EC2 instance, the ``host_id`` field
    on the DDB record stayed ``""`` forever — the instance was never registered
    in the user's host inventory, so it never appeared in the SSH terminal
    quick-connect picker. Fix: after the SG-association block, call
    ``host_inventory.create_host(...)`` and back-write the returned ``host_id``.

GAP-0224 — Host inventory not cleaned up on instance termination.
    ``terminate_instance()`` never read ``item["host_id"]`` and never called
    ``host_inventory.delete_host(...)``, so a stale host entry pointing at a
    dead IP lingered indefinitely (and counted against the per-user host cap).
    Fix: in ``terminate_instance()`` (and therefore the auto-terminate idle
    checker) read ``host_id`` and call ``delete_host`` (plus SSH-key
    disassociation), mirroring the SG-disassociation pattern.

Test isolation (per SECOPS-007 / repo rules):
  * NO global ``@mock_aws`` interception of the EC2 client — the prod EC2 path
    is exercised only with a ``MagicMock`` EC2 client (``app.core.aws.ec2_client``).
    No real boto3 EC2 calls are ever made.
  * Real in-memory moto DynamoDB tables back the DDB writes for both the
    ``ec2_instances`` and ``host_inventory`` tables.
  * ``Settings`` is frozen -> flags flipped with ``object.__setattr__``.
  * The dev/mock path (``S.ec2_mock_enabled is True``) is the default used by
    these tests and must remain UNCHANGED by the fix.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_ec2_instances_table(ddb):
    return ddb.create_table(
        TableName="ec2_instances",
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
    """Base table only — list_hosts/_scan_all_hosts use a base-table query."""
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
class TestEc2HostInventoryGap0223And0224(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        # moto DynamoDB only — the EC2 client (when used) is a MagicMock.
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.ec2_table = _make_ec2_instances_table(ddb)
        self.host_table = _make_host_inventory_table(ddb)

        from app.services import ec2_launcher
        from app.services import host_inventory

        self.ec2_launcher = ec2_launcher
        self.host_inventory = host_inventory
        self.S = ec2_launcher.S

        # Both modules must see the same in-memory tables. ec2_launcher reads
        # T.ec2_instances; host_inventory reads T.host_inventory.
        fake_T = SimpleNamespace(
            ec2_instances=self.ec2_table,
            host_inventory=self.host_table,
        )
        self.stack.enter_context(patch.object(ec2_launcher, "T", fake_T))
        self.stack.enter_context(patch.object(host_inventory, "T", fake_T))

        # Frozen Settings -> object.__setattr__. Default to the dev/mock path
        # and disable orthogonal features so the launch/terminate path is
        # focused on host-inventory integration. Restore on cleanup.
        self._orig = {
            "ec2_mock_enabled": self.S.ec2_mock_enabled,
            "security_groups_enabled": self.S.security_groups_enabled,
            "admin_compute_dashboard_enabled": self.S.admin_compute_dashboard_enabled,
            "ec2_real_ami_ubuntu_2204": self.S.ec2_real_ami_ubuntu_2204,
        }
        object.__setattr__(self.S, "ec2_mock_enabled", True)
        object.__setattr__(self.S, "security_groups_enabled", False)
        object.__setattr__(self.S, "admin_compute_dashboard_enabled", False)
        object.__setattr__(self.S, "ec2_real_ami_ubuntu_2204", "ami-0abcdef1234567890")
        self.addCleanup(self._restore_settings)

    def _restore_settings(self):
        for k, v in self._orig.items():
            object.__setattr__(self.S, k, v)

    def _set_mock(self, enabled: bool):
        object.__setattr__(self.S, "ec2_mock_enabled", enabled)

    def _list_ec2_hosts(self, user):
        return [
            h for h in self.host_inventory.list_hosts(user)["hosts"]
            if h.get("source") == "ec2_auto"
        ]

    # -- GAP-0223: auto-registration --------------------------------------

    def test_launch_creates_host_inventory_entry(self):
        """GAP-0223: launch must register the instance in host inventory and
        back-write the host_id onto the DDB record."""
        item = self.ec2_launcher.launch_instance(
            "user-gap-0223",
            label="My Server",
            instance_type="t3.micro",
            ami_id="ami-ubuntu-2204",
        )

        # host_id is populated on the returned item ...
        self.assertNotEqual(item["host_id"], "")
        # ... and persisted to the DDB instance record.
        stored = self.ec2_table.get_item(
            Key={"user_sub": "user-gap-0223", "sk": item["sk"]}
        ).get("Item")
        self.assertEqual(stored["host_id"], item["host_id"])

        ec2_hosts = self._list_ec2_hosts("user-gap-0223")
        self.assertEqual(len(ec2_hosts), 1)
        self.assertEqual(ec2_hosts[0]["host_id"], item["host_id"])
        self.assertEqual(ec2_hosts[0]["protocol"], "ssh")
        self.assertEqual(ec2_hosts[0]["port"], 22)
        self.assertEqual(ec2_hosts[0]["group"], "EC2 Instances")
        self.assertEqual(ec2_hosts[0]["username"], "ubuntu")
        self.assertEqual(ec2_hosts[0]["hostname"], item["public_ip"])

    def test_launch_rdp_for_windows_ami(self):
        """GAP-0223: Windows AMIs register as RDP on port 3389."""
        item = self.ec2_launcher.launch_instance(
            "user-gap-0223-win",
            label="Windows Box",
            instance_type="t3.small",
            ami_id="ami-windows-2022",
        )
        self.assertNotEqual(item["host_id"], "")
        ec2_hosts = self._list_ec2_hosts("user-gap-0223-win")
        self.assertEqual(len(ec2_hosts), 1)
        self.assertEqual(ec2_hosts[0]["protocol"], "rdp")
        self.assertEqual(ec2_hosts[0]["port"], 3389)
        self.assertEqual(ec2_hosts[0]["os_type"], "windows")

    def test_launch_no_ip_skips_registration_and_does_not_raise(self):
        """If public_ip is empty (real AWS may not assign one immediately),
        launch succeeds with host_id='' and no host entry is created."""
        original_launch = self.ec2_launcher._mock_store.launch

        def patched_launch(**kwargs):
            r = original_launch(**kwargs)
            r["public_ip"] = ""
            return r

        self.stack.enter_context(
            patch.object(self.ec2_launcher._mock_store, "launch", patched_launch)
        )

        item = self.ec2_launcher.launch_instance(
            "user-gap-0223-noip",
            label="No IP",
            instance_type="t3.micro",
            ami_id="ami-ubuntu-2204",
        )
        self.assertNotEqual(item["instance_id"], "")
        self.assertEqual(item["host_id"], "")
        self.assertEqual(self._list_ec2_hosts("user-gap-0223-noip"), [])

    def test_launch_register_failure_does_not_roll_back_launch(self):
        """A create_host failure is swallowed; the instance is still launched
        with host_id='' (registration must never roll back the launch)."""
        with patch.object(
            self.host_inventory, "create_host", side_effect=RuntimeError("boom")
        ):
            item = self.ec2_launcher.launch_instance(
                "user-gap-0223-fail",
                label="Fail",
                instance_type="t3.micro",
                ami_id="ami-ubuntu-2204",
            )
        self.assertNotEqual(item["instance_id"], "")
        self.assertEqual(item["host_id"], "")
        # The instance record was still persisted.
        stored = self.ec2_table.get_item(
            Key={"user_sub": "user-gap-0223-fail", "sk": item["sk"]}
        ).get("Item")
        self.assertIsNotNone(stored)

    def test_launch_dev_mock_path_unchanged(self):
        """SECOPS-007: dev/mock launch never touches boto3 EC2, but still
        registers the host (registration runs in both modes)."""
        mock_ec2 = MagicMock()
        with patch("app.core.aws.ec2_client", return_value=mock_ec2):
            item = self.ec2_launcher.launch_instance(
                "user-gap-0223-dev",
                label="Dev",
                instance_type="t3.micro",
                ami_id="ami-ubuntu-2204",
            )
        mock_ec2.run_instances.assert_not_called()
        self.assertTrue(item["ec2_instance_id"].startswith("i-mock"))
        self.assertNotEqual(item["host_id"], "")

    def test_launch_real_path_registers_host(self):
        """GAP-0223 + GAP-0222 parity: the real EC2 path also auto-registers,
        with no real boto3 calls (EC2 client is a MagicMock)."""
        self._set_mock(False)
        mock_ec2 = MagicMock()
        mock_ec2.run_instances.return_value = {
            "Instances": [
                {
                    "InstanceId": "i-prod0224",
                    "State": {"Name": "pending"},
                    "PublicIpAddress": "203.0.113.5",
                    "PrivateIpAddress": "10.0.2.5",
                }
            ]
        }
        with patch("app.core.aws.ec2_client", return_value=mock_ec2):
            item = self.ec2_launcher.launch_instance(
                "user-gap-0223-prod",
                label="Prod",
                instance_type="t3.micro",
                ami_id="ami-ubuntu-2204",
            )
        mock_ec2.run_instances.assert_called_once()
        self.assertNotEqual(item["host_id"], "")
        ec2_hosts = self._list_ec2_hosts("user-gap-0223-prod")
        self.assertEqual(len(ec2_hosts), 1)
        self.assertEqual(ec2_hosts[0]["hostname"], "203.0.113.5")

    # -- GAP-0224: cleanup on termination ---------------------------------

    def test_terminate_removes_host_inventory_entry(self):
        """GAP-0224: terminate must delete the auto-registered host entry."""
        item = self.ec2_launcher.launch_instance(
            "user-gap-0224",
            label="Short-lived",
            instance_type="t3.micro",
            ami_id="ami-ubuntu-2204",
        )
        host_id = item["host_id"]
        self.assertNotEqual(host_id, "", "precondition: GAP-0223 must register a host")
        # Sanity: the host exists before termination.
        self.assertTrue(any(h["host_id"] == host_id for h in self._list_ec2_hosts("user-gap-0224")))

        self.ec2_launcher.terminate_instance("user-gap-0224", item["instance_id"])

        remaining = [h for h in self._list_ec2_hosts("user-gap-0224") if h["host_id"] == host_id]
        self.assertEqual(remaining, [])

    def test_terminate_noop_when_no_host_id(self):
        """Terminating an instance with host_id='' must not raise."""
        item = self.ec2_launcher.launch_instance(
            "user-gap-0224-nohostid",
            label="No host",
            instance_type="t3.micro",
            ami_id="ami-ubuntu-2204",
        )
        # Simulate a pre-GAP-0223 record by blanking host_id.
        self.ec2_table.update_item(
            Key={"user_sub": "user-gap-0224-nohostid", "sk": item["sk"]},
            UpdateExpression="SET host_id = :empty",
            ExpressionAttributeValues={":empty": ""},
        )
        # Must not raise.
        out = self.ec2_launcher.terminate_instance(
            "user-gap-0224-nohostid", item["instance_id"]
        )
        self.assertEqual(out["status"], "terminated")

    def test_terminate_cleanup_failure_does_not_block_termination(self):
        """A delete_host failure is swallowed; termination still completes."""
        item = self.ec2_launcher.launch_instance(
            "user-gap-0224-fail",
            label="Fail",
            instance_type="t3.micro",
            ami_id="ami-ubuntu-2204",
        )
        with patch.object(
            self.host_inventory, "delete_host", side_effect=RuntimeError("boom")
        ):
            out = self.ec2_launcher.terminate_instance(
                "user-gap-0224-fail", item["instance_id"]
            )
        self.assertEqual(out["status"], "terminated")
        stored = self.ec2_table.get_item(
            Key={"user_sub": "user-gap-0224-fail", "sk": item["sk"]}
        ).get("Item")
        self.assertEqual(stored["status"], "terminated")

    def test_auto_terminate_cleans_up_host(self):
        """GAP-0224: the idle checker's auto-termination also cleans up the
        host inventory entry."""
        item = self.ec2_launcher.launch_instance(
            "user-gap-0224-auto",
            label="Idle",
            instance_type="t3.micro",
            ami_id="ami-ubuntu-2204",
        )
        host_id = item["host_id"]
        self.assertNotEqual(host_id, "")

        # Back-date last_activity_at so the instance reads as long-idle.
        self.ec2_table.update_item(
            Key={"user_sub": "user-gap-0224-auto", "sk": item["sk"]},
            UpdateExpression="SET last_activity_at = :old",
            ExpressionAttributeValues={":old": 1},
        )

        count = self.ec2_launcher.check_idle_instances()
        self.assertGreaterEqual(count, 1)

        remaining = [h for h in self._list_ec2_hosts("user-gap-0224-auto") if h["host_id"] == host_id]
        self.assertEqual(remaining, [])

    def test_terminate_dev_mock_path_unchanged(self):
        """SECOPS-007: dev/mock terminate never touches boto3 EC2 while still
        cleaning up the host inventory entry."""
        item = self.ec2_launcher.launch_instance(
            "user-gap-0224-dev",
            label="Dev",
            instance_type="t3.micro",
            ami_id="ami-ubuntu-2204",
        )
        host_id = item["host_id"]
        mock_ec2 = MagicMock()
        with patch("app.core.aws.ec2_client", return_value=mock_ec2):
            self.ec2_launcher.terminate_instance("user-gap-0224-dev", item["instance_id"])
        mock_ec2.terminate_instances.assert_not_called()
        remaining = [h for h in self._list_ec2_hosts("user-gap-0224-dev") if h["host_id"] == host_id]
        self.assertEqual(remaining, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
