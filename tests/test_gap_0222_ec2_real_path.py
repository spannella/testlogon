"""Offline regression test for GAP-0222 (INFRA-003).

Bug: when ``S.ec2_mock_enabled`` is ``False`` (production with real AWS),
``launch_instance()`` in ``app/services/ec2_launcher.py`` raised
``NotImplementedError("Real EC2 launch not implemented yet")``, and
``stop/start/terminate/reboot_instance`` silently skipped the real AWS EC2 API
(updating DynamoDB only — a split-brain state).

Fix: ``_real_ec2_launch()`` calls ``boto3.client("ec2").run_instances(...)`` via
the new ``app.core.aws.ec2_client()`` helper, and each lifecycle op gained an
``else`` branch that calls the matching boto3 EC2 method. The dev/mock path
(``S.ec2_mock_enabled is True``) is unchanged (SECOPS-007 dev/prod parity).

Test isolation: this test does NOT use global ``@mock_aws`` interception for the
EC2 client (which can leak to real AWS). The EC2 client is replaced with a
``MagicMock`` that records calls — no real boto3 EC2 calls are ever made. A
real in-memory moto DynamoDB table backs the DDB writes only. ``Settings`` is
frozen, so flags are flipped with ``object.__setattr__``.
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
    """Mirror the ec2_instances table key schema from scripts/local-ddb-init.py."""
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


def _run_instances_response(instance_id="i-prod123"):
    return {
        "Instances": [
            {
                "InstanceId": instance_id,
                "State": {"Name": "pending"},
                "PublicIpAddress": "203.0.113.1",
                "PrivateIpAddress": "10.0.1.1",
            }
        ]
    }


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestEc2RealPathGap0222(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        # moto DynamoDB only — the EC2 client is a MagicMock, never real boto3.
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_ec2_instances_table(ddb)

        from app.services import ec2_launcher

        self.ec2_launcher = ec2_launcher
        self.S = ec2_launcher.S

        # Point the service's table handle at the in-memory table.
        self.stack.enter_context(
            patch.object(ec2_launcher, "T", SimpleNamespace(ec2_instances=self.table))
        )

        # Frozen Settings -> object.__setattr__. Disable orthogonal features
        # (security groups, admin quota) so the launch path is focused on the
        # mock/real fork under test. Restore them on cleanup.
        self._orig = {
            "ec2_mock_enabled": self.S.ec2_mock_enabled,
            "security_groups_enabled": self.S.security_groups_enabled,
            "admin_compute_dashboard_enabled": self.S.admin_compute_dashboard_enabled,
            "ec2_real_ami_ubuntu_2204": self.S.ec2_real_ami_ubuntu_2204,
        }
        object.__setattr__(self.S, "security_groups_enabled", False)
        object.__setattr__(self.S, "admin_compute_dashboard_enabled", False)
        object.__setattr__(self.S, "ec2_real_ami_ubuntu_2204", "ami-0abcdef1234567890")
        self.addCleanup(self._restore_settings)

    def _restore_settings(self):
        for k, v in self._orig.items():
            object.__setattr__(self.S, k, v)

    def _set_mock(self, enabled: bool):
        object.__setattr__(self.S, "ec2_mock_enabled", enabled)

    # -- launch ------------------------------------------------------------

    def test_launch_prod_calls_run_instances_and_maps_response(self):
        """GAP-0222: prod launch must call run_instances (not raise) and map fields."""
        self._set_mock(False)
        mock_ec2 = MagicMock()
        mock_ec2.run_instances.return_value = _run_instances_response("i-prod123")

        with patch("app.core.aws.ec2_client", return_value=mock_ec2):
            item = self.ec2_launcher.launch_instance(
                "test-user",
                label="prod-test",
                instance_type="t3.micro",
                ami_id="ami-ubuntu-2204",
                startup_script="echo hi",
            )

        mock_ec2.run_instances.assert_called_once()
        kwargs = mock_ec2.run_instances.call_args.kwargs
        self.assertEqual(kwargs["ImageId"], "ami-0abcdef1234567890")  # alias resolved
        self.assertEqual(kwargs["InstanceType"], "t3.micro")
        self.assertEqual(kwargs["MinCount"], 1)
        self.assertEqual(kwargs["MaxCount"], 1)
        self.assertIn("UserData", kwargs)  # startup_script -> base64 UserData

        self.assertEqual(item["ec2_instance_id"], "i-prod123")
        self.assertEqual(item["public_ip"], "203.0.113.1")
        self.assertEqual(item["private_ip"], "10.0.1.1")
        # Persisted to DDB.
        stored = self.table.get_item(
            Key={"user_sub": "test-user", "sk": item["sk"]}
        ).get("Item")
        self.assertEqual(stored["ec2_instance_id"], "i-prod123")

    def test_launch_prod_without_real_ami_raises_valueerror(self):
        """Unconfigured AMI alias -> clear ValueError, not a boto3 call."""
        self._set_mock(False)
        object.__setattr__(self.S, "ec2_real_ami_ubuntu_2204", "")
        mock_ec2 = MagicMock()
        with patch("app.core.aws.ec2_client", return_value=mock_ec2):
            with self.assertRaises(ValueError):
                self.ec2_launcher.launch_instance(
                    "test-user",
                    label="x",
                    instance_type="t3.micro",
                    ami_id="ami-ubuntu-2204",
                )
        mock_ec2.run_instances.assert_not_called()

    def test_launch_dev_mock_path_unchanged(self):
        """SECOPS-007: dev/mock path must not call boto3 EC2 at all."""
        self._set_mock(True)
        mock_ec2 = MagicMock()
        with patch("app.core.aws.ec2_client", return_value=mock_ec2):
            item = self.ec2_launcher.launch_instance(
                "dev-user",
                label="dev",
                instance_type="t3.micro",
                ami_id="ami-ubuntu-2204",
            )
        mock_ec2.run_instances.assert_not_called()
        self.assertTrue(item["ec2_instance_id"].startswith("i-mock"))

    # -- lifecycle ops (prod) ----------------------------------------------

    def _seed_running_instance(self, user="op-user"):
        """Create a running instance via the mock path, then return its item."""
        self._set_mock(True)
        item = self.ec2_launcher.launch_instance(
            user, label="x", instance_type="t3.micro", ami_id="ami-ubuntu-2204"
        )
        self._set_mock(False)
        return item

    def test_stop_prod_calls_stop_instances(self):
        item = self._seed_running_instance()
        mock_ec2 = MagicMock()
        with patch("app.core.aws.ec2_client", return_value=mock_ec2):
            self.ec2_launcher.stop_instance("op-user", item["instance_id"])
        mock_ec2.stop_instances.assert_called_once_with(
            InstanceIds=[item["ec2_instance_id"]]
        )

    def test_start_prod_calls_start_instances(self):
        item = self._seed_running_instance()
        # Move it to stopped first (prod stop call, mocked).
        mock_ec2 = MagicMock()
        with patch("app.core.aws.ec2_client", return_value=mock_ec2):
            self.ec2_launcher.stop_instance("op-user", item["instance_id"])
            self.ec2_launcher.start_instance("op-user", item["instance_id"])
        mock_ec2.start_instances.assert_called_once_with(
            InstanceIds=[item["ec2_instance_id"]]
        )

    def test_terminate_prod_calls_terminate_instances(self):
        item = self._seed_running_instance()
        mock_ec2 = MagicMock()
        with patch("app.core.aws.ec2_client", return_value=mock_ec2):
            self.ec2_launcher.terminate_instance("op-user", item["instance_id"])
        mock_ec2.terminate_instances.assert_called_once_with(
            InstanceIds=[item["ec2_instance_id"]]
        )

    def test_reboot_prod_calls_reboot_instances(self):
        item = self._seed_running_instance()
        mock_ec2 = MagicMock()
        with patch("app.core.aws.ec2_client", return_value=mock_ec2):
            self.ec2_launcher.reboot_instance("op-user", item["instance_id"])
        mock_ec2.reboot_instances.assert_called_once_with(
            InstanceIds=[item["ec2_instance_id"]]
        )

    def test_lifecycle_dev_mock_does_not_call_boto3(self):
        """SECOPS-007: dev/mock lifecycle ops never touch boto3 EC2."""
        item = self._seed_running_instance()
        self._set_mock(True)
        mock_ec2 = MagicMock()
        with patch("app.core.aws.ec2_client", return_value=mock_ec2):
            self.ec2_launcher.stop_instance("op-user", item["instance_id"])
            self.ec2_launcher.start_instance("op-user", item["instance_id"])
            self.ec2_launcher.reboot_instance("op-user", item["instance_id"])
            self.ec2_launcher.terminate_instance("op-user", item["instance_id"])
        mock_ec2.stop_instances.assert_not_called()
        mock_ec2.start_instances.assert_not_called()
        mock_ec2.reboot_instances.assert_not_called()
        mock_ec2.terminate_instances.assert_not_called()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
