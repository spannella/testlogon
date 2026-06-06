"""Offline regression test for GAP-0238 (INFRA-012).

Claim under audit: "quota not enforced in `k8s_launcher.py`".

Verified reality (see docs/tickets/gap-tickets/writeups/GAP-0238.md, Second-pass
verification 2026-06-05): the claim is INACCURATE. `launch_pod()` already enforces
the per-user admin-assigned quota via step 3b:

    # 3b. Enforce per-user admin quota (INFRA-012)
    if S.admin_compute_dashboard_enabled:
        from app.services.admin_compute import (
            enforce_k8s_quota, QuotaExceeded, SpendingLimitReached,
        )
        try:
            enforce_k8s_quota(user_sub, preset)
        except (QuotaExceeded, SpendingLimitReached) as e:
            raise PodLimitReached(str(e))

This mirrors `ec2_launcher`'s `enforce_ec2_quota` pattern. The fix is already
present in product code, so these tests are LOCK-IN regression guards: they fail
if the step 3b enforcement is ever removed (or accidentally un-gated) and pass on
the current codebase.

Coverage:
 * over-quota  -> enforce_k8s_quota raises QuotaExceeded -> launch_pod raises
   PodLimitReached (wrapping the quota error).
 * under-quota -> enforce_k8s_quota returns None -> launch_pod creates a pod, and
   the enforcement hook was invoked exactly once with (user_sub, preset).
 * feature-flag off -> enforce_k8s_quota is NOT called (parity with EC2 gating).

Test isolation (per task TEST ISOLATION rules + mirrors
tests/test_gap_0225_k8s_real_path.py):
 * The `kubernetes` package is NOT installed; we exercise the dev/mock path only
   (S.k8s_mock_enabled=True) so the real cluster client is never reached.
 * `Settings` (`S`) is FROZEN -> flip flags with object.__setattr__.
 * DynamoDB is backed by an in-memory moto table; the launcher's `T` handle is
   pointed at it via patch.object so no real AWS / global handle is touched.
 * `enforce_k8s_quota` is patched at its definition module
   (`app.services.admin_compute`) because launch_pod lazily imports it from there
   at call time.
 * host auto-register (`create_host`) and timeline writes are stubbed so the test
   stays focused on quota and hermetic (they are best-effort in product code).
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
    """Mirror the k8s_pods table key schema from scripts/local-ddb-init.py."""
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


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestK8sQuotaEnforcedGap0238(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)

        # moto DynamoDB only — the K8s client is never reached (mock path).
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_k8s_pods_table(ddb)

        from app.services import k8s_launcher
        from app.services import admin_compute

        self.k8s = k8s_launcher
        self.admin_compute = admin_compute
        self.S = k8s_launcher.S

        # Point the service's table handle at the in-memory table (T is frozen;
        # patch.object swaps the module-level reference for the test duration).
        self.stack.enter_context(
            patch.object(k8s_launcher, "T", SimpleNamespace(k8s_pods=self.table))
        )

        # Frozen Settings -> object.__setattr__. Enable the mock path and the
        # admin quota gate so step 3b actually fires.
        self._orig = {
            "k8s_mock_enabled": self.S.k8s_mock_enabled,
            "admin_compute_dashboard_enabled": self.S.admin_compute_dashboard_enabled,
        }
        object.__setattr__(self.S, "k8s_mock_enabled", True)
        object.__setattr__(self.S, "admin_compute_dashboard_enabled", True)
        self.addCleanup(self._restore_settings)

        # Keep launch hermetic + focused on quota: stub best-effort side effects.
        self.stack.enter_context(
            patch.object(k8s_launcher, "create_host", return_value={"host_id": ""})
        )
        self.stack.enter_context(
            patch.object(k8s_launcher, "_record_timeline", return_value=None)
        )

    def _restore_settings(self):
        for k, v in self._orig.items():
            object.__setattr__(self.S, k, v)

    # -- over quota --------------------------------------------------------

    def test_over_quota_blocks_launch(self):
        """enforce_k8s_quota raising QuotaExceeded must abort the launch.

        Fails-before: if step 3b were removed, launch_pod would create the pod
        and NOT raise.
        """
        from app.services.admin_compute import QuotaExceeded
        from app.services.k8s_launcher import PodLimitReached

        with patch.object(
            self.admin_compute,
            "enforce_k8s_quota",
            side_effect=QuotaExceeded("Maximum 2 pods allowed"),
        ) as mock_enforce:
            with self.assertRaises(PodLimitReached) as ctx:
                self.k8s.launch_pod(
                    "u_over_quota",
                    label="blocked",
                    image="ubuntu-ssh",
                    preset="small",
                )

        self.assertIn("Maximum 2 pods allowed", str(ctx.exception))
        mock_enforce.assert_called_once_with("u_over_quota", "small")
        # No pod must have been persisted.
        resp = self.table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key(
                "user_sub"
            ).eq("u_over_quota")
        )
        self.assertEqual(resp.get("Count", 0), 0)

    def test_over_quota_spending_limit_also_blocks(self):
        """SpendingLimitReached from the quota check is likewise wrapped/blocked."""
        from app.services.admin_compute import SpendingLimitReached
        from app.services.k8s_launcher import PodLimitReached

        with patch.object(
            self.admin_compute,
            "enforce_k8s_quota",
            side_effect=SpendingLimitReached("Monthly spending limit reached"),
        ):
            with self.assertRaises(PodLimitReached) as ctx:
                self.k8s.launch_pod(
                    "u_spend",
                    label="blocked",
                    image="ubuntu-ssh",
                    preset="small",
                )
        self.assertIn("Monthly spending limit reached", str(ctx.exception))

    # -- under quota -------------------------------------------------------

    def test_under_quota_allows_launch(self):
        """When the quota permits, launch_pod proceeds and invokes the hook once.

        Passes-after / on-current-code: the pod is created and persisted.
        """
        with patch.object(
            self.admin_compute, "enforce_k8s_quota", return_value=None
        ) as mock_enforce:
            item = self.k8s.launch_pod(
                "u_under_quota",
                label="ok",
                image="ubuntu-ssh",
                preset="small",
            )

        mock_enforce.assert_called_once_with("u_under_quota", "small")
        self.assertEqual(item["status"], "running")
        self.assertTrue(item["pod_id"])
        stored = self.table.get_item(
            Key={"user_sub": "u_under_quota", "sk": item["sk"]}
        ).get("Item")
        self.assertIsNotNone(stored)
        self.assertEqual(stored["preset"], "small")

    # -- feature flag gating (EC2 parity) ----------------------------------

    def test_quota_not_enforced_when_feature_disabled(self):
        """admin_compute_dashboard_enabled=False -> enforce_k8s_quota NOT called."""
        object.__setattr__(self.S, "admin_compute_dashboard_enabled", False)
        with patch.object(
            self.admin_compute, "enforce_k8s_quota"
        ) as mock_enforce:
            item = self.k8s.launch_pod(
                "u_flag_off",
                label="ok",
                image="ubuntu-ssh",
                preset="small",
            )
        mock_enforce.assert_not_called()
        self.assertEqual(item["status"], "running")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
