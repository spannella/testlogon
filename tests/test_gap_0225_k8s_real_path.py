"""Offline regression test for GAP-0225 (INFRA-004).

Bug: when ``S.k8s_mock_enabled`` is ``False`` (production), ``launch_pod()`` and
``get_pod_logs()`` in ``app/services/k8s_launcher.py`` raised
``NotImplementedError(...)``, and ``terminate_pod()`` silently skipped the real
Kubernetes API (updating DynamoDB only — a split-brain / zombie-pod state).

Fix: ``_real_k8s_launch()`` calls ``CoreV1Api().create_namespaced_pod(...)`` via a
lazily-imported ``kubernetes`` client (helper ``_get_k8s_core_v1()``);
``get_pod_logs()`` calls ``read_namespaced_pod_log(...)``; and ``terminate_pod()``
gained an ``else`` branch calling ``delete_namespaced_pod(...)``. The dev/mock
path (``S.k8s_mock_enabled is True``) is unchanged (SECOPS-007 dev/prod parity).

Test isolation:
 * The ``kubernetes`` package is NOT installed. ``_get_k8s_core_v1`` is replaced
   with a ``MagicMock``-returning patch so the real cluster config loader never
   runs and no network call is ever made.
 * For the prod path, ``_real_k8s_launch``/``terminate_pod`` lazily do
   ``from kubernetes import client``. A fake ``kubernetes`` module is installed
   into ``sys.modules`` for the duration of those tests so the import succeeds
   without the real package — still no network.
 * A real in-memory moto DynamoDB table backs DDB writes only.
 * ``Settings`` is frozen, so flags are flipped with ``object.__setattr__``.
"""
from __future__ import annotations

import sys
import unittest
from contextlib import ExitStack
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch

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


def _install_fake_kubernetes_module(stack: ExitStack) -> None:
    """Install a minimal fake ``kubernetes`` package into sys.modules.

    The real package is an optional/prod-only dependency and is not installed in
    CI. ``_real_k8s_launch`` / ``terminate_pod`` do ``from kubernetes import
    client`` to build V1* spec objects; this fake satisfies that import with
    trivial recording stubs. No network is ever touched (the CoreV1Api itself is
    a separate MagicMock provided via ``_get_k8s_core_v1``).
    """
    kubernetes = ModuleType("kubernetes")
    client_mod = ModuleType("kubernetes.client")
    config_mod = ModuleType("kubernetes.config")

    # V1* helpers — accept arbitrary kwargs and expose them as attributes so the
    # launcher's response-mapping (which only reads .metadata/.status) is happy
    # for objects WE build. The CoreV1Api response object is supplied separately.
    def _factory(name):
        def _make(**kwargs):
            return SimpleNamespace(_v1=name, **kwargs)
        return _make

    for cls in (
        "V1EnvVar", "V1Container", "V1ResourceRequirements",
        "V1ContainerPort", "V1Pod", "V1ObjectMeta", "V1PodSpec",
        "V1Namespace", "V1DeleteOptions",
    ):
        setattr(client_mod, cls, _factory(cls))
    client_mod.CoreV1Api = MagicMock(name="CoreV1Api")

    config_mod.load_incluster_config = MagicMock()
    config_mod.load_kube_config = MagicMock()

    kubernetes.client = client_mod
    kubernetes.config = config_mod

    stack.enter_context(patch.dict(sys.modules, {
        "kubernetes": kubernetes,
        "kubernetes.client": client_mod,
        "kubernetes.config": config_mod,
    }))


def _make_mock_core_v1():
    core_v1 = MagicMock(name="CoreV1Api_instance")
    pod = MagicMock()
    pod.metadata.name = "ws-testuser-abc123de"
    pod.metadata.namespace = "user-testuser"
    pod.status.phase = "Pending"
    pod.status.pod_ip = "10.1.2.3"
    core_v1.create_namespaced_pod.return_value = pod
    core_v1.read_namespaced_pod_log.return_value = "Starting SSH server\nSSH ready\n"
    return core_v1


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestK8sRealPathGap0225(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        # moto DynamoDB only — the K8s CoreV1Api is a MagicMock, never real.
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_k8s_pods_table(ddb)

        from app.services import k8s_launcher

        self.k8s = k8s_launcher
        self.S = k8s_launcher.S

        # Point the service's table handle at the in-memory table.
        self.stack.enter_context(
            patch.object(k8s_launcher, "T", SimpleNamespace(k8s_pods=self.table))
        )

        # Frozen Settings -> object.__setattr__. Disable the admin quota path so
        # the launch path stays focused on the mock/real fork under test.
        self._orig = {
            "k8s_mock_enabled": self.S.k8s_mock_enabled,
            "admin_compute_dashboard_enabled": self.S.admin_compute_dashboard_enabled,
        }
        object.__setattr__(self.S, "admin_compute_dashboard_enabled", False)
        self.addCleanup(self._restore_settings)

        # Ensure the cached CoreV1Api is reset between tests.
        self.k8s._k8s_core_v1_cache = None
        self.addCleanup(lambda: setattr(self.k8s, "_k8s_core_v1_cache", None))

    def _restore_settings(self):
        for k, v in self._orig.items():
            object.__setattr__(self.S, k, v)

    def _set_mock(self, enabled: bool):
        object.__setattr__(self.S, "k8s_mock_enabled", enabled)

    # -- import safety -----------------------------------------------------

    def test_module_imports_without_kubernetes_installed(self):
        """SECOPS-007: module must import in dev with no `kubernetes` package."""
        self.assertNotIn("kubernetes", sys.modules, "kubernetes must not be installed in CI")
        import importlib
        mod = importlib.import_module("app.services.k8s_launcher")
        self.assertTrue(hasattr(mod, "_real_k8s_launch"))
        self.assertTrue(hasattr(mod, "_get_k8s_core_v1"))

    def test_get_core_v1_raises_runtimeerror_without_package(self):
        """Helper surfaces a clean RuntimeError (not ImportError) when missing."""
        self.k8s._k8s_core_v1_cache = None
        self.assertNotIn("kubernetes", sys.modules)
        with self.assertRaises(RuntimeError):
            self.k8s._get_k8s_core_v1()

    # -- launch ------------------------------------------------------------

    def test_launch_prod_calls_create_namespaced_pod_and_maps_response(self):
        """GAP-0225: prod launch must call create_namespaced_pod (not raise)."""
        self._set_mock(False)
        _install_fake_kubernetes_module(self.stack)
        mock_core_v1 = _make_mock_core_v1()

        with patch.object(self.k8s, "_get_k8s_core_v1", return_value=mock_core_v1):
            item = self.k8s.launch_pod(
                "testuser",
                label="My Pod",
                image="ubuntu-ssh",
                preset="small",
            )

        mock_core_v1.create_namespaced_pod.assert_called_once()
        kwargs = mock_core_v1.create_namespaced_pod.call_args.kwargs
        self.assertEqual(kwargs["namespace"], item["namespace"])
        self.assertIsNotNone(kwargs["body"])

        self.assertNotEqual(item["pod_id"], "")
        self.assertEqual(item["pod_ip"], "10.1.2.3")
        self.assertEqual(item["status"], "running")
        # Persisted to DDB.
        stored = self.table.get_item(
            Key={"user_sub": "testuser", "sk": item["sk"]}
        ).get("Item")
        self.assertEqual(stored["pod_ip"], "10.1.2.3")

    def test_launch_dev_mock_path_unchanged(self):
        """SECOPS-007: dev/mock path must not call the kubernetes client at all."""
        self._set_mock(True)
        mock_core_v1 = MagicMock()
        with patch.object(self.k8s, "_get_k8s_core_v1", return_value=mock_core_v1):
            item = self.k8s.launch_pod(
                "dev-user",
                label="dev",
                image="ubuntu-ssh",
                preset="small",
            )
        mock_core_v1.create_namespaced_pod.assert_not_called()
        self.assertTrue(item["pod_ip"].startswith("10.pod."))

    # -- logs --------------------------------------------------------------

    def _seed_running_pod(self, user="op-user"):
        """Create a running pod via the mock path, then return its item."""
        self._set_mock(True)
        item = self.k8s.launch_pod(
            user, label="x", image="ubuntu-ssh", preset="small"
        )
        self._set_mock(False)
        return item

    def test_get_pod_logs_prod_calls_read_namespaced_pod_log(self):
        """GAP-0225: prod log fetch must call read_namespaced_pod_log (not raise)."""
        item = self._seed_running_pod("logsuser")
        mock_core_v1 = _make_mock_core_v1()
        with patch.object(self.k8s, "_get_k8s_core_v1", return_value=mock_core_v1):
            logs = self.k8s.get_pod_logs("logsuser", item["pod_id"])

        mock_core_v1.read_namespaced_pod_log.assert_called_once_with(
            name=item["k8s_pod_name"],
            namespace=item["namespace"],
            tail_lines=100,
        )
        self.assertIn("Starting SSH server", logs)

    def test_get_pod_logs_dev_mock_path_unchanged(self):
        """SECOPS-007: dev log fetch never calls the kubernetes client."""
        self._set_mock(True)
        item = self.k8s.launch_pod(
            "devlogs", label="x", image="ubuntu-ssh", preset="small"
        )
        mock_core_v1 = MagicMock()
        with patch.object(self.k8s, "_get_k8s_core_v1", return_value=mock_core_v1):
            logs = self.k8s.get_pod_logs("devlogs", item["pod_id"])
        mock_core_v1.read_namespaced_pod_log.assert_not_called()
        self.assertTrue(any("SSH server" in line for line in logs))

    # -- terminate ---------------------------------------------------------

    def test_terminate_prod_calls_delete_namespaced_pod(self):
        """GAP-0225: prod terminate must call delete_namespaced_pod (no silent no-op)."""
        item = self._seed_running_pod("termuser")
        _install_fake_kubernetes_module(self.stack)
        mock_core_v1 = MagicMock()
        with patch.object(self.k8s, "_get_k8s_core_v1", return_value=mock_core_v1):
            self.k8s.terminate_pod("termuser", item["pod_id"])

        mock_core_v1.delete_namespaced_pod.assert_called_once()
        kwargs = mock_core_v1.delete_namespaced_pod.call_args.kwargs
        self.assertEqual(kwargs["name"], item["k8s_pod_name"])
        self.assertEqual(kwargs["namespace"], item["namespace"])
        self.assertIsNotNone(kwargs["body"])
        # DDB still flips to terminated.
        stored = self.table.get_item(
            Key={"user_sub": "termuser", "sk": item["sk"]}
        ).get("Item")
        self.assertEqual(stored["status"], "terminated")

    def test_terminate_dev_mock_does_not_call_kubernetes(self):
        """SECOPS-007: dev/mock terminate never touches the kubernetes client."""
        item = self._seed_running_pod("devterm")
        self._set_mock(True)
        mock_core_v1 = MagicMock()
        with patch.object(self.k8s, "_get_k8s_core_v1", return_value=mock_core_v1):
            self.k8s.terminate_pod("devterm", item["pod_id"])
        mock_core_v1.delete_namespaced_pod.assert_not_called()

    def test_ttl_checker_calls_delete_in_prod(self):
        """Background TTL checker must trigger real K8s deletion in prod."""
        item = self._seed_running_pod("ttluser")
        # Back-date expires_at so the pod appears expired.
        self.table.update_item(
            Key={"user_sub": item["user_sub"], "sk": item["sk"]},
            UpdateExpression="SET expires_at = :old",
            ExpressionAttributeValues={":old": 1},
        )
        _install_fake_kubernetes_module(self.stack)
        mock_core_v1 = MagicMock()
        with patch.object(self.k8s, "_get_k8s_core_v1", return_value=mock_core_v1):
            count = self.k8s.check_expired_pods()

        self.assertGreaterEqual(count, 1)
        mock_core_v1.delete_namespaced_pod.assert_called()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
