"""Offline regression test for GAP-0237 (INFRA-012).

The admin compute dashboard needs to list all EC2 instances / K8s pods across
*every* user filtered by status (e.g. all platform-wide ``running`` instances).
The intended access pattern is a ``ByGlobalStatus`` GSI keyed on ``status``
(partition) + ``created_at`` (sort). That GSI was never added to either the
``ec2_instances`` or ``k8s_pods`` table in ``scripts/local-ddb-init.py``, so
``list_all_instances`` / ``list_all_pods`` fell back to a full-table ``scan``.

The fix:
  * adds the ``ByGlobalStatus`` GSI (``status`` PK, ``created_at`` SK) to both
    TableDefs (with ``attr_types={"created_at": "N", "status": "S"}``);
  * makes ``list_all_instances`` / ``list_all_pods`` ``query()`` that GSI
    (paginating via ``LastEvaluatedKey``) when a status filter is supplied,
    instead of scanning the whole table.

This test is fully hermetic. We create real in-memory moto tables WITH the new
GSI and patch the exact ``T.ec2_instances`` / ``T.k8s_pods`` handles (``T`` is a
frozen dataclass, so we use ``object.__setattr__`` and restore afterwards). A
spy wraps ``.query`` / ``.scan`` so we can assert the GSI path is taken.

FAILS BEFORE FIX: ``list_all_instances(status="running")`` never calls
``query(IndexName="ByGlobalStatus")`` (it scans), so the query spy asserts fail.
PASSES AFTER FIX: the GSI query is used and returns exactly the running items.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_ec2_instances_table(ddb):
    """Mirror scripts/local-ddb-init.py ec2_instances TableDef (post-GAP-0237)."""
    return ddb.create_table(
        TableName="ec2_instances",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByStatus",
                "KeySchema": [
                    {"AttributeName": "user_sub", "KeyType": "HASH"},
                    {"AttributeName": "status", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByCreatedAt",
                "KeySchema": [
                    {"AttributeName": "user_sub", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByGlobalStatus",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_k8s_pods_table(ddb):
    """Mirror scripts/local-ddb-init.py k8s_pods TableDef (post-GAP-0237)."""
    return ddb.create_table(
        TableName="k8s_pods",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "namespace", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByNamespace",
                "KeySchema": [
                    {"AttributeName": "namespace", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByStatus",
                "KeySchema": [
                    {"AttributeName": "user_sub", "KeyType": "HASH"},
                    {"AttributeName": "status", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByCreatedAt",
                "KeySchema": [
                    {"AttributeName": "user_sub", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByGlobalStatus",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


class _OpSpy:
    """Wraps a moto table, recording every .query / .scan call (with kwargs)."""

    def __init__(self, table):
        self._table = table
        self.query_calls = []
        self.scan_calls = []

    def query(self, **kwargs):
        self.query_calls.append(kwargs)
        return self._table.query(**kwargs)

    def scan(self, **kwargs):
        self.scan_calls.append(kwargs)
        return self._table.scan(**kwargs)

    def __getattr__(self, name):
        return getattr(self._table, name)


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestAdminComputeGlobalStatusGsi(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        self.ec2_spy = _OpSpy(_make_ec2_instances_table(ddb))
        self.k8s_spy = _OpSpy(_make_k8s_pods_table(ddb))

        from app.core.tables import T

        self.T = T
        # T is a frozen dataclass — patch handles via object.__setattr__ and
        # restore the originals on cleanup.
        self._orig_ec2 = T.ec2_instances
        self._orig_k8s = T.k8s_pods
        object.__setattr__(T, "ec2_instances", self.ec2_spy)
        object.__setattr__(T, "k8s_pods", self.k8s_spy)

        def _restore():
            object.__setattr__(T, "ec2_instances", self._orig_ec2)
            object.__setattr__(T, "k8s_pods", self._orig_k8s)

        self.addCleanup(_restore)

        from app.services import admin_compute

        self.admin_compute = admin_compute

    # -- seeding helpers ----------------------------------------------------

    def _seed_instance(self, user_sub, instance_id, status, created_at, instance_type="t3.micro"):
        self.ec2_spy.put_item(
            Item={
                "user_sub": user_sub,
                "sk": f"INSTANCE#{instance_id}",
                "instance_id": instance_id,
                "label": instance_id,
                "instance_type": instance_type,
                "ami_name": "Ubuntu",
                "status": status,
                "public_ip": "1.2.3.4",
                "created_at": created_at,
                "last_activity_at": created_at,
                "auto_terminate_after": 0,
            }
        )

    def _seed_pod(self, user_sub, pod_id, status, created_at):
        self.k8s_spy.put_item(
            Item={
                "user_sub": user_sub,
                "sk": f"POD#{pod_id}",
                "pod_id": pod_id,
                "label": pod_id,
                "image": "nginx",
                "preset": "small",
                "status": status,
                "pod_ip": "10.0.0.5",
                "created_at": created_at,
                "ttl_seconds": 3600,
                "expires_at": created_at + 3600,
            }
        )

    # -- instances ----------------------------------------------------------

    def test_list_all_instances_by_status_uses_global_status_gsi(self):
        """FAILS BEFORE FIX: list_all_instances(status=...) scans the table and
        never queries ByGlobalStatus. PASSES AFTER FIX: it queries the GSI and
        returns only the matching-status items across all users."""
        # running across two users; plus stopped/terminated noise.
        self._seed_instance("alice", "i-run-a1", "running", 1000)
        self._seed_instance("bob", "i-run-b1", "running", 2000)
        self._seed_instance("alice", "i-stop-a1", "stopped", 1500)
        self._seed_instance("bob", "i-term-b1", "terminated", 1700)

        result = self.admin_compute.list_all_instances(status="running")

        # The GSI query path must be used (not scan).
        self.assertTrue(
            self.ec2_spy.query_calls,
            "list_all_instances(status=...) must query the ByGlobalStatus GSI, not scan",
        )
        self.assertEqual(self.ec2_spy.query_calls[0].get("IndexName"), "ByGlobalStatus")
        self.assertEqual(
            self.ec2_spy.scan_calls, [],
            "status-filtered listing must not fall back to a full-table scan",
        )

        ids = {i["instance_id"] for i in result["instances"]}
        self.assertEqual(ids, {"i-run-a1", "i-run-b1"})
        self.assertEqual(result["count"], 2)
        for inst in result["instances"]:
            self.assertEqual(inst["status"], "running")

    def test_list_all_instances_by_status_with_user_filter(self):
        """user_sub remains a Python-side filter on top of the GSI query."""
        self._seed_instance("alice", "i-run-a1", "running", 1000)
        self._seed_instance("bob", "i-run-b1", "running", 2000)

        result = self.admin_compute.list_all_instances(status="running", user_sub="alice")

        self.assertEqual(self.ec2_spy.query_calls[0].get("IndexName"), "ByGlobalStatus")
        ids = {i["instance_id"] for i in result["instances"]}
        self.assertEqual(ids, {"i-run-a1"})

    def test_list_all_instances_by_status_paginates_lastevaluatedkey(self):
        """Many running items across users must all be returned via GSI paging.

        Seed 60 running instances and request a small page; the helper must loop
        on LastEvaluatedKey so count == 60 and every running item is reachable.
        """
        for n in range(60):
            self._seed_instance(f"user{n % 5}", f"i-run-{n:03d}", "running", 1000 + n)

        result = self.admin_compute.list_all_instances(status="running", limit=10)

        self.assertEqual(self.ec2_spy.query_calls[0].get("IndexName"), "ByGlobalStatus")
        # count reflects the full GSI result set (all 60), not just one page.
        self.assertEqual(result["count"], 60)
        self.assertEqual(len(result["instances"]), 10)
        self.assertIsNotNone(result["cursor"])

        # Walk every page; the union must cover all 60 running ids exactly once.
        seen = set()
        cursor = None
        for _ in range(20):  # safety bound
            page = self.admin_compute.list_all_instances(status="running", limit=10, cursor=cursor)
            for inst in page["instances"]:
                seen.add(inst["instance_id"])
            cursor = page["cursor"]
            if cursor is None:
                break
        self.assertEqual(len(seen), 60)

    # -- pods ---------------------------------------------------------------

    def test_list_all_pods_by_status_uses_global_status_gsi(self):
        """FAILS BEFORE FIX: list_all_pods(status=...) scans. PASSES AFTER FIX:
        queries ByGlobalStatus, returning only running pods across all users."""
        self._seed_pod("alice", "p-run-a1", "running", 1000)
        self._seed_pod("bob", "p-run-b1", "running", 2000)
        self._seed_pod("alice", "p-pend-a1", "pending", 1500)
        self._seed_pod("bob", "p-term-b1", "terminated", 1700)

        result = self.admin_compute.list_all_pods(status="running")

        self.assertTrue(
            self.k8s_spy.query_calls,
            "list_all_pods(status=...) must query the ByGlobalStatus GSI, not scan",
        )
        self.assertEqual(self.k8s_spy.query_calls[0].get("IndexName"), "ByGlobalStatus")
        self.assertEqual(self.k8s_spy.scan_calls, [])

        ids = {p["pod_id"] for p in result["pods"]}
        self.assertEqual(ids, {"p-run-a1", "p-run-b1"})
        self.assertEqual(result["count"], 2)
        for pod in result["pods"]:
            self.assertEqual(pod["status"], "running")

    def test_list_all_pods_by_status_paginates_lastevaluatedkey(self):
        for n in range(45):
            self._seed_pod(f"user{n % 5}", f"p-run-{n:03d}", "running", 1000 + n)

        result = self.admin_compute.list_all_pods(status="running", limit=10)

        self.assertEqual(self.k8s_spy.query_calls[0].get("IndexName"), "ByGlobalStatus")
        self.assertEqual(result["count"], 45)

    # -- no-status fallback (behaviour parity) ------------------------------

    def test_list_all_instances_without_status_still_scans(self):
        """No status filter keeps the scan fallback (admins rarely do this)."""
        self._seed_instance("alice", "i-run-a1", "running", 1000)
        self._seed_instance("bob", "i-stop-b1", "stopped", 2000)

        result = self.admin_compute.list_all_instances()

        self.assertTrue(self.ec2_spy.scan_calls, "no-status path should scan")
        self.assertEqual(self.ec2_spy.query_calls, [])
        self.assertEqual(result["count"], 2)


if __name__ == "__main__":
    unittest.main()
