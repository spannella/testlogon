"""Offline regression tests for GAP-0230 and GAP-0231 (INFRA-008).

Both gaps live in the instance-monitoring subsystem:

GAP-0230 — Auto-restart policy was never implemented. There was no
``_check_restart_policy`` / ``update_restart_policy`` service code and no
``PATCH /restart-policy`` behaviour, so a crashed instance with a configured
auto-restart preference was never restarted, and the ``max_restarts`` safety
ceiling was unenforceable.

GAP-0231 — Lifecycle event timeline was never implemented. The EC2/K8s launch,
stop, start, terminate, reboot paths wrote nothing under the
``TIMELINE#{resource_id}#{ts}#{event_id}`` SK pattern, so there was no
application-owned audit trail of lifecycle events and no
``GET /timeline`` data.

Hermetic + offline. We do NOT rely on global ``@mock_aws`` interception leaking
to real AWS for the code under test: real in-memory DynamoDB tables are created
with moto and the FROZEN ``T`` table handles are swapped in via
``object.__setattr__`` (then restored on teardown). Functions are called
directly — no FastAPI TestClient, no network. The FROZEN ``S`` settings object
is likewise mutated via ``object.__setattr__`` and restored.

Each test is shaped so the OLD behaviour produces a wrong answer (or an
``AttributeError`` because the function did not exist) and the NEW behaviour is
correct.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack

import boto3
from boto3.dynamodb.conditions import Key

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_compute_table(ddb, name: str, *, namespace_gsi: bool = False):
    """Create an ec2_instances- / k8s_pods-shaped table.

    Mirrors scripts/local-ddb-init.py: PK=user_sub, SK=sk (both String) with
    sparse GSIs on status / created_at. Timeline items (which carry neither)
    are simply absent from those sparse indexes — exactly as in production.
    """
    gsi = [
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
    ]
    attrs = [
        {"AttributeName": "user_sub", "AttributeType": "S"},
        {"AttributeName": "sk", "AttributeType": "S"},
        {"AttributeName": "status", "AttributeType": "S"},
        {"AttributeName": "created_at", "AttributeType": "N"},
    ]
    if namespace_gsi:
        gsi.append({
            "IndexName": "ByNamespace",
            "KeySchema": [
                {"AttributeName": "namespace", "KeyType": "HASH"},
                {"AttributeName": "created_at", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        })
        attrs.append({"AttributeName": "namespace", "AttributeType": "S"})
    return ddb.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=attrs,
        GlobalSecondaryIndexes=gsi,
        BillingMode="PAY_PER_REQUEST",
    )


def _make_metrics_table(ddb, name: str):
    """Create the instance_metrics table: PK=instance_id, SK=sk, ByTs GSI."""
    return ddb.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "instance_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "instance_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "ts", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByTs",
                "KeySchema": [
                    {"AttributeName": "instance_id", "KeyType": "HASH"},
                    {"AttributeName": "ts", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class _BaseComputeMonitoringTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.ec2_table = _make_compute_table(ddb, "ec2_instances")
        self.k8s_table = _make_compute_table(ddb, "k8s_pods", namespace_gsi=True)
        self.metrics_table = _make_metrics_table(ddb, "instance_metrics")

        from app.core.tables import T
        from app.core.settings import S

        self.T = T
        self.S = S

        # Swap the FROZEN T handles for our in-memory tables; restore on teardown.
        for attr, tbl in (
            ("ec2_instances", self.ec2_table),
            ("k8s_pods", self.k8s_table),
            ("instance_metrics", self.metrics_table),
        ):
            orig = getattr(T, attr)
            object.__setattr__(T, attr, tbl)
            self.addCleanup(
                lambda a=attr, o=orig: object.__setattr__(T, a, o)
            )

    def _set_setting(self, name: str, value):
        orig = getattr(self.S, name)
        object.__setattr__(self.S, name, value)
        self.addCleanup(lambda: object.__setattr__(self.S, name, orig))

    def _seed_ec2(self, user_sub: str, instance_id: str, **extra):
        item = {
            "user_sub": user_sub,
            "sk": f"INSTANCE#{instance_id}",
            "instance_id": instance_id,
            "instance_type": "t3.micro",
            "status": "running",
            "created_at": 1000,
        }
        item.update(extra)
        self.ec2_table.put_item(Item=item)
        return item

    def _seed_k8s(self, user_sub: str, pod_id: str, **extra):
        item = {
            "user_sub": user_sub,
            "sk": f"POD#{pod_id}",
            "pod_id": pod_id,
            "status": "running",
            "created_at": 1000,
        }
        item.update(extra)
        self.k8s_table.put_item(Item=item)
        return item

    def _timeline_items(self, table, user_sub, resource_id):
        resp = table.query(
            KeyConditionExpression=Key("user_sub").eq(user_sub)
            & Key("sk").begins_with(f"TIMELINE#{resource_id}#"),
        )
        return resp.get("Items", [])


# ---------------------------------------------------------------------------
# GAP-0231 — Event timeline
# ---------------------------------------------------------------------------

class TestTimelineGap0231(_BaseComputeMonitoringTest):
    def test_record_and_list_timeline_event(self):
        """GAP-0231: record_timeline_event writes a TIMELINE# item; it is
        retrievable via list_timeline_events.

        FAILS BEFORE FIX: record_timeline_event / list_timeline_events did not
        exist (AttributeError). PASSES AFTER FIX.
        """
        from app.services import instance_monitoring as svc

        self._seed_ec2("alice", "i_tl")
        svc.record_timeline_event(
            "alice", "i_tl", "stopped", resource_type="ec2", detail={"k": "v"}
        )

        raw = self._timeline_items(self.ec2_table, "alice", "i_tl")
        self.assertEqual(len(raw), 1)
        self.assertEqual(raw[0]["event_type"], "stopped")
        self.assertTrue(raw[0]["sk"].startswith("TIMELINE#i_tl#"))

        events = svc.list_timeline_events("alice", "i_tl")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "stopped")
        self.assertEqual(events[0]["detail"], {"k": "v"})

    def test_timeline_newest_first(self):
        """Events are returned newest-first (zero-padded ts in the SK)."""
        from app.services import instance_monitoring as svc

        self._seed_ec2("alice", "i_ord")
        svc.record_timeline_event("alice", "i_ord", "launched", ts=100)
        svc.record_timeline_event("alice", "i_ord", "stopped", ts=200)
        svc.record_timeline_event("alice", "i_ord", "terminated", ts=300)

        events = svc.list_timeline_events("alice", "i_ord")
        self.assertEqual(
            [e["event_type"] for e in events],
            ["terminated", "stopped", "launched"],
        )

    def test_list_timeline_unknown_resource_raises(self):
        """list_timeline_events enforces ownership."""
        from app.services import instance_monitoring as svc

        with self.assertRaises(svc.InstanceNotOwned):
            svc.list_timeline_events("alice", "i_nope")

    def test_ec2_lifecycle_writes_timeline(self):
        """GAP-0231: stop -> start -> terminate via the EC2 launcher each emit a
        timeline event.

        FAILS BEFORE FIX: the launcher wrote no TIMELINE# items at all.
        """
        from app.services import ec2_launcher as ec2

        self._set_setting("ec2_mock_enabled", True)
        self._set_setting("security_groups_enabled", False)
        self._set_setting("admin_compute_dashboard_enabled", False)

        item = ec2.launch_instance(
            "alice", label="t", instance_type="t3.micro", ami_id="ami-ubuntu-2204"
        )
        iid = item["instance_id"]
        ec2.stop_instance("alice", iid)
        ec2.start_instance("alice", iid)
        ec2.terminate_instance("alice", iid)

        raw = self._timeline_items(self.ec2_table, "alice", iid)
        types = {i["event_type"] for i in raw}
        self.assertEqual(types, {"launched", "stopped", "started", "terminated"})

    def test_k8s_lifecycle_writes_timeline(self):
        """GAP-0231: K8s launch + terminate emit timeline events into k8s_pods."""
        from app.services import k8s_launcher as k8s

        self._set_setting("k8s_mock_enabled", True)
        self._set_setting("admin_compute_dashboard_enabled", False)

        item = k8s.launch_pod("bob", label="t", image="ubuntu-ssh", preset="small")
        pid = item["pod_id"]
        k8s.terminate_pod("bob", pid)

        raw = self._timeline_items(self.k8s_table, "bob", pid)
        types = {i["event_type"] for i in raw}
        self.assertEqual(types, {"launched", "terminated"})

    def test_timeline_write_is_best_effort(self):
        """A timeline write failure must never raise to the caller."""
        from app.services import instance_monitoring as svc

        class _Boom:
            def put_item(self, **kw):
                raise RuntimeError("ddb down")

        orig = self.T.ec2_instances
        object.__setattr__(self.T, "ec2_instances", _Boom())
        try:
            # Must not raise.
            svc.record_timeline_event("alice", "i_x", "stopped", resource_type="ec2")
        finally:
            object.__setattr__(self.T, "ec2_instances", orig)


# ---------------------------------------------------------------------------
# GAP-0230 — Auto-restart policy
# ---------------------------------------------------------------------------

class TestRestartPolicyGap0230(_BaseComputeMonitoringTest):
    def test_update_restart_policy_persists(self):
        """GAP-0230: update_restart_policy sets the per-instance fields.

        FAILS BEFORE FIX: update_restart_policy did not exist; the fields were
        never written to the instance item.
        """
        from app.services import instance_monitoring as svc

        self._seed_ec2("alice", "i_pol")
        out = svc.update_restart_policy(
            "alice", "i_pol", auto_restart_enabled=True, max_restarts=5
        )
        self.assertTrue(out["auto_restart_enabled"])
        self.assertEqual(out["max_restarts"], 5)
        self.assertEqual(out["resource_type"], "ec2")

        stored = self.ec2_table.get_item(
            Key={"user_sub": "alice", "sk": "INSTANCE#i_pol"}
        )["Item"]
        self.assertTrue(stored["auto_restart_enabled"])
        self.assertEqual(int(stored["max_restarts"]), 5)

    def test_update_restart_policy_rejects_out_of_range(self):
        from app.services import instance_monitoring as svc

        self._seed_ec2("alice", "i_bad")
        with self.assertRaises(ValueError):
            svc.update_restart_policy("alice", "i_bad", max_restarts=99)

    def test_update_restart_policy_k8s(self):
        """Restart policy also works for K8s pods (POD# SK)."""
        from app.services import instance_monitoring as svc

        self._seed_k8s("bob", "p_pol")
        out = svc.update_restart_policy("bob", "p_pol", auto_restart_enabled=True)
        self.assertTrue(out["auto_restart_enabled"])
        self.assertEqual(out["resource_type"], "k8s")

    def test_update_restart_policy_unknown_raises(self):
        from app.services import instance_monitoring as svc

        with self.assertRaises(svc.InstanceNotOwned):
            svc.update_restart_policy("alice", "i_nope", auto_restart_enabled=True)

    def test_check_restart_policy_initiates_restart_when_enabled(self):
        """GAP-0230: critical health + auto_restart_enabled triggers a restart,
        bumps restart_count, and records timeline events.

        FAILS BEFORE FIX: _check_restart_policy did not exist (AttributeError).
        """
        from app.services import instance_monitoring as svc

        self._seed_ec2(
            "alice", "i_run",
            auto_restart_enabled=True, max_restarts=3, restart_count=0,
        )
        instance = self.ec2_table.get_item(
            Key={"user_sub": "alice", "sk": "INSTANCE#i_run"}
        )["Item"]

        performed = []
        orig = svc._perform_restart
        svc._perform_restart = lambda u, inst, rt: performed.append(
            inst.get("instance_id")
        )
        try:
            result = svc._check_restart_policy(
                "alice", instance,
                {"health_status": "critical", "reasons": ["cpu 95%"]},
                resource_type="ec2",
            )
        finally:
            svc._perform_restart = orig

        self.assertTrue(result)
        self.assertEqual(performed, ["i_run"])

        # restart_count incremented + last_restart_at set
        stored = self.ec2_table.get_item(
            Key={"user_sub": "alice", "sk": "INSTANCE#i_run"}
        )["Item"]
        self.assertEqual(int(stored["restart_count"]), 1)
        self.assertGreater(int(stored["last_restart_at"]), 0)

        # timeline records initiated + completed
        types = {i["event_type"] for i in
                 self._timeline_items(self.ec2_table, "alice", "i_run")}
        self.assertIn("auto_restart_initiated", types)
        self.assertIn("auto_restart_completed", types)

    def test_check_restart_policy_respects_max_restarts(self):
        """GAP-0230: restart blocked when restart_count >= max_restarts; a
        restart_limit_reached event is recorded and no restart performed."""
        from app.services import instance_monitoring as svc

        self._seed_ec2(
            "alice", "i_max",
            auto_restart_enabled=True, max_restarts=3, restart_count=3,
        )
        instance = self.ec2_table.get_item(
            Key={"user_sub": "alice", "sk": "INSTANCE#i_max"}
        )["Item"]

        performed = []
        orig = svc._perform_restart
        svc._perform_restart = lambda *a, **kw: performed.append(True)
        try:
            result = svc._check_restart_policy(
                "alice", instance, {"health_status": "critical", "reasons": []},
                resource_type="ec2",
            )
        finally:
            svc._perform_restart = orig

        self.assertFalse(result)
        self.assertEqual(performed, [])
        types = {i["event_type"] for i in
                 self._timeline_items(self.ec2_table, "alice", "i_max")}
        self.assertIn("restart_limit_reached", types)

    def test_check_restart_policy_skips_when_disabled(self):
        """GAP-0230: auto_restart_enabled=False -> no restart."""
        from app.services import instance_monitoring as svc

        instance = {
            "instance_id": "i_off", "auto_restart_enabled": False,
            "max_restarts": 3, "restart_count": 0,
        }
        result = svc._check_restart_policy(
            "alice", instance, {"health_status": "critical", "reasons": []},
            resource_type="ec2",
        )
        self.assertFalse(result)

    def test_check_restart_policy_skips_non_critical(self):
        from app.services import instance_monitoring as svc

        instance = {
            "instance_id": "i_warn", "auto_restart_enabled": True,
            "max_restarts": 3, "restart_count": 0,
        }
        result = svc._check_restart_policy(
            "alice", instance, {"health_status": "warning", "reasons": []},
            resource_type="ec2",
        )
        self.assertFalse(result)

    def test_ingest_critical_triggers_restart_only_when_flag_on(self):
        """GAP-0230: the ingest hook is gated by the global feature flag.

        With the flag OFF (default), a critical datapoint must NOT restart.
        With the flag ON and the instance enabled, it must.
        """
        from app.services import instance_monitoring as svc

        self._set_setting("instance_monitoring_alerts_enabled", False)
        self._seed_ec2(
            "alice", "i_ing",
            auto_restart_enabled=True, max_restarts=3, restart_count=0,
        )

        calls = []
        orig = svc._check_restart_policy
        svc._check_restart_policy = lambda *a, **kw: calls.append(1) or True
        try:
            # Flag OFF -> not called
            self._set_setting("instance_monitoring_auto_restart_enabled", False)
            svc.ingest_datapoint(
                "alice", "i_ing", cpu_pct=99, mem_pct=99, disk_pct=99,
                status="crashed",
            )
            self.assertEqual(calls, [])

            # Flag ON -> called
            self._set_setting("instance_monitoring_auto_restart_enabled", True)
            svc.ingest_datapoint(
                "alice", "i_ing", cpu_pct=99, mem_pct=99, disk_pct=99,
                status="crashed",
            )
            self.assertEqual(calls, [1])
        finally:
            svc._check_restart_policy = orig


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
