"""Regression tests for GAP-0080: idle-worker auto-shutdown stub.

Before the fix, ``check_idle_workers()`` was a stub that always returned ``0``
and was never wired into app startup, so provisioned agent workers were never
auto-stopped and accrued compute cost indefinitely.

These tests run fully offline using moto-backed DynamoDB (no real AWS / dev
stack). They verify that:

  1. A worker idle past its ``idle_timeout_seconds`` is stopped.
  2. A recently-active worker (within timeout) is left running.

Before the fix both the count assertion and the status assertion fail (stub
returns 0 and never changes worker_status); after the fix they pass.
"""

from __future__ import annotations

from types import SimpleNamespace

import boto3
import pytest
from moto import mock_aws

from app.core.time import now_ts


KEY_SCHEMA = [
    {"AttributeName": "pk", "KeyType": "HASH"},
    {"AttributeName": "sk", "KeyType": "RANGE"},
]
ATTR_DEFS = [
    {"AttributeName": "pk", "AttributeType": "S"},
    {"AttributeName": "sk", "AttributeType": "S"},
]


@pytest.fixture
def provisioner(monkeypatch):
    """Wire the provisioner's ``T`` to a moto-backed agent_workers table."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        workers = ddb.create_table(
            TableName="agent_workers_test",
            KeySchema=KEY_SCHEMA,
            AttributeDefinitions=ATTR_DEFS,
            BillingMode="PAY_PER_REQUEST",
        )
        workers.wait_until_exists()

        from app.services import agent_worker_provisioner as svc

        fake_T = SimpleNamespace(agent_workers=workers)
        monkeypatch.setattr(svc, "T", fake_T)

        yield {"svc": svc, "workers": workers}


def _seed_worker(workers, *, user_id, worker_id, status, idle_timeout,
                 last_activity_at=0, started_at=0, compute_type="k8s"):
    workers.put_item(Item={
        "pk": f"USER#{user_id}",
        "sk": f"WORKER#{worker_id}",
        "worker_id": worker_id,
        "user_id": user_id,
        "worker_status": status,
        "compute_type": compute_type,
        "compute_instance_id": "",  # empty -> no real launcher call on stop
        "idle_timeout_seconds": idle_timeout,
        "last_activity_at": last_activity_at,
        "started_at": started_at,
    })


def test_idle_worker_is_stopped(provisioner):
    svc = provisioner["svc"]
    workers = provisioner["workers"]
    user_id, wid = "u1", "w_idle"

    # Last activity 20 minutes ago, timeout 10 minutes -> idle.
    _seed_worker(
        workers, user_id=user_id, worker_id=wid,
        status="ready", idle_timeout=600,
        last_activity_at=now_ts() - 1200,
    )

    count = svc.check_idle_workers()
    assert count == 1, f"Expected 1 idle worker stopped, got {count}"
    assert svc.get_worker(user_id, wid)["worker_status"] == "stopped"


def test_recently_active_worker_is_not_stopped(provisioner):
    svc = provisioner["svc"]
    workers = provisioner["workers"]
    user_id, wid = "u1", "w_active"

    # Activity 5 minutes ago, timeout 2 hours -> well within window.
    _seed_worker(
        workers, user_id=user_id, worker_id=wid,
        status="ready", idle_timeout=7200,
        last_activity_at=now_ts() - 300,
    )

    count = svc.check_idle_workers()
    assert count == 0
    assert svc.get_worker(user_id, wid)["worker_status"] == "ready"


def test_never_started_worker_with_zero_activity_is_left_alone(provisioner):
    """A worker that never ran (last_activity_at=0, started_at=0) is not stopped
    by the idle checker — it is left for the provisioning-timeout path."""
    svc = provisioner["svc"]
    workers = provisioner["workers"]
    user_id, wid = "u1", "w_zero"

    _seed_worker(
        workers, user_id=user_id, worker_id=wid,
        status="ready", idle_timeout=600,
        last_activity_at=0, started_at=0,
    )

    count = svc.check_idle_workers()
    assert count == 0
    assert svc.get_worker(user_id, wid)["worker_status"] == "ready"
