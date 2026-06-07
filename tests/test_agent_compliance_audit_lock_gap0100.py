"""Regression test for GAP-0100: start_audit TOCTOU race condition.

Offline / in-memory only: uses moto's in-memory DynamoDB (no real AWS). The
``compliance_audits`` table handle on ``app.core.tables.T`` is swapped for a
moto-backed table for the duration of the test, and ``ensure_tables`` is
neutralised so the service does not try to create tables against a different
client.

Before the fix, ``start_audit`` performed a read-then-write guard
(``get_running_audit`` then an unconditional ``put_item``). Two concurrent
callers could both pass the read check before either write committed, and both
would create a ``status=running`` audit for the same user.

After the fix, the running-audit guard is an atomic conditional ``put_item``
(``attribute_not_exists`` on a stable ``RUNNING_LOCK`` SK), so exactly one of
two concurrent callers wins and the other gets ``ValueError("audit_in_progress")``.
The assertion below — *exactly one running audit after two concurrent
start_audit calls* — fails on the pre-fix code and passes after the fix.
"""
from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

import app.core.tables as tables_mod
from app.services import agent_compliance as svc


@pytest.fixture
def audits_table(monkeypatch):
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="compliance_security_audits",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        table = ddb.Table("compliance_security_audits")

        # ensure_tables would create tables against the real ddb client; the
        # moto-backed table is already wired below, so make it a no-op.
        monkeypatch.setattr(svc, "ensure_tables", lambda: None)
        original = tables_mod.T.compliance_audits
        object.__setattr__(tables_mod.T, "compliance_audits", table)
        try:
            yield table
        finally:
            object.__setattr__(tables_mod.T, "compliance_audits", original)


def _count_running(user_id: str) -> int:
    """Count audit items (status=running) for a user via a direct scan."""
    items = tables_mod.T.compliance_audits.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk)",
        ExpressionAttributeValues={":pk": svc._user_pk(user_id), ":sk": "AUDIT#"},
    ).get("Items", [])
    return sum(1 for it in items if it.get("status") == "running")


def test_concurrent_start_audit_yields_exactly_one_running(audits_table, monkeypatch):
    """Two concurrent start_audit calls must create exactly one running audit.

    The race condition is the TOCTOU window in which both callers read "no
    running audit" before either has written. We reproduce that window
    deterministically by forcing ``get_running_audit`` to report no running
    audit for both callers (exactly what happens under eventual consistency /
    multi-worker interleaving in production).

    Before the GAP-0100 fix, ``start_audit`` relied on this read as its only
    guard, so both callers proceeded and created two ``status=running`` audits.
    After the fix, the guard is an atomic conditional ``put_item`` on a stable
    ``RUNNING_LOCK`` SK, so only one caller wins and the other gets
    ``ValueError("audit_in_progress")`` — yielding exactly one running audit.
    """
    user_id = "u-gap0100"

    # Simulate the stale-read race window: the pre-flight read never sees the
    # concurrently-created running audit. Pre-fix code trusts this read entirely.
    monkeypatch.setattr(svc, "get_running_audit", lambda *, user_id: None)

    successes: list[str] = []
    in_progress = 0
    for _ in range(2):
        try:
            audit = svc.start_audit(user_id=user_id, agent_id="a1")
            successes.append(audit["audit_id"])
        except ValueError as exc:
            assert str(exc) == "audit_in_progress"
            in_progress += 1

    # Exactly one caller created a running audit; the other was rejected by the
    # atomic lock (not by the read, which is forced to return None above).
    assert _count_running(user_id) == 1, (
        f"expected exactly one running audit, found {_count_running(user_id)}"
    )
    assert len(successes) == 1
    assert in_progress == 1
