"""Regression tests for GAP-0098: trigger_review in-memory lock not distributed.

Offline / in-memory only: uses moto's in-memory DynamoDB (no real AWS). The
``agent_feature_ideas`` table handle on ``app.core.tables.T`` is swapped for a
moto-backed table for the duration of each test, so the conditional ``put_item``
that implements the distributed lock is exercised for real (not mocked).

Before the fix, ``trigger_review`` guarded concurrent runs with a module-level
``set`` (``_RUNNING_REVIEWS``). That set lives in a single process's memory, so
in a multi-worker / multi-instance deployment two concurrent reviews for the same
user+agent both passed the guard and double-ran. After the fix, the guard is a
DynamoDB conditional-write lock (``attribute_not_exists``) that is atomic across
processes: while one review holds the lock, a second concurrent attempt is
rejected with ``REVIEW_IN_PROGRESS``; the lock is released in the ``finally``
block so a subsequent review succeeds.
"""
from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

import app.core.tables as tables_mod
from app.services import agent_pm as svc


@pytest.fixture
def ideas_table():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="agent_feature_ideas",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        table = ddb.Table("agent_feature_ideas")
        original = tables_mod.T.agent_feature_ideas
        object.__setattr__(tables_mod.T, "agent_feature_ideas", table)
        # ensure_tables() would try to (re)create via the real ddb client; the moto
        # table already exists, so neutralize it for these unit tests.
        original_ensure = svc.ensure_tables
        svc.ensure_tables = lambda: None  # type: ignore[assignment]
        try:
            yield table
        finally:
            object.__setattr__(tables_mod.T, "agent_feature_ideas", original)
            svc.ensure_tables = original_ensure  # type: ignore[assignment]


def test_acquire_then_concurrent_acquire_rejected(ideas_table):
    """The second concurrent acquire is rejected while the first holds the lock."""
    assert svc._acquire_review_lock(user_id="u1", agent_id="a1") is True
    # Second attempt for the same scope, lock still held -> conditional write fails.
    assert svc._acquire_review_lock(user_id="u1", agent_id="a1") is False
    # A different scope is unaffected.
    assert svc._acquire_review_lock(user_id="u1", agent_id="a2") is True


def test_release_allows_subsequent_acquire(ideas_table):
    """After release the lock is free again for the same scope."""
    assert svc._acquire_review_lock(user_id="u1", agent_id="a1") is True
    svc._release_review_lock(user_id="u1", agent_id="a1")
    assert svc._acquire_review_lock(user_id="u1", agent_id="a1") is True


def test_trigger_review_rejects_while_one_running(ideas_table, monkeypatch):
    """FAILS BEFORE FIX: a second concurrent review is rejected while one runs.

    Simulates a worker that has acquired the lock (the lock item exists in DDB,
    as it would on another worker/process) and then a second trigger_review call
    arrives. With the old in-process ``set`` guard, a freshly imported module on a
    different worker had an empty set and the second call double-ran. With the DDB
    lock, the existing lock item blocks the second call.
    """
    # Worker A holds the lock (item present in shared DDB).
    assert svc._acquire_review_lock(user_id="u1", agent_id="a1") is True

    # Worker B's trigger_review must observe the held lock and reject.
    with pytest.raises(svc.PmValidationError) as excinfo:
        svc.trigger_review(user_id="u1", agent_id="a1", count=3)
    assert excinfo.value.code == "REVIEW_IN_PROGRESS"

    # No ideas were created by the rejected call.
    assert svc.list_feature_ideas(user_id="u1", limit=50).get("ideas", []) == []


def test_trigger_review_releases_lock_on_success(ideas_table, monkeypatch):
    """A successful review releases the lock so the next review can run."""
    monkeypatch.setattr(svc, "get_pm_config", lambda *, user_id: {"max_ideas_per_review": 2})

    first = svc.trigger_review(user_id="u1", agent_id="a1", count=2)
    assert first["ok"] is True
    assert first["ideas_created"] == 2
    # Lock released -> is_review_running is False and a second review succeeds.
    assert svc.is_review_running(user_id="u1", agent_id="a1") is False
    second = svc.trigger_review(user_id="u1", agent_id="a1", count=2)
    assert second["ok"] is True


def test_trigger_review_releases_lock_on_exception(ideas_table, monkeypatch):
    """The lock is released even when the review body raises."""
    def _boom(*, user_id):  # noqa: ANN001
        raise RuntimeError("boom")

    monkeypatch.setattr(svc, "get_pm_config", _boom)
    with pytest.raises(RuntimeError, match="boom"):
        svc.trigger_review(user_id="u1", agent_id="a1", count=1)
    # finally-block released the lock -> next acquire succeeds.
    assert svc.is_review_running(user_id="u1", agent_id="a1") is False
    assert svc._acquire_review_lock(user_id="u1", agent_id="a1") is True
