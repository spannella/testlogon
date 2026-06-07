"""Regression tests for GAP-0086 and GAP-0087.

GAP-0086: ``create_feedback_request`` must transition the agent state machine
from "working" to "awaiting_feedback" after persisting the feedback record, so
the agent pauses instead of continuing to process (and flooding the feedback
list with duplicate requests). Mirrors the symmetric "working" resume that
``respond_to_feedback`` already performs (GAP-0011).

GAP-0087: ``update_pattern_config`` accepts user-supplied regex patterns. Before
the fix it validated only that each pattern compiled, so a catastrophic-
backtracking ("ReDoS") pattern such as ``(a+)+$`` was stored and later hung the
single-worker monitoring loop on live terminal output. The fix adds a length cap
and a wall-clock safety probe that rejects such patterns at write time.

All tests run fully offline using moto-backed DynamoDB (no real AWS).
"""

from __future__ import annotations

from types import SimpleNamespace

import boto3
import pytest
from moto import mock_aws


WORKER_KEY_SCHEMA = [
    {"AttributeName": "pk", "KeyType": "HASH"},
    {"AttributeName": "sk", "KeyType": "RANGE"},
]
ATTR_DEFS = [
    {"AttributeName": "pk", "AttributeType": "S"},
    {"AttributeName": "sk", "AttributeType": "S"},
]


@pytest.fixture
def agent_tables(monkeypatch):
    """Create moto-backed agent_workers + agent_feedback tables and wire them
    into both services under test."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        workers = ddb.create_table(
            TableName="agent_workers_test",
            KeySchema=WORKER_KEY_SCHEMA,
            AttributeDefinitions=ATTR_DEFS,
            BillingMode="PAY_PER_REQUEST",
        )
        feedback = ddb.create_table(
            TableName="agent_feedback_test",
            KeySchema=WORKER_KEY_SCHEMA,
            AttributeDefinitions=ATTR_DEFS,
            BillingMode="PAY_PER_REQUEST",
        )
        workers.wait_until_exists()
        feedback.wait_until_exists()

        from app.services import terminal_monitor as svc
        from app.services import agent_orchestrator

        # The real ``T`` is a frozen dataclass singleton. Swap each service
        # module's ``T`` reference for a namespace pointing at the moto tables.
        fake_T = SimpleNamespace(agent_feedback=feedback, agent_workers=workers)
        monkeypatch.setattr(svc, "T", fake_T)
        monkeypatch.setattr(agent_orchestrator, "T", fake_T)

        svc._worker_buffers.clear()

        yield {"svc": svc, "orchestrator": agent_orchestrator, "workers": workers}


def _seed_worker(workers, *, user_id, worker_id, agent_state="working"):
    workers.put_item(Item={
        "pk": f"USER#{user_id}",
        "sk": f"WORKER#{worker_id}",
        "worker_id": worker_id,
        "user_id": user_id,
        "agent_state": agent_state,
        "status": "active",
    })


# ─── GAP-0086 ────────────────────────────────────────────────────────────────


def test_create_feedback_request_transitions_to_awaiting_feedback(agent_tables):
    """FAILS before fix (worker stays "working"); PASSES after fix."""
    svc = agent_tables["svc"]
    workers = agent_tables["workers"]
    user_id, worker_id = "user_086", "worker_086"

    _seed_worker(workers, user_id=user_id, worker_id=worker_id, agent_state="working")

    item = svc.create_feedback_request(
        user_id=user_id,
        worker_id=worker_id,
        ticket_id="T-001",
        question="Which approach should I use?",
    )

    # Feedback record is still persisted and returned.
    assert item["feedback_status"] == "pending"

    worker = workers.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"}
    )["Item"]
    assert worker["agent_state"] == "awaiting_feedback", (
        "Worker must be paused after a feedback request is created"
    )


def test_create_feedback_request_duplicate_signal_does_not_raise(agent_tables):
    """A second feedback request while already awaiting_feedback must not raise
    (the invalid transition is caught and logged)."""
    svc = agent_tables["svc"]
    workers = agent_tables["workers"]
    user_id, worker_id = "user_086b", "worker_086b"

    _seed_worker(workers, user_id=user_id, worker_id=worker_id, agent_state="working")

    svc.create_feedback_request(
        user_id=user_id, worker_id=worker_id, ticket_id="T-001", question="Q1",
    )
    # Worker is now awaiting_feedback; the second call must still succeed.
    item = svc.create_feedback_request(
        user_id=user_id, worker_id=worker_id, ticket_id="T-001", question="Q2",
    )
    assert item["feedback_status"] == "pending"

    worker = workers.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"}
    )["Item"]
    assert worker["agent_state"] == "awaiting_feedback"


def test_create_feedback_request_missing_worker_does_not_raise(agent_tables):
    """If no worker row exists, the feedback record is still created and the
    failed transition is swallowed."""
    svc = agent_tables["svc"]
    item = svc.create_feedback_request(
        user_id="ghost", worker_id="nonexistent", ticket_id="T-001",
        question="Q?",
    )
    assert item["feedback_status"] == "pending"


# ─── GAP-0087 ────────────────────────────────────────────────────────────────


def test_safe_pattern_accepted(agent_tables):
    """A simple legitimate pattern set is accepted (must pass before and after
    the fix)."""
    svc = agent_tables["svc"]
    safe = {
        "completion": [r"\[AGENT_COMPLETE\]"],
        "feedback_needed": [r"(?i)please confirm"],
        "error": [r"(?i)fatal error"],
    }
    result = svc.update_pattern_config("user_087", "worker_087", safe)
    assert result == safe


def test_redos_pattern_rejected(agent_tables):
    """FAILS before fix (no error raised); PASSES after fix."""
    svc = agent_tables["svc"]
    redos = {
        "completion": [],
        "feedback_needed": ["(a+)+$"],  # classic catastrophic backtracking
        "error": [],
    }
    with pytest.raises(ValueError, match="rejected by safety check"):
        svc.update_pattern_config("user_087", "worker_087", redos)


def test_nested_quantifier_pattern_rejected(agent_tables):
    """Second canonical catastrophic form must also be rejected."""
    svc = agent_tables["svc"]
    nested = {
        "completion": [],
        "feedback_needed": ["(x+x+)+y"],
        "error": [],
    }
    with pytest.raises(ValueError, match="rejected by safety check"):
        svc.update_pattern_config("user_087", "worker_087", nested)


def test_pattern_length_cap_enforced(agent_tables):
    """A pattern exceeding the length cap is rejected before compilation."""
    svc = agent_tables["svc"]
    with pytest.raises(ValueError, match="Pattern too long"):
        svc.update_pattern_config(
            "user_087", "worker_087",
            {"feedback_needed": ["a" * 501], "completion": [], "error": []},
        )


def test_invalid_regex_still_rejected(agent_tables):
    """The original syntax validation remains in place."""
    svc = agent_tables["svc"]
    with pytest.raises(ValueError, match="Invalid regex pattern"):
        svc.update_pattern_config(
            "user_087", "worker_087",
            {"feedback_needed": ["(unclosed"], "completion": [], "error": []},
        )


def test_default_patterns_pass_safety_probe(agent_tables):
    """All built-in default feedback patterns must survive the ReDoS probe."""
    svc = agent_tables["svc"]
    result = svc.update_pattern_config(
        "user_087", "worker_087", svc.DEFAULT_FEEDBACK_PATTERNS,
    )
    assert result == svc.DEFAULT_FEEDBACK_PATTERNS
