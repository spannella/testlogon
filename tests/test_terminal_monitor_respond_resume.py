"""Regression tests for GAP-0011.

`respond_to_feedback` must, after recording the user's response in DynamoDB:
  1. transition the agent state machine from "awaiting_feedback" back to
     "working" (so the agent resumes instead of staying stuck), and
  2. append the response into the worker's terminal output buffer.

These tests run fully offline using moto-backed DynamoDB (no real AWS). Before
the fix `respond_to_feedback` only wrote the feedback row, so both assertions
failed; after the fix they pass.
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

        # The real `T` is a frozen dataclass shared as a singleton. Swap each
        # service module's `T` reference for a simple namespace pointing at the
        # moto-backed tables.
        fake_T = SimpleNamespace(agent_feedback=feedback, agent_workers=workers)
        monkeypatch.setattr(svc, "T", fake_T)
        monkeypatch.setattr(agent_orchestrator, "T", fake_T)

        # Reset the in-process buffer registry so assertions are deterministic.
        svc._worker_buffers.clear()

        yield {"svc": svc, "orchestrator": agent_orchestrator, "workers": workers}


def _seed(svc, workers, *, user_id, worker_id, request_id):
    from app.core.time import now_ts

    workers.put_item(Item={
        "pk": f"USER#{user_id}",
        "sk": f"WORKER#{worker_id}",
        "worker_id": worker_id,
        "user_id": user_id,
        "agent_state": "awaiting_feedback",
        "status": "active",
    })
    svc.T.agent_feedback.put_item(Item={
        "pk": f"WORKER#{worker_id}",
        "sk": f"FEEDBACK#{request_id}",
        "worker_id": worker_id,
        "request_id": request_id,
        "user_id": user_id,
        "feedback_status": "pending",
        "question": "proceed?",
        "ticket_id": "t1",
        "response_text": "",
        "responded_at": 0,
        "created_at": now_ts(),
    })


def test_respond_to_feedback_transitions_worker_to_working(agent_tables):
    svc = agent_tables["svc"]
    workers = agent_tables["workers"]
    user_id, worker_id, request_id = "user_test_001", "worker_abc", "req_xyz"

    _seed(svc, workers, user_id=user_id, worker_id=worker_id, request_id=request_id)

    svc.respond_to_feedback(
        user_id=user_id,
        worker_id=worker_id,
        request_id=request_id,
        response_text="proceed with option A",
    )

    item = workers.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"}
    )["Item"]
    # FAILS before fix (stays "awaiting_feedback"); PASSES after fix.
    assert item["agent_state"] == "working"

    # Feedback row still correctly recorded the response.
    fb = svc.get_feedback_request(worker_id, request_id)
    assert fb["feedback_status"] == "responded"
    assert fb["response_text"] == "proceed with option A"


def test_respond_to_feedback_appends_to_buffer(agent_tables):
    svc = agent_tables["svc"]
    workers = agent_tables["workers"]
    user_id, worker_id, request_id = "user_test_001", "worker_buf", "req_buf"

    _seed(svc, workers, user_id=user_id, worker_id=worker_id, request_id=request_id)

    svc.respond_to_feedback(
        user_id=user_id,
        worker_id=worker_id,
        request_id=request_id,
        response_text="use approach B",
    )

    buf = svc.get_or_create_buffer(worker_id)
    # FAILS before fix (buffer empty); PASSES after fix.
    assert "approach B" in buf.get_recent(500)
