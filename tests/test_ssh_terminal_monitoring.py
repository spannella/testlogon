"""Regression tests for GAP-0012.

Live SSH browser-terminal output must flow through the AGENT-006 monitoring
pipeline. The integration point is
``terminal_monitor.process_terminal_output(worker_id, chunk)`` which:
  1. appends the chunk to the worker's ring buffer,
  2. runs the PatternMatcher over recent buffered output, and
  3. returns a signal dict when a feedback/completion/error pattern fires
     (else None).

Feeding a known trigger pattern must produce a signal (and let the dispatch
path create a feedback request in DynamoDB); benign output must not.

Before the fix `process_terminal_output` did not exist (AttributeError) and the
SSH forwarding loop never tapped the pipeline. These tests run fully offline
using moto-backed DynamoDB (no real AWS).
"""

from __future__ import annotations

from types import SimpleNamespace

import boto3
import pytest
from moto import mock_aws


KEY_SCHEMA = [
    {"AttributeName": "pk", "KeyType": "HASH"},
    {"AttributeName": "sk", "KeyType": "RANGE"},
]
ATTR_DEFS = [
    {"AttributeName": "pk", "AttributeType": "S"},
    {"AttributeName": "sk", "AttributeType": "S"},
]


@pytest.fixture
def monitor(monkeypatch):
    """Wire terminal_monitor at a moto-backed agent_feedback table and reset
    the in-process buffer registry for deterministic assertions."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        feedback = ddb.create_table(
            TableName="agent_feedback_test",
            KeySchema=KEY_SCHEMA,
            AttributeDefinitions=ATTR_DEFS,
            BillingMode="PAY_PER_REQUEST",
        )
        feedback.wait_until_exists()

        from app.services import terminal_monitor as svc

        fake_T = SimpleNamespace(agent_feedback=feedback)
        monkeypatch.setattr(svc, "T", fake_T)
        svc._worker_buffers.clear()

        yield svc


def test_process_terminal_output_detects_feedback_signal(monitor):
    """A feedback-trigger pattern in the output must yield a feedback signal."""
    result = monitor.process_terminal_output(
        worker_id="worker_test_1",
        chunk="Running task...\n[AGENT_FEEDBACK_NEEDED] Which branch to use?\n",
    )
    assert result is not None  # FAILS before fix (function missing)
    assert result["signal"] == "feedback_needed"


def test_process_terminal_output_returns_none_for_benign_output(monitor):
    """Ordinary build output must not trigger any signal."""
    result = monitor.process_terminal_output(
        worker_id="worker_test_2",
        chunk="Compiling source files...\nLinking objects...\nDone.\n",
    )
    assert result is None


def test_process_terminal_output_accumulates_buffer(monitor):
    """The pattern can straddle chunk boundaries via the accumulating buffer."""
    monitor.process_terminal_output("worker_buf_1", "Part A of output ")
    result = monitor.process_terminal_output("worker_buf_1", "then [AGENT_COMPLETE]")
    assert result is not None
    assert result["signal"] == "completion"


def test_tap_creates_feedback_request_in_ddb(monitor):
    """Simulates the SSH WebSocket monitoring tap: a feedback signal leads to a
    feedback request row in T.agent_feedback. Before the fix the pipeline was
    never invoked so the table stayed empty."""
    worker_id = "worker_ws_test"
    user_id = "user_ws_001"

    signal = monitor.process_terminal_output(
        worker_id=worker_id,
        chunk="[AGENT_FEEDBACK_NEEDED] Confirm the deployment target.\n",
    )
    assert signal is not None
    assert signal["signal"] == "feedback_needed"

    # Dispatch path (mirrors _dispatch_terminal_signal for feedback_needed).
    monitor.create_feedback_request(
        user_id=user_id,
        worker_id=worker_id,
        ticket_id="",
        question=signal["match"],
        terminal_context=monitor.get_or_create_buffer(worker_id).get_recent(2000),
        detected_pattern=signal["pattern"],
    )

    items = monitor.list_feedback_requests(worker_id)
    assert len(items) == 1
    assert items[0]["feedback_status"] == "pending"
    assert "AGENT_FEEDBACK_NEEDED" in items[0]["question"]


def test_benign_output_creates_no_feedback_request(monitor):
    """Benign output must not produce a signal nor any feedback row."""
    worker_id = "worker_ws_benign"
    signal = monitor.process_terminal_output(
        worker_id=worker_id,
        chunk="ls -la\nREADME.md  src/  tests/\n",
    )
    assert signal is None
    assert monitor.list_feedback_requests(worker_id) == []
