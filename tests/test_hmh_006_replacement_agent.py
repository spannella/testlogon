"""HMH-006 — auto-reassign after agent disconnect.

Tests that _handle_helpdesk_presence_event, when HELPDESK_AUTO_REASSIGN_ENABLED,
auto-assigns a replacement agent instead of dropping to awaiting_agent.
"""
from unittest.mock import MagicMock, patch, call
import importlib
import sys

import pytest


def _load_messaging():
    if "app.routers.messaging" in sys.modules:
        return sys.modules["app.routers.messaging"]
    return importlib.import_module("app.routers.messaging")


@pytest.fixture()
def messaging():
    return _load_messaging()


# ---------------------------------------------------------------------------
# Helper: build a minimal assigned helpdesk convo dict
# ---------------------------------------------------------------------------

def _convo(cid="c1", agent="agent-A", version=3, group="grp-1"):
    return {
        "conversation_id": cid,
        "routing_mode": "helpdesk_bridge",
        "routing_state": "assigned",
        "active_agent_user_id": agent,
        "routing_group_id": group,
        "assignment_version": version,
    }


def _release_result(cid="c1", group="grp-1", new_version=4):
    """Simulates what _apply_helpdesk_routing_transition returns after release."""
    return {
        "transition": MagicMock(changed=True),
        "event": {"event_id": "ev-release-1"},
        "conversation": {
            "conversation_id": cid,
            "routing_mode": "helpdesk_bridge",
            "routing_state": "awaiting_agent",
            "active_agent_user_id": "",
            "routing_group_id": group,
            "assignment_version": new_version,
        },
    }


def _assign_result(cid="c1", agent="agent-B", group="grp-1", new_version=5):
    return {
        "transition": MagicMock(changed=True),
        "event": {"event_id": "ev-assign-1"},
        "conversation": {
            "conversation_id": cid,
            "routing_mode": "helpdesk_bridge",
            "routing_state": "assigned",
            "active_agent_user_id": agent,
            "routing_group_id": group,
            "assignment_version": new_version,
        },
    }


# ---------------------------------------------------------------------------
# Test: replacement found → auto-reassign, no fanout alert
# ---------------------------------------------------------------------------

def test_auto_reassign_when_replacement_available(messaging):
    convo = _convo()
    rel_result = _release_result()
    asgn_result = _assign_result()

    call_results = iter([rel_result, asgn_result])

    with (
        patch.object(messaging, "HELPDESK_AUTO_REASSIGN_ENABLED", True),
        patch.object(messaging, "_assigned_helpdesk_conversations_for_agent", return_value=[convo]),
        patch.object(messaging, "record_helpdesk_failover"),
        patch.object(messaging, "_apply_helpdesk_routing_transition", side_effect=lambda **kwargs: next(call_results)),
        patch.object(messaging, "pick_available_agent", return_value="agent-B"),
        patch.object(messaging, "_attach_agent_participant") as mock_attach,
        patch.object(messaging, "fanout_helpdesk_alert") as mock_fanout,
        patch.object(messaging, "_emit_no_agents_online_notice") as mock_no_agents,
    ):
        result = messaging._handle_helpdesk_presence_event(user_id="agent-A", status="offline", ts=9000)

    assert result["action"] == "release_assigned"
    assert result["transitioned"] == 1
    # Replacement found → attach participant
    mock_attach.assert_called_once()
    kwargs = mock_attach.call_args.kwargs
    assert kwargs["agent_user_id"] == "agent-B"
    assert kwargs["conversation_id"] == "c1"
    # No fanout alert since reassigned
    mock_fanout.assert_not_called()
    mock_no_agents.assert_not_called()


# ---------------------------------------------------------------------------
# Test: no replacement → falls back to fanout alert
# ---------------------------------------------------------------------------

def test_falls_back_to_fanout_when_no_replacement(messaging):
    convo = _convo()
    rel_result = _release_result()
    alert_result = {"transition": MagicMock(changed=False), "event": {}, "conversation": {}}

    apply_calls = iter([rel_result, alert_result])

    with (
        patch.object(messaging, "HELPDESK_AUTO_REASSIGN_ENABLED", True),
        patch.object(messaging, "_assigned_helpdesk_conversations_for_agent", return_value=[convo]),
        patch.object(messaging, "record_helpdesk_failover"),
        patch.object(messaging, "_apply_helpdesk_routing_transition", side_effect=lambda **kwargs: next(apply_calls)),
        patch.object(messaging, "pick_available_agent", return_value=None),
        patch.object(messaging, "_attach_agent_participant") as mock_attach,
        patch.object(messaging, "fanout_helpdesk_alert", return_value=1) as mock_fanout,
        patch.object(messaging, "_emit_no_agents_online_notice") as mock_no_agents,
    ):
        result = messaging._handle_helpdesk_presence_event(user_id="agent-A", status="offline", ts=9000)

    assert result["action"] == "release_assigned"
    mock_attach.assert_not_called()
    mock_fanout.assert_called_once_with(conversation_id="c1", group_id="grp-1", created_by="agent-A")
    mock_no_agents.assert_not_called()


# ---------------------------------------------------------------------------
# Test: auto-reassign disabled → always falls back to fanout alert
# ---------------------------------------------------------------------------

def test_no_reassign_when_flag_off(messaging):
    convo = _convo()
    rel_result = _release_result()
    alert_result = {"transition": MagicMock(changed=False), "event": {}, "conversation": {}}

    apply_calls = iter([rel_result, alert_result])

    with (
        patch.object(messaging, "HELPDESK_AUTO_REASSIGN_ENABLED", False),
        patch.object(messaging, "_assigned_helpdesk_conversations_for_agent", return_value=[convo]),
        patch.object(messaging, "record_helpdesk_failover"),
        patch.object(messaging, "_apply_helpdesk_routing_transition", side_effect=lambda **kwargs: next(apply_calls)),
        patch.object(messaging, "pick_available_agent") as mock_pick,
        patch.object(messaging, "_attach_agent_participant") as mock_attach,
        patch.object(messaging, "fanout_helpdesk_alert", return_value=1) as mock_fanout,
        patch.object(messaging, "_emit_no_agents_online_notice"),
    ):
        messaging._handle_helpdesk_presence_event(user_id="agent-A", status="offline", ts=9000)

    mock_pick.assert_not_called()
    mock_attach.assert_not_called()
    mock_fanout.assert_called_once()


# ---------------------------------------------------------------------------
# Test: reassign failure → falls back to fanout (best-effort)
# ---------------------------------------------------------------------------

def test_reassign_exception_falls_back_to_fanout(messaging):
    convo = _convo()
    rel_result = _release_result()
    alert_result = {"transition": MagicMock(changed=False), "event": {}, "conversation": {}}

    def _apply(**kwargs):
        cmd = kwargs.get("cmd")
        if cmd and getattr(cmd, "action", None) == "release_agent":
            return rel_result
        if cmd and getattr(cmd, "action", None) == "assign_agent":
            raise RuntimeError("DDB condition failed")
        return alert_result

    with (
        patch.object(messaging, "HELPDESK_AUTO_REASSIGN_ENABLED", True),
        patch.object(messaging, "_assigned_helpdesk_conversations_for_agent", return_value=[convo]),
        patch.object(messaging, "record_helpdesk_failover"),
        patch.object(messaging, "_apply_helpdesk_routing_transition", side_effect=_apply),
        patch.object(messaging, "pick_available_agent", return_value="agent-B"),
        patch.object(messaging, "_attach_agent_participant") as mock_attach,
        patch.object(messaging, "fanout_helpdesk_alert", return_value=1) as mock_fanout,
        patch.object(messaging, "_emit_no_agents_online_notice"),
    ):
        result = messaging._handle_helpdesk_presence_event(user_id="agent-A", status="offline", ts=9000)

    # transitioned was incremented for the release, not for the failed reassign
    assert result["transitioned"] == 1
    mock_attach.assert_not_called()
    mock_fanout.assert_called_once()
