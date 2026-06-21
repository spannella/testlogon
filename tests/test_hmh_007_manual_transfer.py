"""HMH-007 — manual helpdesk conversation transfer.

Tests POST /helpdesk/conversations/{id}/transfer endpoint.
Uses offline route-handler pattern (no live DDB / no moto needed).
"""
from unittest.mock import MagicMock, patch
import importlib
import sys
import asyncio

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI


def _load_messaging():
    if "app.routers.messaging" in sys.modules:
        return sys.modules["app.routers.messaging"]
    return importlib.import_module("app.routers.messaging")


@pytest.fixture(scope="module")
def messaging():
    return _load_messaging()


# ---------------------------------------------------------------------------
# Helper: a minimal assigned helpdesk convo
# ---------------------------------------------------------------------------

def _convo(cid="conv-1", agent="agent-A", group="grp-1", version=2):
    return {
        "conversation_id": cid,
        "routing_mode": "helpdesk_bridge",
        "routing_state": "assigned",
        "active_agent_user_id": agent,
        "routing_group_id": group,
        "assignment_version": version,
    }


def _transfer_result(cid="conv-1", new_agent="agent-B", group="grp-1", new_version=3):
    return {
        "transition": MagicMock(changed=True),
        "event": {"event_id": "ev-transfer-1"},
        "conversation": {
            "conversation_id": cid,
            "routing_mode": "helpdesk_bridge",
            "routing_state": "assigned",
            "active_agent_user_id": new_agent,
            "routing_group_id": group,
            "assignment_version": new_version,
        },
    }


# ---------------------------------------------------------------------------
# Happy path: caller is current agent, target is group member
# ---------------------------------------------------------------------------

def test_transfer_happy_path(messaging):
    convo = _convo()
    xfer_result = _transfer_result()

    with (
        patch.object(messaging, "_get_conversation_or_404", return_value=convo),
        patch.object(messaging, "_is_helpdesk_group_member", return_value=True),
        patch.object(messaging, "_apply_helpdesk_routing_transition", return_value=xfer_result) as mock_apply,
        patch.object(messaging, "_attach_agent_participant") as mock_attach,
    ):
        body = messaging.TransferHelpdeskIn(target_agent_user_id="agent-B")
        result = messaging.transfer_helpdesk_conversation(
            conversation_id="conv-1",
            body=body,
            user_id="agent-A",
        )

    assert result.ok is True
    assert result.assigned_agent_user_id == "agent-B"
    assert result.previous_agent_user_id == "agent-A"
    assert result.state == "assigned"
    assert result.assignment_version == 3

    # Routing transition called with transfer_agent action
    apply_kwargs = mock_apply.call_args.kwargs
    assert apply_kwargs["cmd"].action == "transfer_agent"
    assert apply_kwargs["cmd"].agent_user_id == "agent-B"
    assert apply_kwargs["actor_user_id"] == "agent-A"

    # Agent participant attached
    attach_kwargs = mock_attach.call_args.kwargs
    assert attach_kwargs["agent_user_id"] == "agent-B"
    assert attach_kwargs["routing_state"] == "assigned"


# ---------------------------------------------------------------------------
# Non-group-member caller → 403
# ---------------------------------------------------------------------------

def test_transfer_caller_not_group_member(messaging):
    convo = _convo()

    # First call for caller check returns False
    with (
        patch.object(messaging, "_get_conversation_or_404", return_value=convo),
        patch.object(messaging, "_is_helpdesk_group_member", return_value=False),
    ):
        from fastapi import HTTPException
        body = messaging.TransferHelpdeskIn(target_agent_user_id="agent-B")
        with pytest.raises(HTTPException) as exc_info:
            messaging.transfer_helpdesk_conversation(
                conversation_id="conv-1",
                body=body,
                user_id="outsider",
            )

    assert exc_info.value.status_code == 403
    assert "not a helpdesk group member" in str(exc_info.value.detail)


# ---------------------------------------------------------------------------
# Non-helpdesk conversation → 400
# ---------------------------------------------------------------------------

def test_transfer_non_helpdesk_conversation(messaging):
    convo = {**_convo(), "routing_mode": "standard"}

    with patch.object(messaging, "_get_conversation_or_404", return_value=convo):
        from fastapi import HTTPException
        body = messaging.TransferHelpdeskIn(target_agent_user_id="agent-B")
        with pytest.raises(HTTPException) as exc_info:
            messaging.transfer_helpdesk_conversation(
                conversation_id="conv-1",
                body=body,
                user_id="agent-A",
            )

    assert exc_info.value.status_code == 400
    assert "not helpdesk-routed" in str(exc_info.value.detail)


# ---------------------------------------------------------------------------
# Not in assigned state → 409
# ---------------------------------------------------------------------------

def test_transfer_wrong_state(messaging):
    convo = {**_convo(), "routing_state": "awaiting_agent"}

    with (
        patch.object(messaging, "_get_conversation_or_404", return_value=convo),
        patch.object(messaging, "_is_helpdesk_group_member", return_value=True),
    ):
        from fastapi import HTTPException
        body = messaging.TransferHelpdeskIn(target_agent_user_id="agent-B")
        with pytest.raises(HTTPException) as exc_info:
            messaging.transfer_helpdesk_conversation(
                conversation_id="conv-1",
                body=body,
                user_id="agent-A",
            )

    assert exc_info.value.status_code == 409
    assert "must be assigned" in str(exc_info.value.detail)


# ---------------------------------------------------------------------------
# Target not in routing group → 400
# ---------------------------------------------------------------------------

def test_transfer_target_not_in_group(messaging):
    convo = _convo()

    def _member_check(group_id, user_id):
        # caller is in group, target is not
        return user_id != "outsider-target"

    with (
        patch.object(messaging, "_get_conversation_or_404", return_value=convo),
        patch.object(messaging, "_is_helpdesk_group_member", side_effect=_member_check),
    ):
        from fastapi import HTTPException
        body = messaging.TransferHelpdeskIn(target_agent_user_id="outsider-target")
        with pytest.raises(HTTPException) as exc_info:
            messaging.transfer_helpdesk_conversation(
                conversation_id="conv-1",
                body=body,
                user_id="agent-A",
            )

    assert exc_info.value.status_code == 400
    assert "not a member" in str(exc_info.value.detail)


# ---------------------------------------------------------------------------
# Transfer to same agent → 400
# ---------------------------------------------------------------------------

def test_transfer_to_same_agent(messaging):
    convo = _convo(agent="agent-A")

    with (
        patch.object(messaging, "_get_conversation_or_404", return_value=convo),
        patch.object(messaging, "_is_helpdesk_group_member", return_value=True),
    ):
        from fastapi import HTTPException
        body = messaging.TransferHelpdeskIn(target_agent_user_id="agent-A")
        with pytest.raises(HTTPException) as exc_info:
            messaging.transfer_helpdesk_conversation(
                conversation_id="conv-1",
                body=body,
                user_id="agent-A",
            )

    assert exc_info.value.status_code == 400
    assert "already assigned" in str(exc_info.value.detail)
