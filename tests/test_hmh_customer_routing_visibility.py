"""HMH-008 — customer-safe helpdesk routing visibility.

The customer (non-agent) participant of a helpdesk_bridge conversation must
receive `routing_mode`, `routing_state`, and the derived `agent_connected` flag
so their routing banner can render — but must NEVER receive the agent's
identity (`active_agent_user_id`) or the agent-only `routing_group_id`.

Hermetic: no AWS. The pin lookup + agent-viewer check are monkeypatched, and we
inspect the ConversationOut the serializer builds.
"""
from __future__ import annotations

import app.routers.messaging as m


def _convo(state: str) -> dict:
    return {
        "type": "dm",
        "routing_mode": "helpdesk_bridge",
        "routing_state": state,
        "routing_group_id": "grp1",
        "active_agent_user_id": "agent_1" if state == "assigned" else "",
        "active_agent_claimed_at": 123,
        "assignment_version": 2,
        "created_at": 0,
    }


def _out(monkeypatch, *, state: str, is_agent: bool):
    monkeypatch.setattr(m, "_get_latest_active_pin", lambda _cid: None)
    monkeypatch.setattr(m, "_is_helpdesk_agent_viewer", lambda _c, _u: is_agent)
    return m._conversation_out_from_items(
        conversation_id="c1",
        convo=_convo(state),
        participant={"status": "active"},
        viewer_user_id="viewer",
    )


def test_customer_sees_status_but_not_agent_identity(monkeypatch):
    out = _out(monkeypatch, state="assigned", is_agent=False)
    # Customer-safe status fields are present.
    assert out.routing_mode == "helpdesk_bridge"
    assert out.routing_state == "assigned"
    assert out.agent_connected is True
    # Agent identity / group are NOT leaked to the customer.
    assert out.active_agent_user_id is None
    assert out.routing_group_id is None


def test_customer_awaiting_agent_is_not_connected(monkeypatch):
    out = _out(monkeypatch, state="awaiting_agent", is_agent=False)
    assert out.routing_state == "awaiting_agent"
    assert out.agent_connected is False
    assert out.active_agent_user_id is None


def test_agent_still_sees_full_routing_payload(monkeypatch):
    out = _out(monkeypatch, state="assigned", is_agent=True)
    assert out.routing_state == "assigned"
    assert out.agent_connected is True
    assert out.active_agent_user_id == "agent_1"
    assert out.routing_group_id == "grp1"
    assert out.assignment_version == 2
