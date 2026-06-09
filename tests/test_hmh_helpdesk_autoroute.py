"""HMH-001/002 — helpdesk agent-availability selection + availability endpoint.

Hermetic: no AWS. The presence/online-members resolver is monkeypatched; we test
the picker, the counter, and the customer-facing availability endpoint (which
must return counts only, never agent identities).
"""
from __future__ import annotations

import app.routers.messaging as m


def test_pick_available_agent_first_online(monkeypatch):
    monkeypatch.setattr(m, "_resolve_online_helpdesk_members", lambda g, ts: ["a", "b", "c"])
    assert m.pick_available_agent("grp", 1000) == "a"
    assert m.count_available_agents("grp", 1000) == 3


def test_pick_available_agent_respects_exclude(monkeypatch):
    monkeypatch.setattr(m, "_resolve_online_helpdesk_members", lambda g, ts: ["a", "b", "c"])
    assert m.pick_available_agent("grp", 1000, exclude={"a"}) == "b"
    assert m.pick_available_agent("grp", 1000, exclude={"a", "b", "c"}) is None


def test_pick_available_agent_none_when_empty(monkeypatch):
    monkeypatch.setattr(m, "_resolve_online_helpdesk_members", lambda g, ts: [])
    assert m.pick_available_agent("grp", 1000) is None
    assert m.count_available_agents("grp", 1000) == 0


def test_picker_never_raises(monkeypatch):
    def _boom(g, ts):
        raise RuntimeError("presence down")
    monkeypatch.setattr(m, "_resolve_online_helpdesk_members", _boom)
    assert m.pick_available_agent("grp", 1000) is None
    assert m.count_available_agents("grp", 1000) == 0


def test_availability_endpoint_counts_only(monkeypatch):
    monkeypatch.setattr(m, "count_available_agents", lambda g, ts: 2)
    out = m.get_helpdesk_availability(group_id="grp", user_id="customer")
    assert out == {"available_agent_count": 2, "any_available": True}
    # Counts only — no agent identities leak.
    assert "agents" not in out and "user_id" not in out and "user_ids" not in out


def test_availability_endpoint_none_available(monkeypatch):
    monkeypatch.setattr(m, "count_available_agents", lambda g, ts: 0)
    out = m.get_helpdesk_availability(group_id="grp", user_id="customer")
    assert out == {"available_agent_count": 0, "any_available": False}
