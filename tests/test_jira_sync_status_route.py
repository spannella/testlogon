from __future__ import annotations

from app.routers import jira_integrations


class _Store:
    def __init__(self, links=None, mirror=None) -> None:
        self._links = links or []
        self._mirror = mirror

    def list_links_for_ticket(self, *, internal_ticket_id: str):
        return list(self._links)

    def get_issue_mirror(self, *, external_issue_id: str):
        return self._mirror


def test_ticket_sync_status_returns_not_linked_when_no_active_link(monkeypatch) -> None:
    monkeypatch.setattr(jira_integrations, "JiraTicketSyncStore", lambda: _Store(links=[]))

    out = jira_integrations.ticket_sync_status(ticket_id="tkt_1", _ctx={"user_sub": "u1"}, _user=type("U", (), {"sub": "u1"})())
    assert out.linked is False
    assert out.sync_state == "not_linked"


def test_ticket_sync_status_returns_link_metadata_and_jira_status(monkeypatch) -> None:
    links = [
        {
            "entity_type": "ticket_external_link",
            "link_id": "jlink_1",
            "external_issue_id": "10001",
            "external_issue_key": "PROJ-9",
            "sync_state": "in_sync",
            "last_synced_at": 1234,
            "updated_at": 2000,
        }
    ]
    mirror = {"status": "In Progress"}
    monkeypatch.setattr(jira_integrations, "JiraTicketSyncStore", lambda: _Store(links=links, mirror=mirror))

    out = jira_integrations.ticket_sync_status(ticket_id="tkt_1", _ctx={"user_sub": "u1"}, _user=type("U", (), {"sub": "u1"})())
    assert out.linked is True
    assert out.link_id == "jlink_1"
    assert out.external_issue_key == "PROJ-9"
    assert out.jira_status == "In Progress"
    assert out.last_synced_at == 1234
