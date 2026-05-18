from __future__ import annotations

import pytest

from app.services.jira_projects import JiraProjectDiscoveryError, list_projects


class FakeStore:
    def __init__(self):
        self.conn = {
            "entity_type": "jira_connection",
            "workspace_id": "ws_1",
            "connection_id": "conn_1",
            "user_id": "user_1",
            "cloud_id": "cloud_1",
            "status": "active",
        }

    def list_workspace_connections(self, *, workspace_id: str, limit: int = 100):
        if workspace_id != "ws_1":
            return []
        return [dict(self.conn)]

    def get_connection(self, *, workspace_id: str, connection_id: str):
        if workspace_id == "ws_1" and connection_id == "conn_1":
            return dict(self.conn)
        return None


class FakeClient:
    def __init__(self, response):
        self.response = response

    def search_projects(self, **kwargs):
        return self.response


def test_list_projects_supports_pagination_and_filters(monkeypatch) -> None:
    store = FakeStore()
    monkeypatch.setattr("app.services.jira_projects.get_or_refresh_access_token", lambda **kwargs: "token")

    client = FakeClient(
        (
            200,
            {
                "startAt": 0,
                "maxResults": 2,
                "isLast": False,
                "values": [
                    {"id": "1", "key": "SUP", "name": "Support", "isPrivate": False},
                    {"id": "2", "key": "OPS", "name": "Operations", "isPrivate": True},
                ],
            },
        )
    )

    result = list_projects(
        workspace_id="ws_1",
        user_sub="user_1",
        cloud_id="cloud_1",
        q="sup",
        project_keys=["SUP", "OPS"],
        cursor=None,
        limit=2,
        store=store,
        client=client,
    )

    assert len(result.items) == 2
    assert result.next_cursor is not None


def test_list_projects_normalizes_jira_api_error(monkeypatch) -> None:
    store = FakeStore()
    monkeypatch.setattr("app.services.jira_projects.get_or_refresh_access_token", lambda **kwargs: "token")
    client = FakeClient((403, {"errorMessages": ["forbidden"]}))

    with pytest.raises(JiraProjectDiscoveryError, match="forbidden") as exc:
        list_projects(
            workspace_id="ws_1",
            user_sub="user_1",
            cloud_id="cloud_1",
            q=None,
            project_keys=None,
            cursor=None,
            limit=25,
            store=store,
            client=client,
        )
    assert exc.value.code == "jira_projects_query_failed"
    assert exc.value.status_code == 400


def test_list_projects_requires_matching_user_connection() -> None:
    store = FakeStore()
    with pytest.raises(JiraProjectDiscoveryError, match="No active Jira connection"):
        list_projects(
            workspace_id="ws_1",
            user_sub="other_user",
            cloud_id="cloud_1",
            q=None,
            project_keys=None,
            cursor=None,
            limit=25,
            store=store,
            client=FakeClient((200, {"values": []})),
        )
