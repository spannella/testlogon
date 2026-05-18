from __future__ import annotations

from app.services.jira_oauth_exchange import JiraOAuthExchangeError, JiraOAuthTokens
from app.services.jira_token_lifecycle import JiraConnectionLifecycleError, get_or_refresh_access_token


class FakeStore:
    def __init__(self, row: dict):
        self.row = dict(row)

    def get_connection(self, *, workspace_id: str, connection_id: str):
        if self.row.get("workspace_id") != workspace_id or self.row.get("connection_id") != connection_id:
            return None
        return dict(self.row)

    def upsert_connection(self, **kwargs):
        self.row.update(kwargs)
        return dict(self.row)


def test_returns_existing_access_token_when_not_expired(monkeypatch) -> None:
    row = {
        "workspace_id": "ws_1",
        "connection_id": "conn_1",
        "status": "active",
        "access_token_ref": "ref://a",
        "refresh_token_ref": "ref://r",
        "expires_at": 9999999999,
    }
    store = FakeStore(row)
    monkeypatch.setattr("app.services.jira_token_lifecycle.get_secret", lambda ref: "access-token")

    token = get_or_refresh_access_token(workspace_id="ws_1", connection_id="conn_1", store=store)
    assert token == "access-token"


def test_refreshes_when_expired_and_updates_connection(monkeypatch) -> None:
    row = {
        "workspace_id": "ws_1",
        "connection_id": "conn_1",
        "status": "active",
        "access_token_ref": "ref://old_access",
        "refresh_token_ref": "ref://old_refresh",
        "expires_at": 0,
        "scopes": ["read:jira-work"],
    }
    store = FakeStore(row)

    def _fake_get_secret(ref):  # noqa: ANN001
        if ref == "ref://old_refresh":
            return "refresh-token"
        if ref.startswith("jira-oauth://access/"):
            return "new-access-token"
        return None

    monkeypatch.setattr("app.services.jira_token_lifecycle.get_secret", _fake_get_secret)
    monkeypatch.setattr(
        "app.services.jira_token_lifecycle.refresh_access_token",
        lambda refresh_token: JiraOAuthTokens(
            access_token="new-access-token",
            refresh_token="new-refresh-token",
            expires_in=300,
            scopes=["read:jira-work", "write:jira-work"],
        ),
    )
    monkeypatch.setattr(
        "app.services.jira_token_lifecycle.put_secret",
        lambda value, prefix: f"{prefix}/saved_{'access' if 'access' in prefix else 'refresh'}",
    )

    token = get_or_refresh_access_token(workspace_id="ws_1", connection_id="conn_1", store=store)
    assert token == "new-access-token"
    assert store.row["status"] == "active"
    assert store.row["access_token_ref"].startswith("jira-oauth://access/")


def test_invalid_refresh_token_marks_connection_disconnected(monkeypatch) -> None:
    row = {
        "workspace_id": "ws_1",
        "connection_id": "conn_1",
        "status": "active",
        "access_token_ref": "ref://old_access",
        "refresh_token_ref": "ref://old_refresh",
        "expires_at": 0,
    }
    store = FakeStore(row)

    monkeypatch.setattr("app.services.jira_token_lifecycle.get_secret", lambda ref: "refresh-token")

    def _raise_invalid(refresh_token):  # noqa: ANN001
        raise JiraOAuthExchangeError(
            code="jira_oauth_refresh_invalid",
            message="invalid",
            status_code=401,
        )

    monkeypatch.setattr("app.services.jira_token_lifecycle.refresh_access_token", _raise_invalid)

    try:
        get_or_refresh_access_token(workspace_id="ws_1", connection_id="conn_1", store=store)
        raise AssertionError("expected JiraConnectionLifecycleError")
    except JiraConnectionLifecycleError as exc:
        assert exc.code == "jira_connection_disconnected"
        assert store.row["status"] == "disconnected"
