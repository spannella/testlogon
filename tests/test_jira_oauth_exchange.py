from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services.jira_oauth_exchange import (
    JiraOAuthExchangeError,
    exchange_authorization_code,
)


def _cfg(**kwargs):
    base = {
        "jira_sync_oauth_token_url": "https://auth.atlassian.com/oauth/token",
        "jira_sync_oauth_client_id": "client_123",
        "jira_sync_oauth_client_secret_ref": "",
        "jira_sync_oauth_client_secret_value": "secret_123",
    }
    base.update(kwargs)
    return SimpleNamespace(**base)


def test_exchange_authorization_code_success(monkeypatch) -> None:
    def _fake_json_post(url, payload, timeout_seconds=15):  # noqa: ANN001
        assert "oauth/token" in url
        assert payload["code"] == "abc"
        return 200, {"access_token": "at", "refresh_token": "rt", "expires_in": 120, "scope": "read:jira-work"}

    monkeypatch.setattr("app.services.jira_oauth_exchange._json_post", _fake_json_post)
    tokens = exchange_authorization_code(code="abc", redirect_uri="https://cb", settings=_cfg())
    assert tokens.access_token == "at"
    assert tokens.refresh_token == "rt"
    assert tokens.scopes == ["read:jira-work"]


def test_exchange_authorization_code_invalid_grant_maps_to_deterministic_error(monkeypatch) -> None:
    def _fake_json_post(url, payload, timeout_seconds=15):  # noqa: ANN001
        return 400, {"error": "invalid_grant"}

    monkeypatch.setattr("app.services.jira_oauth_exchange._json_post", _fake_json_post)
    with pytest.raises(JiraOAuthExchangeError, match="invalid or expired") as exc:
        exchange_authorization_code(code="expired", redirect_uri="https://cb", settings=_cfg())
    assert exc.value.code == "jira_oauth_code_invalid_or_expired"
    assert exc.value.status_code == 401


def test_exchange_authorization_code_requires_client_secret() -> None:
    with pytest.raises(JiraOAuthExchangeError, match="client secret unavailable"):
        exchange_authorization_code(
            code="abc",
            redirect_uri="https://cb",
            settings=_cfg(jira_sync_oauth_client_secret_value="", jira_sync_oauth_client_secret_ref=""),
        )
