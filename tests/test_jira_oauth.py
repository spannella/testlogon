from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services.jira_oauth import (
    JiraOAuthConfigError,
    create_and_store_oauth_state,
    get_jira_oauth_config,
    get_oauth_state,
)


def _cfg(**kwargs):
    base = {
        "jira_sync_oauth_authorize_url": "https://auth.atlassian.com/authorize",
        "jira_sync_oauth_audience": "api.atlassian.com",
        "jira_sync_oauth_client_id": "client_123",
        "jira_sync_oauth_scopes": "read:jira-work write:jira-work offline_access",
        "jira_sync_oauth_state_ttl_seconds": 600,
    }
    base.update(kwargs)
    return SimpleNamespace(**base)


def test_get_jira_oauth_config_success() -> None:
    cfg = get_jira_oauth_config(settings=_cfg())
    assert cfg.client_id == "client_123"
    assert cfg.authorize_url.startswith("https://")


def test_get_jira_oauth_config_missing_client_id_raises_actionable_error() -> None:
    with pytest.raises(JiraOAuthConfigError, match="client id missing"):
        get_jira_oauth_config(settings=_cfg(jira_sync_oauth_client_id=""))


def test_get_jira_oauth_config_invalid_authorize_url_raises() -> None:
    with pytest.raises(JiraOAuthConfigError, match="must be https://"):
        get_jira_oauth_config(settings=_cfg(jira_sync_oauth_authorize_url="http://insecure"))


def test_create_and_store_oauth_state_generates_csrf_safe_state() -> None:
    row = create_and_store_oauth_state(
        workspace_id="ws_1",
        user_sub="user_1",
        redirect_uri="https://app.example.com/callback",
        state_ttl_seconds=600,
    )
    assert len(row.state) >= 32
    loaded = get_oauth_state(row.state)
    assert loaded is not None
    assert loaded.workspace_id == "ws_1"
    assert loaded.user_sub == "user_1"
