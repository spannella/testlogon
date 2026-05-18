from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services.jira_feature_flags import (
    get_jira_feature_flags,
    is_workspace_allowed,
    reset_runtime_outbound_kill_switch_override,
    set_runtime_outbound_kill_switch,
    validate_jira_integration_startup_config,
)


def _cfg(**kwargs):
    base = {
        "jira_sync_enabled": False,
        "jira_sync_read_enabled": False,
        "jira_sync_outbound_enabled": False,
        "jira_sync_inbound_enabled": False,
        "jira_sync_outbound_kill_switch": False,
        "jira_sync_workspace_allowlist": "",
        "jira_sync_require_workspace_allowlist": False,
        "jira_sync_require_oauth_config": True,
        "tickets_jira_workspace_index_name": "jira_workspace-updated_at-index",
        "tickets_jira_issue_index_name": "jira_issue-index",
        "tickets_jira_sync_state_index_name": "jira_sync_state-updated_at-index",
        "jira_sync_oauth_client_id": "",
        "jira_sync_oauth_client_secret_ref": "",
    }
    base.update(kwargs)
    return SimpleNamespace(**base)


def test_runtime_kill_switch_override_takes_precedence() -> None:
    cfg = _cfg(jira_sync_outbound_kill_switch=False)
    reset_runtime_outbound_kill_switch_override()
    try:
        assert get_jira_feature_flags(settings=cfg).outbound_kill_switch is False
        set_runtime_outbound_kill_switch(disabled=True, settings=cfg)
        assert get_jira_feature_flags(settings=cfg).outbound_kill_switch is True
    finally:
        reset_runtime_outbound_kill_switch_override()


def test_workspace_allowlist_parsing_and_matching() -> None:
    cfg = _cfg(jira_sync_workspace_allowlist="ws_1, ws_2,ws_1")
    flags = get_jira_feature_flags(settings=cfg)
    assert flags.workspace_allowlist == ("ws_1", "ws_2")
    assert is_workspace_allowed("ws_2", settings=cfg) is True
    assert is_workspace_allowed("ws_3", settings=cfg) is False


def test_startup_validation_requires_at_least_one_enabled_mode() -> None:
    cfg = _cfg(
        jira_sync_enabled=True,
        jira_sync_read_enabled=False,
        jira_sync_outbound_enabled=False,
        jira_sync_inbound_enabled=False,
        jira_sync_require_oauth_config=False,
    )
    with pytest.raises(RuntimeError, match="requires at least one mode enabled"):
        validate_jira_integration_startup_config(settings=cfg)


def test_startup_validation_requires_oauth_when_requested() -> None:
    cfg = _cfg(
        jira_sync_enabled=True,
        jira_sync_read_enabled=True,
        jira_sync_outbound_enabled=False,
        jira_sync_inbound_enabled=False,
        jira_sync_require_oauth_config=True,
        jira_sync_oauth_client_id="",
        jira_sync_oauth_client_secret_ref="",
    )
    with pytest.raises(RuntimeError, match="OAuth configuration missing"):
        validate_jira_integration_startup_config(settings=cfg)


def test_startup_validation_requires_workspace_allowlist_when_enabled() -> None:
    cfg = _cfg(
        jira_sync_enabled=True,
        jira_sync_read_enabled=True,
        jira_sync_require_workspace_allowlist=True,
        jira_sync_workspace_allowlist="",
        jira_sync_require_oauth_config=False,
    )
    with pytest.raises(RuntimeError, match="workspace allowlist required"):
        validate_jira_integration_startup_config(settings=cfg)


def test_startup_validation_requires_non_empty_jira_index_settings() -> None:
    cfg = _cfg(
        jira_sync_enabled=True,
        jira_sync_read_enabled=True,
        jira_sync_require_oauth_config=False,
        tickets_jira_workspace_index_name="",
        tickets_jira_issue_index_name="jira_issue-index",
        tickets_jira_sync_state_index_name="",
    )
    with pytest.raises(RuntimeError, match="missing required Jira index settings"):
        validate_jira_integration_startup_config(settings=cfg)


def test_startup_validation_actionable_error_prefix() -> None:
    cfg = _cfg(
        jira_sync_enabled=True,
        jira_sync_read_enabled=False,
        jira_sync_outbound_enabled=False,
        jira_sync_inbound_enabled=False,
        jira_sync_require_oauth_config=False,
    )
    with pytest.raises(RuntimeError, match="JIRA startup check failed"):
        validate_jira_integration_startup_config(settings=cfg)


def test_startup_validation_rejects_invalid_webhook_ip_policy_mode(monkeypatch) -> None:
    cfg = _cfg(
        jira_sync_enabled=True,
        jira_sync_read_enabled=True,
        jira_sync_require_oauth_config=False,
    )
    monkeypatch.setenv("JIRA_WEBHOOK_IP_POLICY_MODE", "invalid-mode")
    with pytest.raises(RuntimeError, match="invalid JIRA_WEBHOOK_IP_POLICY_MODE"):
        validate_jira_integration_startup_config(settings=cfg)


def test_startup_validation_rejects_invalid_webhook_allowed_ip_cidr(monkeypatch) -> None:
    cfg = _cfg(
        jira_sync_enabled=True,
        jira_sync_read_enabled=True,
        jira_sync_require_oauth_config=False,
    )
    monkeypatch.setenv("JIRA_WEBHOOK_IP_POLICY_MODE", "enforce")
    monkeypatch.setenv("JIRA_WEBHOOK_ALLOWED_IPS", "10.0.0.0/8,bad-cidr")
    with pytest.raises(RuntimeError, match="invalid JIRA_WEBHOOK_ALLOWED_IPS CIDR entries"):
        validate_jira_integration_startup_config(settings=cfg)


def test_startup_validation_accepts_valid_webhook_ip_policy_env(monkeypatch) -> None:
    cfg = _cfg(
        jira_sync_enabled=True,
        jira_sync_read_enabled=True,
        jira_sync_require_oauth_config=False,
    )
    monkeypatch.setenv("JIRA_WEBHOOK_IP_POLICY_MODE", "monitor")
    monkeypatch.setenv("JIRA_WEBHOOK_ALLOWED_IPS", "10.0.0.0/8,192.168.0.0/16")
    validate_jira_integration_startup_config(settings=cfg)


def test_startup_validation_rejects_invalid_webhook_replay_ttl(monkeypatch) -> None:
    cfg = _cfg(
        jira_sync_enabled=True,
        jira_sync_read_enabled=True,
        jira_sync_require_oauth_config=False,
    )
    monkeypatch.setenv("JIRA_WEBHOOK_REPLAY_TTL_SECONDS", "59")
    with pytest.raises(RuntimeError, match="JIRA_WEBHOOK_REPLAY_TTL_SECONDS must be >="):
        validate_jira_integration_startup_config(settings=cfg)


def test_startup_validation_rejects_invalid_webhook_replay_max_keys(monkeypatch) -> None:
    cfg = _cfg(
        jira_sync_enabled=True,
        jira_sync_read_enabled=True,
        jira_sync_require_oauth_config=False,
    )
    monkeypatch.setenv("JIRA_WEBHOOK_REPLAY_MAX_KEYS", "99")
    with pytest.raises(RuntimeError, match="JIRA_WEBHOOK_REPLAY_MAX_KEYS must be >="):
        validate_jira_integration_startup_config(settings=cfg)


def test_startup_validation_accepts_valid_webhook_replay_limits(monkeypatch) -> None:
    cfg = _cfg(
        jira_sync_enabled=True,
        jira_sync_read_enabled=True,
        jira_sync_require_oauth_config=False,
    )
    monkeypatch.setenv("JIRA_WEBHOOK_REPLAY_TTL_SECONDS", "120")
    monkeypatch.setenv("JIRA_WEBHOOK_REPLAY_MAX_KEYS", "1000")
    validate_jira_integration_startup_config(settings=cfg)


def test_startup_validation_requires_webhook_queue_url_when_inbound_enabled(monkeypatch) -> None:
    cfg = _cfg(
        jira_sync_enabled=True,
        jira_sync_read_enabled=True,
        jira_sync_inbound_enabled=True,
        jira_sync_require_oauth_config=False,
    )
    monkeypatch.delenv("JIRA_WEBHOOK_QUEUE_URL", raising=False)
    with pytest.raises(RuntimeError, match="JIRA_WEBHOOK_QUEUE_URL"):
        validate_jira_integration_startup_config(settings=cfg)


def test_startup_validation_accepts_webhook_queue_url_when_inbound_enabled(monkeypatch) -> None:
    cfg = _cfg(
        jira_sync_enabled=True,
        jira_sync_read_enabled=True,
        jira_sync_inbound_enabled=True,
        jira_sync_require_oauth_config=False,
    )
    monkeypatch.setenv("JIRA_WEBHOOK_QUEUE_URL", "https://sqs.example/queue")
    validate_jira_integration_startup_config(settings=cfg)


def test_startup_validation_rejects_non_http_webhook_queue_url(monkeypatch) -> None:
    cfg = _cfg(
        jira_sync_enabled=True,
        jira_sync_read_enabled=True,
        jira_sync_inbound_enabled=True,
        jira_sync_require_oauth_config=False,
    )
    monkeypatch.setenv("JIRA_WEBHOOK_QUEUE_URL", "sqs://queue-name")
    with pytest.raises(RuntimeError, match="absolute http\\(s\\) URL"):
        validate_jira_integration_startup_config(settings=cfg)


def test_startup_validation_rejects_webhook_queue_url_without_host(monkeypatch) -> None:
    cfg = _cfg(
        jira_sync_enabled=True,
        jira_sync_read_enabled=True,
        jira_sync_inbound_enabled=True,
        jira_sync_require_oauth_config=False,
    )
    monkeypatch.setenv("JIRA_WEBHOOK_QUEUE_URL", "https:///missing-host")
    with pytest.raises(RuntimeError, match="valid scheme and host"):
        validate_jira_integration_startup_config(settings=cfg)
