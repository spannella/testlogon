from __future__ import annotations

from unittest.mock import Mock, patch

from app.services import alerts


def test_post_webhook_with_retry_retries_and_succeeds() -> None:
    ok_response = Mock(status_code=200)
    with patch.object(alerts.requests, "post", side_effect=[Exception("boom"), Exception("boom2"), ok_response]) as post, patch.object(
        alerts.time, "sleep"
    ) as sleep:
        alerts._post_webhook_with_retry("https://example.test/hook", json_payload={"a": 1})

    assert post.call_count == 3
    assert sleep.call_count == 2


def test_post_webhook_with_retry_logs_after_exhaustion() -> None:
    with patch.object(alerts.requests, "post", side_effect=Exception("fail")) as post, patch.object(
        alerts.time, "sleep"
    ) as sleep, patch.object(alerts.logger, "warning") as warning:
        alerts._post_webhook_with_retry("https://example.test/hook", json_payload={"a": 1})

    assert post.call_count == 3
    assert sleep.call_count == 2
    warning.assert_called_once()


def test_send_siem_event_privileged_filter_and_signature() -> None:
    payload = {"event": "admin_role_granted", "user_sub": "root", "actor_sub": "root", "ts": 123}
    ok_response = Mock(status_code=200)
    old = {
        "siem_webhook_enabled": alerts.S.siem_webhook_enabled,
        "siem_webhook_url": alerts.S.siem_webhook_url,
        "siem_root_admin_events_only": alerts.S.siem_root_admin_events_only,
        "siem_webhook_secret": alerts.S.siem_webhook_secret,
    }
    object.__setattr__(alerts.S, "siem_webhook_enabled", True)
    object.__setattr__(alerts.S, "siem_webhook_url", "https://siem.test/hook")
    object.__setattr__(alerts.S, "siem_root_admin_events_only", True)
    object.__setattr__(alerts.S, "siem_webhook_secret", "secret")
    try:
        with patch.object(alerts.requests, "post", return_value=ok_response) as post:
            alerts.send_siem_event(payload)
        post.assert_called_once()
        sent_headers = post.call_args.kwargs["headers"]
        assert "X-SIEM-Signature" in sent_headers
    finally:
        for k, v in old.items():
            object.__setattr__(alerts.S, k, v)


def test_send_siem_event_ignores_non_privileged_when_filter_enabled() -> None:
    payload = {"event": "billing_balance_view", "user_sub": "u1", "ts": 123}
    old = {
        "siem_webhook_enabled": alerts.S.siem_webhook_enabled,
        "siem_webhook_url": alerts.S.siem_webhook_url,
        "siem_root_admin_events_only": alerts.S.siem_root_admin_events_only,
    }
    object.__setattr__(alerts.S, "siem_webhook_enabled", True)
    object.__setattr__(alerts.S, "siem_webhook_url", "https://siem.test/hook")
    object.__setattr__(alerts.S, "siem_root_admin_events_only", True)
    try:
        with patch.object(alerts.requests, "post") as post:
            alerts.send_siem_event(payload)
        post.assert_not_called()
    finally:
        for k, v in old.items():
            object.__setattr__(alerts.S, k, v)


def test_send_siem_event_allows_non_privileged_when_filter_disabled() -> None:
    payload = {"event": "billing_balance_view", "user_sub": "u1", "ts": 123}
    ok_response = Mock(status_code=200)
    old = {
        "siem_webhook_enabled": alerts.S.siem_webhook_enabled,
        "siem_webhook_url": alerts.S.siem_webhook_url,
        "siem_root_admin_events_only": alerts.S.siem_root_admin_events_only,
        "siem_webhook_secret": alerts.S.siem_webhook_secret,
    }
    object.__setattr__(alerts.S, "siem_webhook_enabled", True)
    object.__setattr__(alerts.S, "siem_webhook_url", "https://siem.test/hook")
    object.__setattr__(alerts.S, "siem_root_admin_events_only", False)
    object.__setattr__(alerts.S, "siem_webhook_secret", "")
    try:
        with patch.object(alerts.requests, "post", return_value=ok_response) as post:
            alerts.send_siem_event(payload)
        post.assert_called_once()
    finally:
        for k, v in old.items():
            object.__setattr__(alerts.S, k, v)
