from __future__ import annotations

from unittest.mock import Mock, patch

from app.services import alerts


def test_post_webhook_with_retry_retries_and_succeeds() -> None:
    ok_response = Mock(status_code=200)
    with patch.object(alerts.requests, "post", side_effect=[Exception("boom"), Exception("boom2"), ok_response]) as post, patch.object(
        alerts.time, "sleep"
    ) as sleep:
        ok, err = alerts._post_webhook_with_retry("https://example.test/hook", json_payload={"a": 1})

    assert ok is True
    assert err == ""
    assert post.call_count == 3
    assert sleep.call_count == 2


def test_post_webhook_with_retry_logs_after_exhaustion() -> None:
    with patch.object(alerts.requests, "post", side_effect=Exception("fail")) as post, patch.object(
        alerts.time, "sleep"
    ) as sleep, patch.object(alerts.logger, "warning") as warning:
        ok, err = alerts._post_webhook_with_retry("https://example.test/hook", json_payload={"a": 1})

    assert ok is False
    assert "fail" in err
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


def test_audit_event_cli_payload_has_explicit_rootctl_event_names() -> None:
    captured = {}

    def fake_write_alert(user_sub, *, event, outcome, title, details):
        captured.update(details)
        return {"alert_id": "a1"}

    with patch.object(alerts, "write_alert", side_effect=fake_write_alert), patch.object(
        alerts, "get_profile_identity", return_value={}
    ), patch.object(alerts, "send_push_for_alert"), patch.object(alerts, "send_alert_webhook", return_value={"enabled": False, "delivered": False, "reason": "disabled"}), patch.object(
        alerts, "send_siem_event", return_value={"enabled": False, "delivered": False, "reason": "disabled"}
    ), patch.object(alerts, "get_alert_prefs", return_value={"emails": [], "sms_numbers": [], "email_event_types": [], "sms_event_types": [], "webhook_urls": [], "webhook_event_types": []}), patch.object(
        alerts, "can_send_alert_channel", return_value=False
    ), patch.object(alerts, "record_auth_event"):
        alerts.audit_event("root_password_reset", "root", None, outcome="success", cli=True)

    assert captured["event_source"] == "rootctl"
    assert captured["event_channel"] == "cli"
    assert captured["cli_event_name"] == "rootctl.root_password_reset"
    assert captured["root_cli_event_name"] == "rootctl.root.root_password_reset"


def test_audit_event_records_delivery_failure_telemetry() -> None:
    writes = []

    def fake_write_alert(user_sub, *, event, outcome, title, details):
        writes.append({"event": event, "details": details})
        return {"alert_id": "a1"}

    with patch.object(alerts, "write_alert", side_effect=fake_write_alert), patch.object(
        alerts, "get_profile_identity", return_value={}
    ), patch.object(alerts, "send_push_for_alert"), patch.object(
        alerts, "send_alert_webhook", return_value={"enabled": True, "delivered": False, "reason": "delivery_failed", "target": "alerts_webhook", "url": "https://alerts.test", "error": "status=500"}
    ), patch.object(
        alerts, "send_siem_event", return_value={"enabled": True, "delivered": False, "reason": "delivery_failed", "target": "siem_webhook", "url": "https://siem.test", "error": "status=503"}
    ), patch.object(alerts, "get_alert_prefs", return_value={"emails": [], "sms_numbers": [], "email_event_types": [], "sms_event_types": [], "webhook_urls": [], "webhook_event_types": []}), patch.object(
        alerts, "can_send_alert_channel", return_value=False
    ), patch.object(alerts, "record_auth_event") as record, patch.object(alerts.logger, "warning") as warning:
        alerts.audit_event("admin_role_granted", "root", None, outcome="success", cli=True, correlation_id="corr-99")

    assert len(writes) == 2
    assert writes[1]["event"] == "alerts_delivery_failure"
    failures = writes[1]["details"]["delivery_failures"]
    assert len(failures) == 2
    assert failures[0]["target"] == "alerts_webhook"
    assert failures[1]["target"] == "siem_webhook"
    record.assert_any_call("alerts_delivery_failure")
    warning.assert_called_once()
