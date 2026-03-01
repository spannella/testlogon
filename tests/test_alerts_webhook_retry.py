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


def test_ticket_event_types_are_first_class_alert_types() -> None:
    for event_type in (
        "ticket_created",
        "ticket_assigned",
        "ticket_replied",
        "ticket_status_changed",
        "ticket_reopened",
    ):
        assert event_type in alerts.ALERT_EVENT_TYPES


def test_event_to_type_maps_ticket_events_without_fallback() -> None:
    assert alerts.event_to_type("ticket_created", "success") == "ticket_created"
    assert alerts.event_to_type("ticket_assigned", "success") == "ticket_assigned"
    assert alerts.event_to_type("ticket_replied", "success") == "ticket_replied"
    assert alerts.event_to_type("ticket_status_changed", "success") == "ticket_status_changed"
    assert alerts.event_to_type("ticket_reopened", "success") == "ticket_reopened"


def test_render_ticket_email_template_includes_required_fields() -> None:
    subj, body = alerts.render_ticket_email_template(
        alert_type="ticket_assigned",
        outcome="success",
        payload={
            "ticket_id": "tkt_123",
            "ticket_subject": "Login issue",
            "actor_sub": "admin-1",
            "assignee_admin_sub": "admin-2",
        },
    )
    assert "tkt_123" in subj
    assert "Ticket ID: tkt_123" in body
    assert "Subject: Login issue" in body
    assert "Actor: admin-1" in body
    assert "Assignee: admin-2" in body
    assert "/tickets/tkt_123" in body


def test_audit_event_uses_ticket_email_template_for_ticket_alerts() -> None:
    sent = {}

    def fake_send_alert_email(to_emails, subject, body_text):
        sent["to"] = to_emails
        sent["subject"] = subject
        sent["body"] = body_text

    prefs = {
        "emails": ["user@example.test"],
        "sms_numbers": [],
        "email_event_types": ["ticket_replied"],
        "sms_event_types": [],
        "webhook_urls": [],
        "webhook_event_types": [],
    }
    with patch.object(alerts, "write_alert", return_value={"alert_id": "a1"}), patch.object(
        alerts, "get_profile_identity", return_value={}
    ), patch.object(alerts, "send_push_for_alert"), patch.object(
        alerts, "send_alert_webhook", return_value={"enabled": False, "delivered": False, "reason": "disabled"}
    ), patch.object(
        alerts, "send_siem_event", return_value={"enabled": False, "delivered": False, "reason": "disabled"}
    ), patch.object(
        alerts, "get_alert_prefs", return_value=prefs
    ), patch.object(
        alerts, "can_send_alert_channel", return_value=True
    ), patch.object(
        alerts, "send_alert_email", side_effect=fake_send_alert_email
    ), patch.object(alerts, "record_auth_event"):
        alerts.audit_event(
            "ticket_replied",
            "user-1",
            None,
            outcome="success",
            ticket_id="tkt_123",
            ticket_subject="Reset password",
            actor_sub="admin-1",
        )

    assert sent["to"] == ["user@example.test"]
    assert "Ticket #tkt_123" in sent["subject"]
    assert "Subject: Reset password" in sent["body"]
    assert "Actor: admin-1" in sent["body"]
