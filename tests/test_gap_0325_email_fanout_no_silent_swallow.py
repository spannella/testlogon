"""GAP-0325 regression: the OUTER email-fanout envelope in
``app.services.alerts.audit_event`` must NOT silently swallow exceptions.

Before the fix the email fanout block was wrapped in a bare
``except Exception: pass`` (in addition to the inner swallow inside
``send_alert_email`` that GAP-0324 already fixed). So security-alert emails
(new-device login, MFA changes) could vanish with no trace.

After the fix a failure in the email fanout is LOGGED via
``logger.exception(...)`` and the fanout still proceeds to the SMS / webhook
channels (multi-channel fanout is preserved).

Offline / hermetic: every collaborator (DDB writes, push, webhook, SIEM,
SMS, profile lookup, prefs, rate-limit gate) is patched so no AWS / network.
"""

from unittest.mock import MagicMock, patch

import app.services.alerts as alerts


def _make_prefs():
    # Enable the email + SMS branches for a generic alert_type.
    # alert_type is derived from event_to_type; we patch event_to_type to a
    # fixed value and enable that exact type below.
    return {
        "emails": ["sec@test.local"],
        "email_event_types": ["__test_type__"],
        "sms_numbers": ["+15555550100"],
        "sms_event_types": ["__test_type__"],
        "webhook_urls": [],
        "webhook_event_types": [],
    }


def _common_patches(send_email_mock, send_sms_mock):
    """Context managers that neutralise every external collaborator and force
    the email + SMS branches to be entered."""
    return [
        patch.object(alerts, "event_to_type", return_value="__test_type__"),
        patch.object(alerts, "get_alert_prefs", side_effect=lambda _s: _make_prefs()),
        patch.object(alerts, "can_send_alert_channel", return_value=True),
        patch.object(alerts, "render_ticket_email_template", return_value=None),
        patch.object(alerts, "get_profile_identity", return_value={}),
        patch.object(alerts, "record_auth_event"),
        patch.object(alerts, "send_push_for_alert"),
        patch.object(
            alerts,
            "send_alert_webhook",
            return_value={"enabled": False, "delivered": False},
        ),
        patch.object(
            alerts,
            "send_siem_event",
            return_value={"enabled": False, "delivered": False},
        ),
        patch.object(alerts, "send_alert_webhook_fanout"),
        patch.object(alerts, "write_alert", return_value={"alert_id": "a1"}),
        patch.object(alerts, "send_alert_email", send_email_mock),
        patch.object(alerts, "send_alert_sms", send_sms_mock),
        # keep notification HTML templates off so we hit the plain-text branch
        # (and so an import there can't interfere)
    ]


def test_email_fanout_failure_is_logged_not_swallowed():
    send_email = MagicMock(side_effect=RuntimeError("smtp exploded"))
    send_sms = MagicMock(return_value=[])

    object.__setattr__(alerts.S, "notification_email_templates_enabled", False)

    ctxs = _common_patches(send_email, send_sms)
    with patch.object(alerts, "logger") as log_mock:
        for c in ctxs:
            c.start()
        try:
            # Must NOT raise even though email fanout blows up.
            alerts.audit_event("device_new", "user-123", outcome="info")
        finally:
            for c in reversed(ctxs):
                c.stop()

    # email send was attempted and raised
    assert send_email.called, "email branch was not entered"

    # KEY assertion: the outer email-fanout failure was LOGGED, not silently
    # swallowed. Before the fix logger.exception was never called from here.
    assert log_mock.exception.called, "email fanout failure was not logged"
    logged_msgs = " ".join(str(c.args) for c in log_mock.exception.call_args_list)
    assert "fanout" in logged_msgs.lower()

    # multi-channel fanout preserved: SMS still ran after the email failure
    assert send_sms.called, "SMS fanout did not run after email failure"


def test_successful_email_fanout_does_not_log_exception():
    send_email = MagicMock(return_value=None)
    send_sms = MagicMock(return_value=[])

    object.__setattr__(alerts.S, "notification_email_templates_enabled", False)

    ctxs = _common_patches(send_email, send_sms)
    with patch.object(alerts, "logger") as log_mock:
        for c in ctxs:
            c.start()
        try:
            alerts.audit_event("device_new", "user-123", outcome="info")
        finally:
            for c in reversed(ctxs):
                c.stop()

    assert send_email.called
    assert send_sms.called
    # No fanout exception should be logged on the happy path.
    fanout_logs = [
        c for c in log_mock.exception.call_args_list
        if "fanout" in " ".join(str(a) for a in c.args).lower()
    ]
    assert not fanout_logs, f"unexpected exception log on success: {fanout_logs}"
