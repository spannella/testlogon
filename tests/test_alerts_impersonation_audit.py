from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from app.services import alerts


def test_audit_event_includes_impersonation_actor_effective_from_request_state() -> None:
    request = SimpleNamespace(
        headers={"user-agent": "ua"},
        client=SimpleNamespace(host="127.0.0.1"),
        state=SimpleNamespace(actor_sub="admin-1", effective_sub="user-1", impersonation_id="imp_1"),
    )

    captured = {}

    def fake_write_alert(user_sub, *, event, outcome, title, details):
        captured.update(details)
        return {"alert_id": "a1"}

    with patch.object(alerts, "write_alert", side_effect=fake_write_alert), patch.object(
        alerts, "get_profile_identity", return_value={}
    ), patch.object(alerts, "send_push_for_alert"), patch.object(alerts, "send_alert_webhook"), patch.object(
        alerts, "get_alert_prefs", return_value={"emails": [], "sms_numbers": [], "email_event_types": [], "sms_event_types": [], "webhook_urls": [], "webhook_event_types": []}
    ), patch.object(alerts, "can_send_alert_channel", return_value=False), patch.object(alerts, "record_auth_event"):
        alerts.audit_event("filemgr_file_deleted", "admin-1", request, outcome="success", file_id="f1")

    assert captured.get("actor_sub") == "admin-1"
    assert captured.get("effective_sub") == "user-1"
    assert captured.get("impersonation_id") == "imp_1"
    assert captured.get("impersonation") is True
