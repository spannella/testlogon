from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app.services import signature_packet_reminders as reminders


def test_process_reminders_sends_for_due_pending_signer() -> None:
    now = datetime(2026, 1, 8, tzinfo=timezone.utc)
    sent_at = (now - timedelta(hours=80)).isoformat()
    with (
        patch.object(reminders, "require_signature_pdf_enabled", return_value=None),
        patch.object(reminders, "_now", return_value=now),
        patch.object(reminders.T.signature_packet_signers._t, "scan", return_value={"Items": [{"packet_id": "sp_1", "signer_id": "user-2", "status": "pending", "reminder_last_step": 0}]}),
        patch.object(reminders, "get_packet", return_value={"packet_id": "sp_1", "status": "sent", "sent_at": sent_at, "owner_user_id": "owner-1", "source_name": "nda.pdf"}),
        patch.object(reminders, "_claim_reminder_step", return_value=True) as claim_mock,
        patch.object(reminders, "get_profile_identity", side_effect=[{"display_name": "Signer", "email": "s@example.com"}, {"display_name": "Owner", "email": "o@example.com"}]),
        patch.object(reminders, "send_alert_email") as email_mock,
        patch.object(reminders, "append_packet_event") as event_mock,
        patch.object(reminders, "record_signature_packet_reminder_email") as metric_mock,
    ):
        out = reminders.process_signature_packet_reminders(limit=50)

    assert out["sent"] == 1
    claim_mock.assert_called_once()
    email_mock.assert_called_once()
    assert event_mock.call_args.kwargs["event_type"] == "signer_reminder_sent"
    metric_mock.assert_called_once_with(outcome="sent", reason="none")


def test_process_reminders_skips_non_actionable_status() -> None:
    now = datetime(2026, 1, 8, tzinfo=timezone.utc)
    with (
        patch.object(reminders, "require_signature_pdf_enabled", return_value=None),
        patch.object(reminders, "_now", return_value=now),
        patch.object(reminders.T.signature_packet_signers._t, "scan", return_value={"Items": [{"packet_id": "sp_1", "signer_id": "user-2", "status": "pending"}]}),
        patch.object(reminders, "get_packet", return_value={"packet_id": "sp_1", "status": "completed", "sent_at": (now - timedelta(days=2)).isoformat()}),
        patch.object(reminders, "send_alert_email") as email_mock,
    ):
        out = reminders.process_signature_packet_reminders(limit=10)

    assert out["sent"] == 0
    assert out["skipped"] == 1
    email_mock.assert_not_called()


def test_process_reminders_skips_when_signer_missing_email() -> None:
    now = datetime(2026, 1, 8, tzinfo=timezone.utc)
    with (
        patch.object(reminders, "require_signature_pdf_enabled", return_value=None),
        patch.object(reminders, "_now", return_value=now),
        patch.object(reminders.T.signature_packet_signers._t, "scan", return_value={"Items": [{"packet_id": "sp_1", "signer_id": "user-2", "status": "pending"}]}),
        patch.object(reminders, "get_packet", return_value={"packet_id": "sp_1", "status": "sent", "sent_at": (now - timedelta(days=4)).isoformat(), "owner_user_id": "owner-1"}),
        patch.object(reminders, "_claim_reminder_step", return_value=True),
        patch.object(reminders, "get_profile_identity", side_effect=[{"display_name": "Signer", "email": None}, {"display_name": "Owner", "email": "o@example.com"}]),
        patch.object(reminders, "append_packet_event") as event_mock,
        patch.object(reminders, "record_signature_packet_reminder_email") as metric_mock,
        patch.object(reminders, "send_alert_email") as email_mock,
    ):
        out = reminders.process_signature_packet_reminders(limit=10)

    assert out["sent"] == 0
    assert out["skipped"] == 1
    assert event_mock.call_args.kwargs["event_type"] == "signer_reminder_skipped"
    metric_mock.assert_called_once_with(outcome="skipped", reason="missing_email")
    email_mock.assert_not_called()


def test_process_reminders_idempotent_when_step_already_claimed() -> None:
    now = datetime(2026, 1, 8, tzinfo=timezone.utc)
    with (
        patch.object(reminders, "require_signature_pdf_enabled", return_value=None),
        patch.object(reminders, "_now", return_value=now),
        patch.object(reminders.T.signature_packet_signers._t, "scan", return_value={"Items": [{"packet_id": "sp_1", "signer_id": "user-2", "status": "pending", "reminder_last_step": 0}]}),
        patch.object(reminders, "get_packet", return_value={"packet_id": "sp_1", "status": "sent", "sent_at": (now - timedelta(days=4)).isoformat(), "owner_user_id": "owner-1"}),
        patch.object(reminders, "_claim_reminder_step", return_value=False),
        patch.object(reminders, "send_alert_email") as email_mock,
    ):
        out = reminders.process_signature_packet_reminders(limit=10)

    assert out["sent"] == 0
    assert out["skipped"] == 1
    email_mock.assert_not_called()
