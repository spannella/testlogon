"""GAP-0324: send_alert_email() must log + record + count SES failures, not swallow.

Before the fix: a SES send exception was swallowed by `except Exception: pass` —
no log, no metric, no record_email_failure call.
After the fix: the exception is logged, EMAIL_FAILED is incremented,
record_email_failure(to_emails, subject, error) is called, and the function
returns None (never raises).

Offline / hermetic: boto3.client is patched so the SES send raises; no real AWS.
"""
from __future__ import annotations

from unittest import mock

from app.core.settings import S
import app.services.alerts as alerts


def _force_real_send_path():
    """Bypass dev-mode early-return and the alerts_email_enabled gate."""
    object.__setattr__(S, "dev_mode", False)
    object.__setattr__(S, "alerts_email_enabled", True)
    object.__setattr__(S, "alerts_from_email", "alerts@example.com")


def test_send_alert_email_failure_is_recorded_and_returns_none():
    orig_dev = S.dev_mode
    orig_enabled = S.alerts_email_enabled
    orig_from = S.alerts_from_email
    try:
        _force_real_send_path()

        # Make the SES client's send_email raise.
        fake_ses = mock.MagicMock()
        fake_ses.send_email.side_effect = RuntimeError("SES rejected: quota exhausted")
        fake_boto3 = mock.MagicMock()
        fake_boto3.client.return_value = fake_ses

        to = ["dest1@example.com", "dest2@example.com"]
        subject = "Critical alert"
        body = "something happened"

        with mock.patch.dict("sys.modules", {"boto3": fake_boto3}), \
                mock.patch.object(alerts, "record_email_failure") as rec, \
                mock.patch.object(alerts, "logger") as log, \
                mock.patch("app.metrics.EMAIL_FAILED") as metric:
            result = alerts.send_alert_email(to, subject, body)

        # Returns None, does not raise.
        assert result is None

        # record_email_failure called with the right args.
        rec.assert_called_once()
        args, kwargs = rec.call_args
        passed = list(args) + list(kwargs.values())
        assert to in passed
        assert subject in passed
        # error string includes the SES exception text
        assert any("quota exhausted" in str(a) for a in passed)

        # logged the exception
        assert log.exception.called

        # metric incremented
        metric.inc.assert_called_once()
    finally:
        object.__setattr__(S, "dev_mode", orig_dev)
        object.__setattr__(S, "alerts_email_enabled", orig_enabled)
        object.__setattr__(S, "alerts_from_email", orig_from)


def test_send_alert_email_dev_mode_does_not_record_failure():
    """Dev-mode early-return path is unchanged: no SES, no record_email_failure."""
    orig_dev = S.dev_mode
    try:
        object.__setattr__(S, "dev_mode", True)
        with mock.patch.object(alerts, "record_email_failure") as rec, \
                mock.patch.object(alerts, "_write_dev_log"):
            result = alerts.send_alert_email(["x@example.com"], "s", "b")
        assert result is None
        rec.assert_not_called()
    finally:
        object.__setattr__(S, "dev_mode", orig_dev)
