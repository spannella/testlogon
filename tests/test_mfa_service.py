from types import SimpleNamespace
from unittest.mock import Mock

from app.services import mfa


def test_send_email_code_logs_code_in_dev_mode(monkeypatch):
    ses_mock = Mock()
    logger_mock = Mock()
    monkeypatch.setattr(mfa, "S", SimpleNamespace(dev_mode=True, ses_from_email="noreply@example.com"))
    monkeypatch.setattr(mfa, "ses", ses_mock)
    monkeypatch.setattr(mfa, "logger", logger_mock)

    mfa.send_email_code("user@example.com", "Registration", "123456")

    logger_mock.warning.assert_called_once_with(
        "DEV MODE email verification code for %s (%s): %s",
        "user@example.com",
        "Registration",
        "123456",
    )
    ses_mock.send_email.assert_called_once()


def test_send_email_code_prints_code_to_stderr_in_dev_mode(monkeypatch, capsys):
    ses_mock = Mock()
    monkeypatch.setattr(mfa, "S", SimpleNamespace(dev_mode=True, ses_from_email="noreply@example.com"))
    monkeypatch.setattr(mfa, "ses", ses_mock)

    mfa.send_email_code("user@example.com", "Registration", "123456")

    captured = capsys.readouterr()
    assert "DEV MODE email verification code for user@example.com (Registration): 123456" in captured.err
