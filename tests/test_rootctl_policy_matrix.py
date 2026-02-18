from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.cli import rootctl


@pytest.fixture
def root_config(monkeypatch):
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")


def test_root_recovery_allow_path_emits_audit(capsys, monkeypatch, root_config) -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "root"}}
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users))
    monkeypatch.setattr(rootctl, "check_password_breach", lambda value: 0)
    monkeypatch.setattr(rootctl, "revoke_all_sessions", Mock())
    monkeypatch.setattr(rootctl, "revoke_all_api_keys", Mock())
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(
        [
            "root",
            "reset-password",
            "--actor-sub",
            "root",
            "--reason",
            "incident",
            "--ticket",
            "INC-101",
            "--new-password",
            "StrongerPassphrase!42",
            "--output",
            "json",
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["audit_event"] == "root_password_reset"
    audit.assert_called_once()


@pytest.mark.parametrize(
    ("argv", "expected_event"),
    [
        (
            [
                "user",
                "deactivate",
                "--target-user-sub",
                "u10",
                "--actor-sub",
                "root",
                "--reason",
                "containment",
                "--ticket",
                "INC-201",
                "--confirm",
                "u10",
                "--output",
                "json",
            ],
            "user_deactivated_cli",
        ),
        (
            [
                "admin",
                "grant",
                "--target-user-sub",
                "admin.candidate@example.com",
                "--actor-sub",
                "root",
                "--reason",
                "oncall",
                "--output",
                "json",
            ],
            "admin_role_granted",
        ),
    ],
)
def test_user_admin_allow_matrix_emits_expected_audit(argv, expected_event, capsys, monkeypatch, root_config) -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "admin.candidate@example.com", "role": "user"}}
    account_state = Mock()
    account_state.get_item.return_value = {"Item": {"status": "active"}}
    role_audit = Mock()
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, account_state=account_state, role_audit=role_audit))
    monkeypatch.setattr(rootctl, "revoke_all_sessions", Mock())
    monkeypatch.setattr(rootctl, "revoke_all_api_keys", Mock())
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(argv)
    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["audit_event"] == expected_event
    assert audit.call_args.args[0] == expected_event


@pytest.mark.parametrize(
    ("argv", "expected_rc", "expected_error", "expected_code"),
    [
        (
            [
                "root",
                "reset-password",
                "--actor-sub",
                "not-root",
                "--reason",
                "incident",
                "--ticket",
                "INC-102",
                "--new-password",
                "SafePassword#9",
                "--output",
                "json",
            ],
            3,
            None,
            "role_required",
        ),
        (
            [
                "user",
                "delete",
                "--target-user-sub",
                "u11",
                "--actor-sub",
                "root",
                "--reason",
                "fraud",
                "--ticket",
                "INC-202",
                "--output",
                "json",
            ],
            2,
            "confirm is required for destructive commands",
            None,
        ),
        (
            [
                "admin",
                "grant",
                "--target-user-sub",
                "root",
                "--actor-sub",
                "root",
                "--reason",
                "ops",
                "--output",
                "json",
            ],
            3,
            None,
            "root_immutable",
        ),
    ],
)
def test_privileged_deny_matrix(argv, expected_rc, expected_error, expected_code, capsys, monkeypatch, root_config) -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u11", "role": "user"}}
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, account_state=Mock(), role_audit=Mock()))

    rc = rootctl.main(argv)
    assert rc == expected_rc
    payload = json.loads(capsys.readouterr().err.strip())
    if expected_error is not None:
        assert payload["error"] == expected_error
    if expected_code is not None:
        assert payload["code"] == expected_code


@pytest.mark.parametrize(
    "argv",
    [
        [
            "root",
            "reset-mfa",
            "--actor-sub",
            "root",
            "--reason",
            "drill",
            "--ticket",
            "CHG-1",
            "--dry-run",
            "--output",
            "json",
        ],
        [
            "user",
            "deactivate",
            "--target-user-sub",
            "u12",
            "--actor-sub",
            "root",
            "--reason",
            "drill",
            "--ticket",
            "CHG-2",
            "--confirm",
            "u12",
            "--dry-run",
            "--output",
            "json",
        ],
        [
            "admin",
            "grant",
            "--target-user-sub",
            "candidate@example.com",
            "--actor-sub",
            "root",
            "--reason",
            "drill",
            "--dry-run",
            "--output",
            "json",
        ],
    ],
)
def test_privileged_dry_run_matrix_skips_audit_and_returns_dry_run(argv, capsys, monkeypatch, root_config) -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "candidate@example.com", "role": "user"}}
    account_state = Mock()
    account_state.get_item.return_value = {"Item": {"status": "active"}}
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, account_state=account_state, role_audit=Mock(), totp=Mock(), sms=Mock(), email=Mock(), recovery=Mock()))
    monkeypatch.setattr(rootctl, "revoke_all_sessions", Mock())
    monkeypatch.setattr(rootctl, "revoke_all_api_keys", Mock())
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(argv)
    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["dry_run"] is True
    assert "message" in payload
    audit.assert_not_called()
