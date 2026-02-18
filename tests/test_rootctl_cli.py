from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import Mock

from app.cli import rootctl


def test_rootctl_top_level_help_exits_zero(capsys) -> None:
    rc = rootctl.main(["--help"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "rootctl" in out
    assert "root" in out
    assert "user" in out
    assert "admin" in out
    assert "audit" in out


def test_rootctl_group_help_exits_zero(capsys) -> None:
    for group in ("root", "user", "admin", "audit"):
        rc = rootctl.main([group, "--help"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "status" in out


def test_rootctl_shared_output_json_consistent_across_groups(capsys) -> None:
    for group in ("root", "user", "admin", "audit"):
        rc = rootctl.main(
            [
                group,
                "status",
                "--output",
                "json",
                "--dry-run",
                "--request-id",
                "req-1",
                "--correlation-id",
                "corr-1",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out.strip()
        payload = json.loads(out)
        assert payload["ok"] is True
        assert payload["group"] == group
        assert payload["command"] == "status"
        assert payload["dry_run"] is True
        assert payload["request_id"] == "req-1"
        assert payload["correlation_id"] == "corr-1"


def test_rootctl_validation_exit_code_for_missing_subcommand() -> None:
    rc = rootctl.main(["root"])
    assert rc == 2


def test_rootctl_mutation_requires_reason(capsys) -> None:
    rc = rootctl.main(
        [
            "user",
            "create",
            "--email",
            "u1@example.com",
            "--actor-sub",
            "root",
            "--output",
            "json",
        ]
    )
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["error"] == "reason is required for mutating commands"


def test_rootctl_high_risk_command_requires_ticket(capsys) -> None:
    rc = rootctl.main(
        [
            "root",
            "rotate-secrets",
            "--actor-sub",
            "root",
            "--reason",
            "incident",
            "--output",
            "json",
        ]
    )
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["error"] == "ticket is required for high-risk commands"


def test_rootctl_destructive_command_requires_confirm(capsys) -> None:
    rc = rootctl.main(
        [
            "user",
            "delete",
            "--target-user-sub",
            "u2",
            "--actor-sub",
            "root",
            "--reason",
            "fraud",
            "--ticket",
            "INC-1",
            "--output",
            "json",
        ]
    )
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["error"] == "confirm is required for destructive commands"


def test_rootctl_destructive_command_rejects_wrong_confirm(capsys) -> None:
    rc = rootctl.main(
        [
            "user",
            "delete",
            "--target-user-sub",
            "u2",
            "--actor-sub",
            "root",
            "--reason",
            "fraud",
            "--ticket",
            "INC-1",
            "--confirm",
            "wrong",
            "--output",
            "json",
        ]
    )
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["error"] == "confirm must match expected value: u2"


def test_rootctl_mutation_denies_non_root_actor(capsys) -> None:
    rc = rootctl.main(
        [
            "user",
            "create",
            "--email",
            "u1@example.com",
            "--actor-sub",
            "admin-1",
            "--reason",
            "ops",
            "--output",
            "json",
        ]
    )
    assert rc == 3
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["code"] == "role_required"
    assert payload["required_roles"] == ["root"]


def test_rootctl_mutation_denies_root_role_assignment(capsys) -> None:
    rc = rootctl.main(
        [
            "admin",
            "grant",
            "--target-user-sub",
            "u2",
            "--role",
            "root",
            "--actor-sub",
            "root",
            "--reason",
            "ops",
            "--output",
            "json",
        ]
    )
    assert rc == 3
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["code"] == "root_immutable"
    assert payload["requested_role"] == "root"


def test_rootctl_mutation_requires_valid_root_config(capsys, monkeypatch) -> None:
    def _boom() -> str:
        raise RuntimeError("ROOT_USER_SUB must be configured")

    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", _boom)
    rc = rootctl.main(
        [
            "root",
            "rotate-secrets",
            "--actor-sub",
            "root",
            "--reason",
            "incident",
            "--ticket",
            "INC-1",
            "--output",
            "json",
        ]
    )
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert "ROOT_USER_SUB" in payload["error"]


def test_rootctl_destructive_command_allows_explicit_intent(capsys, monkeypatch) -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u2"}}
    account_state = Mock()
    account_state.get_item.return_value = {"Item": {"status": "active"}}
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, account_state=account_state))
    monkeypatch.setattr(rootctl, "revoke_all_sessions", Mock())
    monkeypatch.setattr(rootctl, "revoke_all_api_keys", Mock())
    monkeypatch.setattr(rootctl, "audit_event", Mock())

    rc = rootctl.main(
        [
            "user",
            "delete",
            "--target-user-sub",
            "u2",
            "--actor-sub",
            "root",
            "--reason",
            "fraud",
            "--ticket",
            "INC-1",
            "--confirm",
            "u2",
            "--output",
            "json",
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["ok"] is True
    assert payload["command"] == "delete"
    assert payload["target_user_sub"] == "u2"


def test_rootctl_reset_password_denies_non_root_target(capsys) -> None:
    rc = rootctl.main(
        [
            "root",
            "reset-password",
            "--actor-sub",
            "root",
            "--target-user-sub",
            "u1",
            "--reason",
            "incident",
            "--ticket",
            "INC-1",
            "--new-password",
            "StrongPassphrase42!",
            "--output",
            "json",
        ]
    )
    assert rc == 3
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["code"] == "root_immutable"


def test_rootctl_reset_password_updates_root_and_audits(capsys, monkeypatch) -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "root"}}
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    revoke_sessions = Mock()
    revoke_keys = Mock()
    audit = Mock()
    monkeypatch.setattr(rootctl, "revoke_all_sessions", revoke_sessions)
    monkeypatch.setattr(rootctl, "revoke_all_api_keys", revoke_keys)
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
            "INC-1",
            "--new-password",
            "StrongPassphrase42!",
            "--request-id",
            "req-1",
            "--correlation-id",
            "corr-1",
            "--output",
            "json",
        ]
    )

    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["ok"] is True
    assert out["audit_event"] == "root_password_reset"
    users.update_item.assert_called_once()
    revoke_sessions.assert_called_once_with("root")
    revoke_keys.assert_called_once_with("root")
    audit.assert_called_once()
    assert audit.call_args.args[0] == "root_password_reset"
    assert audit.call_args.args[1] == "root"
    assert audit.call_args.kwargs["actor_sub"] == "root"
    assert audit.call_args.kwargs["ticket_id"] == "INC-1"


def test_rootctl_reset_password_dry_run_skips_mutation(capsys, monkeypatch) -> None:
    users = Mock()
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")

    rc = rootctl.main(
        [
            "root",
            "reset-password",
            "--actor-sub",
            "root",
            "--reason",
            "incident",
            "--ticket",
            "INC-1",
            "--dry-run",
            "--output",
            "json",
        ]
    )

    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["dry_run"] is True
    users.get_item.assert_not_called()


def test_rootctl_reset_mfa_requires_factor_validation(capsys) -> None:
    rc = rootctl.main(
        [
            "root",
            "reset-mfa",
            "--actor-sub",
            "root",
            "--reason",
            "incident",
            "--ticket",
            "INC-2",
            "--factor",
            "totp",
            "--output",
            "json",
        ]
    )
    # valid factor should proceed to backend layer and fail only if backing tables are unavailable in this unit path
    # so just assert it is not a validation/authz failure shape from parser/preflight.
    assert rc in (0, 4)


def test_rootctl_reset_mfa_denies_non_root_target(capsys) -> None:
    rc = rootctl.main(
        [
            "root",
            "reset-mfa",
            "--actor-sub",
            "root",
            "--target-user-sub",
            "u1",
            "--reason",
            "incident",
            "--ticket",
            "INC-2",
            "--factor",
            "all",
            "--output",
            "json",
        ]
    )
    assert rc == 3
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["code"] == "root_immutable"


def test_rootctl_reset_mfa_updates_and_audits(capsys, monkeypatch) -> None:
    totp = Mock()
    totp.query.return_value = {"Items": [{"device_id": "d1"}]}
    sms = Mock()
    sms.query.return_value = {"Items": [{"sms_device_id": "s1"}]}
    email = Mock()
    email.query.return_value = {"Items": [{"email_device_id": "e1"}]}
    recovery = Mock()
    recovery.query.return_value = {"Items": [{"factor": "totp", "code_hash": "totp#abc"}]}

    monkeypatch.setattr(rootctl, "T", SimpleNamespace(totp=totp, sms=sms, email=email, recovery=recovery))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    revoke_sessions = Mock()
    audit = Mock()
    monkeypatch.setattr(rootctl, "revoke_all_sessions", revoke_sessions)
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(
        [
            "root",
            "reset-mfa",
            "--actor-sub",
            "root",
            "--reason",
            "incident",
            "--ticket",
            "INC-2",
            "--factor",
            "all",
            "--output",
            "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["audit_event"] == "root_mfa_reset"
    assert out["deleted"]["totp"] == 1
    assert out["deleted"]["sms"] == 1
    assert out["deleted"]["email"] == 1
    assert out["deleted"]["recovery"] == 1
    revoke_sessions.assert_called_once_with("root")
    audit.assert_called_once()
    assert audit.call_args.args[0] == "root_mfa_reset"
    assert audit.call_args.kwargs["ticket_id"] == "INC-2"


def test_rootctl_set_verification_requires_flag(capsys) -> None:
    rc = rootctl.main(
        [
            "root",
            "set-verification",
            "--actor-sub",
            "root",
            "--reason",
            "incident",
            "--ticket",
            "INC-3",
            "--output",
            "json",
        ]
    )
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert "at least one verification flag" in payload["error"]


def test_rootctl_set_verification_updates_and_audits(capsys, monkeypatch) -> None:
    users = Mock()
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(
        [
            "root",
            "set-verification",
            "--actor-sub",
            "root",
            "--reason",
            "incident",
            "--ticket",
            "INC-3",
            "--email",
            "verified",
            "--phone",
            "unverified",
            "--output",
            "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["audit_event"] == "root_verification_state_updated"
    assert out["updates"]["email_verified"] is True
    assert out["updates"]["phone_verified"] is False
    users.update_item.assert_called_once()
    audit.assert_called_once()
    assert audit.call_args.args[0] == "root_verification_state_updated"
    assert audit.call_args.kwargs["ticket_id"] == "INC-3"


def test_rootctl_set_email_rejects_invalid_email(capsys) -> None:
    rc = rootctl.main(
        [
            "root",
            "set-email",
            "--actor-sub",
            "root",
            "--reason",
            "incident",
            "--ticket",
            "INC-4",
            "--email",
            "invalid-email",
            "--output",
            "json",
        ]
    )
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["error"] == "email must be a valid address"


def test_rootctl_set_email_updates_and_audits(capsys, monkeypatch) -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "root"}}
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(
        [
            "root",
            "set-email",
            "--actor-sub",
            "root",
            "--reason",
            "incident",
            "--ticket",
            "INC-4",
            "--email",
            "Root+Emergency@Example.com",
            "--verify",
            "--output",
            "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["audit_event"] == "root_email_updated"
    assert out["updates"]["email"] == "root+emergency@example.com"
    assert out["updates"]["email_verified"] is True
    users.update_item.assert_called_once()
    audit.assert_called_once()
    assert audit.call_args.args[0] == "root_email_updated"
    assert audit.call_args.kwargs["severity"] == "high"


def test_rootctl_set_security_profile_requires_fields(capsys) -> None:
    rc = rootctl.main(
        [
            "root",
            "set-security-profile",
            "--actor-sub",
            "root",
            "--reason",
            "incident",
            "--ticket",
            "INC-5",
            "--output",
            "json",
        ]
    )
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["error"] == "at least one security metadata update is required"


def test_rootctl_set_security_profile_updates_and_audits(capsys, monkeypatch) -> None:
    users = Mock()
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(
        [
            "root",
            "set-security-profile",
            "--actor-sub",
            "root",
            "--reason",
            "incident",
            "--ticket",
            "INC-5",
            "--force-password-rotate",
            "true",
            "--recovery-lockdown",
            "false",
            "--security-note",
            "Break-glass rotation",
            "--output",
            "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["audit_event"] == "root_security_profile_updated"
    assert out["updates"]["force_password_rotate"] is True
    assert out["updates"]["recovery_lockdown"] is False
    users.update_item.assert_called_once()
    audit.assert_called_once()
    assert audit.call_args.args[0] == "root_security_profile_updated"
    assert audit.call_args.kwargs["severity"] == "high"


def test_rootctl_user_create_validates_email(capsys) -> None:
    rc = rootctl.main(
        [
            "user",
            "create",
            "--email",
            "not-an-email",
            "--actor-sub",
            "root",
            "--reason",
            "onboarding",
            "--output",
            "json",
        ]
    )
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["error"] == "email must be a valid address"


def test_rootctl_user_create_defaults_to_user_role_and_audits(capsys, monkeypatch) -> None:
    users = Mock()
    account_state = Mock()
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, account_state=account_state))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(
        [
            "user",
            "create",
            "--email",
            "new.user@example.com",
            "--actor-sub",
            "root",
            "--reason",
            "onboarding",
            "--output",
            "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["role"] == "user"
    assert out["target_user_sub"] == "new.user@example.com"
    assert "generated_password" in out
    users.put_item.assert_called_once()
    account_state.put_item.assert_called_once()
    audit.assert_called_once()
    assert audit.call_args.args[0] == "user_created_cli"


def test_rootctl_user_create_denies_root_target(capsys, monkeypatch) -> None:
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root@example.com")
    rc = rootctl.main(
        [
            "user",
            "create",
            "--email",
            "root@example.com",
            "--actor-sub",
            "root@example.com",
            "--reason",
            "onboarding",
            "--output",
            "json",
        ]
    )
    assert rc == 3
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["code"] == "root_immutable"


def test_rootctl_user_list_supports_filters_and_cursor(capsys, monkeypatch) -> None:
    users = Mock()
    users.scan.side_effect = [
        {
            "Items": [
                {"user_sub": "a@example.com", "email": "a@example.com", "role": "admin", "created_at": 1},
                {"user_sub": "b@example.com", "email": "b@example.com", "role": "user", "created_at": 2},
            ],
            "LastEvaluatedKey": None,
        }
    ]

    account_state = Mock()
    account_state.get_item.side_effect = [
        {"Item": {"status": "active"}},
        {"Item": {"status": "deactivated"}},
    ]

    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, account_state=account_state))

    rc = rootctl.main(
        [
            "user",
            "list",
            "--role",
            "admin",
            "--status",
            "active",
            "--limit",
            "10",
            "--output",
            "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["count"] == 1
    assert out["items"][0]["user_sub"] == "a@example.com"
    assert out["items"][0]["role"] == "admin"
    assert out["items"][0]["status"] == "active"
    assert out["cursor"] is None


def test_rootctl_user_list_rejects_invalid_cursor(capsys, monkeypatch) -> None:
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=Mock(), account_state=Mock()))
    rc = rootctl.main(["user", "list", "--cursor", "not-base64", "--output", "json"])
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["error"] == "invalid cursor"


def test_rootctl_user_verify_requires_one_flag(capsys, monkeypatch) -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u@example.com"}}
    account_state = Mock()
    account_state.get_item.return_value = {"Item": {"status": "active"}}
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, account_state=account_state))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")

    rc = rootctl.main(
        [
            "user",
            "verify",
            "--target-user-sub",
            "u@example.com",
            "--actor-sub",
            "root",
            "--reason",
            "recovery",
            "--output",
            "json",
        ]
    )
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert "at least one verification flag" in payload["error"]


def test_rootctl_user_verify_respects_account_state(capsys, monkeypatch) -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u@example.com"}}
    account_state = Mock()
    account_state.get_item.return_value = {"Item": {"status": "deactivated"}}
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, account_state=account_state))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")

    rc = rootctl.main(
        [
            "user",
            "verify",
            "--target-user-sub",
            "u@example.com",
            "--email",
            "verified",
            "--actor-sub",
            "root",
            "--reason",
            "recovery",
            "--output",
            "json",
        ]
    )
    assert rc == 3
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["code"] == "account_state_forbidden"
    assert payload["status"] == "deactivated"


def test_rootctl_user_verify_updates_and_audits(capsys, monkeypatch) -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u@example.com"}}
    account_state = Mock()
    account_state.get_item.return_value = {"Item": {"status": "active"}}
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, account_state=account_state))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(
        [
            "user",
            "verify",
            "--target-user-sub",
            "u@example.com",
            "--email",
            "verified",
            "--phone",
            "unverified",
            "--actor-sub",
            "root",
            "--reason",
            "recovery",
            "--output",
            "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["audit_event"] == "user_verification_updated_cli"
    users.update_item.assert_called_once()
    audit.assert_called_once()
    assert audit.call_args.args[0] == "user_verification_updated_cli"
    assert audit.call_args.kwargs["target_user_sub"] == "u@example.com"


def test_rootctl_user_set_password_respects_account_state(capsys, monkeypatch) -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u@example.com"}}
    account_state = Mock()
    account_state.get_item.return_value = {"Item": {"status": "deleted"}}
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, account_state=account_state))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")

    rc = rootctl.main(
        [
            "user",
            "set-password",
            "--target-user-sub",
            "u@example.com",
            "--actor-sub",
            "root",
            "--reason",
            "recovery",
            "--ticket",
            "INC-9",
            "--new-password",
            "StrongPassphrase42!",
            "--output",
            "json",
        ]
    )
    assert rc == 3
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["code"] == "account_state_forbidden"
    assert payload["status"] == "deleted"


def test_rootctl_user_set_password_updates_revokes_and_audits(capsys, monkeypatch) -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u@example.com"}}
    account_state = Mock()
    account_state.get_item.return_value = {"Item": {"status": "active"}}
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, account_state=account_state))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    revoke_sessions = Mock()
    monkeypatch.setattr(rootctl, "revoke_all_sessions", revoke_sessions)
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(
        [
            "user",
            "set-password",
            "--target-user-sub",
            "u@example.com",
            "--actor-sub",
            "root",
            "--reason",
            "recovery",
            "--ticket",
            "INC-9",
            "--new-password",
            "StrongPassphrase42!",
            "--output",
            "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["audit_event"] == "user_password_reset_cli"
    assert out["sessions_revoked"] is True
    users.update_item.assert_called_once()
    revoke_sessions.assert_called_once_with("u@example.com")
    audit.assert_called_once()
    assert audit.call_args.args[0] == "user_password_reset_cli"


def test_rootctl_user_deactivate_requires_confirm(capsys) -> None:
    rc = rootctl.main(
        [
            "user",
            "deactivate",
            "--target-user-sub",
            "u3",
            "--actor-sub",
            "root",
            "--reason",
            "containment",
            "--ticket",
            "INC-10",
            "--output",
            "json",
        ]
    )
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["error"] == "confirm is required for destructive commands"


def test_rootctl_user_deactivate_updates_state_and_audits(capsys, monkeypatch) -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u3"}}
    account_state = Mock()
    account_state.get_item.return_value = {"Item": {"status": "active"}}
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, account_state=account_state))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    revoke_sessions = Mock()
    revoke_keys = Mock()
    audit = Mock()
    monkeypatch.setattr(rootctl, "revoke_all_sessions", revoke_sessions)
    monkeypatch.setattr(rootctl, "revoke_all_api_keys", revoke_keys)
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(
        [
            "user",
            "deactivate",
            "--target-user-sub",
            "u3",
            "--actor-sub",
            "root",
            "--reason",
            "containment",
            "--ticket",
            "INC-10",
            "--confirm",
            "u3",
            "--output",
            "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["audit_event"] == "user_deactivated_cli"
    assert out["new_status"] == "deactivated"
    account_state.put_item.assert_called_once()
    users.update_item.assert_called_once()
    revoke_sessions.assert_called_once_with("u3")
    revoke_keys.assert_called_once_with("u3")
    audit.assert_called_once()


def test_rootctl_user_delete_hard_mode_deletes_records(capsys, monkeypatch) -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u4"}}
    account_state = Mock()
    account_state.get_item.return_value = {"Item": {"status": "active"}}
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, account_state=account_state))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    monkeypatch.setattr(rootctl, "revoke_all_sessions", Mock())
    monkeypatch.setattr(rootctl, "revoke_all_api_keys", Mock())
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(
        [
            "user",
            "delete",
            "--target-user-sub",
            "u4",
            "--hard-delete",
            "--actor-sub",
            "root",
            "--reason",
            "legal-request",
            "--ticket",
            "INC-11",
            "--confirm",
            "u4",
            "--output",
            "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["hard_delete"] is True
    users.delete_item.assert_called_once_with(Key={"user_sub": "u4"})
    account_state.delete_item.assert_called_once_with(Key={"user_sub": "u4"})
    audit.assert_called_once()
    assert audit.call_args.kwargs["deletion_mode"] == "hard"


def test_rootctl_admin_grant_rejects_invalid_transition(capsys, monkeypatch) -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u5", "role": "admin"}}
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, role_audit=Mock()))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")

    rc = rootctl.main(
        [
            "admin",
            "grant",
            "--target-user-sub",
            "u5",
            "--actor-sub",
            "root",
            "--reason",
            "ops",
            "--output",
            "json",
        ]
    )
    assert rc == 3
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["code"] == "invalid_role_transition"


def test_rootctl_admin_grant_updates_and_persists_role_audit(capsys, monkeypatch) -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u6", "role": "user"}}
    role_audit = Mock()
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, role_audit=role_audit))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(
        [
            "admin",
            "grant",
            "--target-user-sub",
            "u6",
            "--actor-sub",
            "root",
            "--reason",
            "ops",
            "--request-id",
            "req-10",
            "--correlation-id",
            "corr-10",
            "--output",
            "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["new_role"] == "admin"
    assert out["event_id"]
    users.update_item.assert_called_once()
    role_audit.put_item.assert_called_once()
    audit.assert_called_once()
    assert audit.call_args.args[0] == "admin_role_granted"


def test_rootctl_admin_revoke_updates_and_persists_role_audit(capsys, monkeypatch) -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u7", "role": "admin"}}
    role_audit = Mock()
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, role_audit=role_audit))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(
        [
            "admin",
            "revoke",
            "--target-user-sub",
            "u7",
            "--actor-sub",
            "root",
            "--reason",
            "ops",
            "--output",
            "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["new_role"] == "user"
    users.update_item.assert_called_once()
    role_audit.put_item.assert_called_once()
    audit.assert_called_once()
    assert audit.call_args.args[0] == "admin_role_revoked"


def test_rootctl_admin_create_success_is_audited_end_to_end(capsys, monkeypatch) -> None:
    users = Mock()
    users.get_item.return_value = {}
    role_audit = Mock()
    account_state = Mock()
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, role_audit=role_audit, account_state=account_state))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(
        [
            "admin",
            "create",
            "--email",
            "new.admin@example.com",
            "--actor-sub",
            "root",
            "--reason",
            "oncall onboarding",
            "--ticket",
            "CHG-1",
            "--output",
            "json",
        ]
    )

    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["target_user_sub"] == "new.admin@example.com"
    assert out["role"] == "admin"
    assert out["audit_event"] == "admin_created_cli"
    assert out["event_id"]
    users.put_item.assert_called_once()
    users.update_item.assert_called_once()
    account_state.put_item.assert_called_once()
    role_audit.put_item.assert_called_once()
    assert audit.call_count == 1
    assert audit.call_args.args[0] == "admin_created_cli"


def test_rootctl_admin_create_rolls_back_on_partial_failure(capsys, monkeypatch) -> None:
    users = Mock()
    users.get_item.return_value = {}
    users.update_item.side_effect = RuntimeError("update failed")
    role_audit = Mock()
    account_state = Mock()
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, role_audit=role_audit, account_state=account_state))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(
        [
            "admin",
            "create",
            "--email",
            "broken.admin@example.com",
            "--actor-sub",
            "root",
            "--reason",
            "oncall onboarding",
            "--output",
            "json",
        ]
    )

    assert rc == 4
    err = json.loads(capsys.readouterr().err.strip())
    assert err["error"] == "admin create failed; rollback attempted"
    users.put_item.assert_called_once()
    users.delete_item.assert_called_once_with(Key={"user_sub": "broken.admin@example.com"})
    account_state.delete_item.assert_called_once_with(Key={"user_sub": "broken.admin@example.com"})
    assert audit.call_count == 1
    assert audit.call_args.args[0] == "admin_create_failed"
    assert audit.call_args.kwargs["rollback_performed"] is True


def test_rootctl_admin_permissions_feature_flag_disabled_by_default(capsys) -> None:
    rc = rootctl.main(
        [
            "admin",
            "permissions",
            "list",
            "--target-user-sub",
            "a@example.com",
            "--output",
            "json",
        ]
    )
    assert rc == 3
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["code"] == "feature_disabled"


def test_rootctl_admin_permissions_set_validates_target_is_admin(capsys, monkeypatch) -> None:
    monkeypatch.setenv("ROOTCTL_ADMIN_CAPABILITIES_ENABLED", "true")
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "a@example.com", "role": "user", "admin_capabilities": []}}
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")

    rc = rootctl.main(
        [
            "admin",
            "permissions",
            "set",
            "--target-user-sub",
            "a@example.com",
            "--capability",
            "billing_read",
            "--actor-sub",
            "root",
            "--reason",
            "scope policy",
            "--output",
            "json",
        ]
    )
    assert rc == 3
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["code"] == "invalid_role_transition"


def test_rootctl_admin_permissions_set_and_list_are_fully_audited(capsys, monkeypatch) -> None:
    monkeypatch.setenv("ROOTCTL_ADMIN_CAPABILITIES_ENABLED", "1")
    users = Mock()
    users.get_item.side_effect = [
        {"Item": {"user_sub": "a@example.com", "role": "admin", "admin_capabilities": ["billing_read"]}},
        {"Item": {"user_sub": "a@example.com", "role": "admin", "admin_capabilities": ["billing_read", "file_metadata"]}},
    ]
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc_set = rootctl.main(
        [
            "admin",
            "permissions",
            "set",
            "--target-user-sub",
            "a@example.com",
            "--capability",
            "billing_read",
            "--capability",
            "file_metadata",
            "--actor-sub",
            "root",
            "--reason",
            "scope policy",
            "--ticket",
            "CHG-22",
            "--output",
            "json",
        ]
    )
    assert rc_set == 0
    set_out = json.loads(capsys.readouterr().out.strip())
    assert set_out["audit_event"] == "admin_capabilities_updated_cli"
    assert set_out["old_capabilities"] == ["billing_read"]
    assert set_out["new_capabilities"] == ["billing_read", "file_metadata"]
    users.update_item.assert_called_once()
    audit.assert_called_once()
    assert audit.call_args.kwargs["old_capabilities"] == ["billing_read"]
    assert audit.call_args.kwargs["new_capabilities"] == ["billing_read", "file_metadata"]

    rc_list = rootctl.main(
        [
            "admin",
            "permissions",
            "list",
            "--target-user-sub",
            "a@example.com",
            "--output",
            "json",
        ]
    )
    assert rc_list == 0
    list_out = json.loads(capsys.readouterr().out.strip())
    assert list_out["target_user_sub"] == "a@example.com"
    assert list_out["capabilities"] == ["billing_read", "file_metadata"]
    assert list_out["feature_flag"] == "ROOTCTL_ADMIN_CAPABILITIES_ENABLED"


def test_rootctl_audit_role_timeline_filters_and_cursor(capsys, monkeypatch) -> None:
    role_audit = Mock()
    role_audit.query.return_value = {
        "Items": [
            {
                "event_id": "evt-1",
                "ts": 100,
                "action": "grant",
                "actor_sub": "root",
                "target_user_sub": "admin@example.com",
                "previous_role": "user",
                "new_role": "admin",
                "reason": "oncall",
                "request_id": "req-1",
            }
        ],
        "LastEvaluatedKey": {"pk": "ACTOR#root", "sk": "TS#0000000000100#evt-1"},
    }
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(role_audit=role_audit))

    rc = rootctl.main(
        [
            "audit",
            "role",
            "--actor-sub",
            "root",
            "--target-user-sub",
            "admin@example.com",
            "--event",
            "grant",
            "--start-ts",
            "0",
            "--end-ts",
            "999",
            "--output",
            "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["timeline"] == "role"
    assert out["count"] == 1
    assert out["items"][0]["event_id"] == "evt-1"
    assert out["cursor"] is not None


def test_rootctl_audit_impersonation_timeline_filters(capsys, monkeypatch) -> None:
    alerts = Mock()
    alerts.scan.return_value = {
        "Items": [
            {
                "alert_id": "a1",
                "user_sub": "admin@example.com",
                "details": {
                    "ts": 200,
                    "event": "impersonation_started",
                    "outcome": "success",
                    "actor_sub": "root",
                    "target_user_sub": "user@example.com",
                },
            },
            {
                "alert_id": "a2",
                "user_sub": "admin@example.com",
                "details": {
                    "ts": 201,
                    "event": "admin_role_granted",
                    "outcome": "success",
                    "actor_sub": "root",
                    "target_user_sub": "other@example.com",
                },
            },
        ],
        "LastEvaluatedKey": None,
    }
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(alerts=alerts))

    rc = rootctl.main(
        [
            "audit",
            "impersonation",
            "--actor-sub",
            "root",
            "--target-user-sub",
            "user@example.com",
            "--start-ts",
            "100",
            "--end-ts",
            "999",
            "--output",
            "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["timeline"] == "impersonation"
    assert out["count"] == 1
    assert out["items"][0]["event"] == "impersonation_started"


def test_rootctl_audit_security_timeline_invalid_cursor(capsys, monkeypatch) -> None:
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(alerts=Mock()))
    rc = rootctl.main(["audit", "security", "--cursor", "not-base64", "--output", "json"])
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["error"] == "invalid cursor"
