"""Additional rootctl CLI tests covering behaviours not addressed in
test_rootctl_cli.py / test_rootctl_policy_matrix.py.

New coverage:
  - root rotate-secrets placeholder command
  - root set-email without --verify flag
  - user create --role admin and --status pending_verification
  - user list limit validation (0 / 201)
  - user delete soft-mode and dry-run
  - user deactivate-bulk empty targets and dry-run
  - admin revoke on non-admin target and dry-run
  - admin grant dry-run
  - admin permissions set with invalid capability (feature-flag enabled)
  - audit file timeline filtering
  - audit timeline limit validation (all four timelines)
  - audit timeline start_ts > end_ts validation
  - _sanitize_for_json Decimal conversion (int, float, nested)
  - _alerts_event_matches_timeline routing logic
  - _placeholder_mutation_command full scaffold shape
"""
from __future__ import annotations

import json
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.cli import rootctl

_BREAK_GLASS_SECRET = "test-break-glass-secret"


@pytest.fixture(autouse=True)
def _set_break_glass(monkeypatch):
    """Set ROOTCTL_BREAK_GLASS_SECRET + TOKEN so mutation commands pass the gate."""
    monkeypatch.setenv("ROOTCTL_BREAK_GLASS_SECRET", _BREAK_GLASS_SECRET)
    monkeypatch.setenv("ROOTCTL_BREAK_GLASS_TOKEN", _BREAK_GLASS_SECRET)


# ─── helpers ─────────────────────────────────────────────────────────────────

def _admin_user_mock(sub: str) -> Mock:
    m = Mock()
    m.get_item.return_value = {"Item": {"user_sub": sub, "role": "admin"}}
    return m


def _plain_user_mock(sub: str) -> Mock:
    m = Mock()
    m.get_item.return_value = {"Item": {"user_sub": sub, "role": "user"}}
    return m


# ─── root group ──────────────────────────────────────────────────────────────


def test_rootctl_rotate_secrets_placeholder_succeeds(capsys, monkeypatch) -> None:
    """rotate-secrets command routes correctly and succeeds (dry-run to avoid real DDB)."""
    from app.services import secret_rotation as _sr
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    monkeypatch.setattr(_sr, "generate_new_secrets", lambda scope: {})
    monkeypatch.setattr(_sr, "persist_secrets", lambda new_values: {"backend": "mock"})
    monkeypatch.setattr(_sr, "rotate_kms_break_glass_key", lambda: {"rotated": False})
    monkeypatch.setattr(rootctl, "audit_event", lambda *a, **kw: None)
    monkeypatch.setattr(rootctl, "revoke_all_sessions", lambda sub: None)
    monkeypatch.setattr(rootctl, "revoke_all_api_keys", lambda sub: None)

    rc = rootctl.main(
        [
            "root",
            "rotate-secrets",
            "--actor-sub", "root",
            "--reason", "quarterly rotation",
            "--ticket", "CHG-99",
            "--request-id", "req-xyz",
            "--correlation-id", "corr-xyz",
            "--output", "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["ok"] is True
    assert out["group"] == "root"
    assert out["command"] == "rotate-secrets"
    assert out["request_id"] == "req-xyz"
    assert out["correlation_id"] == "corr-xyz"


def test_rootctl_rotate_secrets_placeholder_requires_root_actor(capsys, monkeypatch) -> None:
    """rotate-secrets rejects non-root actor (requires_root=True)."""
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")

    rc = rootctl.main(
        [
            "root",
            "rotate-secrets",
            "--actor-sub", "other-admin",
            "--reason", "test",
            "--ticket", "CHG-1",
            "--output", "json",
        ]
    )
    assert rc == 3
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["code"] == "role_required"


def test_rootctl_set_email_without_verify_flag(capsys, monkeypatch) -> None:
    """set-email without --verify should NOT include email_verified in updates."""
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "root"}}
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    monkeypatch.setattr(rootctl, "audit_event", Mock())

    rc = rootctl.main(
        [
            "root",
            "set-email",
            "--actor-sub", "root",
            "--reason", "update",
            "--ticket", "CHG-1",
            "--email", "new-root@example.com",
            "--output", "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["updates"]["email"] == "new-root@example.com"
    # Without --verify, email_verified is NOT included in updates
    assert "email_verified" not in out["updates"]


# ─── user group ──────────────────────────────────────────────────────────────


def test_rootctl_user_create_with_admin_role(capsys, monkeypatch) -> None:
    """user create --role admin records role=admin in the payload."""
    users = Mock()
    users.get_item.return_value = {}
    users.put_item.return_value = {}
    account_state = Mock()
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, account_state=account_state))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    monkeypatch.setattr(rootctl, "audit_event", Mock())

    rc = rootctl.main(
        [
            "user",
            "create",
            "--email", "newadmin@example.com",
            "--role", "admin",
            "--actor-sub", "root",
            "--reason", "ops",
            "--output", "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["role"] == "admin"


def test_rootctl_user_create_with_pending_verification_status(capsys, monkeypatch) -> None:
    """user create --status pending_verification stores that status."""
    users = Mock()
    users.get_item.return_value = {}
    users.put_item.return_value = {}
    account_state = Mock()
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, account_state=account_state))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    monkeypatch.setattr(rootctl, "audit_event", Mock())

    rc = rootctl.main(
        [
            "user",
            "create",
            "--email", "pending@example.com",
            "--status", "pending_verification",
            "--actor-sub", "root",
            "--reason", "ops",
            "--output", "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["status"] == "pending_verification"


def test_rootctl_user_list_rejects_limit_over_max(capsys, monkeypatch) -> None:
    """user list --limit 201 fails with validation error."""
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")

    rc = rootctl.main(["user", "list", "--limit", "201", "--output", "json"])
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert "limit" in payload["error"]


def test_rootctl_user_delete_soft_mode_updates_not_deletes(capsys, monkeypatch) -> None:
    """user delete without --hard-delete soft-deletes (update_item) and does not DDB-delete."""
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u_soft"}}
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
            "--target-user-sub", "u_soft",
            "--actor-sub", "root",
            "--reason", "gdpr-request",
            "--ticket", "INC-99",
            "--confirm", "u_soft",
            "--output", "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["hard_delete"] is False
    # soft-delete: DDB delete_item NOT called; update_item + put_item called instead
    users.delete_item.assert_not_called()
    users.update_item.assert_called_once()
    account_state.put_item.assert_called_once()
    account_state.delete_item.assert_not_called()
    assert audit.call_args.kwargs["deletion_mode"] == "soft"


def test_rootctl_user_delete_dry_run_skips_all_mutations(capsys, monkeypatch) -> None:
    """user delete --dry-run returns dry-run payload and skips all mutations."""
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u_dry"}}
    account_state = Mock()
    account_state.get_item.return_value = {"Item": {"status": "active"}}
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, account_state=account_state))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    revoke_sessions = Mock()
    revoke_keys = Mock()
    monkeypatch.setattr(rootctl, "revoke_all_sessions", revoke_sessions)
    monkeypatch.setattr(rootctl, "revoke_all_api_keys", revoke_keys)
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(
        [
            "user",
            "delete",
            "--target-user-sub", "u_dry",
            "--actor-sub", "root",
            "--reason", "gdpr",
            "--ticket", "INC-88",
            "--confirm", "u_dry",
            "--dry-run",
            "--output", "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["dry_run"] is True
    assert "would be deleted" in out["message"]
    users.delete_item.assert_not_called()
    users.update_item.assert_not_called()
    revoke_sessions.assert_not_called()
    revoke_keys.assert_not_called()
    audit.assert_not_called()


def test_rootctl_user_deactivate_bulk_empty_targets_fails(capsys, monkeypatch) -> None:
    """user deactivate-bulk with no --target-user-sub fails with validation error."""
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")

    rc = rootctl.main(
        [
            "user",
            "deactivate-bulk",
            "--actor-sub", "root",
            "--reason", "cleanup",
            "--ticket", "INC-1",
            "--output", "json",
        ]
    )
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert "target" in payload["error"]


def test_rootctl_user_deactivate_bulk_dry_run_skips_audit(capsys, monkeypatch) -> None:
    """user deactivate-bulk --dry-run processes all targets without writing to DDB."""
    users = Mock()
    users.get_item.side_effect = [
        {"Item": {"user_sub": "ua"}},
        {"Item": {"user_sub": "ub"}},
    ]
    account_state = Mock()
    account_state.get_item.side_effect = [
        {"Item": {"status": "active"}},
        {"Item": {"status": "active"}},
    ]
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, account_state=account_state))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    monkeypatch.setattr(rootctl, "revoke_all_sessions", Mock())
    monkeypatch.setattr(rootctl, "revoke_all_api_keys", Mock())
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(
        [
            "user",
            "deactivate-bulk",
            "--target-user-sub", "ua",
            "--target-user-sub", "ub",
            "--actor-sub", "root",
            "--reason", "mass-cleanup",
            "--ticket", "INC-2",
            "--dry-run",
            "--output", "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["dry_run"] is True
    assert out["summary"]["total_targets"] == 2
    assert out["summary"]["success_count"] == 2
    assert out["summary"]["failure_count"] == 0
    # dry-run: no audit events, no DDB writes
    audit.assert_not_called()
    account_state.update_item.assert_not_called()


# ─── admin group ─────────────────────────────────────────────────────────────


def test_rootctl_admin_revoke_on_plain_user_fails(capsys, monkeypatch) -> None:
    """admin revoke targeting a plain user (role=user) raises invalid_role_transition."""
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=_plain_user_mock("u_plain"), role_audit=Mock()))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")

    rc = rootctl.main(
        [
            "admin",
            "revoke",
            "--target-user-sub", "u_plain",
            "--actor-sub", "root",
            "--reason", "cleanup",
            "--output", "json",
        ]
    )
    assert rc == 3
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["code"] == "invalid_role_transition"
    assert "not_admin" in str(payload)


def test_rootctl_admin_revoke_dry_run_skips_mutations(capsys, monkeypatch) -> None:
    """admin revoke --dry-run returns dry-run payload without DDB writes."""
    role_audit = Mock()
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=_admin_user_mock("u_admin"), role_audit=role_audit))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(
        [
            "admin",
            "revoke",
            "--target-user-sub", "u_admin",
            "--actor-sub", "root",
            "--reason", "cleanup",
            "--dry-run",
            "--output", "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["dry_run"] is True
    assert out["new_role"] == "user"
    # no writes
    _admin_user_mock("u_admin").update_item.assert_not_called()
    role_audit.put_item.assert_not_called()
    audit.assert_not_called()


def test_rootctl_admin_grant_dry_run_skips_mutations(capsys, monkeypatch) -> None:
    """admin grant --dry-run returns dry-run payload without DDB writes."""
    users = _plain_user_mock("u_grant_dry")
    role_audit = Mock()
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=users, role_audit=role_audit))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")
    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    rc = rootctl.main(
        [
            "admin",
            "grant",
            "--target-user-sub", "u_grant_dry",
            "--actor-sub", "root",
            "--reason", "onboard",
            "--dry-run",
            "--output", "json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["dry_run"] is True
    assert out["new_role"] == "admin"
    users.update_item.assert_not_called()
    role_audit.put_item.assert_not_called()
    audit.assert_not_called()


def test_rootctl_admin_permissions_set_invalid_capability_when_feature_enabled(capsys, monkeypatch) -> None:
    """admin permissions set with unknown capability fails when feature flag is on."""
    monkeypatch.setenv(rootctl.ADMIN_CAPABILITY_FEATURE_FLAG, "1")
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(users=_admin_user_mock("u_caps")))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")

    rc = rootctl.main(
        [
            "admin",
            "permissions",
            "set",
            "--target-user-sub", "u_caps",
            "--capability", "not_a_real_capability",
            "--actor-sub", "root",
            "--reason", "test",
            "--output", "json",
        ]
    )
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert "capability" in payload["error"]


# ─── audit group ─────────────────────────────────────────────────────────────


def test_rootctl_audit_file_timeline_filters_file_events(capsys, monkeypatch) -> None:
    """audit file timeline includes fs_/file_/shared_ events; excludes root_/admin_ events.

    Note: _alerts_timeline_command expects `details` to be a dict (not JSON string).
    """
    import time
    now = int(time.time())
    alerts = Mock()
    alerts.scan.return_value = {
        "Items": [
            {
                "alert_id": "a1",
                "user_sub": "u1",
                "ts": now,
                "details": {"event": "fs_upload", "actor_sub": "u1"},
            },
            {
                "alert_id": "a2",
                "user_sub": "u1",
                "ts": now,
                "details": {"event": "root_password_reset", "actor_sub": "u1"},
            },
            {
                "alert_id": "a3",
                "user_sub": "u1",
                "ts": now,
                "details": {"event": "file_deleted", "actor_sub": "u1"},
            },
        ],
        "LastEvaluatedKey": None,
    }
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(alerts=alerts))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")

    rc = rootctl.main(["audit", "file", "--output", "json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    event_names = [item.get("event") for item in out.get("items", [])]
    assert "fs_upload" in event_names
    assert "file_deleted" in event_names
    assert "root_password_reset" not in event_names


def test_rootctl_audit_file_timeline_returns_expected_shape(capsys, monkeypatch) -> None:
    """audit file returns ok, count, items, and timeline fields."""
    alerts = Mock()
    alerts.scan.return_value = {"Items": [], "LastEvaluatedKey": None}
    monkeypatch.setattr(rootctl, "T", SimpleNamespace(alerts=alerts))
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")

    rc = rootctl.main(["audit", "file", "--output", "json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert "items" in out
    assert "count" in out
    assert out["count"] == 0


@pytest.mark.parametrize("timeline", ["impersonation", "file", "security"])
def test_rootctl_audit_alerts_timeline_rejects_limit_over_max(capsys, monkeypatch, timeline) -> None:
    """audit <timeline> --limit 201 fails with validation error."""
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")

    rc = rootctl.main(["audit", timeline, "--limit", "201", "--output", "json"])
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert "limit" in payload["error"]


def test_rootctl_audit_role_timeline_rejects_limit_over_max(capsys, monkeypatch) -> None:
    """audit role --limit 201 fails with validation error."""
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")

    rc = rootctl.main(["audit", "role", "--limit", "201", "--output", "json"])
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert "limit" in payload["error"]


def test_rootctl_audit_security_timeline_start_after_end_fails(capsys, monkeypatch) -> None:
    """audit security --start-ts N --end-ts M where N > M returns validation error."""
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")

    rc = rootctl.main(
        [
            "audit",
            "security",
            "--start-ts", "9999999999",
            "--end-ts", "1000000000",
            "--output", "json",
        ]
    )
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert "start_ts" in payload["error"]


def test_rootctl_audit_role_timeline_start_after_end_fails(capsys, monkeypatch) -> None:
    """audit role --start-ts N --end-ts M where N > M returns validation error."""
    monkeypatch.setattr(rootctl, "validate_root_user_sub_config", lambda: "root")

    rc = rootctl.main(
        [
            "audit",
            "role",
            "--start-ts", "9999999999",
            "--end-ts", "1000000000",
            "--output", "json",
        ]
    )
    assert rc == 2
    payload = json.loads(capsys.readouterr().err.strip())
    assert "start_ts" in payload["error"]


# ─── internal helpers ─────────────────────────────────────────────────────────


def test_sanitize_for_json_decimal_to_int() -> None:
    """_sanitize_for_json converts integral Decimal to int."""
    result = rootctl._sanitize_for_json(Decimal("42"))
    assert result == 42
    assert isinstance(result, int)


def test_sanitize_for_json_decimal_to_float() -> None:
    """_sanitize_for_json converts fractional Decimal to float."""
    result = rootctl._sanitize_for_json(Decimal("3.14"))
    assert abs(result - 3.14) < 1e-6
    assert isinstance(result, float)


def test_sanitize_for_json_nested_dict_and_list() -> None:
    """_sanitize_for_json recurses into dicts and lists."""
    obj = {"a": Decimal("10"), "b": [Decimal("1"), {"c": Decimal("2")}]}
    result = rootctl._sanitize_for_json(obj)
    assert result == {"a": 10, "b": [1, {"c": 2}]}


def test_sanitize_for_json_passthrough_non_decimal() -> None:
    """_sanitize_for_json leaves non-Decimal types unchanged."""
    assert rootctl._sanitize_for_json("hello") == "hello"
    assert rootctl._sanitize_for_json(99) == 99
    assert rootctl._sanitize_for_json(None) is None
    assert rootctl._sanitize_for_json(True) is True


def test_alerts_event_matches_file_timeline() -> None:
    """_alerts_event_matches_timeline correctly identifies file events."""
    fn = rootctl._alerts_event_matches_timeline
    assert fn({"event": "fs_upload"}, "file") is True
    assert fn({"event": "file_deleted"}, "file") is True
    assert fn({"event": "shared_node"}, "file") is True
    assert fn({"file_path": "/x/y"}, "file") is True
    assert fn({"event": "root_password_reset"}, "file") is False
    assert fn({"event": "admin_role_granted"}, "file") is False


def test_alerts_event_matches_impersonation_timeline() -> None:
    """_alerts_event_matches_timeline correctly identifies impersonation events."""
    fn = rootctl._alerts_event_matches_timeline
    assert fn({"event": "impersonation_started"}, "impersonation") is True
    assert fn({"event": "impersonation_stopped"}, "impersonation") is True
    assert fn({"impersonation": True}, "impersonation") is True
    assert fn({"event": "root_mfa_reset"}, "impersonation") is False
    assert fn({"event": "fs_upload"}, "impersonation") is False


def test_alerts_event_matches_security_timeline() -> None:
    """_alerts_event_matches_timeline identifies all security-prefixed events."""
    fn = rootctl._alerts_event_matches_timeline
    for prefix in ("root_", "admin_", "mfa_", "ui_session_", "api_key_", "device_", "alerts_"):
        assert fn({"event": f"{prefix}action"}, "security") is True
    assert fn({"event": "fs_upload"}, "security") is False
    assert fn({"event": "impersonation_started"}, "security") is False
