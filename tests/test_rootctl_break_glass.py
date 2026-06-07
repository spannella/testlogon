"""Offline regression tests for GAP-0030: break-glass secret gate on rootctl mutations.

These tests do NOT touch real AWS. They exercise the pure-Python preflight /
break-glass auth logic in app.cli.rootctl. The actual DynamoDB mutation is never
reached: the break-glass gate runs as the first preflight step, so a missing /
wrong secret short-circuits before any mutation. The one "happy path" test mocks
the mutation handler to keep it deterministic and AWS-free.

Before the fix: _require_break_glass_auth does not exist and _validate_preflight
performs no secret check -> the "rejected without secret" tests fail.
After the fix: the gate rejects missing/wrong secrets and admits the correct one.
"""
from __future__ import annotations

import argparse

import pytest

from app.cli.rootctl import (
    CliPolicyError,
    _require_break_glass_auth,
    _validate_preflight,
)

CORRECT_SECRET = "test_break_glass_secret_abc123"


def _clear_break_glass_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ROOTCTL_BREAK_GLASS_SECRET", raising=False)
    monkeypatch.delenv("ROOTCTL_BREAK_GLASS_TOKEN", raising=False)
    # Settings.S.rootctl_break_glass_secret defaults to "" in the test env, so the
    # env-var resolution above is sufficient to make the expected secret empty.


def _mutating_args(**overrides) -> argparse.Namespace:
    base = dict(
        group="root",
        command="reset-mfa",
        mutating=True,
        requires_root=True,
        requires_ticket=False,
        requires_confirm=False,
        actor_sub="root@example.com",
        target_user_sub="",
        reason="incident response",
        ticket="",
        role="",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


# --- _require_break_glass_auth unit-level ---------------------------------


def test_break_glass_rejects_when_secret_not_configured(monkeypatch):
    _clear_break_glass_env(monkeypatch)
    with pytest.raises(CliPolicyError) as exc_info:
        _require_break_glass_auth()
    assert exc_info.value.details.get("code") == "break_glass_unconfigured"


def test_break_glass_rejects_wrong_token(monkeypatch):
    monkeypatch.setenv("ROOTCTL_BREAK_GLASS_SECRET", CORRECT_SECRET)
    monkeypatch.setenv("ROOTCTL_BREAK_GLASS_TOKEN", "wrong_token")
    with pytest.raises(CliPolicyError) as exc_info:
        _require_break_glass_auth()
    assert exc_info.value.details.get("code") == "break_glass_auth_failed"


def test_break_glass_rejects_no_token(monkeypatch):
    monkeypatch.setenv("ROOTCTL_BREAK_GLASS_SECRET", CORRECT_SECRET)
    monkeypatch.delenv("ROOTCTL_BREAK_GLASS_TOKEN", raising=False)
    # No interactive token available -> getpass returns "".
    monkeypatch.setattr("app.cli.rootctl.getpass.getpass", lambda *a, **k: "")
    with pytest.raises(CliPolicyError) as exc_info:
        _require_break_glass_auth()
    assert exc_info.value.details.get("code") == "break_glass_no_token"


def test_break_glass_accepts_correct_token(monkeypatch):
    monkeypatch.setenv("ROOTCTL_BREAK_GLASS_SECRET", CORRECT_SECRET)
    monkeypatch.setenv("ROOTCTL_BREAK_GLASS_TOKEN", CORRECT_SECRET)
    # Must not raise.
    _require_break_glass_auth()


def test_break_glass_uses_settings_fallback(monkeypatch):
    # No env secret, but the Settings-backed expected-secret resolver returns one.
    monkeypatch.delenv("ROOTCTL_BREAK_GLASS_SECRET", raising=False)
    monkeypatch.setattr(
        "app.cli.rootctl._break_glass_expected_secret", lambda: CORRECT_SECRET
    )
    monkeypatch.setenv("ROOTCTL_BREAK_GLASS_TOKEN", CORRECT_SECRET)
    _require_break_glass_auth()


# --- _validate_preflight integration --------------------------------------


def test_mutating_preflight_rejected_without_secret(monkeypatch):
    """Mutation is blocked before reaching any DynamoDB call when no secret set."""
    _clear_break_glass_env(monkeypatch)
    monkeypatch.setenv("ROOT_USER_SUB", "root@example.com")
    monkeypatch.setattr(
        "app.cli.rootctl.validate_root_user_sub_config",
        lambda: "root@example.com",
    )
    with pytest.raises(CliPolicyError) as exc_info:
        _validate_preflight(_mutating_args())
    assert exc_info.value.details.get("code") == "break_glass_unconfigured"


def test_mutating_preflight_rejected_with_wrong_secret(monkeypatch):
    monkeypatch.setenv("ROOTCTL_BREAK_GLASS_SECRET", CORRECT_SECRET)
    monkeypatch.setenv("ROOTCTL_BREAK_GLASS_TOKEN", "nope")
    monkeypatch.setattr(
        "app.cli.rootctl.validate_root_user_sub_config",
        lambda: "root@example.com",
    )
    with pytest.raises(CliPolicyError) as exc_info:
        _validate_preflight(_mutating_args())
    assert exc_info.value.details.get("code") == "break_glass_auth_failed"


def test_mutating_preflight_proceeds_with_correct_secret(monkeypatch):
    """With the correct secret, the break-glass gate passes and preflight
    completes the remaining (audit) guards, returning root_sub."""
    monkeypatch.setenv("ROOTCTL_BREAK_GLASS_SECRET", CORRECT_SECRET)
    monkeypatch.setenv("ROOTCTL_BREAK_GLASS_TOKEN", CORRECT_SECRET)
    monkeypatch.setattr(
        "app.cli.rootctl.validate_root_user_sub_config",
        lambda: "root@example.com",
    )
    result = _validate_preflight(_mutating_args())
    assert result == "root@example.com"


def test_read_only_commands_bypass_break_glass(monkeypatch):
    """Read-only commands must not be gated by the break-glass secret."""
    _clear_break_glass_env(monkeypatch)
    monkeypatch.setattr(
        "app.cli.rootctl.validate_root_user_sub_config",
        lambda: "root@example.com",
    )
    args = argparse.Namespace(mutating=False, actor_sub="", reason="")
    assert _validate_preflight(args) == "root@example.com"
