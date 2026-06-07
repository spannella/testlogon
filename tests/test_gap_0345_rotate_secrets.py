"""GAP-0345 regression: rootctl ``rotate-secrets`` must perform REAL secret
rotation (generate new strong values, persist them via the secret-store
abstraction, rotate the KMS break-glass key, emit an audit event) and must
NEVER leak the raw secret values — not the placeholder no-op.

Hermetic / offline: the secret-store persistence and KMS client are patched to
in-memory spies, so no real AWS / no filesystem writes occur.
"""
from __future__ import annotations

import argparse
import json
from types import SimpleNamespace
from unittest.mock import Mock

import app.cli.rootctl as rootctl
from app.services import secret_rotation


ROOT = "root.admin@testdev.local"

# Old (pre-rotation) values we assert the new ones differ from.
OLD_VALUES = {
    "UI_ACCESS_TOKEN_SECRET": "dev-local-old-ui-secret",
    "API_KEY_PEPPER": "dev-local-old-pepper",
    "WS_TOKEN_SECRET": "dev-local-old-ws",
}


def _make_args(**kwargs) -> argparse.Namespace:
    args = argparse.Namespace(
        output="json",
        dry_run=False,
        request_id="req-test-001",
        correlation_id="corr-001",
        actor_sub=ROOT,
        reason="Security incident response",
        ticket="INC-9999",
        requires_root=True,
        requires_ticket=True,
        requires_confirm=False,
        mutating=True,
        group="root",
        command="rotate-secrets",
        scope="all",
    )
    for k, v in kwargs.items():
        setattr(args, k, v)
    return args


def _install_spies(monkeypatch):
    """Patch preflight, persistence, KMS, revocation, and audit to spies.

    Returns a SimpleNamespace of the spies + the captured persisted values.
    """
    monkeypatch.setattr(rootctl, "_validate_preflight", lambda args: ROOT)

    persisted = {}

    def _persist(new_values):
        # Spy that captures what was persisted but never touches disk/AWS.
        persisted.update(new_values)
        return {"backend": "spy", "keys": list(new_values.keys())}

    persist_spy = Mock(side_effect=_persist)
    monkeypatch.setattr(secret_rotation, "persist_secrets", persist_spy)

    kms_spy = Mock(return_value={"rotated": True, "key_id": "kms-spy-key-1", "method": "enable_key_rotation"})
    monkeypatch.setattr(secret_rotation, "rotate_kms_break_glass_key", kms_spy)

    revoke_sessions = Mock()
    revoke_keys = Mock()
    monkeypatch.setattr(rootctl, "revoke_all_sessions", revoke_sessions)
    monkeypatch.setattr(rootctl, "revoke_all_api_keys", revoke_keys)

    audit = Mock()
    monkeypatch.setattr(rootctl, "audit_event", audit)

    return SimpleNamespace(
        persist=persist_spy,
        persisted=persisted,
        kms=kms_spy,
        revoke_sessions=revoke_sessions,
        revoke_keys=revoke_keys,
        audit=audit,
    )


def test_placeholder_is_no_longer_handler() -> None:
    """rotate-secrets must NOT be wired to the no-op placeholder."""
    parser = rootctl.build_parser() if hasattr(rootctl, "build_parser") else rootctl._build_parser()
    args = parser.parse_args(
        ["root", "rotate-secrets", "--actor-sub", "root@test", "--reason", "x", "--ticket", "T-1"]
    )
    assert args.handler is rootctl._rotate_secrets_command
    assert args.handler is not rootctl._placeholder_mutation_command


def test_rotate_generates_new_strong_values_and_persists(monkeypatch) -> None:
    spies = _install_spies(monkeypatch)

    result = rootctl._rotate_secrets_command(_make_args())

    assert result["ok"] is True
    assert result["dry_run"] is False

    # (a) generated new values, (b) persisted via the storage abstraction.
    spies.persist.assert_called_once()
    persisted = spies.persisted
    for env_name, strength in (
        ("UI_ACCESS_TOKEN_SECRET", 40),
        ("API_KEY_PEPPER", 32),
        ("WS_TOKEN_SECRET", 32),
    ):
        assert env_name in persisted, f"{env_name} not persisted"
        new_val = persisted[env_name]
        assert isinstance(new_val, str)
        assert len(new_val) >= strength, f"{env_name} too short ({len(new_val)})"
        assert new_val != OLD_VALUES[env_name], f"{env_name} not changed"

    # New values must be distinct from each other (independently generated).
    assert len({persisted["UI_ACCESS_TOKEN_SECRET"],
                persisted["API_KEY_PEPPER"],
                persisted["WS_TOKEN_SECRET"]}) == 3


def test_rotate_emits_audit_and_rotates_kms(monkeypatch) -> None:
    spies = _install_spies(monkeypatch)

    result = rootctl._rotate_secrets_command(_make_args())

    # (c) audit event emitted with rotation metadata.
    spies.audit.assert_called_once()
    a_args, a_kwargs = spies.audit.call_args
    assert a_args[0] == "rotate_secrets"
    assert a_args[1] == ROOT
    assert a_kwargs["outcome"] == "success"
    assert set(a_kwargs["rotated_secrets"]) == {
        "UI_ACCESS_TOKEN_SECRET", "API_KEY_PEPPER", "WS_TOKEN_SECRET"
    }

    # (e) KMS key rotated via the abstraction.
    spies.kms.assert_called_once()
    assert result["kms"]["rotated"] is True
    assert result["kms"]["key_id"] == "kms-spy-key-1"

    # sessions/api keys revoked because UI/pepper rotated.
    spies.revoke_sessions.assert_called_once_with(ROOT)
    spies.revoke_keys.assert_called_once_with(ROOT)
    assert result["sessions_revoked"] is True
    assert result["api_keys_revoked"] is True


def test_rotate_never_leaks_raw_secret_values(monkeypatch) -> None:
    spies = _install_spies(monkeypatch)

    result = rootctl._rotate_secrets_command(_make_args())

    # (d) raw secret values must not appear in the returned result...
    serialized = json.dumps(result)
    for raw in spies.persisted.values():
        assert raw not in serialized, "raw secret value leaked into result"

    # ...nor in the audit payload (only names/identifiers).
    _, a_kwargs = spies.audit.call_args
    audit_blob = json.dumps({k: v for k, v in a_kwargs.items() if k != "cli"}, default=str)
    for raw in spies.persisted.values():
        assert raw not in audit_blob, "raw secret value leaked into audit event"


def test_dry_run_makes_no_changes(monkeypatch) -> None:
    spies = _install_spies(monkeypatch)

    result = rootctl._rotate_secrets_command(_make_args(dry_run=True))

    assert result["dry_run"] is True
    assert set(result["would_rotate"]) == {
        "UI_ACCESS_TOKEN_SECRET", "API_KEY_PEPPER", "WS_TOKEN_SECRET"
    }
    spies.persist.assert_not_called()
    spies.kms.assert_not_called()
    spies.revoke_sessions.assert_not_called()
    spies.revoke_keys.assert_not_called()
    spies.audit.assert_not_called()


def test_scope_limits_rotation(monkeypatch) -> None:
    spies = _install_spies(monkeypatch)

    rootctl._rotate_secrets_command(_make_args(scope="ui_access_token"))

    assert set(spies.persisted.keys()) == {"UI_ACCESS_TOKEN_SECRET"}
    # api_key_pepper not rotated => api keys not revoked.
    spies.revoke_keys.assert_not_called()
    spies.revoke_sessions.assert_called_once_with(ROOT)


def test_invalid_scope_rejected(monkeypatch) -> None:
    monkeypatch.setattr(rootctl, "_validate_preflight", lambda args: ROOT)
    try:
        rootctl._rotate_secrets_command(_make_args(scope="bogus"))
    except ValueError as exc:
        assert "scope" in str(exc).lower()
    else:
        raise AssertionError("expected ValueError for invalid scope")


def test_generate_new_secrets_helper_distinct_and_strong() -> None:
    a = secret_rotation.generate_new_secrets("all")
    b = secret_rotation.generate_new_secrets("all")
    assert set(a.keys()) == {"UI_ACCESS_TOKEN_SECRET", "API_KEY_PEPPER", "WS_TOKEN_SECRET"}
    # Fresh call yields fresh values.
    for k in a:
        assert a[k] != b[k]
        assert len(a[k]) >= 32
