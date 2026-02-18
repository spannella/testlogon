from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from fastapi import HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.roles import Role
from app.routers import admin_impersonation


def _req():
    return SimpleNamespace(headers={"user-agent": "test"}, client=SimpleNamespace(host="127.0.0.1"))


def _tables(users: Mock, sessions: Mock) -> SimpleNamespace:
    return SimpleNamespace(users=users, sessions=sessions)


def test_start_impersonation_rejects_missing_target() -> None:
    with pytest.raises(HTTPException) as exc:
        admin_impersonation.start_impersonation(
            _req(),
            body={},
            _ctx={"user_sub": "admin", "session_id": "sid", "role": "admin"},
            actor=AuthenticatedUser(sub="admin", role=Role.ADMIN),
        )
    assert exc.value.status_code == 400


def test_start_impersonation_rejects_admin_target_by_default() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "target", "role": "admin"}}
    sessions = Mock()
    fake_settings = SimpleNamespace(
        impersonation_ttl_seconds=600,
        impersonation_max_ttl_seconds=3600,
        impersonation_allow_privileged_targets=False,
        ui_access_token_secret="secret",
    )
    with patch.object(admin_impersonation, "T", _tables(users, sessions)), patch.object(admin_impersonation, "S", fake_settings):
        with pytest.raises(HTTPException) as exc:
            admin_impersonation.start_impersonation(
                _req(),
                body={"target_user_sub": "target", "reason": "support"},
                _ctx={"user_sub": "admin", "session_id": "sid", "role": "admin"},
                actor=AuthenticatedUser(sub="admin", role=Role.ADMIN),
            )
    assert exc.value.status_code == 403
    assert exc.value.detail == "impersonation_not_allowed"


def test_start_impersonation_caps_duration() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "target", "role": "user"}}
    sessions = Mock()
    fake_settings = SimpleNamespace(
        impersonation_ttl_seconds=1800,
        impersonation_max_ttl_seconds=900,
        impersonation_allow_privileged_targets=False,
        ui_access_token_secret="secret",
    )
    with patch.object(admin_impersonation, "T", _tables(users, sessions)), patch.object(
        admin_impersonation, "S", fake_settings
    ), patch.object(admin_impersonation, "now_ts", return_value=1000), patch.object(
        admin_impersonation, "with_ttl", side_effect=lambda item, ttl_epoch: {**item, "ttl_epoch": ttl_epoch}
    ), patch.object(admin_impersonation, "audit_event"):
        resp = admin_impersonation.start_impersonation(
            _req(),
            body={"target_user_sub": "target", "reason": "support", "ticket_id": "INC-1", "duration_seconds": 7200},
            _ctx={"user_sub": "admin", "session_id": "sid", "role": "admin"},
            actor=AuthenticatedUser(sub="admin", role=Role.ADMIN),
        )

    assert resp["ok"] is True
    assert resp["ttl_seconds"] == 900
    assert resp["expires_at"] == 1900


def test_start_impersonation_root_can_impersonate_admin_in_emergency_mode() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "target", "role": "admin"}}
    sessions = Mock()
    fake_settings = SimpleNamespace(
        impersonation_ttl_seconds=600,
        impersonation_max_ttl_seconds=3600,
        impersonation_allow_privileged_targets=True,
        ui_access_token_secret="secret",
    )
    with patch.object(admin_impersonation, "T", _tables(users, sessions)), patch.object(
        admin_impersonation, "S", fake_settings
    ), patch.object(admin_impersonation, "now_ts", return_value=1000), patch.object(
        admin_impersonation, "with_ttl", side_effect=lambda item, ttl_epoch: {**item, "ttl_epoch": ttl_epoch}
    ), patch.object(admin_impersonation, "audit_event"):
        resp = admin_impersonation.start_impersonation(
            _req(),
            body={"target_user_sub": "target", "reason": "incident"},
            _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
            actor=AuthenticatedUser(sub="root", role=Role.ROOT),
        )

    assert resp["ok"] is True
    assert resp["effective_sub"] == "target"


def test_stop_impersonation_invalidates_session_immediately() -> None:
    users = Mock()
    sessions = Mock()
    sessions.get_item.return_value = {
        "Item": {
            "user_sub": "admin",
            "session_id": "imp_1",
            "purpose": "impersonation",
            "effective_sub": "target",
            "revoked": False,
            "expires_at": 99999,
        }
    }
    with patch.object(admin_impersonation, "T", _tables(users, sessions)), patch.object(
        admin_impersonation, "audit_event"
    ), patch.object(admin_impersonation, "now_ts", return_value=1234):
        resp = admin_impersonation.stop_impersonation(
            _req(),
            body={"impersonation_id": "imp_1"},
            _ctx={"user_sub": "admin", "session_id": "sid", "role": "admin"},
            actor=AuthenticatedUser(sub="admin", role=Role.ADMIN),
        )

    assert resp["ok"] is True
    assert resp["stopped"] is True
    sessions.update_item.assert_called_once()


def test_stop_impersonation_rejects_expired_session() -> None:
    users = Mock()
    sessions = Mock()
    sessions.get_item.return_value = {
        "Item": {
            "user_sub": "admin",
            "session_id": "imp_1",
            "purpose": "impersonation",
            "effective_sub": "target",
            "revoked": False,
            "expires_at": 1200,
        }
    }
    with patch.object(admin_impersonation, "T", _tables(users, sessions)), patch.object(admin_impersonation, "now_ts", return_value=1300):
        with pytest.raises(HTTPException) as exc:
            admin_impersonation.stop_impersonation(
                _req(),
                body={"impersonation_id": "imp_1"},
                _ctx={"user_sub": "admin", "session_id": "sid", "role": "admin"},
                actor=AuthenticatedUser(sub="admin", role=Role.ADMIN),
            )
    assert exc.value.status_code == 401
    assert exc.value.detail == "impersonation_expired"


def test_impersonation_mutations_apply_admin_action_rate_limit() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "target", "role": "user"}}
    sessions = Mock()
    sessions.get_item.return_value = {
        "Item": {
            "user_sub": "admin",
            "session_id": "imp_1",
            "purpose": "impersonation",
            "effective_sub": "target",
            "revoked": False,
            "expires_at": 99999,
        }
    }
    fake_settings = SimpleNamespace(
        impersonation_ttl_seconds=600,
        impersonation_max_ttl_seconds=3600,
        impersonation_allow_privileged_targets=False,
        ui_access_token_secret="secret",
    )
    with patch.object(admin_impersonation, "T", _tables(users, sessions)), patch.object(
        admin_impersonation, "S", fake_settings
    ), patch.object(admin_impersonation, "now_ts", return_value=1000), patch.object(
        admin_impersonation, "with_ttl", side_effect=lambda item, ttl_epoch: {**item, "ttl_epoch": ttl_epoch}
    ), patch.object(admin_impersonation, "audit_event"), patch.object(
        admin_impersonation, "rate_limit_admin_action"
    ) as limiter:
        admin_impersonation.start_impersonation(
            _req(),
            body={"target_user_sub": "target", "reason": "support"},
            _ctx={"user_sub": "admin", "session_id": "sid", "role": "admin"},
            actor=AuthenticatedUser(sub="admin", role=Role.ADMIN),
        )
        admin_impersonation.stop_impersonation(
            _req(),
            body={"impersonation_id": "imp_1"},
            _ctx={"user_sub": "admin", "session_id": "sid", "role": "admin"},
            actor=AuthenticatedUser(sub="admin", role=Role.ADMIN),
        )

    assert limiter.call_args_list[0].args == ("admin", "impersonation_start")
    assert limiter.call_args_list[1].args == ("admin", "impersonation_stop")


def test_impersonation_audit_reconstructs_timeline_with_filters() -> None:
    users = Mock()
    sessions = Mock()
    sessions.query.return_value = {
        "Items": [
            {"purpose": "impersonation", "session_id": "imp_1", "actor_sub": "admin", "effective_sub": "u1", "created_at": 200, "expires_at": 900, "revoked": False},
            {"purpose": "impersonation", "session_id": "imp_2", "actor_sub": "admin", "effective_sub": "u2", "created_at": 100, "expires_at": 800, "revoked": True, "revoked_at": 120},
            {"purpose": "other", "session_id": "x", "created_at": 300},
        ]
    }
    with patch.object(admin_impersonation, "T", _tables(users, sessions)), patch.object(admin_impersonation, "now_ts", return_value=1000):
        resp = admin_impersonation.impersonation_audit(
            actor_sub="admin",
            start_ts=0,
            end_ts=500,
            limit=10,
            cursor=None,
            _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
            _actor=AuthenticatedUser(sub="root", role=Role.ROOT),
        )

    assert [x["impersonation_id"] for x in resp["items"]] == ["imp_1", "imp_2"]
    assert resp["items"][0]["actor_sub"] == "admin"
