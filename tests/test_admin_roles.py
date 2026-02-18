from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from fastapi import HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.roles import Role
from app.routers import admin_roles


def _req(x_request_id: str = "req-1"):
    return SimpleNamespace(
        headers={"user-agent": "test", "x-request-id": x_request_id},
        client=SimpleNamespace(host="127.0.0.1"),
    )


def _tables(users: Mock, role_audit: Mock) -> SimpleNamespace:
    return SimpleNamespace(users=users, role_audit=role_audit)


def test_grant_role_requires_existing_user() -> None:
    users = Mock()
    users.get_item.return_value = {}
    role_audit = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)):
        with pytest.raises(HTTPException) as exc:
            admin_roles.grant_role(
                admin_roles.RoleGrantReq(target_user_sub="u1", role="admin", reason="ops"),
                _req(),
                _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
                actor=AuthenticatedUser(sub="root", role=Role.ROOT),
            )
    assert exc.value.status_code == 404


def test_grant_role_rejects_invalid_transition_when_already_admin() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u1", "role": "admin"}}
    role_audit = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)):
        with pytest.raises(HTTPException) as exc:
            admin_roles.grant_role(
                admin_roles.RoleGrantReq(target_user_sub="u1", role="admin", reason="ops"),
                _req(),
                _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
                actor=AuthenticatedUser(sub="root", role=Role.ROOT),
            )
    assert exc.value.status_code == 409
    assert "already admin" in str(exc.value.detail)


def test_grant_role_root_only_success_updates_user_and_writes_immutable_audit() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u1", "role": "user"}}
    role_audit = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)), patch.object(admin_roles, "audit_event") as audit, patch.object(
        admin_roles, "now_ts", return_value=1000
    ):
        resp = admin_roles.grant_role(
            admin_roles.RoleGrantReq(target_user_sub="u1", role="admin", reason="promotion"),
            _req("rid-123"),
            _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
            actor=AuthenticatedUser(sub="root", role=Role.ROOT),
        )
    assert resp["ok"] is True
    assert resp["role"] == "admin"
    assert resp["event_id"]
    users.update_item.assert_called_once()
    role_audit.put_item.assert_called_once()
    assert role_audit.put_item.call_args.kwargs["ConditionExpression"] == "attribute_not_exists(event_id)"
    assert audit.called
    assert any(call.kwargs.get("target_user_sub") == "u1" and call.kwargs.get("actor_sub") == "root" for call in audit.call_args_list)


def test_revoke_role_rejects_when_not_admin() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u1", "role": "user"}}
    role_audit = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)):
        with pytest.raises(HTTPException) as exc:
            admin_roles.revoke_role(
                admin_roles.RoleRevokeReq(target_user_sub="u1", role="admin", reason="cleanup"),
                _req(),
                _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
                actor=AuthenticatedUser(sub="root", role=Role.ROOT),
            )
    assert exc.value.status_code == 409
    assert "not admin" in str(exc.value.detail)


def test_revoke_role_success_updates_user_and_writes_immutable_audit() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u1", "role": "admin"}}
    role_audit = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)), patch.object(admin_roles, "audit_event") as audit, patch.object(
        admin_roles, "now_ts", return_value=1001
    ):
        resp = admin_roles.revoke_role(
            admin_roles.RoleRevokeReq(target_user_sub="u1", role="admin", reason="cleanup"),
            _req("rid-124"),
            _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
            actor=AuthenticatedUser(sub="root", role=Role.ROOT),
        )
    assert resp["ok"] is True
    assert resp["role"] == "user"
    assert resp["event_id"]
    users.update_item.assert_called_once()
    role_audit.put_item.assert_called_once()
    assert role_audit.put_item.call_args.kwargs["ConditionExpression"] == "attribute_not_exists(event_id)"


def test_role_mutations_apply_admin_action_rate_limit() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u1", "role": "user"}}
    role_audit = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)), patch.object(admin_roles, "audit_event"), patch.object(
        admin_roles, "rate_limit_admin_action"
    ) as limiter:
        admin_roles.grant_role(
            admin_roles.RoleGrantReq(target_user_sub="u1", role="admin", reason="ops"),
            _req(),
            _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
            actor=AuthenticatedUser(sub="root", role=Role.ROOT),
        )

    limiter.assert_called_once_with("root", "role_grant")


def test_list_role_audit_queries_by_actor_and_date_range_with_cursor() -> None:
    role_audit = Mock()
    role_audit.query.return_value = {
        "Items": [
            {
                "event_id": "e1",
                "action": "grant",
                "actor_sub": "root",
                "target_user_sub": "u1",
                "previous_role": "user",
                "new_role": "admin",
                "reason": "ops",
                "ip": "127.0.0.1",
                "request_id": "rid",
                "ts": 100,
            }
        ],
        "LastEvaluatedKey": {"pk": "ACTOR#root", "sk": "TS#0000000000100#e1"},
    }
    users = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)), patch.object(admin_roles, "now_ts", return_value=500):
        resp = admin_roles.list_role_audit(
            actor_sub="root",
            start_ts=1,
            end_ts=200,
            limit=10,
            cursor=None,
            _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
            _actor=AuthenticatedUser(sub="root", role=Role.ROOT),
        )

    role_audit.query.assert_called_once()
    assert len(resp["items"]) == 1
    assert resp["items"][0]["actor_sub"] == "root"
    assert resp["cursor"]


def test_list_role_audit_scan_without_actor_and_sorts_desc() -> None:
    role_audit = Mock()
    role_audit.scan.return_value = {
        "Items": [
            {"event_id": "e1", "actor_sub": "a", "target_user_sub": "u1", "ts": 100},
            {"event_id": "e2", "actor_sub": "b", "target_user_sub": "u2", "ts": 200},
        ],
        "LastEvaluatedKey": None,
    }
    users = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)), patch.object(admin_roles, "now_ts", return_value=500):
        resp = admin_roles.list_role_audit(
            actor_sub=None,
            start_ts=1,
            end_ts=400,
            limit=10,
            cursor=None,
            _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
            _actor=AuthenticatedUser(sub="root", role=Role.ROOT),
        )

    role_audit.scan.assert_called_once()
    assert [it["event_id"] for it in resp["items"]] == ["e2", "e1"]
