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
    assert resp["admin_profile"] == {"type": "general"}
    assert resp["event_id"]
    users.update_item.assert_called_once()
    role_audit.put_item.assert_called_once()
    assert role_audit.put_item.call_args.kwargs["ConditionExpression"] == "attribute_not_exists(event_id)"
    audit_item = role_audit.put_item.call_args.kwargs["Item"]
    assert audit_item["previous_admin_profile"] == {"type": "general"}
    assert audit_item["new_admin_profile"] == {"type": "general"}
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
    audit_item = role_audit.put_item.call_args.kwargs["Item"]
    assert audit_item["previous_admin_profile"] == {"type": "general"}
    assert audit_item["new_admin_profile"] is None


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
                "previous_admin_profile": {"type": "general"},
                "new_admin_profile": {"type": "scoped", "scopes": ["billing_support"]},
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
    assert resp["items"][0]["previous_admin_profile"] == {"type": "general"}
    assert resp["items"][0]["new_admin_profile"] == {"type": "scoped", "scopes": ["billing_support"]}
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


def test_grant_role_supports_scoped_admin_profile() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u2", "role": "user"}}
    role_audit = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)), patch.object(admin_roles, "audit_event"), patch.object(
        admin_roles, "now_ts", return_value=1000
    ):
        resp = admin_roles.grant_role(
            admin_roles.RoleGrantReq(
                target_user_sub="u2",
                role="admin",
                reason="billing",
                admin_profile_type="scoped",
                admin_scopes=["billing_support", "auth_support"],
            ),
            _req("rid-125"),
            _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
            actor=AuthenticatedUser(sub="root", role=Role.ROOT),
        )

    assert resp["ok"] is True
    assert resp["admin_profile"] == {"type": "scoped", "scopes": ["auth_support", "billing_support"]}
    expr_vals = users.update_item.call_args.kwargs["ExpressionAttributeValues"]
    assert expr_vals[":admin_profile"] == {"type": "scoped", "scopes": ["auth_support", "billing_support"]}


def test_grant_role_rejects_invalid_admin_profile_type() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u1", "role": "user"}}
    role_audit = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)):
        with pytest.raises(HTTPException) as exc:
            admin_roles.grant_role(
                admin_roles.RoleGrantReq(target_user_sub="u1", role="admin", reason="ops", admin_profile_type="bad"),
                _req(),
                _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
                actor=AuthenticatedUser(sub="root", role=Role.ROOT),
            )

    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "invalid_admin_profile_type"


def test_grant_role_rejects_scoped_admin_profile_with_empty_scopes() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u1", "role": "user"}}
    role_audit = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)):
        with pytest.raises(HTTPException) as exc:
            admin_roles.grant_role(
                admin_roles.RoleGrantReq(target_user_sub="u1", role="admin", reason="ops", admin_profile_type="scoped", admin_scopes=[]),
                _req(),
                _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
                actor=AuthenticatedUser(sub="root", role=Role.ROOT),
            )

    assert exc.value.status_code == 400
    assert exc.value.detail == {"code": "invalid_admin_scopes", "reason": "scoped_profile_requires_non_empty_scopes"}


def test_grant_role_rejects_duplicate_admin_scopes() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u1", "role": "user"}}
    role_audit = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)):
        with pytest.raises(HTTPException) as exc:
            admin_roles.grant_role(
                admin_roles.RoleGrantReq(
                    target_user_sub="u1",
                    role="admin",
                    reason="ops",
                    admin_profile_type="scoped",
                    admin_scopes=["billing_support", "billing_support"],
                ),
                _req(),
                _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
                actor=AuthenticatedUser(sub="root", role=Role.ROOT),
            )

    assert exc.value.status_code == 400
    assert exc.value.detail == {
        "code": "invalid_admin_scopes",
        "reason": "duplicate_scope_values",
        "duplicate_scopes": ["billing_support"],
    }


def test_grant_role_rejects_unknown_admin_scope_values() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u1", "role": "user"}}
    role_audit = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)):
        with pytest.raises(HTTPException) as exc:
            admin_roles.grant_role(
                admin_roles.RoleGrantReq(
                    target_user_sub="u1",
                    role="admin",
                    reason="ops",
                    admin_profile_type="scoped",
                    admin_scopes=["nope"],
                ),
                _req(),
                _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
                actor=AuthenticatedUser(sub="root", role=Role.ROOT),
            )

    assert exc.value.status_code == 400
    assert exc.value.detail == {
        "code": "invalid_admin_scopes",
        "reason": "unknown_scope_values",
        "invalid_scopes": ["nope"],
        "allowed_scopes": ["auth_support", "billing_support", "content_moderation"],
    }


def test_grant_role_rejects_scopes_for_general_profile() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u1", "role": "user"}}
    role_audit = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)):
        with pytest.raises(HTTPException) as exc:
            admin_roles.grant_role(
                admin_roles.RoleGrantReq(
                    target_user_sub="u1",
                    role="admin",
                    reason="ops",
                    admin_profile_type="general",
                    admin_scopes=["auth_support"],
                ),
                _req(),
                _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
                actor=AuthenticatedUser(sub="root", role=Role.ROOT),
            )

    assert exc.value.status_code == 400
    assert exc.value.detail == {"code": "invalid_admin_scopes", "reason": "general_profile_disallows_scopes"}


def test_update_role_profile_updates_admin_to_scoped_profile() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u1", "role": "admin"}}
    role_audit = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)), patch.object(admin_roles, "audit_event") as audit, patch.object(
        admin_roles, "now_ts", return_value=1002
    ):
        resp = admin_roles.update_role_profile(
            admin_roles.RoleUpdateProfileReq(
                target_user_sub="u1",
                admin_profile_type="scoped",
                admin_scopes=["content_moderation", "auth_support"],
                reason="team shift",
            ),
            _req("rid-126"),
            _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
            actor=AuthenticatedUser(sub="root", role=Role.ROOT),
        )

    assert resp["ok"] is True
    assert resp["target_user_sub"] == "u1"
    assert resp["role"] == "admin"
    assert resp["admin_profile"] == {"type": "scoped", "scopes": ["auth_support", "content_moderation"]}
    assert resp["event_id"]
    users.update_item.assert_called_once()
    role_audit.put_item.assert_called_once()
    update_audit_item = role_audit.put_item.call_args.kwargs["Item"]
    assert update_audit_item["action"] == "update_profile"
    assert update_audit_item["previous_admin_profile"] == {"type": "general"}
    assert update_audit_item["new_admin_profile"] == {"type": "scoped", "scopes": ["auth_support", "content_moderation"]}
    assert users.update_item.call_args.kwargs["ExpressionAttributeValues"][":admin_profile"] == {
        "type": "scoped",
        "scopes": ["auth_support", "content_moderation"],
    }
    assert any(call.args[0] == "admin_role_profile_updated" for call in audit.call_args_list)


def test_update_role_profile_supports_scoped_to_general_transition() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u1", "role": "admin", "admin_profile": {"type": "scoped", "scopes": ["billing_support"]}}}
    role_audit = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)), patch.object(admin_roles, "audit_event"):
        resp = admin_roles.update_role_profile(
            admin_roles.RoleUpdateProfileReq(target_user_sub="u1", admin_profile_type="general", admin_scopes=[], reason="promoted"),
            _req("rid-127"),
            _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
            actor=AuthenticatedUser(sub="root", role=Role.ROOT),
        )

    assert resp["admin_profile"] == {"type": "general"}


def test_update_role_profile_rejects_non_root_actor() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u1", "role": "admin"}}
    role_audit = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)):
        with pytest.raises(HTTPException) as exc:
            admin_roles.update_role_profile(
                admin_roles.RoleUpdateProfileReq(target_user_sub="u1", admin_profile_type="general", admin_scopes=[]),
                _req(),
                _ctx={"user_sub": "admin", "session_id": "sid", "role": "admin"},
                actor=AuthenticatedUser(sub="admin", role=Role.ADMIN),
            )

    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "role_required"


def test_update_role_profile_rejects_non_admin_target() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u1", "role": "user"}}
    role_audit = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)):
        with pytest.raises(HTTPException) as exc:
            admin_roles.update_role_profile(
                admin_roles.RoleUpdateProfileReq(target_user_sub="u1", admin_profile_type="general", admin_scopes=[]),
                _req(),
                _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
                actor=AuthenticatedUser(sub="root", role=Role.ROOT),
            )

    assert exc.value.status_code == 409
    assert "not admin" in str(exc.value.detail)


def test_update_role_profile_rejects_root_target() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "root-user", "role": "root"}}
    role_audit = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)), patch.object(admin_roles, "S", SimpleNamespace(root_user_sub="root-user")):
        with pytest.raises(HTTPException) as exc:
            admin_roles.update_role_profile(
                admin_roles.RoleUpdateProfileReq(target_user_sub="root-user", admin_profile_type="general", admin_scopes=[]),
                _req(),
                _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
                actor=AuthenticatedUser(sub="root", role=Role.ROOT),
            )

    assert exc.value.status_code == 409
    assert "cannot modify root" in str(exc.value.detail)


def test_update_role_profile_rejects_invalid_profile_payload() -> None:
    users = Mock()
    users.get_item.return_value = {"Item": {"user_sub": "u1", "role": "admin"}}
    role_audit = Mock()
    with patch.object(admin_roles, "T", _tables(users, role_audit)):
        with pytest.raises(HTTPException) as exc:
            admin_roles.update_role_profile(
                admin_roles.RoleUpdateProfileReq(target_user_sub="u1", admin_profile_type="scoped", admin_scopes=[]),
                _req(),
                _ctx={"user_sub": "root", "session_id": "sid", "role": "root"},
                actor=AuthenticatedUser(sub="root", role=Role.ROOT),
            )

    assert exc.value.status_code == 400
    assert exc.value.detail == {"code": "invalid_admin_scopes", "reason": "scoped_profile_requires_non_empty_scopes"}
