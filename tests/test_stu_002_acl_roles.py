"""STU-002: CRM ACL Role matrix — offline hermetic tests.

Tests service layer directly (no TestClient).
Uses moto in-memory DynamoDB bound via object.__setattr__.
"""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import boto3
import pytest

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None


def _make_acl_table(ddb):
    return ddb.create_table(
        TableName="crm_acl_roles_test",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "assignee_id", "AttributeType": "S"},
            {"AttributeName": "assigned_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "by-assignee",
            "KeySchema": [
                {"AttributeName": "assignee_id", "KeyType": "HASH"},
                {"AttributeName": "assigned_at", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )


@pytest.fixture(autouse=True)
def moto_ddb():
    if mock_aws is None:
        pytest.skip("moto not available")
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = _make_acl_table(ddb)
        from app.core.tables import T
        from app.core.settings import S
        object.__setattr__(T, "crm_acl_roles", table)
        object.__setattr__(S, "crm_acl_enabled", True)
        # Clear module-level cache
        import app.services.crm_acl as svc
        svc._perm_cache.clear()
        yield table
        object.__setattr__(S, "crm_acl_enabled", False)
        svc._perm_cache.clear()


@pytest.fixture()
def audit_mock():
    with patch("app.services.crm_acl.audit_event", autospec=False) as m:
        # The module calls _get_alerts() which returns audit_event — patch at source
        yield m


# We patch audit_event at the module level
@pytest.fixture(autouse=True)
def patch_audit():
    with patch("app.services.alerts.audit_event", return_value=None):
        yield


class TestCreateRole:
    def test_create_role_writes_meta(self):
        from app.services import crm_acl as svc
        result = svc.create_acl_role("root_sub", "SalesRole", "desc", {})
        assert "role_id" in result
        assert result["name"] == "SalesRole"

        fetched = svc.get_acl_role(result["role_id"])
        assert fetched["role_id"] == result["role_id"]

    def test_get_role_not_found(self):
        from fastapi import HTTPException
        from app.services import crm_acl as svc
        with pytest.raises(HTTPException) as exc:
            svc.get_acl_role("nonexistent")
        assert exc.value.status_code == 404

    def test_update_role_patches_name(self):
        from app.services import crm_acl as svc
        role = svc.create_acl_role("root_sub", "OldName", "", {})
        rid = role["role_id"]
        updated = svc.update_acl_role("root_sub", rid, name="NewName")
        assert updated["name"] == "NewName"
        assert updated.get("updated_by_sub") == "root_sub"


class TestDeleteRole:
    def test_delete_role_removes_meta_and_assignments(self):
        from app.services import crm_acl as svc
        role = svc.create_acl_role("root_sub", "TmpRole", "", {})
        rid = role["role_id"]
        svc.assign_role_to_user("root_sub", rid, "alice")
        svc.assign_role_to_user("root_sub", rid, "bob")
        svc.delete_acl_role("root_sub", rid)
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            svc.get_acl_role(rid)

    def test_delete_role_not_found(self):
        from fastapi import HTTPException
        from app.services import crm_acl as svc
        with pytest.raises(HTTPException):
            svc.delete_acl_role("root_sub", "no_such_role")


class TestAssignments:
    def test_assign_writes_assignment_row(self):
        from app.services import crm_acl as svc
        role = svc.create_acl_role("root_sub", "R", "", {})
        rid = role["role_id"]
        svc.assign_role_to_user("root_sub", rid, "alice")
        assignments = svc.list_assignments_for_role(rid)
        assert len(assignments) == 1
        assert assignments[0]["user_sub"] == "alice"

    def test_revoke_removes_assignment(self):
        from app.services import crm_acl as svc
        role = svc.create_acl_role("root_sub", "R", "", {})
        rid = role["role_id"]
        svc.assign_role_to_user("root_sub", rid, "alice")
        svc.revoke_role_from_user("root_sub", rid, "alice")
        assignments = svc.list_assignments_for_role(rid)
        assert len(assignments) == 0

    def test_revoke_idempotent(self):
        from app.services import crm_acl as svc
        role = svc.create_acl_role("root_sub", "R", "", {})
        rid = role["role_id"]
        # Second call should not raise
        svc.revoke_role_from_user("root_sub", rid, "alice")

    def test_get_roles_for_user_via_gsi(self):
        from app.services import crm_acl as svc
        roleA = svc.create_acl_role("root_sub", "RoleA", "", {})
        roleB = svc.create_acl_role("root_sub", "RoleB", "", {})
        svc.assign_role_to_user("root_sub", roleA["role_id"], "alice")
        svc.assign_role_to_user("root_sub", roleB["role_id"], "alice")
        roles = svc.get_roles_for_user("alice")
        role_names = {r["name"] for r in roles}
        assert "RoleA" in role_names
        assert "RoleB" in role_names


class TestCheckPermission:
    def test_check_permission_flag_off(self):
        from app.core.settings import S
        from app.services import crm_acl as svc
        object.__setattr__(S, "crm_acl_enabled", False)
        assert svc.check_permission("nobody", "contacts", "delete") is True

    def test_check_permission_no_roles(self):
        from app.services import crm_acl as svc
        assert svc.check_permission("alice", "contacts", "read") is False

    def test_check_permission_grants_action(self):
        from app.services import crm_acl as svc
        perms = {"contacts": {"read": True, "create": False, "update": False, "delete": False, "export": False, "import_": False, "mass_update": False}}
        role = svc.create_acl_role("root_sub", "ReadRole", "", perms)
        svc.assign_role_to_user("root_sub", role["role_id"], "alice")
        svc._perm_cache.clear()
        assert svc.check_permission("alice", "contacts", "read") is True

    def test_check_permission_denies_missing_action(self):
        from app.services import crm_acl as svc
        perms = {"contacts": {"read": True, "create": False, "update": False, "delete": False, "export": False, "import_": False, "mass_update": False}}
        role = svc.create_acl_role("root_sub", "ReadRole", "", perms)
        svc.assign_role_to_user("root_sub", role["role_id"], "bob")
        svc._perm_cache.clear()
        assert svc.check_permission("bob", "contacts", "export") is False

    def test_check_permission_union(self):
        from app.services import crm_acl as svc
        permsA = {"contacts": {"read": True, "export": False, "create": False, "update": False, "delete": False, "import_": False, "mass_update": False}}
        permsB = {"contacts": {"read": False, "export": True, "create": False, "update": False, "delete": False, "import_": False, "mass_update": False}}
        roleA = svc.create_acl_role("root_sub", "A", "", permsA)
        roleB = svc.create_acl_role("root_sub", "B", "", permsB)
        svc.assign_role_to_user("root_sub", roleA["role_id"], "charlie")
        svc.assign_role_to_user("root_sub", roleB["role_id"], "charlie")
        svc._perm_cache.clear()
        assert svc.check_permission("charlie", "contacts", "read") is True
        assert svc.check_permission("charlie", "contacts", "export") is True

    def test_cache_invalidation_on_revoke(self):
        from app.services import crm_acl as svc
        perms = {"contacts": {"read": True, "create": False, "update": False, "delete": False, "export": False, "import_": False, "mass_update": False}}
        role = svc.create_acl_role("root_sub", "R", "", perms)
        svc.assign_role_to_user("root_sub", role["role_id"], "dave")
        svc._perm_cache.clear()
        # Warm cache
        assert svc.check_permission("dave", "contacts", "read") is True
        # Revoke
        svc.revoke_role_from_user("root_sub", role["role_id"], "dave")
        # Cache should be invalidated
        assert "dave" not in svc._perm_cache
        assert svc.check_permission("dave", "contacts", "read") is False

    def test_require_crm_permission_dep_raises_403(self):
        from fastapi import HTTPException
        from app.services import crm_acl as svc
        from app.auth.deps import AuthenticatedUser
        from app.auth.roles import Role, AdminProfile

        user = AuthenticatedUser(sub="nobody", role=Role.USER, admin_profile=AdminProfile())

        async def run():
            dep_fn = svc.require_crm_permission("contacts", "create")
            inner = dep_fn.dependency
            await inner(user=user)

        loop = asyncio.new_event_loop()
        try:
            with pytest.raises(HTTPException) as exc:
                loop.run_until_complete(run())
            assert exc.value.status_code == 403
        finally:
            loop.close()


class TestListRoles:
    def test_list_roles_returns_items(self):
        from app.services import crm_acl as svc
        svc.create_acl_role("root_sub", "Role1", "", {})
        svc.create_acl_role("root_sub", "Role2", "", {})
        items, cursor = svc.list_acl_roles(limit=10)
        assert len(items) >= 2
