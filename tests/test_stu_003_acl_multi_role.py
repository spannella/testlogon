"""STU-003: ACL multi-role + group propagation — offline hermetic tests."""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import boto3
import pytest

try:
    from moto import mock_aws
except Exception:
    mock_aws = None

from app.auth.roles import AdminProfile, AdminProfileType, AdminScope


def _make_acl_table(ddb):
    return ddb.create_table(
        TableName="crm_acl_roles_test3",
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
        import app.services.crm_acl as svc
        svc._perm_cache.clear()
        yield table
        object.__setattr__(S, "crm_acl_enabled", False)
        svc._perm_cache.clear()


@pytest.fixture(autouse=True)
def patch_audit():
    with patch("app.services.alerts.audit_event", return_value=None):
        yield


def _make_perms(**module_perms):
    """Helper: build permission dict from keyword args of shape contacts__read=True."""
    result = {}
    for k, v in module_perms.items():
        module, action = k.split("__", 1)
        if module not in result:
            result[module] = {"read": False, "create": False, "update": False, "delete": False, "export": False, "import_": False, "mass_update": False}
        result[module][action] = v
    return result


GENERAL_PROFILE = AdminProfile(type=AdminProfileType.GENERAL)
SCOPED_AUTH_PROFILE = AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.AUTH_SUPPORT,))
SCOPED_BILLING_PROFILE = AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.BILLING_SUPPORT,))


class TestMultiRoleUnion:
    def test_union_two_direct_roles(self):
        from app.services import crm_acl as svc
        r1 = svc.create_acl_role("root", "R1", "", _make_perms(contacts__read=True, contacts__export=False))
        r2 = svc.create_acl_role("root", "R2", "", _make_perms(contacts__read=False, contacts__export=True))
        svc.assign_role_to_user("root", r1["role_id"], "alice")
        svc.assign_role_to_user("root", r2["role_id"], "alice")
        svc._perm_cache.clear()
        assert svc.check_permission("alice", "contacts", "read", GENERAL_PROFILE) is True
        assert svc.check_permission("alice", "contacts", "export", GENERAL_PROFILE) is True
        assert svc.check_permission("alice", "tickets", "create", GENERAL_PROFILE) is False

    def test_single_role_no_union_needed(self):
        from app.services import crm_acl as svc
        r1 = svc.create_acl_role("root", "R1", "", _make_perms(contacts__read=True, contacts__export=False))
        svc.assign_role_to_user("root", r1["role_id"], "bob")
        svc._perm_cache.clear()
        assert svc.check_permission("bob", "contacts", "read", GENERAL_PROFILE) is True
        assert svc.check_permission("bob", "contacts", "export", GENERAL_PROFILE) is False


class TestGroupPropagation:
    def test_group_assignment_scoped_profile(self):
        from app.services import crm_acl as svc
        r1 = svc.create_acl_role("root", "R1", "", _make_perms(contacts__read=True))
        svc.assign_role_to_group("root", r1["role_id"], "auth_support")
        svc._perm_cache.clear()
        # charlie has no direct role but is in auth_support group
        assert svc.check_permission("charlie", "contacts", "read", SCOPED_AUTH_PROFILE) is True
        assert svc.check_permission("charlie", "contacts", "export", SCOPED_AUTH_PROFILE) is False

    def test_group_assignment_general_profile(self):
        from app.services import crm_acl as svc
        r2 = svc.create_acl_role("root", "R2", "", _make_perms(contacts__export=True))
        svc.assign_role_to_group("root", r2["role_id"], "billing_support")
        svc._perm_cache.clear()
        assert svc.check_permission("dave", "contacts", "export", GENERAL_PROFILE) is True

    def test_group_plus_direct_union(self):
        from app.services import crm_acl as svc
        r1 = svc.create_acl_role("root", "R1", "", _make_perms(contacts__read=True))
        r2 = svc.create_acl_role("root", "R2", "", _make_perms(contacts__export=True))
        svc.assign_role_to_user("root", r1["role_id"], "alice")
        svc.assign_role_to_group("root", r2["role_id"], "auth_support")
        svc._perm_cache.clear()
        assert svc.check_permission("alice", "contacts", "read", SCOPED_AUTH_PROFILE) is True
        assert svc.check_permission("alice", "contacts", "export", SCOPED_AUTH_PROFILE) is True

    def test_flag_off_returns_true(self):
        from app.core.settings import S
        from app.services import crm_acl as svc
        object.__setattr__(S, "crm_acl_enabled", False)
        assert svc.check_permission("nobody", "contacts", "delete", GENERAL_PROFILE) is True

    def test_assign_group_audit_event(self):
        from app.services import crm_acl as svc
        r = svc.create_acl_role("root", "R", "", {})
        with patch("app.services.alerts.audit_event") as mock_audit:
            svc.assign_role_to_group("root", r["role_id"], "auth_support")
            calls = [c.args[0] for c in mock_audit.call_args_list]
            assert "crm_acl_role.group_assigned" in calls

    def test_revoke_group_audit_event(self):
        from app.services import crm_acl as svc
        r = svc.create_acl_role("root", "R", "", {})
        svc.assign_role_to_group("root", r["role_id"], "auth_support")
        with patch("app.services.alerts.audit_event") as mock_audit:
            svc.revoke_role_from_group("root", r["role_id"], "auth_support")
            calls = [c.args[0] for c in mock_audit.call_args_list]
            assert "crm_acl_role.group_revoked" in calls

    def test_revoke_group_idempotent(self):
        from app.services import crm_acl as svc
        r = svc.create_acl_role("root", "R", "", {})
        # Should not raise even if not assigned
        svc.revoke_role_from_group("root", r["role_id"], "auth_support")
        svc.revoke_role_from_group("root", r["role_id"], "auth_support")

    def test_assign_group_idempotent(self):
        from app.services import crm_acl as svc
        r = svc.create_acl_role("root", "R", "", {})
        svc.assign_role_to_group("root", r["role_id"], "auth_support")
        # Second call should not raise
        svc.assign_role_to_group("root", r["role_id"], "auth_support")

    def test_cache_invalidation_on_group_assignment(self):
        from app.services import crm_acl as svc
        r = svc.create_acl_role("root", "R", "", _make_perms(contacts__read=True))
        svc._perm_cache.clear()
        # Warm cache: charlie has no roles → False
        result1 = svc.check_permission("charlie", "contacts", "read", SCOPED_AUTH_PROFILE)
        assert result1 is False
        # Assign group role
        svc.assign_role_to_group("root", r["role_id"], "auth_support")
        # Cache must be cleared
        assert not svc._perm_cache  # entire cache cleared
        result2 = svc.check_permission("charlie", "contacts", "read", SCOPED_AUTH_PROFILE)
        assert result2 is True

    def test_list_role_assignments_returns_both_types(self):
        from app.services import crm_acl as svc
        r = svc.create_acl_role("root", "R", "", {})
        rid = r["role_id"]
        svc.assign_role_to_user("root", rid, "alice")
        svc.assign_role_to_group("root", rid, "billing_support")
        result = svc.list_role_assignments(rid)
        assert len(result["user_assignments"]) == 1
        assert result["user_assignments"][0]["user_sub"] == "alice"
        assert len(result["group_assignments"]) == 1
        assert result["group_assignments"][0]["group_key"] == "billing_support"

    def test_invalid_group_key_rejected(self):
        from fastapi import HTTPException
        from app.services import crm_acl as svc
        r = svc.create_acl_role("root", "R", "", {})
        with pytest.raises(HTTPException) as exc:
            svc.assign_role_to_group("root", r["role_id"], "INVALID KEY!")
        assert exc.value.status_code == 400

    def test_role_deletion_cascades_to_group_assignments(self):
        from app.services import crm_acl as svc
        r = svc.create_acl_role("root", "R", "", {})
        rid = r["role_id"]
        svc.assign_role_to_group("root", rid, "auth_support")
        svc.delete_acl_role("root", rid)
        # Group assignment row should be gone
        from app.core.tables import T
        resp = T.crm_acl_roles.get_item(Key={"pk": f"ROLE#{rid}", "sk": "GROUP_ASSIGNMENT#auth_support"})
        assert resp.get("Item") is None
