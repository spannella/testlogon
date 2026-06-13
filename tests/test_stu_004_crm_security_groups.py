"""STU-004: CRM Security Groups — offline hermetic tests."""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import boto3
import pytest

try:
    from moto import mock_aws
except Exception:
    mock_aws = None


def _make_sg_table(ddb):
    return ddb.create_table(
        TableName="crm_sg_test",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "record_ref", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "by-record",
            "KeySchema": [
                {"AttributeName": "record_ref", "KeyType": "HASH"},
                {"AttributeName": "created_at", "KeyType": "RANGE"},
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
        table = _make_sg_table(ddb)
        from app.core.tables import T
        from app.core.settings import S
        object.__setattr__(T, "crm_security_groups", table)
        object.__setattr__(S, "crm_acl_enabled", True)
        import app.services.crm_security_groups as svc
        svc._member_cache.clear()
        yield table
        object.__setattr__(S, "crm_acl_enabled", False)
        svc._member_cache.clear()


@pytest.fixture(autouse=True)
def patch_audit():
    with patch("app.services.alerts.audit_event", return_value=None):
        yield


class TestGroupCRUD:
    def test_create_and_get_group(self):
        from app.services import crm_security_groups as svc
        g = svc.create_group("admin1", "Sales", "Sales team", False)
        assert g["name"] == "Sales"
        assert g["is_global"] is False
        fetched = svc.get_group(g["group_id"])
        assert fetched is not None
        assert fetched["name"] == "Sales"

    def test_get_group_not_found(self):
        from app.services import crm_security_groups as svc
        result = svc.get_group("nonexistent")
        assert result is None

    def test_list_groups_returns_meta_rows(self):
        from app.services import crm_security_groups as svc
        svc.create_group("admin1", "G1", "", False)
        svc.create_group("admin1", "G2", "", True)
        items, _ = svc.list_groups(limit=10)
        assert len(items) >= 2

    def test_list_groups_is_global_filter(self):
        from app.services import crm_security_groups as svc
        svc.create_group("admin1", "Local", "", False)
        svc.create_group("admin1", "Global", "", True)
        items, _ = svc.list_groups(limit=10, is_global=True)
        assert all(i.get("is_global") is True for i in items)

    def test_delete_group_cascade(self):
        from app.services import crm_security_groups as svc
        g = svc.create_group("admin1", "ToDelete", "", False)
        gid = g["group_id"]
        svc.add_member("admin1", gid, "alice")
        svc.add_member("admin1", gid, "bob")
        svc.assign_record("admin1", gid, "ticket", "tkt_abc")
        svc.delete_group("admin1", gid)
        assert svc.get_group(gid) is None
        assert svc.get_groups_for_record("ticket", "tkt_abc") == []

    def test_delete_group_not_found(self):
        from fastapi import HTTPException
        from app.services import crm_security_groups as svc
        with pytest.raises(HTTPException) as exc:
            svc.delete_group("admin1", "no_such_group")
        assert exc.value.status_code == 404


class TestMembership:
    def test_add_and_remove_member(self):
        from app.services import crm_security_groups as svc
        g = svc.create_group("admin1", "G", "", False)
        gid = g["group_id"]
        svc.add_member("admin1", gid, "alice", can_edit=True)
        assert gid in svc.get_member_group_ids("alice")
        svc.remove_member("admin1", gid, "alice")
        svc._member_cache.clear()
        assert gid not in svc.get_member_group_ids("alice")

    def test_membership_cache_invalidation(self):
        from app.services import crm_security_groups as svc
        g = svc.create_group("admin1", "G", "", False)
        gid = g["group_id"]
        svc.add_member("admin1", gid, "eve")
        # Warm cache
        ids = svc.get_member_group_ids("eve")
        assert gid in ids
        svc.remove_member("admin1", gid, "eve")
        # Cache should be invalidated (set to [], 0)
        assert svc._member_cache.get("eve") == ([], 0)
        svc._member_cache.clear()
        ids2 = svc.get_member_group_ids("eve")
        assert gid not in ids2


class TestRecordAssignment:
    def test_assign_and_unassign_record(self):
        from app.services import crm_security_groups as svc
        g = svc.create_group("admin1", "G", "", False)
        gid = g["group_id"]
        svc.assign_record("admin1", gid, "ticket", "tkt_abc")
        assert gid in svc.get_groups_for_record("ticket", "tkt_abc")
        svc.unassign_record("admin1", gid, "ticket", "tkt_abc")
        assert gid not in svc.get_groups_for_record("ticket", "tkt_abc")


class TestEnforcement:
    def test_open_access_no_groups(self):
        from app.services import crm_security_groups as svc
        # No record assignments → open access
        assert svc.user_can_access_record("alice", "ticket", "tkt_1") is True

    def test_access_member_of_group(self):
        from app.services import crm_security_groups as svc
        g = svc.create_group("admin1", "G", "", False)
        gid = g["group_id"]
        svc.assign_record("admin1", gid, "ticket", "tkt_1")
        svc.add_member("admin1", gid, "alice")
        svc._member_cache.clear()
        assert svc.user_can_access_record("alice", "ticket", "tkt_1") is True
        svc._member_cache.clear()
        assert svc.user_can_access_record("bob", "ticket", "tkt_1") is False

    def test_admin_bypass(self):
        from app.services import crm_security_groups as svc
        from app.auth.roles import Role
        g = svc.create_group("admin1", "G", "", False)
        gid = g["group_id"]
        svc.assign_record("admin1", gid, "ticket", "tkt_1")
        # charlie is not a member but is ADMIN
        assert svc.user_can_access_record("charlie", "ticket", "tkt_1", role=Role.ADMIN) is True

    def test_flag_off_returns_true(self):
        from app.core.settings import S
        from app.services import crm_security_groups as svc
        object.__setattr__(S, "crm_acl_enabled", False)
        g = svc.create_group("admin1", "G", "", False)
        gid = g["group_id"]
        svc.assign_record("admin1", gid, "ticket", "tkt_1")
        # bob not a member but flag is off
        assert svc.user_can_access_record("bob", "ticket", "tkt_1") is True

    def test_filter_records_by_access(self):
        from app.services import crm_security_groups as svc
        g = svc.create_group("admin1", "G", "", False)
        gid = g["group_id"]
        svc.assign_record("admin1", gid, "ticket", "tkt_1")
        svc.assign_record("admin1", gid, "ticket", "tkt_2")
        svc.add_member("admin1", gid, "alice")
        svc._member_cache.clear()
        # tkt_3 has no group → open access
        records = [
            {"ticket_id": "tkt_1"},
            {"ticket_id": "tkt_2"},
            {"ticket_id": "tkt_3"},
        ]
        result = svc.filter_records_by_access("alice", "ticket", records, record_id_field="ticket_id")
        ids = {r["ticket_id"] for r in result}
        assert "tkt_1" in ids
        assert "tkt_2" in ids
        assert "tkt_3" in ids  # open access

    def test_fail_open_on_ddb_error(self):
        from app.services import crm_security_groups as svc
        with patch.object(svc, "get_groups_for_record", side_effect=Exception("DDB timeout")):
            assert svc.user_can_access_record("alice", "ticket", "tkt_x") is True

    def test_filter_records_flag_off_passthrough(self):
        from app.core.settings import S
        from app.services import crm_security_groups as svc
        object.__setattr__(S, "crm_acl_enabled", False)
        records = [{"ticket_id": "t1"}, {"ticket_id": "t2"}]
        result = svc.filter_records_by_access("alice", "ticket", records)
        assert result == records


class TestGroupDetail:
    def test_get_group_with_detail(self):
        from app.services import crm_security_groups as svc
        g = svc.create_group("admin1", "G", "desc", False)
        gid = g["group_id"]
        svc.add_member("admin1", gid, "alice")
        svc.assign_record("admin1", gid, "ticket", "tkt_abc")
        detail = svc.get_group_with_detail(gid)
        assert detail is not None
        assert detail["meta"]["name"] == "G"
        assert detail["meta"]["member_count"] == 1
        assert detail["meta"]["record_count"] == 1
        assert len(detail["members"]) == 1
        assert len(detail["records"]) == 1
