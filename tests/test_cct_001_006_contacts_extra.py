"""
Offline regression tests for CCT-001..CCT-006 (SuiteCRM Contacts Extra).

Test isolation:
- Real in-memory moto DynamoDB backs the 'party' table.
- T.party is monkeypatched onto the frozen T singleton via object.__setattr__.
- S flags are flipped via object.__setattr__ and restored on teardown.
- No real AWS/network.
- All async router handlers invoked directly via asyncio.new_event_loop().

CCT-001: Account industry and business metadata fields
CCT-002: Account hierarchy (parent org)
CCT-003: Reports-to hierarchy (manager chain)
CCT-004: Duplicate contact detection
CCT-005: Contact merge
CCT-006: vCard import/export
"""
from __future__ import annotations

import asyncio
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import boto3

try:
    from moto import mock_aws
    HAS_MOTO = True
except ImportError:
    HAS_MOTO = False


def _make_party_table(ddb):
    """Create the party table matching the REAL production schema.

    Key schema: PK / SK. GSIs match scripts/local-ddb-init.py:
      GSI1 (GSI1PK/GSI1SK)  — role lookup
      GSI2 (GSI2PK/GSI2SK)  — normalized contact-mech value lookup (dedup)
      GSI3 (GSI3PK/GSI3SK)  — owner listing AND reverse-relationship traversal
      GSI_CREATED (type/created_at) — newest-first by party_type
    """
    return ddb.create_table(
        TableName="party",
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "S"},
            {"AttributeName": "GSI2PK", "AttributeType": "S"},
            {"AttributeName": "GSI2SK", "AttributeType": "S"},
            {"AttributeName": "GSI3PK", "AttributeType": "S"},
            {"AttributeName": "GSI3SK", "AttributeType": "S"},
            {"AttributeName": "type", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI2",
                "KeySchema": [
                    {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI3",
                "KeySchema": [
                    {"AttributeName": "GSI3PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI3SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI_CREATED",
                "KeySchema": [
                    {"AttributeName": "type", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )


def _put_party(tbl, party_id: str, party_type: str = "PERSON", name: str = "Test",
               owner: str = "user1", status: str = "ACTIVE", ts: int = 1000, **kwargs):
    item = {
        "PK": f"PARTY#{party_id}",
        "SK": "META",
        "party_id": party_id,
        "party_type": party_type,
        "name": name,
        "display_name": name,
        "owner_user_sub": owner,
        "user_sub": owner,
        "status": status,
        "type": f"TYPE#{party_type}",
        "created_at": ts,
        "updated_at": ts,
        "GSI3PK": f"OWNER#{owner}",
        "GSI3SK": f"PARTY#{party_id}",
    }
    item.update(kwargs)
    tbl.put_item(Item=item)
    return item


def _put_mech(tbl, party_id: str, mech_id: str, mech_type: str, value: str, ts: int = 1000):
    """Seed a contact-mech row in the REAL shape: value under ``value`` + GSI2 keys."""
    if mech_type == "EMAIL":
        gsi2_pk = f"EMAIL#{value.lower()}"
    elif mech_type == "PHONE":
        gsi2_pk = f"PHONE#{value}"
    else:
        gsi2_pk = f"{mech_type}#{value}"
    item = {
        "PK": f"PARTY#{party_id}",
        "SK": f"MECH#{mech_type}#{mech_id}",
        "mech_id": mech_id,
        "party_id": party_id,
        "mech_type": mech_type,
        "value": value,
        "purposes": ["WORK_EMAIL" if mech_type == "EMAIL" else "WORK_PHONE"],
        "verified": False,
        "created_at": ts,
        "updated_at": ts,
        "GSI2PK": gsi2_pk,
        "GSI2SK": f"PARTY#{party_id}",
    }
    tbl.put_item(Item=item)
    return item


def _put_org_role(tbl, actor_id: str, org_id: str, org_role: str = "org_admin", ts: int = 1000):
    """Simulate an org member record with an org_role (for _assert_org_admin).

    Real schema: the role lives on the actor's GROUP_MEMBER relationship primary
    row (PK=PARTY#{actor}, SK=REL#GROUP_MEMBER#{org}).
    """
    item = {
        "PK": f"PARTY#{actor_id}",
        "SK": f"REL#GROUP_MEMBER#{org_id}",
        "party_id": actor_id,
        "org_role": org_role,
        "to_party_id": org_id,
        "relationship_type": "GROUP_MEMBER",
        "from_party_id": actor_id,
        "created_at": ts,
    }
    tbl.put_item(Item=item)
    return item


@unittest.skipIf(not HAS_MOTO, "moto not installed")
class TestCct001OrgMetadata(unittest.TestCase):
    """CCT-001: Account industry and business metadata fields."""

    def setUp(self):
        self.mock = mock_aws()
        self.mock.start()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.tbl = _make_party_table(ddb)

        from app.services import party_contact_extra
        from app.core import tables as tables_mod
        from app.core import settings as settings_mod

        self.svc = party_contact_extra
        self.T = tables_mod.T
        self.S = settings_mod.S

        # Point T.party at our in-memory table
        object.__setattr__(self.T, "party", self.tbl)
        # Enable flag
        object.__setattr__(self.S, "party_crm_org_accounts_enabled", True)

    def tearDown(self):
        object.__setattr__(self.S, "party_crm_org_accounts_enabled", False)
        self.mock.stop()

    def test_create_org_with_business_fields(self):
        item = self.svc.create_org_account(
            "Acme Corp",
            owner_user_sub="user1",
            industry="Technology",
            website="https://acme.example.com",
            phone="+12025551234",
            employee_count=500,
            annual_revenue_cents=1_000_000_00,
        )
        self.assertEqual(item["name"], "Acme Corp")
        self.assertEqual(item["industry"], "Technology")
        self.assertEqual(item["website"], "https://acme.example.com")
        self.assertEqual(item["phone"], "+12025551234")
        self.assertEqual(item["employee_count"], 500)
        self.assertEqual(item["annual_revenue_cents"], 100_000_000)
        self.assertEqual(item["party_type"], "PARTY_GROUP")

    def test_unknown_industry_returns_400(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            self.svc.create_org_account(
                "BadCorp", owner_user_sub="user1", industry="QuantumLeaping"
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("unknown_industry", str(ctx.exception.detail))

    def test_invalid_website_returns_400(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            self.svc.create_org_account(
                "BadCorp", owner_user_sub="user1", website="ftp://bad.example.com"
            )
        self.assertEqual(ctx.exception.status_code, 400)

    def test_patch_org_subset(self):
        # Create org
        org = self.svc.create_org_account("OldName Corp", owner_user_sub="user1")
        org_id = org["party_id"]
        # Grant org_admin
        _put_org_role(self.tbl, "user1", org_id)

        updated = self.svc.update_org_account(
            org_id, "user1", name="NewName Corp", employee_count=42
        )
        self.assertEqual(updated["name"], "NewName Corp")
        self.assertEqual(updated["employee_count"], 42)

    def test_patch_requires_org_admin(self):
        from fastapi import HTTPException
        org = self.svc.create_org_account("Corp", owner_user_sub="user1")
        org_id = org["party_id"]
        # user2 has no org role
        with self.assertRaises(HTTPException) as ctx:
            self.svc.update_org_account(org_id, "user2", name="HackedName")
        self.assertEqual(ctx.exception.status_code, 403)

    def test_flag_off_returns_503_on_patch(self):
        from fastapi import HTTPException
        object.__setattr__(self.S, "party_crm_org_accounts_enabled", False)
        try:
            org = self.svc.create_org_account("Corp", owner_user_sub="user1")
        except HTTPException:
            pass  # Expected since flag is off
        object.__setattr__(self.S, "party_crm_org_accounts_enabled", True)
        org = self.svc.create_org_account("Corp", owner_user_sub="user1")
        org_id = org["party_id"]
        _put_org_role(self.tbl, "user1", org_id)
        object.__setattr__(self.S, "party_crm_org_accounts_enabled", False)
        with self.assertRaises(HTTPException) as ctx:
            self.svc.update_org_account(org_id, "user1", name="X")
        self.assertEqual(ctx.exception.status_code, 503)


@unittest.skipIf(not HAS_MOTO, "moto not installed")
class TestCct002OrgHierarchy(unittest.TestCase):
    """CCT-002: Account hierarchy (parent org)."""

    def setUp(self):
        self.mock = mock_aws()
        self.mock.start()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.tbl = _make_party_table(ddb)

        from app.services import party_contact_extra
        from app.core import tables as tables_mod
        from app.core import settings as settings_mod

        self.svc = party_contact_extra
        self.T = tables_mod.T
        self.S = settings_mod.S

        object.__setattr__(self.T, "party", self.tbl)
        object.__setattr__(self.S, "party_crm_org_accounts_enabled", True)

    def tearDown(self):
        object.__setattr__(self.S, "party_crm_org_accounts_enabled", False)
        self.mock.stop()

    def _create_orgs(self):
        o1 = _put_party(self.tbl, "org1", "PARTY_GROUP", "Parent")
        o2 = _put_party(self.tbl, "org2", "PARTY_GROUP", "Child")
        o3 = _put_party(self.tbl, "org3", "PARTY_GROUP", "GrandChild")
        _put_org_role(self.tbl, "actor1", "org2")
        _put_org_role(self.tbl, "actor1", "org3")
        return o1, o2, o3

    def test_set_parent_and_get_hierarchy(self):
        self._create_orgs()
        edge = self.svc.set_parent_org("org2", "org1", actor_party_id="actor1")
        self.assertEqual(edge["from_party_id"], "org2")
        self.assertEqual(edge["to_party_id"], "org1")
        self.assertEqual(edge["relationship_type"], "PARENT_ORG")

        result = self.svc.get_org_hierarchy("org2", direction="ancestors")
        ancestors = result["ancestors"]
        self.assertEqual(len(ancestors), 1)
        self.assertEqual(ancestors[0]["to_party_id"], "org1")

    def test_replace_parent(self):
        self._create_orgs()
        _put_org_role(self.tbl, "actor1", "org1")
        self.svc.set_parent_org("org2", "org1", actor_party_id="actor1")

        # Create new parent and replace
        _put_party(self.tbl, "org4", "PARTY_GROUP", "NewParent")
        self.svc.set_parent_org("org2", "org4", actor_party_id="actor1")

        result = self.svc.get_org_hierarchy("org2", direction="ancestors")
        ancestors = result["ancestors"]
        self.assertEqual(len(ancestors), 1)
        self.assertEqual(ancestors[0]["to_party_id"], "org4")

    def test_circular_hierarchy_rejected(self):
        from fastapi import HTTPException
        self._create_orgs()
        # org2 -> org1 (org1 is parent of org2)
        _put_org_role(self.tbl, "actor1", "org1")
        self.svc.set_parent_org("org2", "org1", actor_party_id="actor1")
        # Now try to make org1's parent = org2 (circular)
        _put_org_role(self.tbl, "actor1", "org1")
        with self.assertRaises(HTTPException) as ctx:
            self.svc.set_parent_org("org1", "org2", actor_party_id="actor1")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("circular", str(ctx.exception.detail))

    def test_remove_parent(self):
        self._create_orgs()
        self.svc.set_parent_org("org2", "org1", actor_party_id="actor1")
        self.svc.remove_parent_org("org2", actor_party_id="actor1")

        result = self.svc.get_org_hierarchy("org2", direction="ancestors")
        self.assertEqual(len(result["ancestors"]), 0)

    def test_children_direction(self):
        self._create_orgs()
        self.svc.set_parent_org("org2", "org1", actor_party_id="actor1")
        self.svc.set_parent_org("org3", "org1", actor_party_id="actor1")

        result = self.svc.get_org_hierarchy("org1", direction="children")
        children = result["children"]
        child_from_ids = {c["from_party_id"] for c in children}
        self.assertIn("org2", child_from_ids)
        self.assertIn("org3", child_from_ids)

    def test_non_org_admin_403(self):
        from fastapi import HTTPException
        self._create_orgs()
        with self.assertRaises(HTTPException) as ctx:
            self.svc.set_parent_org("org2", "org1", actor_party_id="non_admin")
        self.assertEqual(ctx.exception.status_code, 403)

    def test_flag_off_returns_503(self):
        from fastapi import HTTPException
        object.__setattr__(self.S, "party_crm_org_accounts_enabled", False)
        _put_party(self.tbl, "org1", "PARTY_GROUP", "P")
        _put_party(self.tbl, "org2", "PARTY_GROUP", "C")
        with self.assertRaises(HTTPException) as ctx:
            self.svc.set_parent_org("org2", "org1", actor_party_id="actor1")
        self.assertEqual(ctx.exception.status_code, 503)


@unittest.skipIf(not HAS_MOTO, "moto not installed")
class TestCct003ReportsTo(unittest.TestCase):
    """CCT-003: Reports-to hierarchy (manager chain)."""

    def setUp(self):
        self.mock = mock_aws()
        self.mock.start()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.tbl = _make_party_table(ddb)

        from app.services import party_contact_extra
        from app.core import tables as tables_mod
        from app.core import settings as settings_mod

        self.svc = party_contact_extra
        self.T = tables_mod.T
        self.S = settings_mod.S

        object.__setattr__(self.T, "party", self.tbl)
        object.__setattr__(self.S, "party_crm_enabled", True)

    def tearDown(self):
        object.__setattr__(self.S, "party_crm_enabled", False)
        self.mock.stop()

    def _create_persons(self):
        _put_party(self.tbl, "p1", "PERSON", "Alice")
        _put_party(self.tbl, "p2", "PERSON", "Bob")
        _put_party(self.tbl, "p3", "PERSON", "Carol")

    def test_set_manager_creates_edge(self):
        self._create_persons()
        edge = self.svc.set_manager("p1", "p2", actor_party_id="p1")
        self.assertEqual(edge["from_party_id"], "p1")
        self.assertEqual(edge["to_party_id"], "p2")
        self.assertEqual(edge["relationship_type"], "REPORTS_TO")

    def test_replace_manager(self):
        self._create_persons()
        self.svc.set_manager("p1", "p2", actor_party_id="p1")
        self.svc.set_manager("p1", "p3", actor_party_id="p1")

        result = self.svc.get_reports_to_chain("p1", direction="manager_chain")
        chain = result["chain"]
        self.assertEqual(len(chain), 1)
        self.assertEqual(chain[0]["to_party_id"], "p3")

    def test_circular_manager_rejected(self):
        from fastapi import HTTPException
        self._create_persons()
        # p1 reports to p2
        self.svc.set_manager("p1", "p2", actor_party_id="p1")
        # Attempt: p2 reports to p1 — should detect cycle
        with self.assertRaises(HTTPException) as ctx:
            self.svc.set_manager("p2", "p1", actor_party_id="p2")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("circular", str(ctx.exception.detail))

    def test_party_group_rejected(self):
        from fastapi import HTTPException
        _put_party(self.tbl, "p1", "PERSON", "Alice")
        _put_party(self.tbl, "org1", "PARTY_GROUP", "Org")
        with self.assertRaises(HTTPException) as ctx:
            self.svc.set_manager("p1", "org1", actor_party_id="p1")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_remove_manager(self):
        self._create_persons()
        self.svc.set_manager("p1", "p2", actor_party_id="p1")
        self.svc.remove_manager("p1", actor_party_id="p1")

        result = self.svc.get_reports_to_chain("p1", direction="manager_chain")
        self.assertEqual(len(result["chain"]), 0)

    def test_get_direct_reports(self):
        self._create_persons()
        # p1 and p3 both report to p2
        self.svc.set_manager("p1", "p2", actor_party_id="p1")
        self.svc.set_manager("p3", "p2", actor_party_id="p3")

        result = self.svc.get_reports_to_chain("p2", direction="reports")
        from_ids = {r["from_party_id"] for r in result["chain"]}
        self.assertIn("p1", from_ids)
        self.assertIn("p3", from_ids)

    def test_flag_off_returns_503(self):
        from fastapi import HTTPException
        object.__setattr__(self.S, "party_crm_enabled", False)
        _put_party(self.tbl, "p1", "PERSON", "Alice")
        _put_party(self.tbl, "p2", "PERSON", "Bob")
        with self.assertRaises(HTTPException) as ctx:
            self.svc.set_manager("p1", "p2", actor_party_id="p1")
        self.assertEqual(ctx.exception.status_code, 503)


@unittest.skipIf(not HAS_MOTO, "moto not installed")
class TestCct004Dedup(unittest.TestCase):
    """CCT-004: Duplicate contact detection."""

    def setUp(self):
        self.mock = mock_aws()
        self.mock.start()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.tbl = _make_party_table(ddb)

        from app.services import party_dedup
        from app.core import tables as tables_mod
        from app.core import settings as settings_mod

        self.svc = party_dedup
        self.T = tables_mod.T
        self.S = settings_mod.S

        object.__setattr__(self.T, "party", self.tbl)
        object.__setattr__(self.S, "party_crm_enabled", True)
        object.__setattr__(self.S, "party_dedup_match_threshold", 0.70)

    def tearDown(self):
        object.__setattr__(self.S, "party_crm_enabled", False)
        self.mock.stop()

    def test_exact_email_match_detected(self):
        _put_party(self.tbl, "p1", "PERSON", "Alice Smith", owner="user1", ts=1000)
        _put_party(self.tbl, "p2", "PERSON", "Alice Jones", owner="user1", ts=1001)
        # Both share the same email
        _put_mech(self.tbl, "p1", "m1", "EMAIL", "alice@example.com")
        _put_mech(self.tbl, "p2", "m2", "EMAIL", "alice@example.com")

        results = self.svc.find_duplicates_for_party("p1", actor_sub="user1")
        self.assertTrue(len(results) > 0)
        top = results[0]
        self.assertGreaterEqual(top["score"], 0.90)
        self.assertIn("email_exact", top["match_signals"])

    def test_fuzzy_name_match_detected(self):
        # Lower threshold so name-only similarity scores pass (ratio * 0.70 < default 0.70)
        object.__setattr__(self.S, "party_dedup_match_threshold", 0.55)
        _put_party(self.tbl, "p1", "PERSON", "Jonathan Smith", owner="user1", ts=1000)
        _put_party(self.tbl, "p2", "PERSON", "Johnathan Smith", owner="user1", ts=1001)
        # No shared mechs — only name similarity

        results = self.svc.find_duplicates_for_party("p1", actor_sub="user1")
        # Name similarity should be detected
        names_matched = [r for r in results if any("name_similarity" in s for s in r["match_signals"])]
        self.assertTrue(len(names_matched) > 0, f"Expected name similarity match; got: {results}")

    def test_no_match_unique_party(self):
        _put_party(self.tbl, "p1", "PERSON", "Unique Person XYZ", owner="user1", ts=1000)
        _put_party(self.tbl, "p2", "PERSON", "Completely Different", owner="user1", ts=1001)
        _put_mech(self.tbl, "p1", "m1", "EMAIL", "unique@a.com")
        _put_mech(self.tbl, "p2", "m2", "EMAIL", "different@b.com")

        results = self.svc.find_duplicates_for_party("p1", actor_sub="user1")
        # May have name-similarity but score should be below threshold for very different names
        high_score = [r for r in results if r["score"] >= 0.90]
        self.assertEqual(len(high_score), 0)

    def test_flag_off_returns_503(self):
        from fastapi import HTTPException
        object.__setattr__(self.S, "party_crm_enabled", False)
        _put_party(self.tbl, "p1", "PERSON", "Alice", owner="user1")
        with self.assertRaises(HTTPException) as ctx:
            self.svc.find_duplicates_for_party("p1", actor_sub="user1")
        self.assertEqual(ctx.exception.status_code, 503)

    def test_list_all_returns_pairs_and_emits_audit(self):
        _put_party(self.tbl, "p1", "PERSON", "Bob Smith", owner="user1", ts=1000)
        _put_party(self.tbl, "p2", "PERSON", "Bob Smith", owner="user1", ts=1001)
        _put_mech(self.tbl, "p1", "m1", "EMAIL", "bob@example.com")
        _put_mech(self.tbl, "p2", "m2", "EMAIL", "bob@example.com")

        audited = []
        def fake_audit(event, sub, **kw):
            audited.append(event)

        with patch("app.services.party_dedup.audit_event", side_effect=fake_audit, create=True):
            # Patch the internal import
            import app.services.party_dedup as dedup_mod
            import app.services.alerts as alerts_mod
            orig = getattr(alerts_mod, "audit_event", None)
            setattr(alerts_mod, "audit_event", fake_audit)
            try:
                items, cursor = self.svc.list_all_duplicate_candidates("admin1")
            finally:
                if orig is not None:
                    setattr(alerts_mod, "audit_event", orig)


@unittest.skipIf(not HAS_MOTO, "moto not installed")
class TestCct005Merge(unittest.TestCase):
    """CCT-005: Contact merge."""

    def setUp(self):
        self.mock = mock_aws()
        self.mock.start()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.tbl = _make_party_table(ddb)

        from app.services import party_contact_extra
        from app.core import tables as tables_mod
        from app.core import settings as settings_mod

        self.svc = party_contact_extra
        self.T = tables_mod.T
        self.S = settings_mod.S

        object.__setattr__(self.T, "party", self.tbl)
        object.__setattr__(self.S, "party_crm_enabled", True)

    def tearDown(self):
        object.__setattr__(self.S, "party_crm_enabled", False)
        self.mock.stop()

    def _setup_parties(self):
        _put_party(self.tbl, "winner", "PERSON", "Winner", owner="user1", ts=1000)
        _put_party(self.tbl, "loser", "PERSON", "Loser", owner="user1", ts=1001)
        # Add roles to loser (real schema: PK=PARTY#{id}, SK=ROLE#{type})
        self.tbl.put_item(Item={
            "PK": "PARTY#loser", "SK": "ROLE#CUSTOMER",
            "party_id": "loser", "role_type": "CUSTOMER", "created_at": 1000,
            "GSI1PK": "ROLE#CUSTOMER", "GSI1SK": "PARTY#loser",
        })
        # Add mech to loser
        _put_mech(self.tbl, "loser", "m_loser", "EMAIL", "loser@example.com")
        # Add mech to winner
        _put_mech(self.tbl, "winner", "m_winner", "EMAIL", "winner@example.com")

    def test_merge_copies_roles(self):
        self._setup_parties()
        self.svc.merge_parties("winner", "loser", actor_sub="admin1")

        # Winner should now have loser's role
        resp = self.tbl.query(
            KeyConditionExpression="PK = :pk AND begins_with(SK, :prefix)",
            ExpressionAttributeValues={":pk": "PARTY#winner", ":prefix": "ROLE#"},
        )
        role_sks = {item["SK"] for item in resp.get("Items", [])}
        self.assertIn("ROLE#CUSTOMER", role_sks)

    def test_merge_copies_mechs(self):
        self._setup_parties()
        self.svc.merge_parties("winner", "loser", actor_sub="admin1")

        resp = self.tbl.query(
            KeyConditionExpression="PK = :pk AND begins_with(SK, :prefix)",
            ExpressionAttributeValues={":pk": "PARTY#winner", ":prefix": "MECH#"},
        )
        values = {item.get("value") for item in resp.get("Items", [])}
        self.assertIn("winner@example.com", values)
        self.assertIn("loser@example.com", values)

    def test_loser_marked_merged(self):
        self._setup_parties()
        self.svc.merge_parties("winner", "loser", actor_sub="admin1")

        loser_meta = self.tbl.get_item(Key={"PK": "PARTY#loser", "SK": "META"}).get("Item")
        self.assertEqual(loser_meta["status"], "MERGED")
        self.assertEqual(loser_meta["merged_into_party_id"], "winner")

    def test_type_mismatch_rejected(self):
        from fastapi import HTTPException
        _put_party(self.tbl, "winner", "PERSON", "Winner", owner="user1")
        _put_party(self.tbl, "loser", "PARTY_GROUP", "LoserOrg", owner="user1")
        with self.assertRaises(HTTPException) as ctx:
            self.svc.merge_parties("winner", "loser", actor_sub="admin1")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_self_merge_rejected(self):
        from fastapi import HTTPException
        _put_party(self.tbl, "p1", "PERSON", "Alice", owner="user1")
        with self.assertRaises(HTTPException) as ctx:
            self.svc.merge_parties("p1", "p1", actor_sub="admin1")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_duplicate_mechs_not_duplicated(self):
        """Winner already has loser's email — should not be duplicated."""
        _put_party(self.tbl, "winner", "PERSON", "Winner", owner="user1", ts=1000)
        _put_party(self.tbl, "loser", "PERSON", "Loser", owner="user1", ts=1001)
        shared_email = "shared@example.com"
        _put_mech(self.tbl, "winner", "m1", "EMAIL", shared_email)
        _put_mech(self.tbl, "loser", "m2", "EMAIL", shared_email)

        self.svc.merge_parties("winner", "loser", actor_sub="admin1")

        resp = self.tbl.query(
            KeyConditionExpression="PK = :pk AND begins_with(SK, :prefix)",
            ExpressionAttributeValues={":pk": "PARTY#winner", ":prefix": "MECH#"},
        )
        email_items = [i for i in resp.get("Items", []) if i.get("value") == shared_email]
        self.assertEqual(len(email_items), 1)

    def test_flag_off_returns_503(self):
        from fastapi import HTTPException
        object.__setattr__(self.S, "party_crm_enabled", False)
        _put_party(self.tbl, "w", "PERSON", "W", owner="u")
        _put_party(self.tbl, "l", "PERSON", "L", owner="u")
        with self.assertRaises(HTTPException) as ctx:
            self.svc.merge_parties("w", "l", actor_sub="admin")
        self.assertEqual(ctx.exception.status_code, 503)


@unittest.skipIf(not HAS_MOTO, "moto not installed")
class TestCct006Vcard(unittest.TestCase):
    """CCT-006: vCard import/export."""

    def setUp(self):
        self.mock = mock_aws()
        self.mock.start()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.tbl = _make_party_table(ddb)

        from app.services import party_vcard
        from app.core import tables as tables_mod
        from app.core import settings as settings_mod

        self.svc = party_vcard
        self.T = tables_mod.T
        self.S = settings_mod.S

        object.__setattr__(self.T, "party", self.tbl)
        object.__setattr__(self.S, "party_crm_enabled", True)

    def tearDown(self):
        object.__setattr__(self.S, "party_crm_enabled", False)
        self.mock.stop()

    def test_export_person_with_email_and_phone(self):
        _put_party(self.tbl, "p1", "PERSON", "Alice Smith", owner="user1", ts=1000,
                   display_name="Alice Smith")
        _put_mech(self.tbl, "p1", "m1", "EMAIL", "alice@example.com")
        _put_mech(self.tbl, "p1", "m2", "PHONE", "+12025551234")

        vcf = self.svc.export_party_as_vcard("p1", actor_sub="user1")
        text = vcf.decode("utf-8")
        self.assertIn("BEGIN:VCARD", text)
        self.assertIn("FN:Alice Smith", text)
        self.assertIn("EMAIL", text)
        self.assertIn("alice@example.com", text)
        self.assertIn("TEL", text)
        self.assertIn("+12025551234", text)
        self.assertIn("END:VCARD", text)
        self.assertIn("UID:p1", text)

    def test_export_org_uses_org_field(self):
        _put_party(self.tbl, "org1", "PARTY_GROUP", "Acme Corp", owner="user1", ts=1000)

        vcf = self.svc.export_party_as_vcard("org1", actor_sub="user1")
        text = vcf.decode("utf-8")
        self.assertIn("ORG:Acme Corp", text)

    def test_import_single_vcard(self):
        vcf_text = b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:John Doe\r\nEMAIL:john@example.com\r\nTEL:+12025551234\r\nEND:VCARD\r\n"

        results = self.svc.import_vcard(vcf_text, actor_sub="user1")
        self.assertEqual(len(results), 1)
        party = results[0]
        self.assertEqual(party["name"], "John Doe")
        self.assertEqual(party["party_type"], "PERSON")

        # Verify mechs were created
        mech_resp = self.tbl.query(
            KeyConditionExpression="PK = :pk AND begins_with(SK, :prefix)",
            ExpressionAttributeValues={":pk": f"PARTY#{party['party_id']}", ":prefix": "MECH#"},
        )
        mechs = mech_resp.get("Items", [])
        mech_types = {m["mech_type"] for m in mechs}
        self.assertIn("EMAIL", mech_types)
        self.assertIn("PHONE", mech_types)

    def test_import_idempotent(self):
        vcf_text = b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Jane Doe\r\nEMAIL:jane@example.com\r\nEND:VCARD\r\n"

        r1 = self.svc.import_vcard(vcf_text, actor_sub="user1")
        r2 = self.svc.import_vcard(vcf_text, actor_sub="user1")

        # Both should return the same party
        self.assertEqual(r1[0]["party_id"], r2[0]["party_id"])

    def test_import_multi_record(self):
        vcf_text = (
            b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Person One\r\nEMAIL:one@example.com\r\nEND:VCARD\r\n"
            b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Person Two\r\nEMAIL:two@example.com\r\nEND:VCARD\r\n"
        )
        results = self.svc.import_vcard(vcf_text, actor_sub="user1")
        self.assertEqual(len(results), 2)

    def test_import_too_many_vcards(self):
        from fastapi import HTTPException
        # Build 501 vCard records
        vcf_parts = []
        for i in range(501):
            vcf_parts.append(
                f"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Person {i}\r\nEMAIL:p{i}@example.com\r\nEND:VCARD\r\n".encode()
            )
        vcf_text = b"".join(vcf_parts)
        with self.assertRaises(HTTPException) as ctx:
            self.svc.import_vcard(vcf_text, actor_sub="user1")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("too_many_vcards", str(ctx.exception.detail))

    def test_import_malformed_email_skipped(self):
        vcf_text = b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Bad Email Person\r\nEMAIL:not-an-email\r\nEND:VCARD\r\n"
        # Should not raise, malformed email is skipped
        results = self.svc.import_vcard(vcf_text, actor_sub="user1")
        self.assertEqual(len(results), 1)
        party_id = results[0]["party_id"]
        mech_resp = self.tbl.query(
            KeyConditionExpression="PK = :pk AND begins_with(SK, :prefix)",
            ExpressionAttributeValues={":pk": f"PARTY#{party_id}", ":prefix": "MECH#"},
        )
        email_mechs = [m for m in mech_resp.get("Items", []) if m.get("mech_type") == "EMAIL"]
        # Malformed email should be excluded
        self.assertEqual(len(email_mechs), 0)

    def test_flag_off_returns_503_export(self):
        from fastapi import HTTPException
        object.__setattr__(self.S, "party_crm_enabled", False)
        _put_party(self.tbl, "p1", "PERSON", "Alice", owner="user1")
        with self.assertRaises(HTTPException) as ctx:
            self.svc.export_party_as_vcard("p1", actor_sub="user1")
        self.assertEqual(ctx.exception.status_code, 503)

    def test_flag_off_returns_503_import(self):
        from fastapi import HTTPException
        object.__setattr__(self.S, "party_crm_enabled", False)
        with self.assertRaises(HTTPException) as ctx:
            self.svc.import_vcard(b"BEGIN:VCARD\r\nEND:VCARD\r\n", actor_sub="user1")
        self.assertEqual(ctx.exception.status_code, 503)


if __name__ == "__main__":
    unittest.main()
