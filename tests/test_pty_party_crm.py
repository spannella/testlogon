"""PTY-015 — Party/CRM hermetic offline pytest suite.

Covers PTY-001..PTY-012:
  * settings flags default off (PTY-001)
  * party single-table CRUD + idempotency (PTY-004)
  * roles (PTY-005)
  * relationships + inbound mirror (PTY-006)
  * contact mechanisms (PTY-007)
  * B2B org accounts + ORG_ADMIN guard (PTY-008)
  * contacts → party migration (PTY-009)
  * ensure_person_party back-fill (PTY-010)
  * router flag-guard + happy path (PTY-011 / PTY-012)
  * flag-off regression: legacy contacts surface unchanged (PTY-009/PTY-015)

Fully offline: moto in-memory DynamoDB tables bound to the frozen ``T`` singleton
via ``object.__setattr__``; frozen ``S`` flipped the same way; ``audit_event``
patched to a no-op; route-handler coroutines driven on a fresh asyncio loop (no
TestClient). No real AWS / network.
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

from fastapi import HTTPException


def _make_party_table(ddb):
    return ddb.create_table(
        TableName="party_test",
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
        BillingMode="PAY_PER_REQUEST",
    )


def _make_contacts_table(ddb):
    return ddb.create_table(
        TableName="Contacts_test",
        KeySchema=[
            {"AttributeName": "owner_id", "KeyType": "HASH"},
            {"AttributeName": "contact_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "owner_id", "AttributeType": "S"},
            {"AttributeName": "contact_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@unittest.skipIf(mock_aws is None, "moto not installed")
class _PartyTestBase(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.party_table = _make_party_table(ddb)
        self.contacts_table = _make_contacts_table(ddb)

        from app.core import tables as tables_mod
        from app.core import settings as settings_mod

        self.T = tables_mod.T
        self.S = settings_mod.S

        self._prev_party = getattr(self.T, "party", None)
        self._prev_contacts = getattr(self.T, "contacts", None)
        object.__setattr__(self.T, "party", self.party_table)
        object.__setattr__(self.T, "contacts", self.contacts_table)
        self.addCleanup(object.__setattr__, self.T, "party", self._prev_party)
        self.addCleanup(object.__setattr__, self.T, "contacts", self._prev_contacts)

        self._prev_enabled = self.S.party_crm_enabled
        object.__setattr__(self.S, "party_crm_enabled", True)
        self.addCleanup(
            object.__setattr__, self.S, "party_crm_enabled", self._prev_enabled
        )

        self.stack.enter_context(
            patch("app.services.party.audit_event", lambda *a, **k: None)
        )

        import app.services.party as svc

        self.svc = svc


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-001 — settings flags default off
# ═══════════════════════════════════════════════════════════════════════════════


class TestPartyFlags(unittest.TestCase):
    def test_flags_default_off(self):
        # Re-evaluate from a fresh import of Settings defaults (env unset).
        import os

        for var in (
            "PARTY_CRM_ENABLED",
            "PARTY_CRM_CONTACTS_MIGRATION_ENABLED",
            "PARTY_CRM_ORG_ACCOUNTS_ENABLED",
            "PARTY_CRM_PROFILE_SYNC_ENABLED",
        ):
            self.assertNotIn(var, os.environ, f"{var} unexpectedly set in env")

        from app.core.settings import Settings

        s = Settings()
        self.assertFalse(s.party_crm_enabled)
        self.assertFalse(s.party_crm_contacts_migration_enabled)
        self.assertFalse(s.party_crm_org_accounts_enabled)
        self.assertFalse(s.party_crm_profile_sync_enabled)
        self.assertEqual(s.party_table_name, "party")

    def test_T_party_handle_present(self):
        from app.core import tables as tables_mod

        self.assertTrue(hasattr(tables_mod.T, "party"))
        self.assertIsNotNone(tables_mod.T.party)
        self.assertTrue(hasattr(tables_mod.T, "contacts"))


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-004 — Party CRUD
# ═══════════════════════════════════════════════════════════════════════════════


class TestPartyCRUD(_PartyTestBase):
    def test_create_person(self):
        p = self.svc.create_party("PERSON")
        self.assertEqual(p["party_type"], "PERSON")
        self.assertEqual(p["status"], "ACTIVE")
        self.assertEqual(len(p["party_id"]), 32)
        self.assertEqual(p["type"], "TYPE#PERSON")

    def test_create_invalid_type(self):
        with self.assertRaises(ValueError):
            self.svc.create_party("CORPORATION")

    def test_create_with_user_sub_writes_gsi3(self):
        p = self.svc.create_party("PERSON", user_sub="sub123")
        raw = self.party_table.get_item(
            Key={"PK": f"PARTY#{p['party_id']}", "SK": "META"}
        )["Item"]
        self.assertEqual(raw["GSI3PK"], "OWNER#sub123")
        self.assertEqual(raw["GSI3SK"], f"PARTY#{p['party_id']}")

    def test_create_without_user_sub_no_gsi3(self):
        p = self.svc.create_party("PARTY_GROUP")
        raw = self.party_table.get_item(
            Key={"PK": f"PARTY#{p['party_id']}", "SK": "META"}
        )["Item"]
        self.assertNotIn("GSI3PK", raw)

    def test_idempotent_replay(self):
        a = self.svc.create_party("PERSON", correlation_id="abc")
        b = self.svc.create_party("PERSON", correlation_id="abc")
        self.assertEqual(a["party_id"], b["party_id"])
        resp = self.party_table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key("PK").eq(
                f"PARTY#{a['party_id']}"
            )
        )
        metas = [i for i in resp["Items"] if i["SK"] == "META"]
        self.assertEqual(len(metas), 1)

    def test_get_party_not_found(self):
        self.assertIsNone(self.svc.get_party("nope"))

    def test_list_by_type(self):
        ids = [self.svc.create_party("PERSON")["party_id"] for _ in range(3)]
        result = self.svc.list_parties("PERSON")
        got = {p["party_id"] for p in result["parties"]}
        self.assertTrue(set(ids).issubset(got))

    def test_list_all_types(self):
        self.svc.create_party("PERSON")
        self.svc.create_party("PARTY_GROUP")
        result = self.svc.list_parties(None)
        self.assertIsNone(result["next_cursor"])
        self.assertGreaterEqual(result["count"], 2)

    def test_status_update_valid(self):
        p = self.svc.create_party("PERSON")
        u = self.svc.update_party_status(p["party_id"], "INACTIVE")
        self.assertEqual(u["status"], "INACTIVE")

    def test_status_update_noop(self):
        p = self.svc.create_party("PERSON")
        u = self.svc.update_party_status(p["party_id"], "ACTIVE")
        self.assertEqual(u["status"], "ACTIVE")

    def test_status_update_invalid_transition(self):
        p = self.svc.create_party("PERSON")
        self.svc.update_party_status(p["party_id"], "MERGED")
        with self.assertRaises(ValueError):
            self.svc.update_party_status(p["party_id"], "ACTIVE")

    def test_status_update_not_found(self):
        with self.assertRaises(KeyError):
            self.svc.update_party_status("ghost", "INACTIVE")


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-005 — Roles
# ═══════════════════════════════════════════════════════════════════════════════


class TestPartyRoles(_PartyTestBase):
    def setUp(self):
        super().setUp()
        self.pid = self.svc.create_party("PERSON")["party_id"]

    def test_add_role(self):
        r = self.svc.add_role(self.pid, "CUSTOMER")
        self.assertEqual(r["role_type"], "CUSTOMER")
        self.assertEqual(r["GSI1PK"], "ROLE#CUSTOMER")

    def test_add_role_invalid(self):
        with self.assertRaises(ValueError):
            self.svc.add_role(self.pid, "CEO")

    def test_add_role_unknown_party(self):
        with self.assertRaises(KeyError):
            self.svc.add_role("ghost", "CUSTOMER")

    def test_add_role_idempotent(self):
        self.svc.add_role(self.pid, "SUPPLIER")
        self.svc.add_role(self.pid, "SUPPLIER")
        roles = self.svc.list_roles(self.pid)
        self.assertEqual(len([r for r in roles if r["role_type"] == "SUPPLIER"]), 1)

    def test_remove_role(self):
        self.svc.add_role(self.pid, "EMPLOYEE")
        self.svc.remove_role(self.pid, "EMPLOYEE")
        self.assertEqual(self.svc.list_roles(self.pid), [])

    def test_remove_role_nonexistent(self):
        self.svc.remove_role(self.pid, "EMPLOYEE")  # no error

    def test_list_roles_scoped(self):
        other = self.svc.create_party("PERSON")["party_id"]
        self.svc.add_role(self.pid, "BILL_TO")
        self.svc.add_role(other, "SHIP_TO")
        roles = self.svc.list_roles(self.pid)
        self.assertEqual([r["role_type"] for r in roles], ["BILL_TO"])

    def test_parties_with_role(self):
        ids = [self.svc.create_party("PERSON")["party_id"] for _ in range(3)]
        for i in ids:
            self.svc.add_role(i, "CUSTOMER")
        rows = self.svc.parties_with_role("CUSTOMER")
        found = {r["party_id"] for r in rows}
        self.assertTrue(set(ids).issubset(found))
        for r in rows:
            self.assertTrue(r["SK"].startswith("ROLE#"))

    def test_parties_with_role_invalid(self):
        with self.assertRaises(ValueError):
            self.svc.parties_with_role("UNKNOWN")


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-006 — Relationships
# ═══════════════════════════════════════════════════════════════════════════════


class TestPartyRelationships(_PartyTestBase):
    def test_create_employment(self):
        r = self.svc.create_relationship("p1", "p2", "EMPLOYMENT")
        self.assertEqual(r["relationship_type"], "EMPLOYMENT")
        self.assertEqual(len(r["rel_id"]), 32)
        primary = self.party_table.get_item(
            Key={"PK": "PARTY#p1", "SK": "REL#EMPLOYMENT#p2"}
        )["Item"]
        self.assertEqual(primary["to_party_id"], "p2")
        mirror = self.party_table.get_item(
            Key={"PK": "PARTY#p2", "SK": "MIRROR#EMPLOYMENT#p1"}
        )["Item"]
        self.assertEqual(mirror["GSI3PK"], "REL_TO#p2")

    def test_self_rejected(self):
        with self.assertRaises(ValueError):
            self.svc.create_relationship("p1", "p1", "EMPLOYMENT")

    def test_invalid_type(self):
        with self.assertRaises(ValueError):
            self.svc.create_relationship("p1", "p2", "BEST_FRIENDS")

    def test_idempotent(self):
        a = self.svc.create_relationship("p1", "p2", "EMPLOYMENT", correlation_id="x")
        b = self.svc.create_relationship("p1", "p2", "EMPLOYMENT", correlation_id="x")
        self.assertEqual(a["rel_id"], b["rel_id"])

    def test_list_outbound_inbound(self):
        self.svc.create_relationship("p1", "p2", "EMPLOYMENT")
        out = self.svc.list_relationships("p1", direction="from")
        self.assertEqual(out["count"], 1)
        inb = self.svc.list_relationships("p2", direction="to")
        self.assertEqual(inb["count"], 1)

    def test_list_both(self):
        self.svc.create_relationship("p1", "p2", "EMPLOYMENT")
        self.svc.create_relationship("p3", "p1", "GROUP_MEMBER")
        both = self.svc.list_relationships("p1", direction="both")
        self.assertEqual(both["count"], 2)
        self.assertIsNone(both["next_cursor"])

    def test_delete_removes_both(self):
        self.svc.create_relationship("p1", "p2", "EMPLOYMENT")
        self.svc.delete_relationship("p1", "p2", "EMPLOYMENT")
        self.assertEqual(
            self.svc.list_relationships("p1", direction="from")["count"], 0
        )
        self.assertEqual(
            self.svc.list_relationships("p2", direction="to")["count"], 0
        )

    def test_delete_nonexistent_no_error(self):
        self.svc.delete_relationship("p1", "p99", "EMPLOYMENT")


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-007 — Contact mechanisms
# ═══════════════════════════════════════════════════════════════════════════════


class TestContactMechs(_PartyTestBase):
    def setUp(self):
        super().setUp()
        self.pid = self.svc.create_party("PERSON")["party_id"]

    def test_add_email_normalized(self):
        m = self.svc.add_contact_mech(
            self.pid, "EMAIL", "  Alice@X.com ", ["PRIMARY_EMAIL"]
        )
        self.assertEqual(m["value"], "alice@x.com")
        self.assertEqual(m["GSI2PK"], "EMAIL#alice@x.com")

    def test_add_phone_normalized(self):
        m = self.svc.add_contact_mech(self.pid, "PHONE", "(415) 555-1212", [])
        self.assertEqual(m["value"], "+14155551212")

    def test_find_by_email(self):
        self.svc.add_contact_mech(self.pid, "EMAIL", "Alice@X.com", [])
        found = self.svc.find_party_by_contact("EMAIL", "alice@x.com ")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["party_id"], self.pid)

    def test_invalid_purpose(self):
        with self.assertRaises(HTTPException) as ctx:
            self.svc.add_contact_mech(self.pid, "EMAIL", "a@b.com", ["FAKE"])
        self.assertEqual(ctx.exception.status_code, 400)

    def test_add_unknown_party(self):
        with self.assertRaises(HTTPException) as ctx:
            self.svc.add_contact_mech("ghost", "EMAIL", "a@b.com", [])
        self.assertEqual(ctx.exception.status_code, 404)

    def test_list_type_filter(self):
        self.svc.add_contact_mech(self.pid, "EMAIL", "a@b.com", [])
        self.svc.add_contact_mech(self.pid, "PHONE", "4155551212", [])
        emails = self.svc.list_contact_mechs(self.pid, mech_type="EMAIL")
        self.assertEqual(len(emails), 1)
        allm = self.svc.list_contact_mechs(self.pid)
        self.assertEqual(len(allm), 2)

    def test_idempotent_correlation(self):
        a = self.svc.add_contact_mech(
            self.pid, "EMAIL", "a@b.com", [], correlation_id="c1"
        )
        b = self.svc.add_contact_mech(
            self.pid, "EMAIL", "a@b.com", [], correlation_id="c1"
        )
        self.assertEqual(a["mech_id"], b["mech_id"])
        self.assertEqual(len(self.svc.list_contact_mechs(self.pid)), 1)

    def test_postal_requires_line1(self):
        with self.assertRaises(HTTPException):
            self.svc.add_contact_mech(self.pid, "POSTAL", {"city": "X"}, [])

    def test_postal_add_and_lookup(self):
        addr = {"line1": "1 Infinite Loop", "city": "Cupertino"}
        m = self.svc.add_contact_mech(self.pid, "POSTAL", addr, ["SHIPPING"])
        self.assertTrue(m["GSI2PK"].startswith("POSTAL#"))
        self.assertIsInstance(m["value"], dict)
        found = self.svc.find_party_by_contact("POSTAL", addr)
        self.assertEqual(len(found), 1)

    def test_remove(self):
        m = self.svc.add_contact_mech(self.pid, "EMAIL", "a@b.com", [])
        self.svc.remove_contact_mech(self.pid, m["mech_id"])
        self.assertEqual(self.svc.list_contact_mechs(self.pid), [])

    def test_remove_nonexistent(self):
        with self.assertRaises(HTTPException) as ctx:
            self.svc.remove_contact_mech(self.pid, "nope")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_update_purposes(self):
        m = self.svc.add_contact_mech(self.pid, "EMAIL", "a@b.com", ["PRIMARY_EMAIL"])
        u = self.svc.update_contact_mech(
            self.pid, m["mech_id"], purposes=["WORK"], verified=True
        )
        self.assertEqual(u["purposes"], ["WORK"])
        self.assertTrue(u["verified"])
        self.assertEqual(u["value"], "a@b.com")  # value unchanged


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-008 — Org accounts
# ═══════════════════════════════════════════════════════════════════════════════


class TestOrgAccounts(_PartyTestBase):
    def setUp(self):
        super().setUp()
        object.__setattr__(self.S, "party_crm_org_accounts_enabled", True)
        self.addCleanup(
            object.__setattr__, self.S, "party_crm_org_accounts_enabled", False
        )
        self.owner_sub = "owner_sub"
        self.owner_pid = self.svc.create_party("PERSON", user_sub=self.owner_sub)[
            "party_id"
        ]

    def test_create_org_basic(self):
        org = self.svc.create_org_account("Acme Corp", owner_user_sub=self.owner_sub)
        self.assertEqual(org["name"], "Acme Corp")
        self.assertEqual(org["party_type"], "PARTY_GROUP")
        roles = {r["role_type"] for r in self.svc.list_roles(org["party_id"])}
        self.assertEqual(roles, {"CUSTOMER", "BILL_TO"})
        owner_rel = self.party_table.get_item(
            Key={
                "PK": f"PARTY#{self.owner_pid}",
                "SK": f"REL#OWNER#{org['party_id']}",
            }
        )["Item"]
        self.assertEqual(owner_rel["org_role"], "owner")

    def test_create_org_idempotent(self):
        a = self.svc.create_org_account(
            "Acme", owner_user_sub=self.owner_sub, correlation_id="c1"
        )
        b = self.svc.create_org_account(
            "Acme", owner_user_sub=self.owner_sub, correlation_id="c1"
        )
        self.assertEqual(a["party_id"], b["party_id"])

    def test_create_org_no_owner_party(self):
        with self.assertRaises(HTTPException) as ctx:
            self.svc.create_org_account("X", owner_user_sub="nobody")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_create_org_empty_name(self):
        with self.assertRaises(HTTPException) as ctx:
            self.svc.create_org_account("  ", owner_user_sub=self.owner_sub)
        self.assertEqual(ctx.exception.status_code, 422)

    def test_add_member_and_list(self):
        org = self.svc.create_org_account("Acme", owner_user_sub=self.owner_sub)
        member_pid = self.svc.create_party("PERSON", user_sub="m1")["party_id"]
        rel = self.svc.add_member(
            org["party_id"], self.owner_pid, member_pid, role_type="member"
        )
        self.assertEqual(rel["org_role"], "member")
        members = self.svc.list_members(org["party_id"])
        self.assertEqual(members["count"], 1)
        self.assertEqual(members["members"][0]["org_role"], "member")

    def test_add_member_non_admin_denied(self):
        org = self.svc.create_org_account("Acme", owner_user_sub=self.owner_sub)
        member_pid = self.svc.create_party("PERSON", user_sub="m1")["party_id"]
        self.svc.add_member(org["party_id"], self.owner_pid, member_pid, "member")
        other_pid = self.svc.create_party("PERSON", user_sub="m2")["party_id"]
        with self.assertRaises(HTTPException) as ctx:
            self.svc.add_member(org["party_id"], member_pid, other_pid, "member")
        self.assertEqual(ctx.exception.status_code, 403)

    def test_add_member_self_rejected(self):
        org = self.svc.create_org_account("Acme", owner_user_sub=self.owner_sub)
        with self.assertRaises(HTTPException) as ctx:
            self.svc.add_member(
                org["party_id"], self.owner_pid, org["party_id"], "member"
            )
        self.assertEqual(ctx.exception.status_code, 422)

    def test_add_member_invalid_role(self):
        org = self.svc.create_org_account("Acme", owner_user_sub=self.owner_sub)
        member_pid = self.svc.create_party("PERSON", user_sub="m1")["party_id"]
        with self.assertRaises(HTTPException) as ctx:
            self.svc.add_member(org["party_id"], self.owner_pid, member_pid, "ceo")
        self.assertEqual(ctx.exception.status_code, 422)

    def test_remove_member(self):
        org = self.svc.create_org_account("Acme", owner_user_sub=self.owner_sub)
        member_pid = self.svc.create_party("PERSON", user_sub="m1")["party_id"]
        self.svc.add_member(org["party_id"], self.owner_pid, member_pid, "member")
        self.svc.remove_member(org["party_id"], self.owner_pid, member_pid)
        self.assertEqual(self.svc.list_members(org["party_id"])["count"], 0)

    def test_remove_owner_blocked(self):
        org = self.svc.create_org_account("Acme", owner_user_sub=self.owner_sub)
        with self.assertRaises(HTTPException) as ctx:
            self.svc.remove_member(org["party_id"], self.owner_pid, self.owner_pid)
        self.assertEqual(ctx.exception.status_code, 409)


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-009 — Contacts migration
# ═══════════════════════════════════════════════════════════════════════════════


class TestContactsMigration(_PartyTestBase):
    def setUp(self):
        super().setUp()
        object.__setattr__(self.S, "party_crm_contacts_migration_enabled", True)
        self.addCleanup(
            object.__setattr__,
            self.S,
            "party_crm_contacts_migration_enabled",
            False,
        )
        import app.services.party_contacts_migration as mig

        self.mig = mig
        self.contacts_table.put_item(
            Item={
                "owner_id": "alice",
                "contact_id": "bob",
                "display_name": "Bob",
                "is_favorite": True,
                "is_blocked": False,
            }
        )
        self.contacts_table.put_item(
            Item={
                "owner_id": "alice",
                "contact_id": "carol",
                "display_name": "Carol",
                "is_favorite": False,
                "is_blocked": True,
            }
        )

    def test_backfill_scoped(self):
        stats = self.mig.run_contacts_backfill(owner_id="alice")
        self.assertEqual(stats["scanned"], 2)
        self.assertEqual(stats["projected"], 2)
        self.assertEqual(stats["errors"], 0)

    def test_favorite_blocked_carried(self):
        self.mig.run_contacts_backfill(owner_id="alice")
        owner_pid = self.mig._person_party_id("alice")
        bob_pid = self.mig._person_party_id("bob")
        rel = self.party_table.get_item(
            Key={"PK": f"PARTY#{owner_pid}", "SK": f"REL#CONTACT_REL#{bob_pid}"}
        )["Item"]
        self.assertTrue(rel["is_favorite"])
        self.assertEqual(rel["migrated_from"], "contacts")
        # contact role written on bob's party
        roles = {r["role_type"] for r in self.svc.list_roles(bob_pid)}
        self.assertIn("CONTACT", roles)

    def test_backfill_idempotent(self):
        self.mig.run_contacts_backfill(owner_id="alice")
        before = self.party_table.scan()["Count"]
        stats = self.mig.run_contacts_backfill(owner_id="alice")
        after = self.party_table.scan()["Count"]
        self.assertEqual(stats["projected"], 2)
        self.assertEqual(before, after)

    def test_backfill_all_owners(self):
        self.contacts_table.put_item(
            Item={"owner_id": "dave", "contact_id": "erin", "display_name": "Erin"}
        )
        stats = self.mig.run_contacts_backfill()
        self.assertEqual(stats["scanned"], 3)
        self.assertEqual(stats["projected"], 3)

    def test_backfill_flag_off_raises(self):
        object.__setattr__(
            self.S, "party_crm_contacts_migration_enabled", False
        )
        with self.assertRaises(RuntimeError):
            self.mig.run_contacts_backfill(owner_id="alice")

    def test_contacts_table_unchanged(self):
        self.mig.run_contacts_backfill(owner_id="alice")
        bob = self.contacts_table.get_item(
            Key={"owner_id": "alice", "contact_id": "bob"}
        )["Item"]
        self.assertEqual(bob["display_name"], "Bob")
        self.assertTrue(bob["is_favorite"])


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-010 — ensure_person_party
# ═══════════════════════════════════════════════════════════════════════════════


class TestEnsurePersonParty(_PartyTestBase):
    def test_ensure_creates_and_backfills(self):
        with patch(
            "app.services.profile.get_profile_identity",
            return_value={"email": "alice@test.local", "phone": "+12025551234"},
        ), patch("app.services.addresses.list_addresses", return_value=[]):
            pid = self.svc.ensure_person_party("alice")
        meta = self.svc.get_party(pid)
        self.assertEqual(meta["party_type"], "PERSON")
        self.assertEqual(meta["user_sub"], "alice")
        mechs = {m["mech_type"] for m in self.svc.list_contact_mechs(pid)}
        self.assertEqual(mechs, {"EMAIL", "PHONE"})

    def test_ensure_idempotent(self):
        with patch(
            "app.services.profile.get_profile_identity",
            return_value={"email": None, "phone": None},
        ), patch("app.services.addresses.list_addresses", return_value=[]):
            a = self.svc.ensure_person_party("alice")
            b = self.svc.ensure_person_party("alice")
        self.assertEqual(a, b)

    def test_ensure_postal_from_primary_address(self):
        addrs = [
            {
                "address_id": "addr1",
                "is_primary_mailing": True,
                "line1": "1 Main St",
                "city": "Town",
            },
            {"address_id": "addr2", "is_primary_mailing": False, "line1": "2 Side St"},
        ]
        with patch(
            "app.services.profile.get_profile_identity",
            return_value={"email": None, "phone": None},
        ), patch("app.services.addresses.list_addresses", return_value=addrs):
            pid = self.svc.ensure_person_party("alice")
        postal = self.svc.list_contact_mechs(pid, mech_type="POSTAL")
        self.assertEqual(len(postal), 1)

    def test_ensure_flag_off_raises(self):
        object.__setattr__(self.S, "party_crm_enabled", False)
        with self.assertRaises(HTTPException) as ctx:
            self.svc.ensure_person_party("alice")
        self.assertEqual(ctx.exception.status_code, 404)


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-011 / PTY-012 — Router flag guard + happy path
# ═══════════════════════════════════════════════════════════════════════════════


class TestPartyRouter(_PartyTestBase):
    def setUp(self):
        super().setUp()
        import app.routers.party as router

        self.router = router
        self.ctx = {"user_sub": "alice"}

    def test_flag_off_503(self):
        object.__setattr__(self.S, "party_crm_enabled", False)
        from app.models import CrmPartyIn

        with self.assertRaises(HTTPException) as ctx:
            _run(
                self.router.create_party_endpoint(
                    CrmPartyIn(party_type="PERSON"), ctx=self.ctx
                )
            )
        self.assertEqual(ctx.exception.status_code, 503)

    def test_create_and_get(self):
        from app.models import CrmPartyIn

        out = _run(
            self.router.create_party_endpoint(
                CrmPartyIn(party_type="PERSON"), ctx=self.ctx
            )
        )
        self.assertEqual(out.party_type.value, "PERSON")
        got = _run(self.router.get_party_endpoint(out.party_id, ctx=self.ctx))
        self.assertEqual(got.party_id, out.party_id)

    def test_get_not_found(self):
        with self.assertRaises(HTTPException) as ctx:
            _run(self.router.get_party_endpoint("ghost", ctx=self.ctx))
        self.assertEqual(ctx.exception.status_code, 404)

    def test_add_role_via_router(self):
        from app.models import CrmPartyIn, CrmPartyRoleIn

        p = _run(
            self.router.create_party_endpoint(
                CrmPartyIn(party_type="PERSON"), ctx=self.ctx
            )
        )
        r = _run(
            self.router.add_role_endpoint(
                p.party_id, CrmPartyRoleIn(role_type="CUSTOMER"), ctx=self.ctx
            )
        )
        self.assertEqual(r.role_type.value, "CUSTOMER")

    def test_add_mech_via_router(self):
        from app.models import CrmContactMechIn, CrmPartyIn

        p = _run(
            self.router.create_party_endpoint(
                CrmPartyIn(party_type="PERSON"), ctx=self.ctx
            )
        )
        out = _run(
            self.router.add_contact_mech_endpoint(
                p.party_id,
                CrmContactMechIn(mech_type="EMAIL", value="X@Y.com"),
                ctx=self.ctx,
            )
        )
        self.assertEqual(out.mech_type.value, "EMAIL")
        self.assertEqual(out.value, "x@y.com")

    def test_org_flag_off_503(self):
        from app.models import CrmCreateOrgAccountIn

        with self.assertRaises(HTTPException) as ctx:
            _run(
                self.router.create_org_endpoint(
                    CrmCreateOrgAccountIn(name="X"), ctx=self.ctx
                )
            )
        self.assertEqual(ctx.exception.status_code, 503)

    def test_org_create_and_member(self):
        object.__setattr__(self.S, "party_crm_org_accounts_enabled", True)
        self.addCleanup(
            object.__setattr__, self.S, "party_crm_org_accounts_enabled", False
        )
        from app.models import CrmCreateOrgAccountIn, CrmOrgMemberIn, CrmPartyIn

        # Alice's PERSON party (owner) + Bob's PERSON party (member).
        _run(
            self.router.create_party_endpoint(
                CrmPartyIn(party_type="PERSON"), ctx={"user_sub": "alice"}
            )
        )
        bob = _run(
            self.router.create_party_endpoint(
                CrmPartyIn(party_type="PERSON"), ctx={"user_sub": "bob"}
            )
        )
        org = _run(
            self.router.create_org_endpoint(
                CrmCreateOrgAccountIn(name="E2E Corp"), ctx={"user_sub": "alice"}
            )
        )
        self.assertEqual(org.name, "E2E Corp")
        self.assertTrue(org.org_party_id)
        rel = _run(
            self.router.add_org_member_endpoint(
                org.org_party_id,
                CrmOrgMemberIn(member_party_id=bob.party_id, role_type="member"),
                ctx={"user_sub": "alice"},
            )
        )
        self.assertEqual(rel.relationship_type.value, "GROUP_MEMBER")
        members = _run(
            self.router.list_org_members_endpoint(
                org.org_party_id, cursor=None, ctx={"user_sub": "alice"}
            )
        )
        self.assertEqual(len(members["members"]), 1)


# ═══════════════════════════════════════════════════════════════════════════════
# Flag-off regression: legacy contacts surface unchanged (PTY-009 / PTY-015)
# ═══════════════════════════════════════════════════════════════════════════════


class TestFlagOffRegression(_PartyTestBase):
    def setUp(self):
        super().setUp()
        object.__setattr__(self.S, "party_crm_enabled", False)
        object.__setattr__(self.S, "party_crm_contacts_migration_enabled", False)
        import app.routers.contacts as contacts

        self.contacts = contacts

    def test_add_contact_no_party_writes(self):
        with patch(
            "app.routers.contacts.get_profile_identity",
            return_value={"display_name": "Bob", "profile_photo_url": None},
        ):
            from app.routers.contacts import AddContactIn

            out = self.contacts.add_contact(
                AddContactIn(user_id="bob"), ctx={"user_sub": "alice"}
            )
        self.assertEqual(out.contact_id, "bob")
        # No party rows created.
        self.assertEqual(self.party_table.scan()["Count"], 0)
        # Contact row present in legacy table.
        row = self.contacts_table.get_item(
            Key={"owner_id": "alice", "contact_id": "bob"}
        )["Item"]
        self.assertEqual(row["display_name"], "Bob")

    def test_list_contacts_no_party_consult(self):
        self.contacts_table.put_item(
            Item={
                "owner_id": "alice",
                "contact_id": "bob",
                "display_name": "Bob",
                "is_favorite": False,
                "is_blocked": False,
                "added_at": "2026-01-01",
            }
        )
        result = self.contacts.list_contacts(ctx={"user_sub": "alice"})
        self.assertIn("contacts", result)
        self.assertEqual(len(result["contacts"]), 1)
        self.assertEqual(self.party_table.scan()["Count"], 0)


if __name__ == "__main__":
    unittest.main()
