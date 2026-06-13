"""CAS-001 through CAS-017 — hermetic offline tests.

Covers:
  CAS-001  — Settings flags/table defaults, table handle resolution
  CAS-002  — Sequential case number allocation (_next_case_number)
  CAS-003  — Priority field on ticket creation & update_priority
  CAS-005  — contact_id / account_id soft FKs
  CAS-007  — Ticket watchers / CC list (TicketWatcherStore)
  CAS-011  — Case-to-case relationship links (TicketLinkStore)

Pattern: moto in-memory DynamoDB, frozen T/S via object.__setattr__, no TestClient.
"""
from __future__ import annotations

import asyncio
import contextlib
import types
import unittest
from typing import Any
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mk_table(ddb, name: str, pk: str, sk: str | None = None, gsi_specs: list | None = None, attr_types: dict | None = None):
    """Create a minimal DDB table in moto."""
    attr_defs = [{"AttributeName": pk, "AttributeType": "S"}]
    key_schema = [{"AttributeName": pk, "KeyType": "HASH"}]
    if sk:
        attr_defs.append({"AttributeName": sk, "AttributeType": "S"})
        key_schema.append({"AttributeName": sk, "KeyType": "RANGE"})
    gsis = []
    if gsi_specs:
        for gs in gsi_specs:
            ks = [{"AttributeName": gs["pk"], "KeyType": "HASH"}]
            if "sk" in gs:
                ks.append({"AttributeName": gs["sk"], "KeyType": "RANGE"})
            # add attr defs for GSI keys
            for attr_name in ([gs["pk"]] + ([gs["sk"]] if "sk" in gs else [])):
                attr_type = (attr_types or {}).get(attr_name, "S")
                if not any(a["AttributeName"] == attr_name for a in attr_defs):
                    attr_defs.append({"AttributeName": attr_name, "AttributeType": attr_type})
            gsis.append({
                "IndexName": gs["name"],
                "KeySchema": ks,
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            })
    kwargs: dict[str, Any] = {
        "TableName": name,
        "KeySchema": key_schema,
        "AttributeDefinitions": attr_defs,
        "BillingMode": "PAY_PER_REQUEST",
    }
    if gsis:
        kwargs["GlobalSecondaryIndexes"] = gsis
    ddb.create_table(**kwargs)
    return ddb.Table(name)


# ===========================================================================
# CAS-001: Settings smoke tests
# ===========================================================================

class TestCas001Settings(unittest.TestCase):
    def test_crm_cases_flags_default_off(self):
        from app.core.settings import S
        assert S.crm_cases_enabled is False
        assert S.crm_cases_sla_enabled is False
        assert S.crm_cases_portal_enabled is False
        assert S.crm_cases_kb_enabled is False
        assert S.crm_cases_csat_enabled is False
        assert S.crm_cases_email_inbound_enabled is False

    def test_crm_cases_table_name_defaults(self):
        from app.core.settings import S
        assert S.crm_cases_counter_table == "crm_cases_counters"
        assert S.crm_cases_links_table == "crm_cases_links"
        assert S.crm_cases_templates_table == "crm_cases_templates"
        assert S.crm_cases_portal_sessions_table == "crm_cases_portal_sessions"
        assert S.crm_cases_sla_config_table == "crm_cases_sla_config"
        assert S.crm_kb_articles_table == "crm_kb_articles"

    def test_crm_cases_s3_defaults(self):
        from app.core.settings import S
        assert S.crm_cases_attachments_bucket == "local-uploads"
        assert S.crm_cases_attachments_s3_prefix == "ticket-attachments/"

    def test_cas003_index_name_default(self):
        from app.core.settings import S
        assert S.tickets_priority_index_name == "crm_cases_priority_index"

    def test_cas005_index_name_defaults(self):
        from app.core.settings import S
        assert S.tickets_contact_index_name == "crm_cases_contact_index"
        assert S.tickets_account_index_name == "crm_cases_account_index"

    def test_cas007_watcher_table_default(self):
        from app.core.settings import S
        assert S.crm_cases_watchers_table == "crm_cases_watchers"

    def test_cas004_email_rate_default(self):
        from app.core.settings import S
        assert S.crm_cases_email_transactional_per_hour == 20


# ===========================================================================
# CAS-001: Table handle resolution smoke test
# ===========================================================================

class TestCas001TableHandles(unittest.TestCase):
    def test_table_handles_exist(self):
        from app.core.tables import T
        # All six CAS-001 handles must be present on T
        assert hasattr(T, "crm_cases_counters")
        assert hasattr(T, "crm_cases_links")
        assert hasattr(T, "crm_cases_templates")
        assert hasattr(T, "crm_cases_portal_sessions")
        assert hasattr(T, "crm_cases_sla_config")
        assert hasattr(T, "crm_kb_articles")
        assert hasattr(T, "crm_cases_watchers")


# ===========================================================================
# CAS-002: _next_case_number + create_ticket with case_number
# ===========================================================================

class TestCas002CaseNumber(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.counter_table = _mk_table(ddb, "crm_cases_counters", "counter_id", "scope")
        self.ticket_table = _mk_table(
            ddb, "tickets", "pk", "sk",
            gsi_specs=[
                {"name": "ByOwner", "pk": "gsi1pk", "sk": "gsi1sk"},
                {"name": "ByStatus", "pk": "gsi2pk", "sk": "gsi2sk"},
                {"name": "ByAssignee", "pk": "gsi3pk", "sk": "gsi3sk"},
                {"name": "crm_cases_priority_index", "pk": "gsi_priority_pk", "sk": "gsi_priority_sk"},
                {"name": "crm_cases_contact_index", "pk": "gsi_contact_pk", "sk": "gsi_contact_sk"},
                {"name": "crm_cases_account_index", "pk": "gsi_account_pk", "sk": "gsi_account_sk"},
            ],
        )
        from app.core.tables import T, _FloatSafeTable
        from app.services import tickets as tix_mod
        self.T = T
        object.__setattr__(T, "crm_cases_counters", _FloatSafeTable(self.counter_table))
        object.__setattr__(T, "tickets", _FloatSafeTable(self.ticket_table))
        from app.services.tickets import STORE
        object.__setattr__(STORE, "_table", _FloatSafeTable(self.ticket_table))
        self.STORE = STORE
        self.tix_mod = tix_mod

        from app.core.settings import S
        self.S = S
        object.__setattr__(S, "crm_cases_enabled", True)

    def tearDown(self):
        from app.core.settings import S
        object.__setattr__(S, "crm_cases_enabled", False)
        self.stack.close()

    def test_first_case_number_is_case_0001(self):
        from app.services.tickets import _next_case_number
        result = _next_case_number()
        assert result == "CASE-0001"

    def test_sequential_numbers(self):
        from app.services.tickets import _next_case_number
        nums = [_next_case_number() for _ in range(3)]
        assert nums == ["CASE-0001", "CASE-0002", "CASE-0003"]

    def test_overflow_beyond_9999(self):
        # Seed counter to 9999 then call _next_case_number
        self.counter_table.update_item(
            Key={"counter_id": "TICKETS", "scope": "GLOBAL"},
            UpdateExpression="SET #n = :val",
            ExpressionAttributeNames={"#n": "n"},
            ExpressionAttributeValues={":val": 9999},
        )
        from app.services.tickets import _next_case_number
        result = _next_case_number()
        assert result == "CASE-10000"

    def test_create_ticket_with_flag_on_gets_case_number(self):
        ticket = self.STORE.create_ticket(
            owner_sub="u1",
            subject="Test ticket",
            description="A description",
        )
        assert ticket["case_number"] == "CASE-0001"
        # Retrieve should also return it
        got = self.STORE.get_ticket(ticket["ticket_id"])
        assert got["case_number"] == "CASE-0001"

    def test_create_ticket_with_flag_off_no_case_number(self):
        object.__setattr__(self.S, "crm_cases_enabled", False)
        ticket = self.STORE.create_ticket(
            owner_sub="u2",
            subject="No case number",
            description="Description",
        )
        assert ticket["case_number"] is None
        # Counter should not have been touched
        resp = self.counter_table.get_item(Key={"counter_id": "TICKETS", "scope": "GLOBAL"})
        assert "Item" not in resp

    def test_idempotent_create_no_double_increment(self):
        first = self.STORE.create_ticket(
            owner_sub="u3",
            subject="First",
            description="D",
        )
        # Re-create with same ticket_id should return existing
        second = self.STORE.create_ticket(
            owner_sub="u3",
            subject="First",
            description="D",
            ticket_id=first["ticket_id"],
        )
        assert first["ticket_id"] == second["ticket_id"]
        assert second["case_number"] == "CASE-0001"
        # Counter should still be 1
        resp = self.counter_table.get_item(Key={"counter_id": "TICKETS", "scope": "GLOBAL"})
        assert int(resp["Item"]["n"]) == 1

    def test_ticketout_model_accepts_none_case_number(self):
        from app.routers.tickets import TicketOut
        out = TicketOut.model_validate({
            "ticket_id": "t1",
            "subject": "S",
            "owner_sub": "u1",
            "status": "open",
            "created_at": 1000,
            "updated_at": 1000,
            "version": 1,
            "messages": [],
            "activity": [],
        })
        assert out.case_number is None

    def test_ticketout_model_accepts_case_number(self):
        from app.routers.tickets import TicketOut
        out = TicketOut.model_validate({
            "ticket_id": "t1",
            "subject": "S",
            "owner_sub": "u1",
            "status": "open",
            "created_at": 1000,
            "updated_at": 1000,
            "version": 1,
            "case_number": "CASE-0042",
            "messages": [],
            "activity": [],
        })
        assert out.case_number == "CASE-0042"


# ===========================================================================
# CAS-003: Priority field
# ===========================================================================

class TestCas003Priority(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.counter_table = _mk_table(ddb, "crm_cases_counters", "counter_id", "scope")
        self.ticket_table = _mk_table(
            ddb, "tickets", "pk", "sk",
            gsi_specs=[
                {"name": "ByOwner", "pk": "gsi1pk", "sk": "gsi1sk"},
                {"name": "ByStatus", "pk": "gsi2pk", "sk": "gsi2sk"},
                {"name": "ByAssignee", "pk": "gsi3pk", "sk": "gsi3sk"},
                {"name": "crm_cases_priority_index", "pk": "gsi_priority_pk", "sk": "gsi_priority_sk"},
                {"name": "crm_cases_contact_index", "pk": "gsi_contact_pk", "sk": "gsi_contact_sk"},
                {"name": "crm_cases_account_index", "pk": "gsi_account_pk", "sk": "gsi_account_sk"},
            ],
        )
        from app.core.tables import T, _FloatSafeTable
        self.T = T
        object.__setattr__(T, "crm_cases_counters", _FloatSafeTable(self.counter_table))
        object.__setattr__(T, "tickets", _FloatSafeTable(self.ticket_table))
        from app.services.tickets import STORE
        object.__setattr__(STORE, "_table", _FloatSafeTable(self.ticket_table))
        self.STORE = STORE

        from app.core.settings import S
        self.S = S
        object.__setattr__(S, "crm_cases_enabled", True)
        object.__setattr__(S, "tickets_priority_index_name", "crm_cases_priority_index")

    def tearDown(self):
        from app.core.settings import S
        object.__setattr__(S, "crm_cases_enabled", False)
        self.stack.close()

    def test_create_with_explicit_priority(self):
        ticket = self.STORE.create_ticket(
            owner_sub="u1", subject="Urgent ticket", description="D", priority="urgent"
        )
        assert ticket["priority"] == "urgent"

    def test_create_with_default_priority(self):
        ticket = self.STORE.create_ticket(
            owner_sub="u1", subject="Default ticket", description="D"
        )
        assert ticket["priority"] == "medium"

    def test_create_with_invalid_priority_defaults_to_medium(self):
        ticket = self.STORE.create_ticket(
            owner_sub="u1", subject="Invalid prio", description="D", priority="critical"
        )
        assert ticket["priority"] == "medium"

    def test_create_with_flag_off_no_priority(self):
        object.__setattr__(self.S, "crm_cases_enabled", False)
        ticket = self.STORE.create_ticket(
            owner_sub="u1", subject="No prio", description="D", priority="urgent"
        )
        assert ticket["priority"] is None

    def test_update_priority_success(self):
        ticket = self.STORE.create_ticket(
            owner_sub="u1", subject="T", description="D", priority="low"
        )
        updated = self.STORE.update_priority(
            ticket_id=ticket["ticket_id"],
            new_priority="high",
            actor_sub="admin1",
        )
        assert updated is not None
        assert updated["priority"] == "high"

    def test_update_priority_invalid_value_raises(self):
        ticket = self.STORE.create_ticket(
            owner_sub="u1", subject="T", description="D"
        )
        with pytest.raises(ValueError, match="invalid priority"):
            self.STORE.update_priority(
                ticket_id=ticket["ticket_id"],
                new_priority="critical",
                actor_sub="admin1",
            )

    def test_update_priority_unknown_ticket_returns_none(self):
        result = self.STORE.update_priority(
            ticket_id="tkt_nonexistent",
            new_priority="urgent",
            actor_sub="admin1",
        )
        assert result is None

    def test_list_tickets_by_priority(self):
        for _ in range(2):
            self.STORE.create_ticket(owner_sub="u1", subject="U", description="D", priority="urgent")
        self.STORE.create_ticket(owner_sub="u1", subject="H", description="D", priority="high")
        result = self.STORE.list_tickets(priority="urgent")
        assert len(result["tickets"]) == 2
        for t in result["tickets"]:
            assert t["priority"] == "urgent"

    def test_list_tickets_priority_filter_invalid_value_returns_empty(self):
        # When flag is on but an unrecognized priority string is passed (bypasses
        # Pydantic — tested at service level), the service returns [] immediately.
        result = self.STORE.list_tickets(priority="not_a_real_priority")
        assert result == {"tickets": [], "next_cursor": None}

    def test_ticketout_model_has_priority_field(self):
        from app.routers.tickets import TicketOut
        out = TicketOut.model_validate({
            "ticket_id": "t1",
            "subject": "S",
            "owner_sub": "u1",
            "status": "open",
            "created_at": 1000,
            "updated_at": 1000,
            "version": 1,
            "priority": "urgent",
            "messages": [],
            "activity": [],
        })
        assert out.priority == "urgent"


# ===========================================================================
# CAS-005: contact_id / account_id soft FKs
# ===========================================================================

class TestCas005ContactAccount(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.counter_table = _mk_table(ddb, "crm_cases_counters", "counter_id", "scope")
        self.ticket_table = _mk_table(
            ddb, "tickets", "pk", "sk",
            gsi_specs=[
                {"name": "ByOwner", "pk": "gsi1pk", "sk": "gsi1sk"},
                {"name": "ByStatus", "pk": "gsi2pk", "sk": "gsi2sk"},
                {"name": "ByAssignee", "pk": "gsi3pk", "sk": "gsi3sk"},
                {"name": "crm_cases_priority_index", "pk": "gsi_priority_pk", "sk": "gsi_priority_sk"},
                {"name": "crm_cases_contact_index", "pk": "gsi_contact_pk", "sk": "gsi_contact_sk"},
                {"name": "crm_cases_account_index", "pk": "gsi_account_pk", "sk": "gsi_account_sk"},
            ],
        )
        from app.core.tables import T, _FloatSafeTable
        self.T = T
        object.__setattr__(T, "crm_cases_counters", _FloatSafeTable(self.counter_table))
        object.__setattr__(T, "tickets", _FloatSafeTable(self.ticket_table))
        from app.services.tickets import STORE
        object.__setattr__(STORE, "_table", _FloatSafeTable(self.ticket_table))
        self.STORE = STORE

        from app.core.settings import S
        self.S = S
        object.__setattr__(S, "crm_cases_enabled", True)
        object.__setattr__(S, "tickets_contact_index_name", "crm_cases_contact_index")
        object.__setattr__(S, "tickets_account_index_name", "crm_cases_account_index")

    def tearDown(self):
        from app.core.settings import S
        object.__setattr__(S, "crm_cases_enabled", False)
        self.stack.close()

    def test_create_ticket_with_contact_id(self):
        ticket = self.STORE.create_ticket(
            owner_sub="u1", subject="T", description="D", contact_id="cnt_abc"
        )
        assert ticket["contact_id"] == "cnt_abc"
        assert ticket["account_id"] is None

    def test_create_ticket_with_account_id(self):
        ticket = self.STORE.create_ticket(
            owner_sub="u1", subject="T", description="D", account_id="acc_xyz"
        )
        assert ticket["account_id"] == "acc_xyz"

    def test_create_ticket_without_fks_when_flag_off(self):
        object.__setattr__(self.S, "crm_cases_enabled", False)
        ticket = self.STORE.create_ticket(
            owner_sub="u1", subject="T", description="D",
            contact_id="cnt_abc", account_id="acc_xyz",
        )
        assert ticket["contact_id"] is None
        assert ticket["account_id"] is None

    def test_update_contact_account(self):
        ticket = self.STORE.create_ticket(owner_sub="u1", subject="T", description="D")
        updated = self.STORE.update_contact_account(
            ticket_id=ticket["ticket_id"],
            contact_id="cnt_new",
            account_id="acc_new",
            actor_sub="admin1",
        )
        assert updated is not None
        assert updated["contact_id"] == "cnt_new"
        assert updated["account_id"] == "acc_new"

    def test_list_tickets_by_contact(self):
        self.STORE.create_ticket(owner_sub="u1", subject="T1", description="D", contact_id="cnt_001")
        self.STORE.create_ticket(owner_sub="u1", subject="T2", description="D", contact_id="cnt_001")
        self.STORE.create_ticket(owner_sub="u1", subject="T3", description="D", contact_id="cnt_002")
        result = self.STORE.list_tickets_by_contact(contact_id="cnt_001")
        assert len(result["tickets"]) == 2

    def test_list_tickets_by_account(self):
        self.STORE.create_ticket(owner_sub="u1", subject="T1", description="D", account_id="acc_001")
        self.STORE.create_ticket(owner_sub="u1", subject="T2", description="D", account_id="acc_002")
        result = self.STORE.list_tickets_by_account(account_id="acc_001")
        assert len(result["tickets"]) == 1


# ===========================================================================
# CAS-007: Ticket watchers
# ===========================================================================

class TestCas007Watchers(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.watcher_table = _mk_table(
            ddb, "crm_cases_watchers", "ticket_id", "sk",
            gsi_specs=[{"name": "ByWatcher", "pk": "watcher_sub", "sk": "created_at"}],
            attr_types={"created_at": "N"},
        )
        from app.core.tables import T, _FloatSafeTable
        self.T = T
        object.__setattr__(T, "crm_cases_watchers", _FloatSafeTable(self.watcher_table))
        from app.services.ticket_watchers import WATCHER_STORE, TicketWatcherStore
        # Re-bind the singleton to use the fresh table
        object.__setattr__(WATCHER_STORE, "_table", _FloatSafeTable(self.watcher_table))
        self.STORE = WATCHER_STORE

    def tearDown(self):
        self.stack.close()

    def test_add_watcher(self):
        result = self.STORE.add_watcher(ticket_id="tkt_1", watcher_sub="u_alice", actor_sub="admin")
        assert result["ticket_id"] == "tkt_1"
        assert result["watcher_sub"] == "u_alice"
        assert result["added_by_sub"] == "admin"

    def test_add_watcher_idempotent(self):
        self.STORE.add_watcher(ticket_id="tkt_1", watcher_sub="u_alice", actor_sub="admin")
        self.STORE.add_watcher(ticket_id="tkt_1", watcher_sub="u_alice", actor_sub="admin2")
        watchers = self.STORE.list_watchers(ticket_id="tkt_1")
        assert len(watchers) == 1  # Idempotent — should not duplicate

    def test_list_watchers(self):
        self.STORE.add_watcher(ticket_id="tkt_1", watcher_sub="u_alice", actor_sub="admin")
        self.STORE.add_watcher(ticket_id="tkt_1", watcher_sub="u_bob", actor_sub="admin")
        watchers = self.STORE.list_watchers(ticket_id="tkt_1")
        assert len(watchers) == 2
        subs = {w["watcher_sub"] for w in watchers}
        assert subs == {"u_alice", "u_bob"}

    def test_remove_watcher(self):
        self.STORE.add_watcher(ticket_id="tkt_1", watcher_sub="u_alice", actor_sub="admin")
        removed = self.STORE.remove_watcher(ticket_id="tkt_1", watcher_sub="u_alice")
        assert removed is True
        watchers = self.STORE.list_watchers(ticket_id="tkt_1")
        assert len(watchers) == 0

    def test_remove_nonexistent_watcher(self):
        removed = self.STORE.remove_watcher(ticket_id="tkt_1", watcher_sub="u_nobody")
        assert removed is False

    def test_get_watcher_subs(self):
        self.STORE.add_watcher(ticket_id="tkt_2", watcher_sub="u_1", actor_sub="admin")
        self.STORE.add_watcher(ticket_id="tkt_2", watcher_sub="u_2", actor_sub="admin")
        subs = self.STORE.get_watcher_subs(ticket_id="tkt_2")
        assert set(subs) == {"u_1", "u_2"}

    def test_list_tickets_for_watcher(self):
        self.STORE.add_watcher(ticket_id="tkt_1", watcher_sub="u_shared", actor_sub="admin")
        self.STORE.add_watcher(ticket_id="tkt_2", watcher_sub="u_shared", actor_sub="admin")
        self.STORE.add_watcher(ticket_id="tkt_3", watcher_sub="u_other", actor_sub="admin")
        result = self.STORE.list_tickets_for_watcher(watcher_sub="u_shared")
        assert set(result) == {"tkt_1", "tkt_2"}

    def test_watchers_are_ticket_scoped(self):
        self.STORE.add_watcher(ticket_id="tkt_A", watcher_sub="u_1", actor_sub="admin")
        self.STORE.add_watcher(ticket_id="tkt_B", watcher_sub="u_2", actor_sub="admin")
        # tkt_A should only have u_1
        assert self.STORE.get_watcher_subs(ticket_id="tkt_A") == ["u_1"]
        # tkt_B should only have u_2
        assert self.STORE.get_watcher_subs(ticket_id="tkt_B") == ["u_2"]


# ===========================================================================
# CAS-011: Case-to-case relationship links
# ===========================================================================

class TestCas011Links(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.links_table = _mk_table(
            ddb, "crm_cases_links", "ticket_id", "sk",
            gsi_specs=[{"name": "ByRelated", "pk": "related_ticket_id", "sk": "created_at"}],
            attr_types={"created_at": "N"},
        )
        from app.core.tables import T, _FloatSafeTable
        object.__setattr__(T, "crm_cases_links", _FloatSafeTable(self.links_table))
        from app.services.ticket_links import LINK_STORE
        object.__setattr__(LINK_STORE, "_table", _FloatSafeTable(self.links_table))
        self.STORE = LINK_STORE

    def tearDown(self):
        self.stack.close()

    def test_create_link_duplicate(self):
        link = self.STORE.create_link(
            ticket_id="tkt_A",
            related_ticket_id="tkt_B",
            link_type="duplicate",
            created_by_sub="admin",
        )
        assert link["link_type"] == "duplicate"
        assert link["ticket_id"] == "tkt_A"
        assert link["related_ticket_id"] == "tkt_B"

    def test_create_link_blocks(self):
        link = self.STORE.create_link(
            ticket_id="tkt_A",
            related_ticket_id="tkt_C",
            link_type="blocks",
            created_by_sub="admin",
        )
        assert link["link_type"] == "blocks"

    def test_create_link_relates_to(self):
        link = self.STORE.create_link(
            ticket_id="tkt_A",
            related_ticket_id="tkt_D",
            link_type="relates_to",
            created_by_sub="admin",
        )
        assert link["link_type"] == "relates_to"

    def test_create_link_invalid_type_raises(self):
        with pytest.raises(ValueError, match="invalid link_type"):
            self.STORE.create_link(
                ticket_id="tkt_A",
                related_ticket_id="tkt_B",
                link_type="supersedes",
                created_by_sub="admin",
            )

    def test_create_link_self_raises(self):
        with pytest.raises(ValueError, match="must be different"):
            self.STORE.create_link(
                ticket_id="tkt_A",
                related_ticket_id="tkt_A",
                link_type="duplicate",
                created_by_sub="admin",
            )

    def test_create_link_idempotent(self):
        self.STORE.create_link(ticket_id="tkt_A", related_ticket_id="tkt_B",
                               link_type="duplicate", created_by_sub="admin")
        self.STORE.create_link(ticket_id="tkt_A", related_ticket_id="tkt_B",
                               link_type="duplicate", created_by_sub="admin2")
        links = self.STORE.list_links(ticket_id="tkt_A")
        assert len(links) == 1

    def test_list_links_forward(self):
        self.STORE.create_link(ticket_id="tkt_A", related_ticket_id="tkt_B",
                               link_type="duplicate", created_by_sub="admin")
        self.STORE.create_link(ticket_id="tkt_A", related_ticket_id="tkt_C",
                               link_type="blocks", created_by_sub="admin")
        links = self.STORE.list_links(ticket_id="tkt_A")
        assert len(links) == 2

    def test_list_reverse_links(self):
        self.STORE.create_link(ticket_id="tkt_A", related_ticket_id="tkt_B",
                               link_type="duplicate", created_by_sub="admin")
        # Reverse: tkt_B should see it in reverse
        rev = self.STORE.list_reverse_links(ticket_id="tkt_B")
        assert len(rev) == 1
        assert rev[0]["ticket_id"] == "tkt_A"

    def test_list_all_links_combines_forward_and_reverse(self):
        self.STORE.create_link(ticket_id="tkt_A", related_ticket_id="tkt_B",
                               link_type="duplicate", created_by_sub="admin")
        self.STORE.create_link(ticket_id="tkt_C", related_ticket_id="tkt_A",
                               link_type="relates_to", created_by_sub="admin")
        all_links = self.STORE.list_all_links(ticket_id="tkt_A")
        # Should see both directions
        assert len(all_links) == 2

    def test_delete_link(self):
        self.STORE.create_link(ticket_id="tkt_A", related_ticket_id="tkt_B",
                               link_type="duplicate", created_by_sub="admin")
        removed = self.STORE.delete_link(ticket_id="tkt_A", related_ticket_id="tkt_B")
        assert removed is True
        links = self.STORE.list_links(ticket_id="tkt_A")
        assert len(links) == 0

    def test_delete_nonexistent_link(self):
        removed = self.STORE.delete_link(ticket_id="tkt_A", related_ticket_id="tkt_Z")
        assert removed is False

    def test_gsi_numeric_sort_key_accepted(self):
        """Regression: ByRelated GSI with numeric created_at must not raise ValidationException."""
        from decimal import Decimal
        self.STORE.create_link(
            ticket_id="tkt_X",
            related_ticket_id="tkt_Y",
            link_type="relates_to",
            created_by_sub="admin",
        )
        # Query via GSI — would raise if created_at stored as String when attr_type is N
        resp = self.links_table.query(
            IndexName="ByRelated",
            KeyConditionExpression="related_ticket_id = :rtid",
            ExpressionAttributeValues={":rtid": "tkt_Y"},
        )
        assert len(resp["Items"]) == 1
        # moto returns Decimal for numeric values; ensure it IS numeric (not a string)
        created_at_val = resp["Items"][0]["created_at"]
        assert isinstance(created_at_val, (int, Decimal)), f"Expected numeric, got {type(created_at_val)}"


# ===========================================================================
# CAS-001: app.main import smoke test is validated by the test runner
# (no TestClient needed — just importing app.main verifies all wiring)
# ===========================================================================

class TestCas001AppMainImport(unittest.TestCase):
    def test_app_main_imports_without_error(self):
        import importlib
        import app.main as _m
        # If we get here without an exception, import succeeded
        assert hasattr(_m, "app")
