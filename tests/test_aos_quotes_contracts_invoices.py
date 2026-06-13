"""Hermetic offline tests for the AOS QUOTES/CONTRACTS/INVOICE-PAYMENT backend
(QUO-001, QUO-003, QUO-004, QUO-005) including the D1 (signed_amount_cents) and
D5 (admin record-payment) money reconciliations.

Isolation: a single in-memory moto DynamoDB resource created inside an explicit
context; the exact frozen ``T.*`` table handles are patched via
``object.__setattr__`` and restored on cleanup. Frozen ``S`` flags flipped via
``object.__setattr__``. ``audit_event`` / ``send_alert_email`` patched. Route
handler functions are called directly (no TestClient).
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import boto3
from moto import mock_aws

from app.core.settings import S
from app.core.tables import T


def _aos_quotes_table(ddb):
    return ddb.create_table(
        TableName="aos_quotes_test",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
            {"AttributeName": "GSI2PK", "AttributeType": "S"},
            {"AttributeName": "GSI2SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {"IndexName": "GSI1", "KeySchema": [
                {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                {"AttributeName": "GSI1SK", "KeyType": "RANGE"}],
             "Projection": {"ProjectionType": "ALL"}},
            {"IndexName": "GSI2", "KeySchema": [
                {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                {"AttributeName": "GSI2SK", "KeyType": "RANGE"}],
             "Projection": {"ProjectionType": "ALL"}},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _aos_contracts_table(ddb):
    return ddb.create_table(
        TableName="aos_contracts_test",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
            {"AttributeName": "GSI2PK", "AttributeType": "S"},
            {"AttributeName": "GSI2SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {"IndexName": "contracts-all-index", "KeySchema": [
                {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                {"AttributeName": "GSI1SK", "KeyType": "RANGE"}],
             "Projection": {"ProjectionType": "ALL"}},
            {"IndexName": "contracts-by-stage-index", "KeySchema": [
                {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                {"AttributeName": "GSI2SK", "KeyType": "RANGE"}],
             "Projection": {"ProjectionType": "ALL"}},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _invoices_table(ddb):
    return ddb.create_table(
        TableName="invoices_test",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
            {"AttributeName": "GSI2PK", "AttributeType": "S"},
            {"AttributeName": "GSI2SK", "AttributeType": "N"},
            {"AttributeName": "GSI3PK", "AttributeType": "S"},
            {"AttributeName": "GSI3SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {"IndexName": "GSI1", "KeySchema": [
                {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                {"AttributeName": "GSI1SK", "KeyType": "RANGE"}],
             "Projection": {"ProjectionType": "ALL"}},
            {"IndexName": "GSI2", "KeySchema": [
                {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                {"AttributeName": "GSI2SK", "KeyType": "RANGE"}],
             "Projection": {"ProjectionType": "ALL"}},
            {"IndexName": "GSI3", "KeySchema": [
                {"AttributeName": "GSI3PK", "KeyType": "HASH"},
                {"AttributeName": "GSI3SK", "KeyType": "RANGE"}],
             "Projection": {"ProjectionType": "ALL"}},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _billing_table(ddb):
    return ddb.create_table(
        TableName="billing_test",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


# ---------------------------------------------------------------------------
# QUO-001 — quotes service
# ---------------------------------------------------------------------------

class QuotesServiceTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.tbl = _aos_quotes_table(ddb)

        prev_tbl = T.aos_quotes
        object.__setattr__(T, "aos_quotes", self.tbl)
        self.addCleanup(lambda: object.__setattr__(T, "aos_quotes", prev_tbl))

        prev_flag = S.aos_quotes_enabled
        object.__setattr__(S, "aos_quotes_enabled", True)
        self.addCleanup(lambda: object.__setattr__(S, "aos_quotes_enabled", prev_flag))

        self.audit = self.stack.enter_context(
            patch("app.services.aos_quotes.audit_event", MagicMock())
        )
        import app.services.aos_quotes as svc
        self.svc = svc

    def _line(self, **kw):
        base = {"description": "Widget", "qty": 1, "unit_price_cents": 1000,
                "discount_bps": 0, "tax_rate_bps": 0}
        base.update(kw)
        return base

    def test_create_quote_basic(self):
        q = self.svc.create_quote("alice", "Q1", line_items=[self._line()])
        self.assertEqual(q["quote_number"], "AOS-00001")
        self.assertEqual(q["stage"], "draft")
        self.assertEqual(q["total_cents"], 1000)
        self.assertTrue(q["quote_id"].startswith("quo_"))
        self.audit.assert_any_call("quote.created", "alice", quote_id=q["quote_id"],
                                   quote_number="AOS-00001")

    def test_totals_computation(self):
        items = [
            self._line(qty=2, unit_price_cents=1000, discount_bps=1000, tax_rate_bps=0),
            self._line(qty=1, unit_price_cents=5000, discount_bps=0, tax_rate_bps=2000),
        ]
        q = self.svc.create_quote("alice", "Q", line_items=items)
        # line1: gross=2000 disc=200 net=1800 tax=0 -> 1800
        # line2: gross=5000 disc=0 net=5000 tax=1000 -> 6000
        self.assertEqual(q["subtotal_cents"], 7000)
        self.assertEqual(q["discount_cents"], 200)
        self.assertEqual(q["tax_cents"], 1000)
        self.assertEqual(q["total_cents"], 7800)
        self.assertEqual(q["line_items"][0]["line_total_cents"], 1800)
        self.assertEqual(q["line_items"][1]["line_total_cents"], 6000)

    def test_counter_monotonic(self):
        a = self.svc.create_quote("alice", "A", line_items=[self._line()])
        b = self.svc.create_quote("alice", "B", line_items=[self._line()])
        self.assertEqual(a["quote_number"], "AOS-00001")
        self.assertEqual(b["quote_number"], "AOS-00002")

    def test_get_not_found_and_wrong_owner(self):
        q = self.svc.create_quote("alice", "A", line_items=[self._line()])
        self.assertIsNone(self.svc.get_quote("alice", "quo_nope"))
        self.assertIsNone(self.svc.get_quote("bob", q["quote_id"]))

    def test_list_no_filter_and_stage(self):
        q1 = self.svc.create_quote("alice", "A", line_items=[self._line()])
        self.svc.create_quote("alice", "B", line_items=[self._line()])
        self.svc.transition_stage("alice", q1["quote_id"], "sent")
        all_q = self.svc.list_quotes("alice")
        self.assertEqual(len(all_q["quotes"]), 2)
        drafts = self.svc.list_quotes("alice", stage="draft")
        self.assertEqual(len(drafts["quotes"]), 1)
        sent = self.svc.list_quotes("alice", stage="sent")
        self.assertEqual(len(sent["quotes"]), 1)

    def test_stage_transition_valid_and_invalid(self):
        q = self.svc.create_quote("alice", "A", line_items=[self._line()])
        out = self.svc.transition_stage("alice", q["quote_id"], "sent")
        self.assertEqual(out["stage"], "sent")
        with self.assertRaises(ValueError):
            self.svc.transition_stage("alice", q["quote_id"], "draft")

    def test_invalid_draft_to_accepted(self):
        q = self.svc.create_quote("alice", "A", line_items=[self._line()])
        with self.assertRaises(ValueError) as ctx:
            self.svc.transition_stage("alice", q["quote_id"], "accepted")
        self.assertIn("invalid transition", str(ctx.exception))

    def test_terminal_rejected(self):
        q = self.svc.create_quote("alice", "A", line_items=[self._line()])
        self.svc.transition_stage("alice", q["quote_id"], "sent")
        self.svc.transition_stage("alice", q["quote_id"], "rejected")
        with self.assertRaises(ValueError):
            self.svc.transition_stage("alice", q["quote_id"], "accepted")

    def test_update_recomputes_totals(self):
        q = self.svc.create_quote("alice", "A", line_items=[self._line()])
        out = self.svc.update_quote(
            "alice", q["quote_id"],
            line_items=[self._line(qty=3, unit_price_cents=2000)],
        )
        self.assertEqual(out["total_cents"], 6000)

    def test_admin_list_cross_user(self):
        self.svc.create_quote("alice", "A", line_items=[self._line()])
        self.svc.create_quote("bob", "B", line_items=[self._line()])
        out = self.svc.admin_list_quotes()
        self.assertEqual(len(out["quotes"]), 2)

    def test_flag_off_returns_none(self):
        object.__setattr__(S, "aos_quotes_enabled", False)
        self.assertIsNone(self.svc.create_quote("alice", "A", line_items=[self._line()]))


# ---------------------------------------------------------------------------
# QUO-004 — contracts service
# ---------------------------------------------------------------------------

class ContractsServiceTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.tbl = _aos_contracts_table(ddb)

        prev = T.aos_contracts
        object.__setattr__(T, "aos_contracts", self.tbl)
        self.addCleanup(lambda: object.__setattr__(T, "aos_contracts", prev))

        pf = S.aos_contracts_enabled
        pf2 = S.aos_contracts_renewal_notifications_enabled
        object.__setattr__(S, "aos_contracts_enabled", True)
        object.__setattr__(S, "aos_contracts_renewal_notifications_enabled", True)
        self.addCleanup(lambda: object.__setattr__(S, "aos_contracts_enabled", pf))
        self.addCleanup(
            lambda: object.__setattr__(S, "aos_contracts_renewal_notifications_enabled", pf2)
        )

        self.stack.enter_context(patch("app.services.aos_contracts.audit_event", MagicMock()))
        self.email = self.stack.enter_context(
            patch("app.services.aos_contracts.send_alert_email", MagicMock())
        )
        import app.services.aos_contracts as svc
        self.svc = svc

    def test_create_draft(self):
        c = self.svc.create_contract("alice", title="SLA", start_date=1000, value_cents=5000)
        self.assertEqual(c["stage"], "draft")
        self.assertTrue(c["contract_number"].startswith("CON-"))
        self.assertTrue(c["contract_id"].startswith("con_"))

    def test_sequential_numbers(self):
        a = self.svc.create_contract("alice", title="A", start_date=1)
        b = self.svc.create_contract("alice", title="B", start_date=1)
        self.assertTrue(a["contract_number"].endswith("00001"))
        self.assertTrue(b["contract_number"].endswith("00002"))

    def test_ownership(self):
        c = self.svc.create_contract("alice", title="A", start_date=1)
        self.assertIsNone(self.svc.get_contract("bob", c["contract_id"]))

    def test_transition_valid_invalid(self):
        from fastapi import HTTPException
        c = self.svc.create_contract("alice", title="A", start_date=1, end_date=100)
        out = self.svc.transition_stage("alice", c["contract_id"], "active")
        self.assertEqual(out["stage"], "active")
        # draft->expired invalid (from a fresh one)
        c2 = self.svc.create_contract("alice", title="B", start_date=1)
        with self.assertRaises(HTTPException) as ctx:
            self.svc.transition_stage("alice", c2["contract_id"], "expired")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_terminal_locked(self):
        from fastapi import HTTPException
        c = self.svc.create_contract("alice", title="A", start_date=1, end_date=100)
        self.svc.transition_stage("alice", c["contract_id"], "active")
        self.svc.transition_stage("alice", c["contract_id"], "terminated")
        with self.assertRaises(HTTPException):
            self.svc.transition_stage("alice", c["contract_id"], "active")

    def test_renewal_notification_and_idempotent(self):
        from app.core.time import now_ts
        now = now_ts()
        c = self.svc.create_contract(
            "alice", title="A", start_date=now - 10, end_date=now + 5 * 86400,
            renewal_notice_days=30,
        )
        self.svc.transition_stage("alice", c["contract_id"], "active")
        sent = self.svc.check_expiring_contracts()
        self.assertEqual(sent, 1)
        self.email.assert_called_once()
        # second run: idempotent
        sent2 = self.svc.check_expiring_contracts()
        self.assertEqual(sent2, 0)

    def test_renewal_open_ended_skipped(self):
        from app.core.time import now_ts
        c = self.svc.create_contract("alice", title="A", start_date=now_ts())
        self.svc.transition_stage("alice", c["contract_id"], "active")
        self.assertEqual(self.svc.check_expiring_contracts(), 0)

    def test_admin_list_cross_user(self):
        self.svc.create_contract("alice", title="A", start_date=1)
        self.svc.create_contract("bob", title="B", start_date=1)
        out = self.svc.admin_list_contracts()
        self.assertEqual(out["count"], 2)

    def test_flag_off(self):
        object.__setattr__(S, "aos_contracts_enabled", False)
        self.assertIsNone(self.svc.create_contract("alice", title="A", start_date=1))


# ---------------------------------------------------------------------------
# QUO-005 — invoice lifecycle + D1/D5 money reconciliations
# ---------------------------------------------------------------------------

class InvoiceLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.inv = _invoices_table(ddb)
        self.bill = _billing_table(ddb)

        pinv, pbill = T.invoices, T.billing
        object.__setattr__(T, "invoices", self.inv)
        object.__setattr__(T, "billing", self.bill)
        self.addCleanup(lambda: object.__setattr__(T, "invoices", pinv))
        self.addCleanup(lambda: object.__setattr__(T, "billing", pbill))

        flags = {
            "aos_standalone_invoices_enabled": True,
            "invoices_enabled": True,
            "invoices_tax_bps": 0,
        }
        self._prev = {k: getattr(S, k) for k in flags}
        for k, v in flags.items():
            object.__setattr__(S, k, v)
        self.addCleanup(self._restore_flags)

        self.stack.enter_context(patch("app.services.invoices.audit_event", MagicMock(), create=True))
        # audit/send live in alerts; patch those used by invoices lazily
        self.stack.enter_context(patch("app.services.alerts.audit_event", MagicMock()))
        self.stack.enter_context(patch("app.services.alerts.send_alert_email", MagicMock()))
        # Avoid real S3 round-trips
        self.stack.enter_context(patch.object(__import__("app.services.invoices", fromlist=["_s3"]), "_s3", MagicMock()))
        import app.services.invoices as svc
        self.svc = svc

    def _restore_flags(self):
        for k, v in self._prev.items():
            object.__setattr__(S, k, v)

    def _manual(self, **kw):
        base = dict(
            admin_user_sub="admin1", buyer_user_sub="buyer1",
            buyer_name="ACME", buyer_email="ap@acme.com",
            billing_address={}, line_items=[
                {"description": "Consulting", "quantity": 5,
                 "unit_price_cents": 10000, "tax_rate_bps": 0}],
            payment_terms_days=30,
        )
        base.update(kw)
        return self.svc.create_manual_invoice(**base)

    def _ledger_entries(self, pk):
        resp = self.bill.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :sk)",
            ExpressionAttributeValues={":pk": pk, ":sk": "LEDGER#"},
        )
        return resp.get("Items", [])

    def _balance(self, pk):
        return self.bill.get_item(Key={"pk": pk, "sk": "BALANCE"}).get("Item") or {}

    def test_manual_create_happy(self):
        inv = self._manual()
        self.assertEqual(inv["status"], "draft")
        self.assertEqual(inv["invoice_type"], "b2b")
        self.assertEqual(inv["total_cents"], 50000)
        self.assertEqual(inv["payment_terms_days"], 30)
        raw = self.inv.get_item(
            Key={"pk": "USER#buyer1", "sk": f"INV#{inv['invoice_number']}"}
        )["Item"]
        self.assertNotIn("GSI3PK", raw)
        self.assertEqual(raw["GSI1PK"], "USER#buyer1#TYPE#b2b")
        self.assertEqual(int(raw["due_date"]), int(raw["created_at"]) + 2592000)

    def test_draft_to_sent_enrolls_scanner(self):
        inv = self._manual()
        self.svc.update_invoice_status("buyer1", inv["invoice_number"], "sent")
        raw = self.inv.get_item(
            Key={"pk": "USER#buyer1", "sk": f"INV#{inv['invoice_number']}"}
        )["Item"]
        self.assertEqual(raw["status"], "sent")
        self.assertEqual(raw["GSI3PK"], "STATUS#sent")

    def test_sent_to_paid_d1_credit(self):
        inv = self._manual()
        n = inv["invoice_number"]
        self.svc.update_invoice_status("buyer1", n, "sent")
        out = self.svc.update_invoice_status("buyer1", n, "paid", payment_ref="TXN-1")
        self.assertEqual(out["status"], "paid")
        entries = self._ledger_entries("USER#buyer1")
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e["type"], "b2b_invoice_payment")
        self.assertEqual(int(e["amount_cents"]), 50000)
        self.assertEqual(int(e["signed_amount_cents"]), 50000)  # D1 positive
        self.assertEqual(int(self._balance("USER#buyer1")["payments_settled_cents"]), 50000)

    def test_draft_to_void_no_ledger(self):
        inv = self._manual()
        out = self.svc.update_invoice_status("buyer1", inv["invoice_number"], "void")
        self.assertEqual(out["status"], "void")
        self.assertIsNotNone(out["voided_at"])
        self.assertEqual(self._ledger_entries("USER#buyer1"), [])

    def test_paid_void_requires_admin(self):
        from fastapi import HTTPException
        inv = self._manual()
        n = inv["invoice_number"]
        self.svc.update_invoice_status("buyer1", n, "sent")
        self.svc.update_invoice_status("buyer1", n, "paid")
        with self.assertRaises(HTTPException) as ctx:
            self.svc.update_invoice_status("buyer1", n, "void", admin=False)
        self.assertEqual(ctx.exception.status_code, 409)

    def test_paid_void_admin_canonical_reversal(self):
        inv = self._manual()
        n = inv["invoice_number"]
        self.svc.update_invoice_status("buyer1", n, "sent")
        self.svc.update_invoice_status("buyer1", n, "paid")
        out = self.svc.update_invoice_status("buyer1", n, "void", admin=True)
        self.assertEqual(out["status"], "void")
        entries = self._ledger_entries("USER#buyer1")
        # one payment + one reversal
        types = sorted(e["type"] for e in entries)
        self.assertEqual(types, ["adjustment", "b2b_invoice_payment"])
        rev = [e for e in entries if e["type"] == "adjustment"][0]
        self.assertEqual(int(rev["amount_cents"]), 50000)        # positive (A4)
        self.assertEqual(int(rev["signed_amount_cents"]), -50000)  # D1 negative
        self.assertEqual(rev["reason"], "void")
        # balance net to 0 (50000 in, 50000 out)
        self.assertEqual(int(self._balance("USER#buyer1")["payments_settled_cents"]), 0)

    def test_void_idempotent(self):
        inv = self._manual()
        n = inv["invoice_number"]
        self.svc.update_invoice_status("buyer1", n, "sent")
        self.svc.update_invoice_status("buyer1", n, "paid")
        self.svc.update_invoice_status("buyer1", n, "void", admin=True)
        raw = self.inv.get_item(Key={"pk": "USER#buyer1", "sk": f"INV#{n}"})["Item"]
        first_sk = raw["void_reversal_ledger_sk"]
        # second void → already terminal → 409
        from fastapi import HTTPException
        with self.assertRaises(HTTPException):
            self.svc.update_invoice_status("buyer1", n, "void", admin=True)
        entries = [e for e in self._ledger_entries("USER#buyer1") if e["type"] == "adjustment"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["sk"], first_sk)

    def test_invalid_transition(self):
        from fastapi import HTTPException
        inv = self._manual()
        n = inv["invoice_number"]
        self.svc.update_invoice_status("buyer1", n, "sent")
        self.svc.update_invoice_status("buyer1", n, "paid")
        with self.assertRaises(HTTPException) as ctx:
            self.svc.update_invoice_status("buyer1", n, "sent")
        self.assertEqual(ctx.exception.status_code, 409)

    def test_check_overdue(self):
        from app.core.time import now_ts
        inv = self._manual(payment_terms_days=1)
        n = inv["invoice_number"]
        self.svc.update_invoice_status("buyer1", n, "sent")
        # backdate due_date and GSI3SK into the past
        past = now_ts() - 10
        self.inv.update_item(
            Key={"pk": "USER#buyer1", "sk": f"INV#{n}"},
            UpdateExpression="SET due_date = :d, GSI3SK = :d",
            ExpressionAttributeValues={":d": past},
        )
        count = self.svc.check_overdue_invoices()
        self.assertEqual(count, 1)
        raw = self.inv.get_item(Key={"pk": "USER#buyer1", "sk": f"INV#{n}"})["Item"]
        self.assertEqual(raw["status"], "overdue")
        self.assertNotIn("GSI3PK", raw)

    def test_check_overdue_skips_paid(self):
        from app.core.time import now_ts
        inv = self._manual(payment_terms_days=1)
        n = inv["invoice_number"]
        self.svc.update_invoice_status("buyer1", n, "sent")
        self.svc.update_invoice_status("buyer1", n, "paid")  # clears GSI3
        count = self.svc.check_overdue_invoices()
        self.assertEqual(count, 0)

    def test_generated_invoice_unaffected(self):
        from app.models import InvoiceOut
        gen = self.svc.create_invoice(
            user_sub="x", invoice_type="tip", amount_cents=500,
            line_items=[{"description": "Tip", "quantity": 1, "amount_cents": 500}],
        )
        raw = self.inv.get_item(Key={"pk": "USER#x", "sk": f"INV#{gen['invoice_number']}"})["Item"]
        self.assertNotIn("GSI3PK", raw)
        self.assertIsNone(InvoiceOut(**gen).payment_terms_days)

    def test_render_lines_due_terms(self):
        lines = self.svc._render_invoice_lines(
            {"invoice_number": "INV-1", "created_at": 1000,
             "payment_terms_days": 30, "due_date": 2592000, "status": "sent",
             "line_items": []}
        )
        joined = "\n".join(lines)
        self.assertIn("Net 30", joined)
        self.assertIn("Due", joined)

    # --- D5 admin record-external-payment ---

    def test_record_external_payment_happy(self):
        inv = self._manual()
        n = inv["invoice_number"]
        self.svc.update_invoice_status("buyer1", n, "sent")
        out = self.svc.record_external_payment(
            admin_user_sub="admin1", owner_user_sub="buyer1",
            invoice_number=n, amount_cents=50000, reference="WIRE-9",
            reason="bank transfer",
        )
        self.assertEqual(out["status"], "paid")
        raw = self.inv.get_item(Key={"pk": "USER#buyer1", "sk": f"INV#{n}"})["Item"]
        self.assertIn("external_payment_ledger_sk", raw)
        self.assertNotIn("GSI3PK", raw)
        entries = self._ledger_entries("USER#buyer1")
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e["type"], "invoice_payment_external")
        self.assertEqual(int(e["amount_cents"]), 50000)
        self.assertEqual(int(e["signed_amount_cents"]), 50000)  # D1 positive
        self.assertEqual(e["state"], "settled")
        self.assertEqual(e["meta"]["reference"], "WIRE-9")
        self.assertEqual(int(self._balance("USER#buyer1")["payments_settled_cents"]), 50000)

    def test_record_external_payment_idempotent(self):
        from fastapi import HTTPException
        inv = self._manual()
        n = inv["invoice_number"]
        self.svc.update_invoice_status("buyer1", n, "sent")
        self.svc.record_external_payment(
            admin_user_sub="admin1", owner_user_sub="buyer1",
            invoice_number=n, amount_cents=50000,
        )
        with self.assertRaises(HTTPException) as ctx:
            self.svc.record_external_payment(
                admin_user_sub="admin1", owner_user_sub="buyer1",
                invoice_number=n, amount_cents=50000,
            )
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "already_paid")
        entries = self._ledger_entries("USER#buyer1")
        self.assertEqual(len(entries), 1)
        self.assertEqual(int(self._balance("USER#buyer1")["payments_settled_cents"]), 50000)

    def test_record_external_payment_void_invoice(self):
        from fastapi import HTTPException
        inv = self._manual()
        n = inv["invoice_number"]
        self.svc.update_invoice_status("buyer1", n, "void")
        with self.assertRaises(HTTPException) as ctx:
            self.svc.record_external_payment(
                admin_user_sub="admin1", owner_user_sub="buyer1",
                invoice_number=n, amount_cents=50000,
            )
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "invalid_state")
        self.assertEqual(self._ledger_entries("USER#buyer1"), [])

    def test_record_external_payment_mismatch_flagged(self):
        inv = self._manual()
        n = inv["invoice_number"]
        self.svc.update_invoice_status("buyer1", n, "sent")
        out = self.svc.record_external_payment(
            admin_user_sub="admin1", owner_user_sub="buyer1",
            invoice_number=n, amount_cents=40000,
        )
        self.assertEqual(out["status"], "paid")
        e = self._ledger_entries("USER#buyer1")[0]
        self.assertEqual(int(e["amount_cents"]), 40000)
        self.assertEqual(int(e["signed_amount_cents"]), 40000)
        self.assertTrue(e["meta"]["amount_mismatch"])
        self.assertEqual(int(e["meta"]["expected_cents"]), 50000)

    def test_record_external_payment_not_found(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            self.svc.record_external_payment(
                admin_user_sub="admin1", owner_user_sub="buyer1",
                invoice_number="INV-NOPE", amount_cents=100,
            )
        self.assertEqual(ctx.exception.status_code, 404)

    def test_require_standalone_flag_off(self):
        from fastapi import HTTPException
        object.__setattr__(S, "aos_standalone_invoices_enabled", False)
        with self.assertRaises(HTTPException) as ctx:
            self.svc._require_standalone_enabled()
        self.assertEqual(ctx.exception.status_code, 404)


# ---------------------------------------------------------------------------
# QUO-003 — conversion
# ---------------------------------------------------------------------------

class QuoteConversionTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.quotes = _aos_quotes_table(ddb)
        self.inv = _invoices_table(ddb)

        pq, pi = T.aos_quotes, T.invoices
        object.__setattr__(T, "aos_quotes", self.quotes)
        object.__setattr__(T, "invoices", self.inv)
        self.addCleanup(lambda: object.__setattr__(T, "aos_quotes", pq))
        self.addCleanup(lambda: object.__setattr__(T, "invoices", pi))

        prev = {
            "aos_quotes_enabled": S.aos_quotes_enabled,
            "aos_contracts_enabled": S.aos_contracts_enabled,
            "invoices_enabled": S.invoices_enabled,
            "invoices_tax_bps": S.invoices_tax_bps,
        }
        object.__setattr__(S, "aos_quotes_enabled", True)
        object.__setattr__(S, "aos_contracts_enabled", True)
        object.__setattr__(S, "invoices_enabled", True)
        object.__setattr__(S, "invoices_tax_bps", 0)
        self.addCleanup(lambda: [object.__setattr__(S, k, v) for k, v in prev.items()])

        self.stack.enter_context(patch("app.services.aos_quotes.audit_event", MagicMock()))
        self.stack.enter_context(patch("app.services.aos_quote_conversion.audit_event", MagicMock()))
        self.stack.enter_context(patch.object(__import__("app.services.invoices", fromlist=["_s3"]), "_s3", MagicMock()))
        self.stack.enter_context(patch("app.services.alerts.audit_event", MagicMock()))
        # contract creation mocked to a canned dict (avoids needing the contracts table)
        self.mock_contract = self.stack.enter_context(
            patch("app.services.aos_quote_conversion.create_contract",
                  MagicMock(return_value={"contract_id": "con_test", "contract_number": "CON-1",
                                          "title": "C", "stage": "draft"}))
        )
        import app.services.aos_quotes as qs
        import app.services.aos_quote_conversion as cs
        self.qs = qs
        self.cs = cs

    def _accepted_quote(self, **kw):
        q = self.qs.create_quote(
            "alice", "Q",
            line_items=[{"description": "Widget", "qty": 2, "unit_price_cents": 1000,
                         "discount_bps": 0, "tax_rate_bps": 1000}],
            **kw,
        )
        self.qs.transition_stage("alice", q["quote_id"], "sent")
        self.qs.transition_stage("alice", q["quote_id"], "accepted")
        return q

    def test_convert_to_invoice_basic(self):
        q = self._accepted_quote()
        inv = self.cs.convert_to_invoice(user_sub="alice", quote_id=q["quote_id"])
        self.assertEqual(inv["invoice_type"], "shop")
        self.assertEqual(inv["aos_quote_id"], q["quote_id"])
        # subtotal=2000, tax=200, total=2200
        self.assertEqual(inv["total_cents"], 2200)
        raw = self.quotes.get_item(
            Key={"pk": "USER#alice", "sk": f"QUOTE#{q['quote_id']}"}
        )["Item"]
        self.assertEqual(raw["stage"], "converted")
        self.assertEqual(raw["converted_to_invoice_number"], inv["invoice_number"])

    def test_convert_invoice_rejects_draft(self):
        from fastapi import HTTPException
        q = self.qs.create_quote(
            "alice", "Q",
            line_items=[{"description": "W", "qty": 1, "unit_price_cents": 100}],
        )
        with self.assertRaises(HTTPException) as ctx:
            self.cs.convert_to_invoice(user_sub="alice", quote_id=q["quote_id"])
        self.assertEqual(ctx.exception.status_code, 400)

    def test_convert_invoice_already_converted(self):
        from fastapi import HTTPException
        q = self._accepted_quote()
        self.cs.convert_to_invoice(user_sub="alice", quote_id=q["quote_id"])
        with self.assertRaises(HTTPException) as ctx:
            self.cs.convert_to_invoice(user_sub="alice", quote_id=q["quote_id"])
        self.assertEqual(ctx.exception.status_code, 409)

    def test_convert_invoice_wrong_owner(self):
        from fastapi import HTTPException
        q = self._accepted_quote()
        with self.assertRaises(HTTPException) as ctx:
            self.cs.convert_to_invoice(user_sub="bob", quote_id=q["quote_id"])
        self.assertEqual(ctx.exception.status_code, 404)

    def test_convert_to_contract_basic(self):
        q = self._accepted_quote()
        c = self.cs.convert_to_contract(user_sub="alice", quote_id=q["quote_id"])
        self.assertEqual(c["contract_id"], "con_test")
        self.mock_contract.assert_called_once()
        _, kwargs = self.mock_contract.call_args
        self.assertEqual(kwargs["aos_quote_id"], q["quote_id"])
        self.assertEqual(kwargs["value_cents"], q["total_cents"])
        raw = self.quotes.get_item(
            Key={"pk": "USER#alice", "sk": f"QUOTE#{q['quote_id']}"}
        )["Item"]
        self.assertEqual(raw["stage"], "converted")
        self.assertEqual(raw["converted_to_contract_id"], "con_test")

    def test_convert_contract_flag_off(self):
        from fastapi import HTTPException
        q = self._accepted_quote()
        object.__setattr__(S, "aos_contracts_enabled", False)
        with self.assertRaises(HTTPException) as ctx:
            self.cs.convert_to_contract(user_sub="alice", quote_id=q["quote_id"])
        self.assertEqual(ctx.exception.status_code, 409)


if __name__ == "__main__":
    unittest.main()
