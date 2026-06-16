"""Hermetic offline tests for the SuiteCRM INVOICES + CURRENCY + TAX subsystem.

Covers INV-001 (extended invoice fields), INV-002 (currency registry),
INV-003 (currency conversion at transaction time), INV-004 (PDF currency
display), INV-005 (tax rate registry), and INV-006 (per-line tax).

Isolation contract (per CLAUDE.md + the GAP hermetic pattern):
- moto in-memory DynamoDB; frozen ``T`` handles bound via ``object.__setattr__``
  and restored on cleanup.
- frozen ``S`` flags toggled via ``object.__setattr__`` and restored.
- S3 client patched to an in-memory ``_FakeS3`` so no real AWS / no moto-S3
  global interception is needed.
- Route coroutines invoked directly on a fresh ``asyncio.new_event_loop()``.
- NO TestClient, NO real AWS, NO network.
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack
from decimal import Decimal
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None


# --------------------------------------------------------------------------
# In-memory S3 (avoids real AWS / moto S3 global interception)
# --------------------------------------------------------------------------
class _FakeS3:
    def __init__(self):
        self.store = {}

    def put_object(self, Bucket, Key, Body, ContentType=None, **kw):
        self.store[(Bucket, Key)] = Body
        return {}

    def get_object(self, Bucket, Key, **kw):
        if (Bucket, Key) not in self.store:
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")

        class _Body:
            def __init__(self, data):
                self._data = data

            def read(self):
                return self._data

        return {"Body": _Body(self.store[(Bucket, Key)])}


# --------------------------------------------------------------------------
# Table factories
# --------------------------------------------------------------------------
def _make_invoices_table(ddb):
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
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_currencies_table(ddb):
    return ddb.create_table(
        TableName="crm_currencies_test",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "S"},
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
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_tax_rates_table(ddb):
    return ddb.create_table(
        TableName="crm_tax_rates_test",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "S"},
            {"AttributeName": "GSI2PK", "AttributeType": "S"},
            {"AttributeName": "GSI2SK", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "taxrates-active-index",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "taxrates-jurisdiction-index",
                "KeySchema": [
                    {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class _Base(unittest.TestCase):
    """Sets up moto tables + frozen T/S binding shared across all INV tests."""

    # Flags subclasses may override before _bind() runs.
    flags = {}

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.invoices_table = _make_invoices_table(ddb)
        self.currencies_table = _make_currencies_table(ddb)
        self.tax_rates_table = _make_tax_rates_table(ddb)

        from app.core import tables as tables_mod
        self.T = tables_mod.T
        for name, handle in (
            ("invoices", self.invoices_table),
            ("crm_currencies", self.currencies_table),
            ("crm_tax_rates", self.tax_rates_table),
        ):
            original = getattr(self.T, name)
            object.__setattr__(self.T, name, handle)
            self.addCleanup(object.__setattr__, self.T, name, original)

        from app.core.settings import S
        self.S = S
        # Always enable invoices for these tests.
        defaults = {"invoices_enabled": True}
        defaults.update(self.flags)
        for key, val in defaults.items():
            original = getattr(S, key)
            object.__setattr__(S, key, val)
            self.addCleanup(object.__setattr__, S, key, original)

        # In-memory S3 for the invoice PDF pipeline.
        self.fake_s3 = _FakeS3()
        from app.services import invoices as inv_mod
        original_s3 = inv_mod._s3
        inv_mod._s3 = self.fake_s3
        self.addCleanup(setattr, inv_mod, "_s3", original_s3)

    def set_flag(self, key, val):
        original = getattr(self.S, key)
        object.__setattr__(self.S, key, val)
        self.addCleanup(object.__setattr__, self.S, key, original)


# ==========================================================================
# INV-002: currency registry + exchange rates
# ==========================================================================
class TestCurrencyRegistry(_Base):
    flags = {"crm_currencies_enabled": True}

    def _svc(self):
        from app.services import crm_currencies
        return crm_currencies

    def test_flag_off_raises(self):
        self.set_flag("crm_currencies_enabled", False)
        svc = self._svc()
        with self.assertRaises(ValueError):
            svc.create_currency("eur", "Euro", "€", Decimal("1.08"))
        with self.assertRaises(ValueError):
            svc.get_exchange_rate("eur", "usd")

    def test_create_and_get(self):
        svc = self._svc()
        out = svc.create_currency("EUR", "Euro", "€", Decimal("1.08"))
        self.assertEqual(out["iso_code"], "eur")
        self.assertEqual(out["rate_to_usd"], 1.08)
        self.assertTrue(out["is_active"])
        raw = self.currencies_table.get_item(Key={"pk": "CURRENCY#eur", "sk": "META"})["Item"]
        self.assertEqual(raw["GSI1PK"], "CURRENCIES#ACTIVE")
        self.assertEqual(raw["GSI1SK"], "eur")
        self.assertEqual(svc.get_currency("eur")["name"], "Euro")
        self.assertIsNone(svc.get_currency("xxx"))

    def test_duplicate_rejected(self):
        svc = self._svc()
        svc.create_currency("eur", "Euro", "€", Decimal("1.08"))
        with self.assertRaises(ValueError):
            svc.create_currency("EUR", "Euro", "€", Decimal("1.08"))

    def test_invalid_iso_length(self):
        svc = self._svc()
        with self.assertRaises(ValueError):
            svc.create_currency("eu", "X", "X", Decimal("1"))

    def test_list_and_deactivate(self):
        svc = self._svc()
        svc.create_currency("eur", "Euro", "€", Decimal("1.08"))
        svc.create_currency("gbp", "Pound", "£", Decimal("1.27"))
        self.assertEqual({c["iso_code"] for c in svc.list_currencies(True)}, {"eur", "gbp"})
        svc.update_currency("gbp", is_active=False)
        self.assertEqual({c["iso_code"] for c in svc.list_currencies(True)}, {"eur"})
        self.assertEqual({c["iso_code"] for c in svc.list_currencies(False)}, {"eur", "gbp"})
        # Reactivate.
        svc.update_currency("gbp", is_active=True)
        self.assertIn("gbp", {c["iso_code"] for c in svc.list_currencies(True)})

    def test_rate_update(self):
        svc = self._svc()
        svc.create_currency("eur", "Euro", "€", Decimal("1.08"))
        svc.update_currency("eur", rate_to_usd=Decimal("1.10"))
        self.assertEqual(svc.get_currency("eur")["rate_to_usd"], 1.10)

    def test_exchange_rates(self):
        svc = self._svc()
        svc.create_currency("eur", "Euro", "€", Decimal("1.08"))
        svc.create_currency("gbp", "Pound", "£", Decimal("1.27"))
        # usd->eur = 1/1.08
        r = svc.get_exchange_rate("usd", "eur")
        self.assertAlmostEqual(float(r), 1 / 1.08, places=5)
        # eur->usd = 1.08
        self.assertAlmostEqual(float(svc.get_exchange_rate("eur", "usd")), 1.08, places=5)
        # eur->gbp cross-rate
        self.assertAlmostEqual(float(svc.get_exchange_rate("eur", "gbp")), 1.08 / 1.27, places=4)
        # same currency
        self.assertEqual(svc.get_exchange_rate("eur", "eur"), Decimal("1"))

    def test_exchange_rate_errors(self):
        svc = self._svc()
        with self.assertRaises(ValueError):
            svc.get_exchange_rate("eur", "usd")  # eur not found
        svc.create_currency("gbp", "Pound", "£", Decimal("1.27"))
        svc.update_currency("gbp", is_active=False)
        with self.assertRaises(ValueError):
            svc.get_exchange_rate("gbp", "usd")  # inactive

    def test_convert_amount(self):
        svc = self._svc()
        svc.create_currency("eur", "Euro", "€", Decimal("1.08"))
        # usd->eur 10000 cents
        self.assertEqual(svc.convert_amount(10000, "usd", "eur"), round(10000 / 1.08))
        # same currency: no lookup
        self.assertEqual(svc.convert_amount(5000, "eur", "eur"), 5000)
        # eur->usd
        self.assertEqual(svc.convert_amount(10000, "eur", "usd"), 10800)

    def test_audit_emitted(self):
        svc = self._svc()
        with patch("app.services.crm_currencies.audit_event") as mock_audit:
            svc.create_currency("eur", "Euro", "€", Decimal("1.08"))
            svc.update_currency("eur", rate_to_usd=Decimal("1.10"))
        events = [c.args[0] for c in mock_audit.call_args_list]
        self.assertIn("currency.created", events)
        self.assertIn("currency.rate_updated", events)

    def test_router_post_and_flag_gate(self):
        from app.routers import crm_currencies as router
        from app.models import CurrencyCreateIn

        class _User:
            sub = "admin1"

        loop = asyncio.new_event_loop()
        try:
            body = CurrencyCreateIn(iso_code="eur", name="Euro", symbol="€", rate_to_usd=Decimal("1.08"))
            out = loop.run_until_complete(router.create_currency_endpoint(body, _User()))
            self.assertEqual(out.iso_code, "eur")
            # flag off → 404
            self.set_flag("crm_currencies_enabled", False)
            from fastapi import HTTPException
            with self.assertRaises(HTTPException) as ctx:
                loop.run_until_complete(router.create_currency_endpoint(body, _User()))
            self.assertEqual(ctx.exception.status_code, 404)
        finally:
            loop.close()


# ==========================================================================
# INV-005: tax rate registry
# ==========================================================================
class TestTaxRateRegistry(_Base):
    flags = {"crm_tax_rates_enabled": True}

    def _svc(self):
        from app.services import crm_tax_rates
        return crm_tax_rates

    def test_flag_off_raises(self):
        self.set_flag("crm_tax_rates_enabled", False)
        with self.assertRaises(ValueError):
            self._svc().create_tax_rate(name="X", rate_bps=950, jurisdiction="US-CA")

    def test_create_success(self):
        svc = self._svc()
        out = svc.create_tax_rate(name="CA Sales Tax", rate_bps=950, jurisdiction="us-ca")
        self.assertTrue(out["tax_rate_id"].startswith("tr_"))
        self.assertEqual(out["rate_bps"], 950)
        self.assertEqual(out["jurisdiction"], "US-CA")
        raw = self.tax_rates_table.get_item(
            Key={"pk": f"TAXRATE#{out['tax_rate_id']}", "sk": "META"}
        )["Item"]
        self.assertEqual(raw["GSI1PK"], "TAXRATES#ACTIVE")

    def test_rate_bps_out_of_range(self):
        svc = self._svc()
        with self.assertRaises(ValueError):
            svc.create_tax_rate(name="X", rate_bps=10001, jurisdiction="US")

    def test_list_active_only(self):
        svc = self._svc()
        a = svc.create_tax_rate(name="A Tax", rate_bps=100, jurisdiction="US")
        svc.create_tax_rate(name="B Tax", rate_bps=200, jurisdiction="US")
        svc.update_tax_rate(a["tax_rate_id"], is_active=False)
        names = {r["name"] for r in svc.list_tax_rates(active_only=True)["tax_rates"]}
        self.assertEqual(names, {"B Tax"})

    def test_list_by_jurisdiction(self):
        svc = self._svc()
        svc.create_tax_rate(name="CA Tax", rate_bps=950, jurisdiction="US-CA")
        svc.create_tax_rate(name="DE VAT", rate_bps=1900, jurisdiction="DE")
        res = svc.list_tax_rates(jurisdiction="US-CA")["tax_rates"]
        self.assertEqual([r["name"] for r in res], ["CA Tax"])

    def test_jurisdiction_active_filter(self):
        svc = self._svc()
        a = svc.create_tax_rate(name="CA A", rate_bps=950, jurisdiction="US-CA")
        svc.create_tax_rate(name="CA B", rate_bps=850, jurisdiction="US-CA")
        svc.update_tax_rate(a["tax_rate_id"], is_active=False)
        res = svc.list_tax_rates(jurisdiction="US-CA", active_only=True)["tax_rates"]
        self.assertEqual([r["name"] for r in res], ["CA B"])

    def test_deactivate_reactivate_sparse_gsi(self):
        svc = self._svc()
        tr = svc.create_tax_rate(name="T", rate_bps=500, jurisdiction="US")
        tid = tr["tax_rate_id"]
        svc.update_tax_rate(tid, is_active=False)
        raw = self.tax_rates_table.get_item(Key={"pk": f"TAXRATE#{tid}", "sk": "META"})["Item"]
        self.assertNotIn("GSI1PK", raw)
        svc.update_tax_rate(tid, is_active=True)
        self.assertIn(tid, {r["tax_rate_id"] for r in svc.list_tax_rates(active_only=True)["tax_rates"]})

    def test_get_not_found(self):
        self.assertIsNone(self._svc().get_tax_rate("tr_missing"))

    def test_get_by_name(self):
        svc = self._svc()
        svc.create_tax_rate(name="EU VAT Standard", rate_bps=2000, jurisdiction="EU")
        hit = svc.get_tax_rate_by_name("EU VAT Standard")
        self.assertEqual(hit["rate_bps"], 2000)
        self.assertIsNone(svc.get_tax_rate_by_name("Nonexistent"))

    def test_update_name_updates_gsi_keys(self):
        svc = self._svc()
        tr = svc.create_tax_rate(name="Old Name", rate_bps=100, jurisdiction="US")
        svc.update_tax_rate(tr["tax_rate_id"], name="New Name")
        raw = self.tax_rates_table.get_item(
            Key={"pk": f"TAXRATE#{tr['tax_rate_id']}", "sk": "META"}
        )["Item"]
        self.assertEqual(raw["GSI1SK"], "New Name")

    def test_update_not_found(self):
        with self.assertRaises(KeyError):
            self._svc().update_tax_rate("tr_missing", name="x")

    def test_audit_create_and_deactivate(self):
        svc = self._svc()
        with patch("app.services.crm_tax_rates.audit_event") as mock_audit:
            tr = svc.create_tax_rate(name="T", rate_bps=500, jurisdiction="US")
            svc.update_tax_rate(tr["tax_rate_id"], is_active=False)
        events = [c.args[0] for c in mock_audit.call_args_list]
        self.assertIn("tax_rate.created", events)
        self.assertIn("tax_rate.deactivated", events)

    def test_router_flag_off_404(self):
        from app.routers import crm_tax_rates as router
        from app.models import TaxRateCreateIn
        from fastapi import HTTPException

        class _User:
            sub = "admin1"

        self.set_flag("crm_tax_rates_enabled", False)
        loop = asyncio.new_event_loop()
        try:
            body = TaxRateCreateIn(name="T", rate_bps=500, jurisdiction="US")
            with self.assertRaises(HTTPException) as ctx:
                loop.run_until_complete(router.create_tax_rate_endpoint(body, _User()))
            self.assertEqual(ctx.exception.status_code, 404)
        finally:
            loop.close()


# ==========================================================================
# INV-001: extended invoice fields
# ==========================================================================
class TestInvoiceFields(_Base):
    flags = {"aos_invoice_fields_enabled": True}

    def _svc(self):
        from app.services import invoices
        return invoices

    def test_flag_off_no_change(self):
        self.set_flag("aos_invoice_fields_enabled", False)
        svc = self._svc()
        out = svc.create_invoice(
            user_sub="u1", invoice_type="shop", amount_cents=1000,
            line_items=[{"description": "x", "amount_cents": 1000}],
            unit_price_cents_per_item=[1000], discount_cents=200,
            shipping_cents=50, billing_address={"street": "1 Main"},
        )
        self.assertEqual(out["discount_cents"], 0)
        self.assertEqual(out["shipping_cents"], 0)
        self.assertIsNone(out["billing_address"])
        self.assertEqual(out["line_items"][0]["unit_price_cents"], 0)
        self.assertEqual(out["total_cents"], 1000 + out["tax_cents"])

    def test_unit_price_persisted(self):
        svc = self._svc()
        out = svc.create_invoice(
            user_sub="u1", invoice_type="shop", amount_cents=1500,
            line_items=[
                {"description": "a", "amount_cents": 1000},
                {"description": "b", "amount_cents": 500},
            ],
            unit_price_cents_per_item=[1000, 500],
        )
        self.assertEqual(out["line_items"][0]["unit_price_cents"], 1000)
        self.assertEqual(out["line_items"][1]["unit_price_cents"], 500)

    def test_discount_shipping_total(self):
        svc = self._svc()
        out = svc.create_invoice(
            user_sub="u1", invoice_type="shop", amount_cents=1000,
            line_items=[{"description": "x", "amount_cents": 1000}],
            tax_cents=80, discount_cents=200, shipping_cents=50,
        )
        self.assertEqual(out["total_cents"], 1000 + 80 + 50 - 200)
        self.assertEqual(out["discount_cents"], 200)

    def test_discount_cap(self):
        svc = self._svc()
        out = svc.create_invoice(
            user_sub="u1", invoice_type="shop", amount_cents=1000,
            line_items=[{"description": "x", "amount_cents": 1000}],
            tax_cents=0, discount_cents=2000,
        )
        self.assertEqual(out["discount_cents"], 1000)
        self.assertGreaterEqual(out["total_cents"], 0)

    def test_addresses_persisted(self):
        svc = self._svc()
        ba = {"street": "1 Main", "city": "SF", "state": "CA", "postal_code": "94000", "country": "US"}
        sa = {"street": "2 Elm", "city": "LA", "state": "CA", "postal_code": "90000", "country": "US"}
        out = svc.create_invoice(
            user_sub="u1", invoice_type="shop", amount_cents=1000,
            line_items=[{"description": "x", "amount_cents": 1000}],
            billing_address=ba, shipping_address=sa,
        )
        got = svc.get_invoice("u1", out["invoice_number"])
        self.assertEqual(got["billing_address"]["city"], "SF")
        self.assertEqual(got["shipping_address"]["city"], "LA")

    def test_pdf_contains_discount_and_address(self):
        svc = self._svc()
        out = svc.create_invoice(
            user_sub="u1", invoice_type="shop", amount_cents=1000,
            line_items=[{"description": "x", "amount_cents": 1000}],
            discount_cents=200,
            billing_address={"street": "1 Main", "city": "SF", "country": "US"},
        )
        pdf = svc.download_invoice_pdf("u1", out["invoice_number"])
        self.assertIn(b"Discount", pdf)
        self.assertIn(b"BILLING ADDRESS", pdf)
        self.assertTrue(pdf.startswith(b"%PDF"))

    def test_backward_compat_old_item(self):
        svc = self._svc()
        from app.core.time import now_ts
        from app.models import InvoiceOut
        self.invoices_table.put_item(Item={
            "pk": "USER#u9", "sk": "INV#INV-2020-00001",
            "invoice_id": "inv_x", "invoice_number": "INV-2020-00001",
            "user_sub": "u9", "invoice_type": "shop",
            "amount_cents": 1000, "tax_cents": 0, "total_cents": 1000,
            "currency": "usd", "status": "generated",
            "line_items": [{"description": "x", "quantity": 1, "amount_cents": 1000}],
            "created_at": now_ts(),
        })
        got = svc.get_invoice("u9", "INV-2020-00001")
        self.assertEqual(got["discount_cents"], 0)
        self.assertIsNone(got["billing_address"])
        InvoiceOut(**got)  # must not raise

    def test_idempotency_with_new_fields(self):
        svc = self._svc()
        a = svc.create_invoice(
            user_sub="u1", invoice_type="shop", amount_cents=1000,
            line_items=[{"description": "x", "amount_cents": 1000}],
            ledger_entry_id="led_1", discount_cents=100,
        )
        b = svc.create_invoice(
            user_sub="u1", invoice_type="shop", amount_cents=1000,
            line_items=[{"description": "x", "amount_cents": 1000}],
            ledger_entry_id="led_1", discount_cents=999,
        )
        self.assertEqual(a["invoice_number"], b["invoice_number"])
        self.assertEqual(b["discount_cents"], 100)


# ==========================================================================
# INV-003: currency conversion at transaction time
# ==========================================================================
class TestCurrencyConversion(_Base):
    flags = {
        "crm_currencies_enabled": True,
        "aos_invoice_currency_conversion_enabled": True,
    }

    def _svc(self):
        from app.services import invoices
        return invoices

    def _seed_eur(self, rate="1.08", active=True):
        from app.services import crm_currencies
        crm_currencies.create_currency("eur", "Euro", "€", Decimal(rate), is_active=active)

    def test_conversion_math(self):
        self._seed_eur("1.08")
        out = self._svc().create_invoice(
            user_sub="u1", invoice_type="tip", amount_cents=10000,
            line_items=[{"description": "x", "amount_cents": 10000}], currency="eur",
        )
        self.assertEqual(out["usd_amount_cents"], 10800)
        self.assertEqual(out["original_amount_cents"], 10000)
        self.assertEqual(out["original_currency"], "eur")
        self.assertAlmostEqual(out["exchange_rate_snapshot"], 1.08, places=5)
        self.assertEqual(out["amount_cents"], 10000)

    def test_usd_invoice_no_conversion(self):
        out = self._svc().create_invoice(
            user_sub="u1", invoice_type="tip", amount_cents=5000,
            line_items=[{"description": "x", "amount_cents": 5000}], currency="usd",
        )
        self.assertEqual(out["usd_amount_cents"], 5000)
        self.assertEqual(out["original_currency"], "usd")
        self.assertIsNone(out["exchange_rate_snapshot"])

    def test_primary_flag_off(self):
        self._seed_eur("1.08")
        self.set_flag("aos_invoice_currency_conversion_enabled", False)
        out = self._svc().create_invoice(
            user_sub="u1", invoice_type="tip", amount_cents=10000,
            line_items=[{"description": "x", "amount_cents": 10000}], currency="eur",
        )
        self.assertEqual(out["usd_amount_cents"], 10000)
        self.assertIsNone(out["exchange_rate_snapshot"])
        self.assertEqual(out["original_currency"], "eur")

    def test_unknown_currency_fail_open(self):
        out = self._svc().create_invoice(
            user_sub="u1", invoice_type="tip", amount_cents=10000,
            line_items=[{"description": "x", "amount_cents": 10000}], currency="jpy",
        )
        self.assertIsNotNone(out)
        self.assertEqual(out["usd_amount_cents"], 10000)
        self.assertIsNone(out["exchange_rate_snapshot"])

    def test_inactive_currency_fail_open(self):
        self._seed_eur("1.08", active=False)
        out = self._svc().create_invoice(
            user_sub="u1", invoice_type="tip", amount_cents=10000,
            line_items=[{"description": "x", "amount_cents": 10000}], currency="eur",
        )
        self.assertEqual(out["usd_amount_cents"], 10000)
        self.assertIsNone(out["exchange_rate_snapshot"])

    def test_idempotency_preserves_snapshot(self):
        self._seed_eur("1.08")
        a = self._svc().create_invoice(
            user_sub="u1", invoice_type="tip", amount_cents=10000,
            line_items=[{"description": "x", "amount_cents": 10000}],
            currency="eur", ledger_entry_id="led_eur",
        )
        from app.services import crm_currencies
        crm_currencies.update_currency("eur", rate_to_usd=Decimal("1.20"))
        b = self._svc().create_invoice(
            user_sub="u1", invoice_type="tip", amount_cents=10000,
            line_items=[{"description": "x", "amount_cents": 10000}],
            currency="eur", ledger_entry_id="led_eur",
        )
        self.assertEqual(a["usd_amount_cents"], 10800)
        self.assertEqual(b["usd_amount_cents"], 10800)


# ==========================================================================
# INV-004: multi-currency PDF display
# ==========================================================================
class TestMulticurrencyPdf(_Base):
    flags = {
        "crm_currencies_enabled": True,
        "aos_invoice_currency_conversion_enabled": True,
        "aos_invoice_multicurrency_display_enabled": True,
    }

    def test_pdf_usd_equivalent_footer(self):
        from app.services import crm_currencies, invoices
        crm_currencies.create_currency("eur", "Euro", "EUR", Decimal("1.08"))
        out = invoices.create_invoice(
            user_sub="u1", invoice_type="tip", amount_cents=10000,
            line_items=[{"description": "x", "amount_cents": 10000}], currency="eur",
        )
        pdf = invoices.download_invoice_pdf("u1", out["invoice_number"])
        self.assertIn(b"USD equivalent", pdf)
        self.assertIn(b"Exchange rate", pdf)

    def test_pdf_usd_invoice_no_footer(self):
        from app.services import invoices
        out = invoices.create_invoice(
            user_sub="u1", invoice_type="tip", amount_cents=5000,
            line_items=[{"description": "x", "amount_cents": 5000}], currency="usd",
        )
        pdf = invoices.download_invoice_pdf("u1", out["invoice_number"])
        self.assertNotIn(b"USD equivalent", pdf)


# ==========================================================================
# INV-006: per-line tax
# ==========================================================================
class TestPerLineTax(_Base):
    flags = {"aos_per_line_tax_enabled": True}

    def _svc(self):
        from app.services import invoices
        return invoices

    def test_raw_bps_single_rate(self):
        out = self._svc().create_invoice(
            user_sub="u1", invoice_type="shop", amount_cents=2000,
            line_items=[
                {"description": "a", "amount_cents": 1000, "tax_rate_bps": 950},
                {"description": "b", "amount_cents": 1000, "tax_rate_bps": 950},
            ],
            per_line_tax=True,
        )
        self.assertEqual(out["line_items"][0]["tax_cents"], 95)
        self.assertEqual(out["tax_cents"], 190)
        self.assertEqual(out["tax_breakdown"][0]["rate_bps"], 950)

    def test_mixed_rates(self):
        out = self._svc().create_invoice(
            user_sub="u1", invoice_type="shop", amount_cents=3000,
            line_items=[
                {"description": "a", "amount_cents": 1000, "tax_rate_bps": 950},
                {"description": "b", "amount_cents": 1000, "tax_rate_bps": 2000},
                {"description": "c", "amount_cents": 1000, "tax_rate_bps": 0},
            ],
            per_line_tax=True,
        )
        rates = {b["rate_bps"] for b in out["tax_breakdown"]}
        self.assertEqual(rates, {950, 2000})
        self.assertEqual(out["tax_cents"], 95 + 200)

    def test_tax_rate_id_lookup(self):
        from app.services import crm_tax_rates
        self.set_flag("crm_tax_rates_enabled", True)
        tr = crm_tax_rates.create_tax_rate(name="EU VAT", rate_bps=2000, jurisdiction="EU")
        out = self._svc().create_invoice(
            user_sub="u1", invoice_type="shop", amount_cents=1000,
            line_items=[{"description": "a", "amount_cents": 1000, "tax_rate_id": tr["tax_rate_id"]}],
            per_line_tax=True,
        )
        self.assertEqual(out["line_items"][0]["tax_rate_bps"], 2000)
        self.assertEqual(out["tax_breakdown"][0]["name"], "EU VAT")

    def test_tax_rate_id_inactive_fail_open(self):
        from app.services import crm_tax_rates
        self.set_flag("crm_tax_rates_enabled", True)
        tr = crm_tax_rates.create_tax_rate(name="X", rate_bps=2000, jurisdiction="EU")
        crm_tax_rates.update_tax_rate(tr["tax_rate_id"], is_active=False)
        out = self._svc().create_invoice(
            user_sub="u1", invoice_type="shop", amount_cents=1000,
            line_items=[{"description": "a", "amount_cents": 1000, "tax_rate_id": tr["tax_rate_id"]}],
            per_line_tax=True,
        )
        self.assertEqual(out["line_items"][0]["tax_rate_bps"], 0)

    def test_tax_rate_id_exception_fail_open(self):
        self.set_flag("crm_tax_rates_enabled", True)
        with patch("app.services.crm_tax_rates.get_tax_rate", side_effect=RuntimeError("boom")):
            out = self._svc().create_invoice(
                user_sub="u1", invoice_type="shop", amount_cents=1000,
                line_items=[{"description": "a", "amount_cents": 1000, "tax_rate_id": "tr_x"}],
                per_line_tax=True,
            )
        self.assertIsNotNone(out)
        self.assertEqual(out["line_items"][0]["tax_rate_bps"], 0)

    def test_all_zero_rates_fallback(self):
        self.set_flag("invoices_tax_bps", 500)
        out = self._svc().create_invoice(
            user_sub="u1", invoice_type="shop", amount_cents=1000,
            line_items=[{"description": "a", "amount_cents": 1000, "tax_rate_bps": 0}],
            per_line_tax=True,
        )
        self.assertEqual(out["tax_cents"], (1000 * 500) // 10000)

    def test_explicit_tax_cents_honoured(self):
        out = self._svc().create_invoice(
            user_sub="u1", invoice_type="shop", amount_cents=1000,
            line_items=[{"description": "a", "amount_cents": 1000, "tax_rate_bps": 2000}],
            per_line_tax=True, tax_cents=999,
        )
        self.assertEqual(out["tax_cents"], 999)
        self.assertEqual(out["tax_breakdown"][0]["rate_bps"], 2000)

    def test_flag_off_ignores_per_line(self):
        self.set_flag("aos_per_line_tax_enabled", False)
        out = self._svc().create_invoice(
            user_sub="u1", invoice_type="shop", amount_cents=1000,
            line_items=[{"description": "a", "amount_cents": 1000, "tax_rate_bps": 2000}],
            per_line_tax=True,
        )
        self.assertEqual(out["line_items"][0]["tax_rate_bps"], 0)
        self.assertEqual(out["tax_breakdown"], [])

    def test_pdf_tax_column_and_breakdown(self):
        out = self._svc().create_invoice(
            user_sub="u1", invoice_type="shop", amount_cents=1000,
            line_items=[{"description": "a", "amount_cents": 1000, "tax_rate_bps": 950}],
            per_line_tax=True,
        )
        pdf = self._svc().download_invoice_pdf("u1", out["invoice_number"])
        self.assertIn(b"Tax Rate", pdf)
        self.assertTrue(pdf.startswith(b"%PDF"))

    def test_pdf_zero_rates_no_column(self):
        self.set_flag("aos_per_line_tax_enabled", False)
        out = self._svc().create_invoice(
            user_sub="u1", invoice_type="shop", amount_cents=1000,
            line_items=[{"description": "a", "amount_cents": 1000}],
        )
        pdf = self._svc().download_invoice_pdf("u1", out["invoice_number"])
        self.assertNotIn(b"Tax Rate", pdf)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
