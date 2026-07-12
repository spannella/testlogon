"""SHOP-001: Inventory Management — unit tests for stock logic.

Mirrors the Mock-based style of tests/test_catalog_search.py: the catalog
DynamoDB table handle is replaced with a Mock and the router coroutines are
driven directly via asyncio.run.
"""
import asyncio
import unittest
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.routers import catalog


def _conditional_error(op="UpdateItem"):
    return ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, op)


ITEM = {
    "PK": "CAT#c1",
    "SK": "ITEM#i1",
    "entity": "item",
    "category_id": "c1",
    "item_id": "i1",
    "creator_id": "alice",
    "name": "Headphones",
    "price_cents": 4999,
    "currency": "USD",
    "image_urls": [],
    "attributes": {},
    "stock_count": 50,
    "low_stock_threshold": 5,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z",
}

CAT_META = {"PK": "CAT#c1", "SK": "META", "entity": "category", "category_id": "c1", "creator_id": "alice"}


class TestComputeStockStatus(unittest.TestCase):
    def test_unlimited(self):
        self.assertEqual(catalog._compute_stock_status({}), "unlimited")
        self.assertEqual(catalog._compute_stock_status({"stock_count": None}), "unlimited")

    def test_out_of_stock(self):
        self.assertEqual(catalog._compute_stock_status({"stock_count": 0}), "out_of_stock")
        self.assertEqual(catalog._compute_stock_status({"stock_count": -1}), "out_of_stock")

    def test_low_stock(self):
        self.assertEqual(
            catalog._compute_stock_status({"stock_count": 5, "low_stock_threshold": 5}), "low_stock"
        )
        self.assertEqual(
            catalog._compute_stock_status({"stock_count": 3, "low_stock_threshold": 5}), "low_stock"
        )

    def test_in_stock(self):
        self.assertEqual(
            catalog._compute_stock_status({"stock_count": 50, "low_stock_threshold": 5}), "in_stock"
        )


class TestCatalogItemOut(unittest.TestCase):
    def test_includes_stock_fields(self):
        out = catalog._catalog_item_out(ITEM)
        self.assertEqual(out.stock_count, 50)
        self.assertEqual(out.stock_status, "in_stock")
        self.assertEqual(out.low_stock_threshold, 5)

    def test_unlimited_when_unset(self):
        item = {**ITEM}
        item.pop("stock_count")
        out = catalog._catalog_item_out(item)
        self.assertIsNone(out.stock_count)
        self.assertEqual(out.stock_status, "unlimited")


def _make_table(item=ITEM, meta=CAT_META, update_side_effect=None, update_return=None):
    table = Mock()
    # _find_item_by_id -> scan (legacy) OR query via ByItemId GSI (current)
    items_resp = {"Items": [item] if item else [], "LastEvaluatedKey": None}
    table.scan.return_value = items_resp
    table.query.return_value = items_resp  # ByItemId GSI path added after test written
    # _require_category_owner -> get_item META
    table.get_item.return_value = {"Item": meta} if meta else {}
    if update_side_effect is not None:
        table.update_item.side_effect = update_side_effect
    else:
        table.update_item.return_value = update_return or {"Attributes": dict(item or {})}
    return table


class TestAdjustStock(unittest.TestCase):
    def _run(self, body, table):
        ctx = {"user_sub": "alice"}
        with patch.object(catalog, "T", Mock(catalog=table)):
            return asyncio.run(catalog.adjust_stock("i1", body, ctx=ctx))

    def test_absolute_set(self):
        from app.models import CatalogStockAdjustIn

        table = _make_table(update_return={"Attributes": {**ITEM, "stock_count": 100}})
        out = self._run(CatalogStockAdjustIn(absolute=100), table)
        self.assertEqual(out.stock_count, 100)
        self.assertEqual(out.stock_status, "in_stock")

    def test_delta_increment(self):
        from app.models import CatalogStockAdjustIn

        table = _make_table(update_return={"Attributes": {**ITEM, "stock_count": 55}})
        out = self._run(CatalogStockAdjustIn(delta=5), table)
        self.assertEqual(out.stock_count, 55)

    def test_delta_decrement(self):
        from app.models import CatalogStockAdjustIn

        table = _make_table(update_return={"Attributes": {**ITEM, "stock_count": 47}})
        out = self._run(CatalogStockAdjustIn(delta=-3), table)
        self.assertEqual(out.stock_count, 47)

    def test_delta_prevents_negative(self):
        from app.models import CatalogStockAdjustIn

        item = {**ITEM, "stock_count": 3}
        table = _make_table(item=item, update_side_effect=_conditional_error())
        with self.assertRaises(HTTPException) as cm:
            self._run(CatalogStockAdjustIn(delta=-5), table)
        self.assertEqual(cm.exception.status_code, 409)
        self.assertIn("Insufficient stock", cm.exception.detail)

    def test_item_not_found(self):
        from app.models import CatalogStockAdjustIn

        table = _make_table(item=None)
        with self.assertRaises(HTTPException) as cm:
            self._run(CatalogStockAdjustIn(absolute=10), table)
        self.assertEqual(cm.exception.status_code, 404)

    def test_non_owner_forbidden(self):
        from app.models import CatalogStockAdjustIn

        table = _make_table(meta={**CAT_META, "creator_id": "bob"})
        with self.assertRaises(HTTPException) as cm:
            self._run(CatalogStockAdjustIn(absolute=10), table)
        self.assertEqual(cm.exception.status_code, 403)


class TestStockAdjustValidation(unittest.TestCase):
    def test_both_modes_rejected(self):
        from app.models import CatalogStockAdjustIn

        with self.assertRaises(Exception):
            CatalogStockAdjustIn(delta=5, absolute=10)

    def test_neither_mode_rejected(self):
        from app.models import CatalogStockAdjustIn

        with self.assertRaises(Exception):
            CatalogStockAdjustIn()


class _FakeS:
    def __init__(self, alerts_enabled=True, default_threshold=5):
        self.catalog_stock_alerts_enabled = alerts_enabled
        self.catalog_default_low_stock_threshold = default_threshold


class TestLowStockAlert(unittest.TestCase):
    def test_alert_written_when_below_threshold(self):
        calls = {}

        def fake_write_alert(user_sub, **kwargs):
            calls["user_sub"] = user_sub
            calls.update(kwargs)

        # _check_low_stock_alert now writes a DDB dedup sentinel before firing the
        # alert (GAP-0347); patch T.catalog so the sentinel put_item succeeds.
        fake_tbl = Mock()
        fake_tbl.put_item.return_value = {}  # sentinel write succeeds
        with patch.object(catalog, "S", _FakeS(alerts_enabled=True)), \
             patch.object(catalog, "T", Mock(catalog=fake_tbl)), \
             patch("app.services.alerts.write_alert", fake_write_alert):
            catalog._check_low_stock_alert({**ITEM, "low_stock_threshold": 5}, 3)
        self.assertEqual(calls.get("event"), "catalog.low_stock")
        self.assertEqual(calls.get("user_sub"), "alice")

    def test_no_alert_when_above_threshold(self):
        calls = []

        def fake_write_alert(user_sub, **kwargs):
            calls.append(kwargs)

        with patch.object(catalog, "S", _FakeS(alerts_enabled=True)), patch(
            "app.services.alerts.write_alert", fake_write_alert
        ):
            catalog._check_low_stock_alert({**ITEM, "low_stock_threshold": 5}, 50)
        self.assertEqual(calls, [])

    def test_no_alert_when_disabled(self):
        calls = []

        def fake_write_alert(user_sub, **kwargs):
            calls.append(kwargs)

        with patch.object(catalog, "S", _FakeS(alerts_enabled=False)), patch(
            "app.services.alerts.write_alert", fake_write_alert
        ):
            catalog._check_low_stock_alert({**ITEM, "low_stock_threshold": 5}, 1)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
