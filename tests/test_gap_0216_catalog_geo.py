"""Offline regression test for GAP-0216 (GEO-001).

GAP-0216 — ``app/routers/catalog.py`` never enforced per-item
``geo_mode``/``geo_countries`` on the two catalog read paths:

  * ``GET /ui/catalog/categories/{category_id}/items`` (``list_items``)
  * ``GET /ui/catalog/items/search`` (``search_items``)

GEO-001 stores catalog geo rules *inline on the item record* in the catalog
DynamoDB table (PK = SK = ``ITEM#{item_id}``) with ``geo_mode`` /
``geo_countries`` fields (set via ``PATCH /ui/geo/catalog/{item_id}``).
The shared ``app/services/geo_check.check_geo_access`` helper — already wired
into video/broadcast endpoints — resolves the viewer's country (in dev mode
from the ``X-Geo-Country`` header) and decides allow/block. The bug was that
``catalog.py`` never called it, so a viewer in a blocked region still saw and
could search for geo-fenced items.

The fix filters geo-blocked items out of both responses.

Test isolation (critical): NO reliance on global moto interception (it leaks to
real AWS). A real in-memory DynamoDB table is created with moto and the exact
table handle the router uses — ``T.catalog`` — is monkeypatched in place via
``object.__setattr__`` (``T`` is a frozen dataclass) and restored afterwards.
The async handlers are invoked through ``asyncio.run`` with a hand-built
``Request`` carrying the country signal; the FastAPI TestClient is unusable in
this repo. Settings ``S`` is frozen, so any override uses ``object.__setattr__``
with restore in cleanup.
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack

import boto3
from fastapi import Request

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_catalog_table(ddb):
    """Mirror the shopping_catalog table: PK/SK strings + GSI1."""
    return ddb.create_table(
        TableName="shopping_catalog_test",
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
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


def _make_request(country: str | None) -> Request:
    """Build a minimal ASGI Request carrying an X-Geo-Country header (dev mode)."""
    headers = []
    if country is not None:
        headers.append((b"x-geo-country", country.encode("ascii")))
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/ui/catalog/items/search",
        "headers": headers,
        "query_string": b"",
        "client": ("203.0.113.7", 12345),
    }
    return Request(scope)


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestCatalogGeoGap0216(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_catalog_table(ddb)

        from app.core.tables import T
        from app.core.settings import S
        from app.routers import catalog as catalog_router

        self.catalog = catalog_router
        self.T = T

        # Swap the exact handle the router uses (T.catalog), restore after.
        original_catalog = T.catalog
        object.__setattr__(T, "catalog", self.table)
        self.addCleanup(lambda: object.__setattr__(T, "catalog", original_catalog))

        # Ensure dev_mode + geo blocking are on (X-Geo-Country header path).
        for attr, want in (("dev_mode", True), ("geo_blocking_enabled", True)):
            orig = getattr(S, attr)
            object.__setattr__(S, attr, want)
            self.addCleanup(lambda a=attr, o=orig: object.__setattr__(S, a, o))

        self.ctx = {"user_sub": "viewer-sub-001", "role": None, "admin_profile": None}

    def _seed_category(self, category_id: str):
        # No creator_id -> list_items skips the subscription gate.
        self.table.put_item(
            Item={
                "PK": self.catalog.cat_pk(category_id),
                "SK": "META",
                "entity": "category",
                "category_id": category_id,
                "name": "GeoCat",
                "created_at": self.catalog.now_iso(),
                "GSI1PK": "CATS",
                "GSI1SK": f"geocat#{category_id}",
            }
        )

    def _seed_item(self, category_id, item_id, name, *, geo_mode=None, geo_countries=None):
        item = {
            "PK": self.catalog.cat_pk(category_id),
            "SK": self.catalog.item_pk(item_id),
            "entity": "item",
            "category_id": category_id,
            "item_id": item_id,
            "name": name,
            "description": name,
            "price_cents": 100,
            "currency": "USD",
            "image_urls": [],
            "attributes": {},
            "created_at": self.catalog.now_iso(),
            "updated_at": self.catalog.now_iso(),
        }
        if geo_mode is not None:
            item["geo_mode"] = geo_mode
            item["geo_countries"] = geo_countries
        self.table.put_item(Item=item)

    # ── list_items ────────────────────────────────────────────────────────

    def test_list_items_hides_geo_blocked_item(self):
        """Allow-US-only item is hidden from a CN viewer, shown to a US viewer.

        FAILS BEFORE FIX: list_items never checked geo, so the item appeared for
        every viewer regardless of country.
        PASSES AFTER FIX: the CN viewer's list excludes it; the US viewer's does not.
        """
        cat = "cat_geo_list"
        self._seed_category(cat)
        self._seed_item(cat, "itm_open", "Open Item")
        self._seed_item(
            cat, "itm_us", "US Only Item", geo_mode="allow", geo_countries=["US"]
        )

        cn_out = asyncio.run(
            self.catalog.list_items(cat, _make_request("CN"), ctx=self.ctx, page_size=50, next_token=None)
        )
        cn_names = {i.name for i in cn_out.items}
        self.assertIn("Open Item", cn_names)
        self.assertNotIn(
            "US Only Item",
            cn_names,
            "GAP-0216: allow-US item must be hidden from a CN viewer",
        )

        us_out = asyncio.run(
            self.catalog.list_items(cat, _make_request("US"), ctx=self.ctx, page_size=50, next_token=None)
        )
        us_names = {i.name for i in us_out.items}
        self.assertIn("US Only Item", us_names)
        self.assertIn("Open Item", us_names)

    def test_list_items_block_mode(self):
        """Block-RU item is hidden from RU viewer, shown to a US viewer."""
        cat = "cat_geo_block"
        self._seed_category(cat)
        self._seed_item(
            cat, "itm_block", "No Russia Item", geo_mode="block", geo_countries=["RU"]
        )

        ru_names = {
            i.name
            for i in asyncio.run(
                self.catalog.list_items(cat, _make_request("RU"), ctx=self.ctx, page_size=50, next_token=None)
            ).items
        }
        self.assertNotIn("No Russia Item", ru_names)

        us_names = {
            i.name
            for i in asyncio.run(
                self.catalog.list_items(cat, _make_request("US"), ctx=self.ctx, page_size=50, next_token=None)
            ).items
        }
        self.assertIn("No Russia Item", us_names)

    # ── search_items ──────────────────────────────────────────────────────

    def test_search_items_excludes_geo_blocked(self):
        """Geo-blocked item must not appear in search results for a blocked viewer.

        FAILS BEFORE FIX: search_items scanned all items with no geo check.
        PASSES AFTER FIX: the blocked viewer's results omit the geo-fenced item.
        """
        cat = "cat_geo_search"
        self._seed_category(cat)
        unique = "ExclusiveUSOnlyItemGAP0216"
        self._seed_item(
            cat, "itm_search", unique, geo_mode="allow", geo_countries=["US"]
        )

        cn_names = [
            i.name
            for i in asyncio.run(
                self.catalog.search_items(_make_request("CN"), q="Exclusive", ctx=self.ctx, page_size=50, next_token=None)
            ).items
        ]
        self.assertNotIn(
            unique,
            cn_names,
            "GAP-0216: geo-blocked item must not surface in search for a CN viewer",
        )

        us_names = [
            i.name
            for i in asyncio.run(
                self.catalog.search_items(_make_request("US"), q="Exclusive", ctx=self.ctx, page_size=50, next_token=None)
            ).items
        ]
        self.assertIn(unique, us_names)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
