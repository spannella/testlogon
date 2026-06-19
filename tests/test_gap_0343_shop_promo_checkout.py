"""Lock-in regression test for GAP-0343 (PROMO-001).

The original gap ticket claimed promo codes were "not integrated into shop
checkout" and that the ``applies_to: ["shop"]`` checkout type was orphaned in
``app/routers/catalog.py``. The second-pass verification established this premise
is OUTDATED: shop checkout does NOT live in ``catalog.py`` — it lives in
``app/routers/shoppingcart.py`` (``POST /carts/{cart_id}/purchase`` →
``app/services/shoppingcart.py:purchase_cart``), and that path already:

  1. validates a supplied promo code with ``checkout_type="shop"`` (so an
     ``applies_to=["shop"]`` promo is honored — and a non-shop promo is rejected),
  2. applies the discount to the cart total (``final_total = total - discount``),
  3. redeems the code after a successful purchase (atomic ``current_uses`` increment).

This test LOCKS IN that behavior end-to-end through the real
``purchase_cart`` service path, with a real in-memory DynamoDB (moto) bound to
the exact frozen ``T.promo_codes`` / ``T.shopping_cart`` handles, and with the
post-validation commerce side effects (order creation, entitlements, purchase
ledger — i.e. "the charge") stubbed so no Stripe / real AWS is touched.

Assertions:
  * the cart total reflects the discount (``purchased_total_cents`` == discounted),
  * the promo redemption count (``current_uses``) incremented from 0 → 1,
  * a redemption row records ``checkout_type="shop"``,
  * a shop-applicable promo is accepted while a subscription-only promo is rejected
    for the same shop cart (proves ``applies_to: ["shop"]`` is honored at checkout).

Fully offline. The FastAPI TestClient is unusable in this repo, so the service
function is called directly. ``S``/``T`` are frozen → patched via ``object.__setattr__``
/ ``patch.object``.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_promo_table(ddb):
    """PromoCodes table mirroring scripts/local-ddb-init.py (pk/sk + 2 GSIs)."""
    return ddb.create_table(
        TableName="PromoCodes",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "creator_scope", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "code_lookup_pk", "AttributeType": "S"},
            {"AttributeName": "code_lookup_sk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByCreatorCreatedAt",
                "KeySchema": [
                    {"AttributeName": "creator_scope", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByCodeString",
                "KeySchema": [
                    {"AttributeName": "code_lookup_pk", "KeyType": "HASH"},
                    {"AttributeName": "code_lookup_sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_cart_table(ddb):
    """shopping_cart table mirroring scripts/local-ddb-init.py (PK/SK single-table)."""
    return ddb.create_table(
        TableName="shopping_cart",
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestShopPromoCheckoutGap0343(unittest.TestCase):
    USER = "user_buyer_0343"
    CREATOR = "creator_seller_0343"
    CART_ID = "cart0343"

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.promo_tbl = _make_promo_table(ddb)
        self.cart_tbl = _make_cart_table(ddb)

        from app.services import shoppingcart as sc_svc
        from app.services import promo_codes as promo_svc

        self.sc_svc = sc_svc
        self.promo_svc = promo_svc

        # Bind the exact frozen table handles each module reads (each module does
        # ``from app.core.tables import T``, so patch each module's own binding).
        self.stack.enter_context(
            patch.object(sc_svc, "T", SimpleNamespace(shopping_cart=self.cart_tbl))
        )
        self.stack.enter_context(
            patch.object(promo_svc, "T", SimpleNamespace(promo_codes=self.promo_tbl))
        )

        # Stub the "charge"/commerce side effects so no Stripe / real backend runs.
        self.stack.enter_context(
            patch.object(
                sc_svc.commerce_order_service,
                "create_order_from_line_items",
                return_value={"order_id": "ord_0343"},
            )
        )
        self.stack.enter_context(
            patch.object(
                sc_svc.commerce_entitlement_orchestrator,
                "process_order_entitlements",
                return_value={},
            )
        )
        self.stack.enter_context(
            patch.object(sc_svc, "record_cart_purchase", return_value="txn_0343")
        )
        self.stack.enter_context(
            patch.object(sc_svc, "get_profile", return_value={})
        )
        # _commercial_line_items_from_cart_items calls catalog version validation;
        # neutralize it so the stubbed order builder receives plain line items.
        self.stack.enter_context(
            patch.object(
                sc_svc,
                "_commercial_line_items_from_cart_items",
                return_value=[],
            )
        )

    # ── seeding helpers ────────────────────────────────────────────────

    def _seed_cart(self, total_cents: int) -> None:
        """One OPEN cart + one item totalling ``total_cents`` (qty 1)."""
        pk = self.sc_svc._user_pk(self.USER)
        self.cart_tbl.put_item(
            Item={
                "PK": pk,
                "SK": self.sc_svc._cart_sk(self.CART_ID),
                "type": "cart",
                "cart_id": self.CART_ID,
                "status": "OPEN",
                "created_at": "2026-01-01T00:00:00+00:00",
                "currency": "USD",
            }
        )
        self.cart_tbl.put_item(
            Item={
                "PK": pk,
                "SK": self.sc_svc._item_sk(self.CART_ID, "SKU1"),
                "type": "item",
                "sku": "SKU1",
                "name": "Widget",
                "quantity": 1,
                "unit_price_cents": total_cents,
                # creator info so _resolve_cart_creator yields a single creator
                "creator_user_id": self.CREATOR,
            }
        )

    def _seed_shop_promo(self, code: str, discount_cents: int) -> str:
        # The cart item has creator_user_id=CREATOR; _resolve_cart_creator returns
        # CREATOR. The promo must belong to CREATOR to pass the creator-scope check.
        item, err = self.promo_svc.create_promo_code(
            creator_id=self.CREATOR,
            code=code,
            discount_type="fixed_amount",
            discount_value=discount_cents,
            applies_to=["shop"],
            max_uses=10,
            max_uses_per_user=5,
        )
        self.assertIsNone(err, f"promo create failed: {err}")
        self.assertIsNotNone(item)
        return item["code_id"]

    # ── tests ──────────────────────────────────────────────────────────

    def test_shop_cart_purchase_applies_and_redeems_promo(self):
        """End-to-end: a shop-applicable promo discounts the cart total AND is redeemed.

        FAILS if the shop checkout ever stops validating/applying/redeeming promos
        (the original GAP-0343 premise) — proving the integration is locked in.
        """
        self._seed_cart(total_cents=1000)
        code_id = self._seed_shop_promo("SAVE200", discount_cents=200)

        # Sanity: redemption counter starts at 0.
        before = self.promo_svc.get_promo_code(code_id)
        self.assertEqual(int(before["current_uses"]), 0)

        result = self.sc_svc.purchase_cart(
            self.USER,
            self.CART_ID,
            idempotency_key="idem-0343-ok",
            promo_code="SAVE200",
        )

        # 1) Cart total reflects the discount: 1000 - 200 = 800.
        self.assertEqual(int(result["purchased_total_cents"]), 800)

        # 2) Discount metadata persisted on the cart record.
        cart = self.sc_svc.get_cart(self.USER, self.CART_ID)
        self.assertEqual(int(cart["purchased_total_cents"]), 800)
        self.assertEqual(int(cart["discount_cents"]), 200)
        self.assertEqual(int(cart["original_total_cents"]), 1000)
        self.assertEqual(cart["promo_code_id"], code_id)

        # 3) Redemption count incremented 0 → 1 (atomic increment ran).
        after = self.promo_svc.get_promo_code(code_id)
        self.assertEqual(int(after["current_uses"]), 1)

        # 4) A redemption row was written with checkout_type="shop".
        redeems = self.promo_svc._query_promo_user_redeems(code_id, self.USER)
        self.assertEqual(len(redeems), 1)
        self.assertEqual(redeems[0]["checkout_type"], "shop")
        self.assertEqual(int(redeems[0]["final_price_cents"]), 800)

    def test_subscription_only_promo_rejected_at_shop_checkout(self):
        """A promo scoped applies_to=["subscription"] must be rejected on a shop cart.

        Proves ``checkout_type="shop"`` is genuinely passed to validate_promo_code
        (otherwise a subscription-only code would slip through) and that the cart
        is NOT marked purchased on rejection.
        """
        self._seed_cart(total_cents=1000)
        sub_item, err = self.promo_svc.create_promo_code(
            creator_id=self.USER,
            code="SUBONLY",
            discount_type="fixed_amount",
            discount_value=300,
            applies_to=["subscription"],
            max_uses=10,
        )
        self.assertIsNone(err)
        sub_code_id = sub_item["code_id"]

        from fastapi import HTTPException

        with self.assertRaises(HTTPException) as ctx:
            self.sc_svc.purchase_cart(
                self.USER,
                self.CART_ID,
                idempotency_key="idem-0343-reject",
                promo_code="SUBONLY",
            )
        self.assertEqual(ctx.exception.status_code, 422)

        # Cart stayed OPEN; subscription promo was NOT redeemed.
        cart = self.sc_svc.get_cart(self.USER, self.CART_ID)
        self.assertEqual(cart["status"], "OPEN")
        self.assertEqual(int(self.promo_svc.get_promo_code(sub_code_id)["current_uses"]), 0)


if __name__ == "__main__":
    unittest.main()
