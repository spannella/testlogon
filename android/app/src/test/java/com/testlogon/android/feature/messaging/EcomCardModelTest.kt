package com.testlogon.android.feature.messaging

import com.testlogon.android.feature.messaging.EcomCardModel.OrderCard
import com.testlogon.android.feature.messaging.EcomCardModel.OrderMode
import com.testlogon.android.feature.messaging.EcomCardModel.ProductCard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** EPIC F (FE-150 / FE-151) — pure build/encode/parse + price-format + preview + PII-strip tests. */
class EcomCardModelTest {

    // ---- FE-150 product: build + round-trip ----

    @Test
    fun product_build_trims_title_and_defaults_blanks() {
        val p = EcomCardModel.buildProductPayload(
            categoryId = "cat1", itemId = "it1", title = "  Widget  ",
            priceCents = 1999, currency = " ", imageUrl = "", inStock = true,
        )
        assertEquals("Widget", p.title)
        assertEquals("USD", p.currency)
        assertNull(p.imageUrl)
    }

    @Test
    fun product_encode_parse_round_trips_all_fields() {
        val p = ProductCard(
            categoryId = "electronics", itemId = "sku-42", title = "Noise; Cancelling = Headphones",
            priceCents = 129900, currency = "USD", imageUrl = "https://x/y.png?a=1;b=2", inStock = true,
        )
        val body = EcomCardModel.encode(p)
        assertTrue(EcomCardModel.isCard(body))
        val back = EcomCardModel.parse(body) as ProductCard
        assertEquals(p, back)
    }

    @Test
    fun product_out_of_stock_round_trips() {
        val p = ProductCard("c", "i", "T", 500, "USD", null, inStock = false)
        val back = EcomCardModel.parse(EcomCardModel.encode(p)) as ProductCard
        assertFalse(back.inStock)
    }

    // ---- FE-151 order: build + round-trip + modes ----

    @Test
    fun order_recommendation_keeps_buyer_name() {
        val o = EcomCardModel.buildOrderPayload(
            orderId = "o1", summary = "2x Mug", status = "shipped",
            mode = OrderMode.RECOMMENDATION, totalCents = 2500, currency = "USD", buyerName = "Alice Smith",
        )
        assertEquals("Alice Smith", o.buyerName)
    }

    @Test
    fun order_encode_parse_round_trips_gift_mode() {
        val o = OrderCard("o2", "Gift box", "processing", OrderMode.GIFT, 4200, "USD", "Bob")
        val back = EcomCardModel.parse(EcomCardModel.encode(o)) as OrderCard
        assertEquals(o, back)
    }

    @Test
    fun order_without_total_round_trips_null_total() {
        val o = OrderCard("o3", "Item", "pending", OrderMode.RECOMMENDATION, null, null, null)
        val back = EcomCardModel.parse(EcomCardModel.encode(o)) as OrderCard
        assertNull(back.totalCents)
        assertNull(back.currency)
    }

    @Test
    fun order_unknown_mode_wire_falls_back_to_recommendation() {
        // Hand-crafted body with a bogus mode -> conservative RECOMMENDATION, not a throw.
        val body = EcomCardModel.SENTINEL + EcomCardModel.WIRE_ORDER + ";oid=o9;sum=X;st=ok;mode=bogus"
        val back = EcomCardModel.parse(body) as OrderCard
        assertEquals(OrderMode.RECOMMENDATION, back.mode)
    }

    // ---- FE-151 PII CHOKE POINT: receipt mode carries NO buyer name ----

    @Test
    fun receipt_build_strips_buyer_name() {
        val o = EcomCardModel.buildOrderPayload(
            orderId = "o1", summary = "1x Book", status = "delivered",
            mode = OrderMode.RECEIPT, totalCents = 1500, currency = "USD",
            buyerName = "Jane Doe, 123 Main St, Springfield",
        )
        assertNull("receipt must not carry buyer name/address PII", o.buyerName)
    }

    @Test
    fun receipt_encoded_body_contains_no_buyer_pii() {
        // Even if an OrderCard is hand-built with a name in receipt mode, encode must not emit it.
        val leaky = OrderCard("o1", "1x Book", "delivered", OrderMode.RECEIPT, 1500, "USD", "Jane Doe")
        val body = EcomCardModel.encode(leaky)
        assertFalse("encoded receipt body leaked buyer name", body.contains("Jane"))
        assertFalse("encoded receipt body leaked buyer key", body.contains("buyer="))
    }

    @Test
    fun receipt_parse_never_surfaces_buyer_name_even_from_crafted_body() {
        // A crafted receipt body that smuggles a buyer= field must still parse to null buyer name.
        val crafted = EcomCardModel.SENTINEL + EcomCardModel.WIRE_ORDER +
            ";oid=o1;sum=1x Book;st=delivered;mode=receipt;buyer=Jane Doe"
        val back = EcomCardModel.parse(crafted) as OrderCard
        assertNull(back.buyerName)
    }

    // ---- price format ----

    @Test
    fun format_price_usd_uses_symbol_and_grouping() {
        assertEquals("$1,299.00", EcomCardModel.formatPrice(129900, "USD"))
    }

    @Test
    fun format_price_unknown_currency_appends_code() {
        assertEquals("12.34 JPY", EcomCardModel.formatPrice(1234, "jpy"))
    }

    // ---- previews ----

    @Test
    fun product_preview_and_body_preview_match() {
        val p = ProductCard("c", "i", "Cool Thing", 100, "USD", null, true)
        assertEquals("[Product: Cool Thing]", EcomCardModel.productPreview(p))
        assertEquals("[Product: Cool Thing]", EcomCardModel.previewForBody(EcomCardModel.encode(p)))
    }

    @Test
    fun order_preview_and_body_preview_match_and_carry_no_pii() {
        val o = OrderCard("o1", "3x Socks", "shipped", OrderMode.RECEIPT, 900, "USD", null)
        assertEquals("[Order: 3x Socks]", EcomCardModel.orderPreview(o))
        assertEquals("[Order: 3x Socks]", EcomCardModel.previewForBody(EcomCardModel.encode(o)))
    }

    // ---- negative: non-card + foreign sentinel ----

    @Test
    fun parse_returns_null_for_plain_text_and_other_sentinels() {
        assertNull(EcomCardModel.parse("just a normal message"))
        assertNull(EcomCardModel.parse(null))
        assertNull(EcomCardModel.parse("TLXFER1:crypto_transfer;asset=USDC;amt=1"))
        assertNull(EcomCardModel.previewForBody("hello"))
    }
}
