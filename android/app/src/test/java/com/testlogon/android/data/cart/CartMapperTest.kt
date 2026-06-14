package com.testlogon.android.data.cart

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-210 — exhaustive DTO -> domain mapper coverage: full items payload, null/empty items, total
 * fallback, derived subtotal, and blank-string -> null normalization for image/category.
 */
class CartMapperTest {

    private fun itemDto(
        sku: String = "SKU-1",
        lineTotal: Long = 3998,
        image: String? = "http://h/a.png",
        category: String? = "cat_1",
    ) = CartItemOutDto(
        sku = sku,
        name = "Widget",
        quantity = 2,
        unitPriceCents = 1999,
        lineTotalCents = lineTotal,
        updatedAt = "t",
        itemId = "itm_1",
        categoryId = category,
        imageUrl = image,
    )

    @Test
    fun itemsResp_fullPayload_mapsAllFields() {
        val total = CartTotalDto(cartId = "cart_1", totalCents = 4498, currency = "USD").toDomain()
        val cart = CartItemsRespDto(cartId = "cart_1", items = listOf(itemDto())).toDomain(total)
        assertEquals("cart_1", cart.cartId)
        assertEquals(1, cart.items.size)
        assertEquals(4498L, cart.totalCents)
        assertEquals("USD", cart.currency)
        assertEquals(2, cart.itemCount)
        assertEquals(3998L, cart.subtotalCents)
        assertEquals("http://h/a.png", cart.items[0].imageUrl)
        assertEquals("cat_1", cart.items[0].categoryId)
    }

    @Test
    fun itemsResp_nullItems_yieldsEmptyCart() {
        val cart = CartItemsRespDto(cartId = "cart_1", items = null).toDomain(null)
        assertTrue(cart.isEmpty)
        assertEquals(0, cart.itemCount)
        assertEquals(0L, cart.subtotalCents)
        assertEquals(0L, cart.totalCents)
        assertEquals("USD", cart.currency)
    }

    @Test
    fun itemsResp_nullTotal_fallsBackToDerivedSubtotal() {
        val cart = CartItemsRespDto(cartId = "cart_1", items = listOf(itemDto(lineTotal = 1000))).toDomain(null)
        assertEquals(1000L, cart.totalCents)
    }

    @Test
    fun item_blankImageAndCategory_mapToNull() {
        val cart = CartItemsRespDto(
            cartId = "cart_1",
            items = listOf(itemDto(image = "  ", category = "")),
        ).toDomain(null)
        assertNull(cart.items[0].imageUrl)
        assertNull(cart.items[0].categoryId)
    }

    @Test
    fun cartTotal_nullFields_default() {
        val total = CartTotalDto(cartId = "cart_1", totalCents = null, currency = null).toDomain()
        assertEquals(0L, total.totalCents)
        assertEquals("USD", total.currency)
    }
}
