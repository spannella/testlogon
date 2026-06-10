package com.testlogon.android.feature.cart

import com.testlogon.android.data.cart.CartItem
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-212 — pure [CartSearch.filter] coverage: empty/whitespace query returns all, SKU + name
 * substring match, case + diacritic folding, zero-match, and matched-subtotal math.
 */
class CartSearchTest {

    private fun item(sku: String, name: String, lineTotal: Long = 1000) =
        CartItem(sku = sku, name = name, quantity = 1, unitPriceCents = lineTotal, lineTotalCents = lineTotal)

    private val items = listOf(
        item("TL-SHIRT-BLK-M", "TestLogon Tee shirt", 2000),
        item("TL-MUG", "Coffee Mug", 1500),
        item("TL-CAFE", "Café Blend", 500),
    )

    @Test
    fun emptyQuery_returnsAll_withFullSubtotal() {
        val r = CartSearch.filter(items, "")
        assertEquals(3, r.items.size)
        assertEquals(3, r.matchedCount)
        assertEquals(3, r.totalCount)
        assertEquals(4000L, r.matchedSubtotalCents)
        assertFalse(r.isFiltering)
    }

    @Test
    fun whitespaceQuery_treatedAsNoFilter() {
        val r = CartSearch.filter(items, "   ")
        assertEquals(3, r.items.size)
        assertFalse(r.isFiltering)
    }

    @Test
    fun skuMatch() {
        val r = CartSearch.filter(items, "TL-MUG")
        assertEquals(listOf("TL-MUG"), r.items.map { it.sku })
    }

    @Test
    fun nameMatch_caseInsensitive() {
        val r = CartSearch.filter(items, "SHIRT")
        assertEquals(listOf("TL-SHIRT-BLK-M"), r.items.map { it.sku })
        assertTrue(r.isFiltering)
    }

    @Test
    fun diacriticFolding_cafeMatchesCafé() {
        assertEquals(listOf("TL-CAFE"), CartSearch.filter(items, "cafe").items.map { it.sku })
        assertEquals(listOf("TL-CAFE"), CartSearch.filter(items, "CAFÉ").items.map { it.sku })
    }

    @Test
    fun zeroMatch() {
        val r = CartSearch.filter(items, "zzz")
        assertTrue(r.items.isEmpty())
        assertEquals(0, r.matchedCount)
        assertEquals(3, r.totalCount)
        assertEquals(0L, r.matchedSubtotalCents)
        assertTrue(r.isFiltering)
    }

    @Test
    fun matchedSubtotal_sumsMatchesOnly() {
        // "co" matches "Coffee Mug" (1500) only (not "Café Blend" -> "cafe blend"; not the tee).
        val r = CartSearch.filter(items, "coffee")
        assertEquals(1500L, r.matchedSubtotalCents)
    }
}
