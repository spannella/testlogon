package com.testlogon.android.data.sellerstore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ECOM (catalog depth) — JVM unit tests for [CatalogSellerMath]. Pure logic, no Android/network deps.
 */
class CatalogSellerMathTest {

    // ── variant effective price ──────────────────────────────────────────────

    @Test
    fun `variant price sums positive and negative deltas over base`() {
        assertEquals(1500L, CatalogSellerMath.variantEffectivePriceCents(1000L, listOf(300L, 200L)))
        assertEquals(800L, CatalogSellerMath.variantEffectivePriceCents(1000L, listOf(-200L)))
    }

    @Test
    fun `variant price floors at zero, never negative`() {
        assertEquals(0L, CatalogSellerMath.variantEffectivePriceCents(500L, listOf(-900L)))
    }

    @Test
    fun `variant price with no deltas equals base`() {
        assertEquals(2500L, CatalogSellerMath.variantEffectivePriceCents(2500L, emptyList()))
    }

    // ── bundle total ─────────────────────────────────────────────────────────

    @Test
    fun `bundle total sums unit price times quantity across lines`() {
        val lines = listOf(
            BundleLineMath(quantity = 2, unitPriceCents = 500L),
            BundleLineMath(quantity = 3, unitPriceCents = 100L),
        )
        assertEquals(1300L, CatalogSellerMath.bundleTotalCents(lines))
    }

    @Test
    fun `bundle total treats null unit price as zero and ignores non-positive qty`() {
        val lines = listOf(
            BundleLineMath(quantity = 4, unitPriceCents = null),
            BundleLineMath(quantity = 0, unitPriceCents = 999L),
            BundleLineMath(quantity = -1, unitPriceCents = 999L),
            BundleLineMath(quantity = 2, unitPriceCents = 250L),
        )
        assertEquals(500L, CatalogSellerMath.bundleTotalCents(lines))
    }

    // ── price component active window ────────────────────────────────────────

    @Test
    fun `price component active within window`() {
        assertTrue(CatalogSellerMath.isPriceComponentActive(effectiveAt = 100L, expiresAt = 200L, asOf = 150L))
    }

    @Test
    fun `price component with null expiry is active once effective`() {
        assertTrue(CatalogSellerMath.isPriceComponentActive(effectiveAt = 100L, expiresAt = null, asOf = 100L))
    }

    @Test
    fun `price component not yet effective is inactive`() {
        assertFalse(CatalogSellerMath.isPriceComponentActive(effectiveAt = 200L, expiresAt = null, asOf = 150L))
    }

    @Test
    fun `price component past expiry is inactive`() {
        assertFalse(CatalogSellerMath.isPriceComponentActive(effectiveAt = 100L, expiresAt = 140L, asOf = 150L))
    }

    // ── resolve active amount (newest-effective-first) ───────────────────────

    @Test
    fun `resolve picks newest effective active component`() {
        val comps = listOf(
            PriceComponentMath(amountCents = 900L, effectiveAt = 100L, expiresAt = null),
            PriceComponentMath(amountCents = 800L, effectiveAt = 200L, expiresAt = null),
        )
        assertEquals(800L, CatalogSellerMath.resolveActiveAmountCents(comps, asOf = 250L))
    }

    @Test
    fun `resolve skips expired newest and falls to older active`() {
        val comps = listOf(
            PriceComponentMath(amountCents = 700L, effectiveAt = 100L, expiresAt = null),
            PriceComponentMath(amountCents = 600L, effectiveAt = 200L, expiresAt = 220L),
        )
        assertEquals(700L, CatalogSellerMath.resolveActiveAmountCents(comps, asOf = 300L))
    }

    @Test
    fun `resolve returns null when none active`() {
        val comps = listOf(
            PriceComponentMath(amountCents = 600L, effectiveAt = 500L, expiresAt = null),
        )
        assertNull(CatalogSellerMath.resolveActiveAmountCents(comps, asOf = 100L))
    }

    // ── validation ───────────────────────────────────────────────────────────

    @Test
    fun `validatePriceComponent accepts a good component`() {
        assertNull(CatalogSellerMath.validatePriceComponent("PROMO", 1000L, 100L, 200L))
        assertNull(CatalogSellerMath.validatePriceComponent("DEFAULT", 0L, 0L, null))
    }

    @Test
    fun `validatePriceComponent rejects bad type, negative amount, and inverted window`() {
        assertEquals("Choose a price type", CatalogSellerMath.validatePriceComponent("BOGUS", 100L, 0L, null))
        assertEquals("Amount can't be negative", CatalogSellerMath.validatePriceComponent("LIST", -1L, 0L, null))
        assertEquals("Expiry must be after the effective time", CatalogSellerMath.validatePriceComponent("LIST", 100L, 200L, 150L))
    }

    @Test
    fun `validateVariant requires non-blank feature mapping`() {
        assertNull(CatalogSellerMath.validateVariant(mapOf("fc1" to "fv1")))
        assertEquals("Pick at least one option", CatalogSellerMath.validateVariant(emptyMap()))
        assertEquals("Every option needs a value", CatalogSellerMath.validateVariant(mapOf("fc1" to "")))
    }

    @Test
    fun `validateBundleComponent guards self-reference and quantity`() {
        assertNull(CatalogSellerMath.validateBundleComponent("p1", "c1", 1))
        assertEquals("A bundle can't contain itself", CatalogSellerMath.validateBundleComponent("p1", "p1", 1))
        assertEquals("Quantity must be at least 1", CatalogSellerMath.validateBundleComponent("p1", "c1", 0))
        assertEquals("Pick a component product", CatalogSellerMath.validateBundleComponent("p1", "", 1))
    }

    // ── flags & formatting ───────────────────────────────────────────────────

    @Test
    fun `isBundleType true only for bundle and kit`() {
        assertTrue(CatalogSellerMath.isBundleType("bundle"))
        assertTrue(CatalogSellerMath.isBundleType("kit"))
        assertFalse(CatalogSellerMath.isBundleType("standalone"))
        assertFalse(CatalogSellerMath.isBundleType(null))
    }

    @Test
    fun `isValidPriceType matches server enum case-sensitively`() {
        assertTrue(CatalogSellerMath.isValidPriceType("AVERAGE_COST"))
        assertFalse(CatalogSellerMath.isValidPriceType("average_cost"))
        assertFalse(CatalogSellerMath.isValidPriceType(null))
    }

    @Test
    fun `formatCents renders dollars and cents`() {
        assertEquals("$12.34", CatalogSellerMath.formatCents(1234L))
        assertEquals("$0.05", CatalogSellerMath.formatCents(5L))
        assertEquals("-$1.00", CatalogSellerMath.formatCents(-100L))
    }

    @Test
    fun `formatDeltaCents renders explicit sign`() {
        assertEquals("+$3.00", CatalogSellerMath.formatDeltaCents(300L))
        assertEquals("-$2.50", CatalogSellerMath.formatDeltaCents(-250L))
        assertEquals("$0.00", CatalogSellerMath.formatDeltaCents(0L))
    }
}
