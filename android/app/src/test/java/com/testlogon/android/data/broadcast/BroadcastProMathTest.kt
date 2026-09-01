package com.testlogon.android.data.broadcast

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure JVM unit tests for [BroadcastProMath] — the broadcast PRO authoring validation core (product price /
 * add / reorder + multi-input layout). No Android, no coroutines, no network. Each test pins one wire
 * constraint from app/routers/broadcast.py so a drift is caught at build time.
 */
class BroadcastProMathTest {

    private fun reasonOf(v: BroadcastProMath.Validation): String? =
        (v as? BroadcastProMath.Validation.Invalid)?.reason

    // ---- product price ------------------------------------------------------

    @Test
    fun `price at or above catalog is rejected`() {
        assertFalse(BroadcastProMath.isBroadcastPriceValid(1000L, catalogPriceCents = 1000L))
        assertEquals(
            "PRICE_NOT_BELOW_CATALOG",
            reasonOf(BroadcastProMath.validateBroadcastPriceCents(1500L, 1000L)),
        )
    }

    @Test
    fun `price strictly below catalog and within bounds is valid`() {
        assertTrue(BroadcastProMath.isBroadcastPriceValid(999L, catalogPriceCents = 1000L))
        assertTrue(BroadcastProMath.validateBroadcastPriceCents(1L, 2L).isValid)
    }

    @Test
    fun `price null or non-positive or over max is rejected`() {
        assertEquals("PRICE_REQUIRED", reasonOf(BroadcastProMath.validateBroadcastPriceCents(null, 1000L)))
        assertEquals("PRICE_TOO_LOW", reasonOf(BroadcastProMath.validateBroadcastPriceCents(0L, 1000L)))
        assertEquals("PRICE_TOO_LOW", reasonOf(BroadcastProMath.validateBroadcastPriceCents(-5L, 1000L)))
        assertEquals(
            "PRICE_TOO_HIGH",
            reasonOf(BroadcastProMath.validateBroadcastPriceCents(BroadcastProMath.PRICE_MAX_CENTS + 1, null)),
        )
    }

    @Test
    fun `price bounds hold when catalog is unknown so only absolute bounds apply`() {
        // catalog null/0 -> cannot pre-check below-catalog; absolute bounds still enforced.
        assertTrue(BroadcastProMath.validateBroadcastPriceCents(5000L, null).isValid)
        assertTrue(BroadcastProMath.validateBroadcastPriceCents(5000L, 0L).isValid)
        assertEquals("PRICE_TOO_LOW", reasonOf(BroadcastProMath.validateBroadcastPriceCents(0L, null)))
    }

    @Test
    fun `expiry is optional and bounded 60 to 86400`() {
        assertTrue(BroadcastProMath.validateExpirySeconds(null).isValid)
        assertTrue(BroadcastProMath.validateExpirySeconds(60L).isValid)
        assertTrue(BroadcastProMath.validateExpirySeconds(86_400L).isValid)
        assertEquals("EXPIRY_TOO_SHORT", reasonOf(BroadcastProMath.validateExpirySeconds(59L)))
        assertEquals("EXPIRY_TOO_LONG", reasonOf(BroadcastProMath.validateExpirySeconds(86_401L)))
    }

    @Test
    fun `discountPct floors to whole percent and clamps`() {
        assertEquals(25, BroadcastProMath.discountPct(1000L, 750L))
        assertEquals(0, BroadcastProMath.discountPct(1000L, 1000L))
        assertEquals(0, BroadcastProMath.discountPct(0L, 100L))
        assertEquals(99, BroadcastProMath.discountPct(1000L, 1L)) // 99.9% floors to 99
    }

    // ---- add product --------------------------------------------------------

    @Test
    fun `add product requires non-blank ids and in-range display order`() {
        assertTrue(BroadcastProMath.validateAddProduct("i1", "c1", 0).isValid)
        assertTrue(BroadcastProMath.validateAddProduct("i1", "c1", 999).isValid)
        assertEquals("ITEM_ID_REQUIRED", reasonOf(BroadcastProMath.validateAddProduct("  ", "c1", 0)))
        assertEquals("CATEGORY_ID_REQUIRED", reasonOf(BroadcastProMath.validateAddProduct("i1", "", 0)))
        assertEquals("DISPLAY_ORDER_OUT_OF_RANGE", reasonOf(BroadcastProMath.validateAddProduct("i1", "c1", 1000)))
        assertEquals("DISPLAY_ORDER_OUT_OF_RANGE", reasonOf(BroadcastProMath.validateAddProduct("i1", "c1", -1)))
    }

    // ---- reorder ------------------------------------------------------------

    @Test
    fun `reorder rejects empty over-long blank and duplicate`() {
        assertTrue(BroadcastProMath.validateReorder(listOf("a", "b", "c")).isValid)
        assertEquals("REORDER_EMPTY", reasonOf(BroadcastProMath.validateReorder(emptyList())))
        assertEquals("REORDER_TOO_MANY", reasonOf(BroadcastProMath.validateReorder((1..51).map { "i$it" })))
        assertEquals("REORDER_BLANK_ID", reasonOf(BroadcastProMath.validateReorder(listOf("a", " "))))
        assertEquals("REORDER_DUPLICATE_ID", reasonOf(BroadcastProMath.validateReorder(listOf("a", "a"))))
    }

    // ---- layout mode --------------------------------------------------------

    @Test
    fun `only the four wire modes are valid`() {
        assertTrue(BroadcastProMath.isValidLayoutMode("single"))
        assertTrue(BroadcastProMath.isValidLayoutMode("side_by_side"))
        assertTrue(BroadcastProMath.isValidLayoutMode("pip"))
        assertTrue(BroadcastProMath.isValidLayoutMode("grid"))
        assertFalse(BroadcastProMath.isValidLayoutMode("quad"))
        assertFalse(BroadcastProMath.isValidLayoutMode(""))
    }

    // ---- layout slot --------------------------------------------------------

    @Test
    fun `valid in-frame slot passes`() {
        assertTrue(BroadcastProMath.validateLayoutSlot("in1", 0.0, 0.0, 0.5, 0.5, 0).isValid)
        assertTrue(BroadcastProMath.validateLayoutSlot("in1", 0.5, 0.5, 0.5, 0.5, 10).isValid)
    }

    @Test
    fun `slot rejects blank input out-of-range coords and overflow`() {
        assertEquals("SLOT_INPUT_REQUIRED", reasonOf(BroadcastProMath.validateLayoutSlot("", 0.0, 0.0, 0.5, 0.5, 0)))
        assertEquals("SLOT_X_OUT_OF_RANGE", reasonOf(BroadcastProMath.validateLayoutSlot("in1", -0.1, 0.0, 0.5, 0.5, 0)))
        assertEquals("SLOT_WIDTH_OUT_OF_RANGE", reasonOf(BroadcastProMath.validateLayoutSlot("in1", 0.0, 0.0, 0.0, 0.5, 0)))
        assertEquals("SLOT_OVERFLOWS_X", reasonOf(BroadcastProMath.validateLayoutSlot("in1", 0.7, 0.0, 0.5, 0.5, 0)))
        assertEquals("SLOT_OVERFLOWS_Y", reasonOf(BroadcastProMath.validateLayoutSlot("in1", 0.0, 0.7, 0.5, 0.5, 0)))
    }

    @Test
    fun `slot z_index bounded 0 to 10`() {
        assertEquals("SLOT_Z_OUT_OF_RANGE", reasonOf(BroadcastProMath.validateLayoutSlot("in1", 0.0, 0.0, 0.5, 0.5, -1)))
        assertEquals("SLOT_Z_OUT_OF_RANGE", reasonOf(BroadcastProMath.validateLayoutSlot("in1", 0.0, 0.0, 0.5, 0.5, 11)))
    }

    // ---- layout switch ------------------------------------------------------

    @Test
    fun `layout switch validates mode inputs and primary membership`() {
        assertTrue(BroadcastProMath.validateLayoutSwitch("grid", null, null).isValid)
        assertTrue(BroadcastProMath.validateLayoutSwitch("pip", "a", listOf("a", "b")).isValid)
        assertEquals("LAYOUT_MODE_INVALID", reasonOf(BroadcastProMath.validateLayoutSwitch("quad", null, null)))
        assertEquals("LAYOUT_INPUTS_EMPTY", reasonOf(BroadcastProMath.validateLayoutSwitch("grid", null, emptyList())))
        assertEquals("LAYOUT_INPUT_DUPLICATE", reasonOf(BroadcastProMath.validateLayoutSwitch("grid", null, listOf("a", "a"))))
        assertEquals("LAYOUT_PRIMARY_BLANK", reasonOf(BroadcastProMath.validateLayoutSwitch("pip", " ", null)))
        assertEquals(
            "LAYOUT_PRIMARY_NOT_IN_INPUTS",
            reasonOf(BroadcastProMath.validateLayoutSwitch("pip", "z", listOf("a", "b"))),
        )
    }

    // ---- degrade-on-404 -----------------------------------------------------

    @Test
    fun `benign pro read failure is 404 and 410 only`() {
        assertTrue(BroadcastProMath.isBenignProReadFailure(404))
        assertTrue(BroadcastProMath.isBenignProReadFailure(410))
        assertFalse(BroadcastProMath.isBenignProReadFailure(403))
        assertFalse(BroadcastProMath.isBenignProReadFailure(500))
    }
}
