package com.testlogon.android.data.affiliates

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-265 (fill) — pure create-form validation/normalization tests for [AffiliateMath]. */
class AffiliateMathTest {

    private fun valid(r: AffiliateMath.CreateResult): AffiliateLinkCreateRequest {
        assertTrue("expected Valid, was $r", r is AffiliateMath.CreateResult.Valid)
        return (r as AffiliateMath.CreateResult.Valid).request
    }

    private fun error(r: AffiliateMath.CreateResult): AffiliateMath.CreateError {
        assertTrue("expected Invalid, was $r", r is AffiliateMath.CreateResult.Invalid)
        return (r as AffiliateMath.CreateResult.Invalid).error
    }

    @Test
    fun blankTargetId_isRejected() {
        assertEquals(
            AffiliateMath.CreateError.BLANK_TARGET_ID,
            error(AffiliateMath.validateCreate("catalog_item", "", null, null)),
        )
    }

    @Test
    fun whitespaceTargetId_isRejected() {
        assertEquals(
            AffiliateMath.CreateError.BLANK_TARGET_ID,
            error(AffiliateMath.validateCreate("catalog_item", "   ", null, null)),
        )
    }

    @Test
    fun nullTargetId_isRejected() {
        assertEquals(
            AffiliateMath.CreateError.BLANK_TARGET_ID,
            error(AffiliateMath.validateCreate("catalog_item", null, null, null)),
        )
    }

    @Test
    fun minimalValid_trimsTargetId() {
        val req = valid(AffiliateMath.validateCreate("catalog_item", "  cat_1  ", null, null))
        assertEquals("cat_1", req.targetId)
        assertEquals("catalog_item", req.targetType)
        assertNull(req.commissionPercent)
        assertNull(req.customCode)
    }

    @Test
    fun blankTargetType_fallsBackToDefault() {
        assertEquals(
            AffiliateMath.DEFAULT_TARGET_TYPE,
            valid(AffiliateMath.validateCreate("   ", "cat_1", null, null)).targetType,
        )
        assertEquals(
            AffiliateMath.DEFAULT_TARGET_TYPE,
            valid(AffiliateMath.validateCreate(null, "cat_1", null, null)).targetType,
        )
    }

    @Test
    fun customTargetType_preserved() {
        assertEquals(
            "video",
            valid(AffiliateMath.validateCreate("video", "vid_1", null, null)).targetType,
        )
    }

    @Test
    fun commissionAtBounds_accepted() {
        assertEquals(0, valid(AffiliateMath.validateCreate(null, "c", 0, null)).commissionPercent)
        assertEquals(100, valid(AffiliateMath.validateCreate(null, "c", 100, null)).commissionPercent)
    }

    @Test
    fun commissionInRange_accepted() {
        assertEquals(15, valid(AffiliateMath.validateCreate(null, "c", 15, null)).commissionPercent)
    }

    @Test
    fun commissionNegative_isRejected() {
        assertEquals(
            AffiliateMath.CreateError.COMMISSION_OUT_OF_RANGE,
            error(AffiliateMath.validateCreate(null, "c", -1, null)),
        )
    }

    @Test
    fun commissionOver100_isRejected() {
        assertEquals(
            AffiliateMath.CreateError.COMMISSION_OUT_OF_RANGE,
            error(AffiliateMath.validateCreate(null, "c", 101, null)),
        )
    }

    @Test
    fun blankCustomCode_collapsesToNull() {
        assertNull(valid(AffiliateMath.validateCreate(null, "c", null, "   ")).customCode)
        assertNull(valid(AffiliateMath.validateCreate(null, "c", null, "")).customCode)
    }

    @Test
    fun validCustomCode_trimmedAndKept() {
        assertEquals(
            "spring-2026_promo",
            valid(AffiliateMath.validateCreate(null, "c", null, "  spring-2026_promo  ")).customCode,
        )
    }

    @Test
    fun tooShortCustomCode_isRejected() {
        assertEquals(
            AffiliateMath.CreateError.INVALID_CUSTOM_CODE,
            error(AffiliateMath.validateCreate(null, "c", null, "ab")),
        )
    }

    @Test
    fun customCodeWithIllegalChars_isRejected() {
        assertEquals(
            AffiliateMath.CreateError.INVALID_CUSTOM_CODE,
            error(AffiliateMath.validateCreate(null, "c", null, "bad code!")),
        )
        assertEquals(
            AffiliateMath.CreateError.INVALID_CUSTOM_CODE,
            error(AffiliateMath.validateCreate(null, "c", null, "-startsWithDash")),
        )
    }

    @Test
    fun isCreatable_reflectsTargetIdPresence() {
        assertFalse(AffiliateMath.isCreatable(null))
        assertFalse(AffiliateMath.isCreatable(""))
        assertFalse(AffiliateMath.isCreatable("   "))
        assertTrue(AffiliateMath.isCreatable("cat_1"))
    }

    @Test
    fun fullyPopulatedRequest_mapsEveryField() {
        val req = valid(AffiliateMath.validateCreate("video", " vid_9 ", 25, " promo_9 "))
        assertEquals("video", req.targetType)
        assertEquals("vid_9", req.targetId)
        assertEquals(25, req.commissionPercent)
        assertEquals("promo_9", req.customCode)
    }
}
