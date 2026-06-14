package com.testlogon.android.feature.promo

import com.testlogon.android.data.promo.DiscountType
import com.testlogon.android.data.promo.PromoCode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale

/** AND-266 — pure promo formatting + form validation tests. */
class PromoFormatTest {

    private fun samplePromo(
        type: DiscountType = DiscountType.PERCENTAGE,
        value: Int = 25,
        trialDays: Int = 0,
        maxUses: Int = 100,
        currentUses: Int = 12,
        expiresAt: Long = 0,
    ) = PromoCode(
        codeId = "pc_1",
        code = "SUMMER25",
        discountType = type,
        rawDiscountType = type.name,
        discountValue = value,
        freeTrialDays = trialDays,
        appliesTo = listOf("subscription"),
        minPurchaseCents = 0,
        maxUses = maxUses,
        maxUsesPerUser = 1,
        currentUses = currentUses,
        active = true,
        expiresAtEpochSeconds = expiresAt,
        createdAtEpochSeconds = 0,
    )

    @Test
    fun discountSummary_percentage() {
        assertEquals("25% off", samplePromo(value = 25).discountSummary(Locale.US))
    }

    @Test
    fun discountSummary_fixedAmount_usesCents() {
        val s = samplePromo(type = DiscountType.FIXED_AMOUNT, value = 750).discountSummary(Locale.US)
        assertTrue(s, s.contains("7.50"))
        assertTrue(s.endsWith("off"))
    }

    @Test
    fun discountSummary_freeTrial() {
        assertEquals("7-day trial", samplePromo(type = DiscountType.FREE_TRIAL, trialDays = 7).discountSummary(Locale.US))
    }

    @Test
    fun usageLabel_unlimitedWhenMaxUsesZero() {
        assertEquals("12 / ∞", samplePromo(maxUses = 0).usageLabel())
        assertEquals("12 / 100", samplePromo(maxUses = 100).usageLabel())
    }

    @Test
    fun expiryLabel_neverWhenZero() {
        assertEquals("Never", samplePromo(expiresAt = 0).expiryLabel(Locale.US))
    }

    @Test
    fun isExpired_pastEpochIsExpired_zeroNeverExpires() {
        val now = 1_800_000_000L
        assertTrue(samplePromo(expiresAt = now - 1000).isExpired(now))
        assertFalse(samplePromo(expiresAt = now + 1000).isExpired(now))
        assertFalse(samplePromo(expiresAt = 0).isExpired(now))
    }

    @Test
    fun validate_rejectsBlankAndShortCode() {
        assertEquals(PromoFormError.CODE_REQUIRED, CreatePromoForm(code = "  ").validate())
        assertEquals(PromoFormError.CODE_LENGTH, CreatePromoForm(code = "AB", discountValue = 10).validate())
    }

    @Test
    fun validate_percentRange() {
        assertEquals(
            PromoFormError.PERCENT_RANGE,
            CreatePromoForm(code = "SAVE", discountType = DiscountType.PERCENTAGE, discountValue = 0).validate(),
        )
        assertNull(
            CreatePromoForm(code = "SAVE", discountType = DiscountType.PERCENTAGE, discountValue = 50).validate(),
        )
    }

    @Test
    fun toRequest_uppercasesCode_andMapsEnum() {
        val req = CreatePromoForm(code = " summer25 ", discountType = DiscountType.FIXED_AMOUNT, discountValue = 500).toRequest()
        assertEquals("SUMMER25", req.code)
        assertEquals("fixed_amount", req.discountType)
        assertEquals(500, req.discountValue)
    }
}
