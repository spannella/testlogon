package com.testlogon.android.feature.promo

import com.testlogon.android.data.promo.DiscountType
import com.testlogon.android.data.promo.PromoCode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-266 (buyer surface) — correctness for the pure checkout promo math: code-format validation,
 * discount-cents/final-price computation (percentage/fixed/free-trial clamps mirroring the backend
 * _calculate_discount), and the buyer eligibility gates (active/expiry/usage/per-user/applies_to/min).
 * Pure + deterministic (the clock is injected as nowEpochSeconds).
 */
class PromoCodeMathTest {

    private val now = 1_000_000L

    private fun promo(
        code: String = "SUMMER25",
        discountType: DiscountType = DiscountType.PERCENTAGE,
        discountValue: Int = 25,
        freeTrialDays: Int = 0,
        appliesTo: List<String> = listOf("shop"),
        minPurchaseCents: Int = 0,
        maxUses: Int = 0,
        maxUsesPerUser: Int = 1,
        currentUses: Int = 0,
        active: Boolean = true,
        expiresAtEpochSeconds: Long = 0L,
    ) = PromoCode(
        codeId = "pc_1",
        code = code,
        discountType = discountType,
        rawDiscountType = discountType.name.lowercase(),
        discountValue = discountValue,
        freeTrialDays = freeTrialDays,
        appliesTo = appliesTo,
        minPurchaseCents = minPurchaseCents,
        maxUses = maxUses,
        maxUsesPerUser = maxUsesPerUser,
        currentUses = currentUses,
        active = active,
        expiresAtEpochSeconds = expiresAtEpochSeconds,
        createdAtEpochSeconds = 0L,
    )

    // ---- format ----

    @Test
    fun normalize_trimsAndUppercases() {
        assertEquals("SAVE10", PromoCodeMath.normalizeCode("  save10  "))
    }

    @Test
    fun format_validAndInvalid() {
        assertTrue(PromoCodeMath.isValidFormat("SUMMER25"))
        assertTrue(PromoCodeMath.isValidFormat("a-b_c"))
        assertFalse(PromoCodeMath.isValidFormat(""))
        assertFalse(PromoCodeMath.isValidFormat("  "))
        assertFalse(PromoCodeMath.isValidFormat("ab")) // too short
        assertFalse(PromoCodeMath.isValidFormat("has space"))
        assertFalse(PromoCodeMath.isValidFormat("bad!char"))
        assertFalse(PromoCodeMath.isValidFormat("x".repeat(31))) // too long
        assertTrue(PromoCodeMath.isValidFormat("x".repeat(30)))
    }

    // ---- discount math ----

    @Test
    fun percentage_floorsAndClamps() {
        // 25% of 999 = 249.75 -> floor 249; final 999 - 249 = 750
        assertEquals(249, PromoCodeMath.discountCents(DiscountType.PERCENTAGE, 25, 999))
        assertEquals(750, PromoCodeMath.finalPriceCents(DiscountType.PERCENTAGE, 25, 999))
    }

    @Test
    fun percentage_over100_isClampedToPrice() {
        assertEquals(1000, PromoCodeMath.discountCents(DiscountType.PERCENTAGE, 250, 1000))
        assertEquals(0, PromoCodeMath.finalPriceCents(DiscountType.PERCENTAGE, 250, 1000))
    }

    @Test
    fun fixed_capsAtPrice() {
        assertEquals(1000, PromoCodeMath.discountCents(DiscountType.FIXED_AMOUNT, 1500, 1000))
        assertEquals(0, PromoCodeMath.finalPriceCents(DiscountType.FIXED_AMOUNT, 1500, 1000))
        assertEquals(300, PromoCodeMath.discountCents(DiscountType.FIXED_AMOUNT, 300, 1000))
        assertEquals(700, PromoCodeMath.finalPriceCents(DiscountType.FIXED_AMOUNT, 300, 1000))
    }

    @Test
    fun freeTrial_discountsWholePrice() {
        assertEquals(1000, PromoCodeMath.discountCents(DiscountType.FREE_TRIAL, 0, 1000))
        assertEquals(0, PromoCodeMath.finalPriceCents(DiscountType.FREE_TRIAL, 0, 1000))
    }

    @Test
    fun nonPositivePrice_yieldsZeroDiscount() {
        assertEquals(0, PromoCodeMath.discountCents(DiscountType.PERCENTAGE, 25, 0))
        assertEquals(0, PromoCodeMath.discountCents(DiscountType.FIXED_AMOUNT, 500, -10))
        assertEquals(0, PromoCodeMath.finalPriceCents(DiscountType.PERCENTAGE, 25, 0))
    }

    // ---- eligibility gates ----

    @Test
    fun eligible_happyPath_null() {
        assertNull(PromoCodeMath.ineligibility(promo(), "shop", 5000, now))
    }

    @Test
    fun inactive_isRejected() {
        assertEquals(
            PromoCodeMath.Ineligibility.INACTIVE,
            PromoCodeMath.ineligibility(promo(active = false), "shop", 5000, now),
        )
    }

    @Test
    fun expired_isRejected_butFutureExpiryOk() {
        assertEquals(
            PromoCodeMath.Ineligibility.EXPIRED,
            PromoCodeMath.ineligibility(promo(expiresAtEpochSeconds = now - 1), "shop", 5000, now),
        )
        assertNull(
            PromoCodeMath.ineligibility(promo(expiresAtEpochSeconds = now + 100), "shop", 5000, now),
        )
    }

    @Test
    fun usageLimit_isRejected() {
        assertEquals(
            PromoCodeMath.Ineligibility.USAGE_LIMIT,
            PromoCodeMath.ineligibility(promo(maxUses = 10, currentUses = 10), "shop", 5000, now),
        )
    }

    @Test
    fun perUserLimit_isRejected() {
        assertEquals(
            PromoCodeMath.Ineligibility.ALREADY_USED,
            PromoCodeMath.ineligibility(promo(maxUsesPerUser = 1), "shop", 5000, now, userRedemptions = 1),
        )
    }

    @Test
    fun appliesTo_mismatch_isRejected() {
        assertEquals(
            PromoCodeMath.Ineligibility.NOT_APPLICABLE,
            PromoCodeMath.ineligibility(promo(appliesTo = listOf("subscription")), "shop", 5000, now),
        )
    }

    @Test
    fun freeTrial_onlyForSubscription() {
        assertEquals(
            PromoCodeMath.Ineligibility.NOT_APPLICABLE,
            PromoCodeMath.ineligibility(
                promo(discountType = DiscountType.FREE_TRIAL, appliesTo = listOf("subscription", "shop")),
                "shop", 5000, now,
            ),
        )
        assertNull(
            PromoCodeMath.ineligibility(
                promo(
                    discountType = DiscountType.FREE_TRIAL,
                    freeTrialDays = 7,
                    appliesTo = listOf("subscription"),
                ),
                "subscription", 5000, now,
            ),
        )
    }

    @Test
    fun minPurchase_belowMin_isRejected() {
        assertEquals(
            PromoCodeMath.Ineligibility.BELOW_MIN,
            PromoCodeMath.ineligibility(promo(minPurchaseCents = 10000), "shop", 5000, now),
        )
        assertNull(PromoCodeMath.ineligibility(promo(minPurchaseCents = 5000), "shop", 5000, now))
    }

    // ---- full preview ----

    @Test
    fun preview_eligible_percentage() {
        val p = PromoCodeMath.preview(promo(discountValue = 20), "shop", 5000, now)
        assertTrue(p.eligible)
        assertEquals(1000, p.discountCents)
        assertEquals(4000, p.finalPriceCents)
        assertEquals(0, p.freeTrialDays)
        assertNull(p.reason)
    }

    @Test
    fun preview_ineligible_keepsOriginalPrice() {
        val p = PromoCodeMath.preview(promo(active = false), "shop", 5000, now)
        assertFalse(p.eligible)
        assertEquals(0, p.discountCents)
        assertEquals(5000, p.finalPriceCents)
        assertEquals(PromoCodeMath.Ineligibility.INACTIVE, p.reason)
    }

    @Test
    fun preview_freeTrial_surfacesTrialDays() {
        val p = PromoCodeMath.preview(
            promo(discountType = DiscountType.FREE_TRIAL, freeTrialDays = 14, appliesTo = listOf("subscription")),
            "subscription", 999, now,
        )
        assertTrue(p.eligible)
        assertEquals(999, p.discountCents)
        assertEquals(0, p.finalPriceCents)
        assertEquals(14, p.freeTrialDays)
    }
}
