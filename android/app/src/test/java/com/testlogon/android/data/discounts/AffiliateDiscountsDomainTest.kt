package com.testlogon.android.data.discounts

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-267/269 — pure JVM tests for the best-effort [deriveKind] heuristic and the [AffiliateDiscount]
 * derived accessors (displayCode / shareText). No Android types, no network.
 */
class AffiliateDiscountsDomainTest {

    @Test
    fun deriveKind_percent() {
        assertEquals(DiscountKind.PERCENT, deriveKind("20% OFF"))
        assertEquals(DiscountKind.PERCENT, deriveKind("Save 15 percent"))
    }

    @Test
    fun deriveKind_fixed() {
        assertEquals(DiscountKind.FIXED, deriveKind("$5 OFF"))
        assertEquals(DiscountKind.FIXED, deriveKind("10 USD off"))
    }

    @Test
    fun deriveKind_freeTrial() {
        assertEquals(DiscountKind.FREE_TRIAL, deriveKind("FREE TRIAL"))
        assertEquals(DiscountKind.FREE_TRIAL, deriveKind("14-day free trial"))
    }

    @Test
    fun deriveKind_unknown_neverThrows() {
        assertEquals(DiscountKind.UNKNOWN, deriveKind("BOGO"))
        assertEquals(DiscountKind.UNKNOWN, deriveKind(null))
        assertEquals(DiscountKind.UNKNOWN, deriveKind(""))
        assertEquals(DiscountKind.UNKNOWN, deriveKind("   "))
    }

    @Test
    fun derivedKind_readsFromPromoValueDisplay() {
        assertEquals(DiscountKind.PERCENT, sampleDiscount(promoValueDisplay = "25% OFF").derivedKind)
        assertEquals(DiscountKind.UNKNOWN, sampleDiscount(promoValueDisplay = null).derivedKind)
    }

    @Test
    fun displayCode_prefersPromoCode_thenAffiliateCode_elseNull() {
        assertEquals("PROMO", sampleDiscount(promoCode = "PROMO", affiliateCode = "AFF").displayCode)
        assertEquals("AFF", sampleDiscount(promoCode = null, affiliateCode = "AFF").displayCode)
        assertEquals("AFF", sampleDiscount(promoCode = "  ", affiliateCode = "AFF").displayCode)
        assertNull(sampleDiscount(promoCode = null, affiliateCode = null).displayCode)
    }

    @Test
    fun shareText_prefersClickThroughUrl_elseCode_elseNull() {
        assertEquals(
            "https://x.test/sale",
            sampleDiscount(clickThroughUrl = "https://x.test/sale", promoCode = "P").shareText(),
        )
        assertEquals("P", sampleDiscount(clickThroughUrl = null, promoCode = "P").shareText())
        assertNull(sampleDiscount(clickThroughUrl = null, promoCode = null, affiliateCode = null).shareText())
    }

    private fun sampleDiscount(
        creativeId: String = "cr_1",
        affiliateCode: String? = "AFF",
        promoCode: String? = "PROMO",
        promoValueDisplay: String? = "20% OFF",
        clickThroughUrl: String? = "https://x.test/sale",
    ) = AffiliateDiscount(
        creativeId = creativeId,
        campaignId = "cmp_1",
        ownerSub = "usr_a",
        affiliateCode = affiliateCode,
        promoCode = promoCode,
        promoValueDisplay = promoValueDisplay,
        clickThroughUrl = clickThroughUrl,
        clickCount = 1,
        redemptionCount = 0,
        createdAtEpochSeconds = 0,
        updatedAtEpochSeconds = 0,
    )
}
