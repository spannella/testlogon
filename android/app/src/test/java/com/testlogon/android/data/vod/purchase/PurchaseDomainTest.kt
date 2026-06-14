package com.testlogon.android.data.vod.purchase

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-193 — pure purchase domain (entitlement status derivation + offer tier construction). */
class PurchaseDomainTest {

    @Test
    fun purchaseTypeOption_fromWire() {
        assertEquals(PurchaseTypeOption.PERMANENT, PurchaseTypeOption.fromWire("permanent"))
        assertEquals(PurchaseTypeOption.RENTAL, PurchaseTypeOption.fromWire("rental"))
        assertEquals(PurchaseTypeOption.UNKNOWN, PurchaseTypeOption.fromWire("bogus"))
        assertEquals(PurchaseTypeOption.UNKNOWN, PurchaseTypeOption.fromWire(null))
    }

    @Test
    fun offer_tiers_includeDefaultPlusPermanentAndViewOnce_dedup() {
        val offer = VodAccessOutDto(
            entitled = false, purchaseAvailable = true, priceCents = 1499,
            purchaseType = "permanent", reason = "not_purchased",
        ).toOffer()
        val types = offer.tiers().map { it.type }
        assertTrue(types.contains(PurchaseTypeOption.PERMANENT))
        assertTrue(types.contains(PurchaseTypeOption.VIEW_ONCE))
        // permanent default is not duplicated
        assertEquals(types.size, types.toSet().size)
        assertEquals(1499L, offer.tiers().first().priceCents)
    }

    @Test
    fun entitlement_active_whenNoExpiryAndUnlimitedViews() {
        val e = VodPurchaseOutDto(
            videoId = "v1", alreadyOwned = false, grantedAt = 100L, grantType = "purchase",
            amountCents = 1499, purchaseType = "permanent", viewsRemaining = -1, expiresAt = null,
        ).toEntitlement()
        assertEquals(EntitlementStatus.ACTIVE, e.statusAt(1_000L))
        assertTrue(e.isUnlockedAt(1_000L))
    }

    @Test
    fun entitlement_expired_pastExpiry() {
        val e = VodPurchaseOutDto(
            videoId = "v1", alreadyOwned = false, grantedAt = 100L, grantType = "purchase",
            amountCents = 399, purchaseType = "rental", viewsRemaining = -1, expiresAt = 500L,
        ).toEntitlement()
        assertEquals(EntitlementStatus.EXPIRED, e.statusAt(600L))
        assertFalse(e.isUnlockedAt(600L))
    }

    @Test
    fun entitlement_consumed_whenZeroViews() {
        val e = VodPurchaseOutDto(
            videoId = "v1", alreadyOwned = false, grantedAt = 100L, grantType = "purchase",
            amountCents = 399, purchaseType = "view_once", viewsRemaining = 0, expiresAt = null,
        ).toEntitlement()
        assertEquals(EntitlementStatus.CONSUMED, e.statusAt(200L))
        assertFalse(e.isUnlockedAt(200L))
    }
}
