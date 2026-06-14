package com.testlogon.android.data.vod.rental

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-192 — pure rental expiry / countdown / gating logic (TC-AND-192-03/04/05). JVM, no Android.
 */
class RentalDomainTest {

    private fun access(
        active: Boolean = true,
        expiresAt: Long? = null,
        remainingSeconds: Long = 0L,
        viewsRemaining: Int = -1,
    ) = RentalAccess(
        active = active, tier = "rental", reason = null, expiresAt = expiresAt,
        remainingSeconds = remainingSeconds, viewsRemaining = viewsRemaining,
        rentalId = "r1", started = true,
    )

    @Test
    fun gating_activeWindowOpen_unlimitedViews_isActive() {
        assertTrue(access(active = true, expiresAt = 100L, viewsRemaining = -1).isActiveAt(10L))
    }

    @Test
    fun gating_serverInactive_isLocked() {
        assertFalse(access(active = false, expiresAt = 100L).isActiveAt(10L))
    }

    @Test
    fun gating_zeroViews_locksDespiteFutureExpiry() {
        // TC-AND-192-05: views_remaining == 0 locks even though the window is open.
        assertFalse(access(active = true, expiresAt = 86_400L, viewsRemaining = 0).isActiveAt(10L))
    }

    @Test
    fun gating_pastExpiry_isLocked() {
        assertFalse(access(active = true, expiresAt = 5L).isActiveAt(10L))
    }

    @Test
    fun gating_nullExpiry_neverExpiresOnTime() {
        assertTrue(access(active = true, expiresAt = null, viewsRemaining = -1).isActiveAt(1_000L))
    }

    @Test
    fun remaining_anchorsOnAbsoluteExpiry() {
        assertEquals(90L, access(expiresAt = 100L).remainingAt(nowSeconds = 10L, anchorSeconds = 0L))
    }

    @Test
    fun remaining_anchorsOnRemainingSecondsWhenNoExpiry() {
        // remaining=60 at anchor=0; at now=20 -> 40 left.
        assertEquals(40L, access(expiresAt = null, remainingSeconds = 60L).remainingAt(20L, 0L))
    }

    @Test
    fun remaining_neverNegative() {
        assertEquals(0L, access(expiresAt = 5L).remainingAt(nowSeconds = 99L, anchorSeconds = 0L))
    }

    @Test
    fun countdown_labelUnderOneDay() {
        assertEquals("02:14:09", RentalCountdown.label(2 * 3600L + 14 * 60L + 9L))
    }

    @Test
    fun countdown_labelOverOneDay() {
        assertEquals("1d 03:00:00", RentalCountdown.label(86_400L + 3 * 3600L))
    }

    @Test
    fun countdown_clampsNegative() {
        assertEquals("00:00:00", RentalCountdown.label(-5L))
    }

    @Test
    fun countdown_a11yNaturalLanguage() {
        assertEquals("2 hours 14 minutes", RentalCountdown.accessibilityLabel(2 * 3600L + 14 * 60L))
        assertEquals("1 hour 1 minute", RentalCountdown.accessibilityLabel(3600L + 60L))
        assertEquals("expired", RentalCountdown.accessibilityLabel(0L))
    }
}
