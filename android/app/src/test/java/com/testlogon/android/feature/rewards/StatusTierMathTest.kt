package com.testlogon.android.feature.rewards

import com.testlogon.android.data.rewards.RewardsStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure JVM tests for the REWARDS STATUS / loyalty TIER math (a membership ladder driven by LIFETIME
 * reward points -- DISTINCT from the fee tiers). Mirrors the web frontend/src/lib/statusTiers.test.ts:
 * the canonical table, current-tier / next-tier / progress rules, negative/zero/top guards, the
 * multiplier label, and the authoritative-preferred / client-estimate resolution. No Android / Compose.
 */
class StatusTierMathTest {

    private fun authoritative(
        tierId: String = "gold",
        name: String = "Gold",
        lifetime: Long = 30000L,
        multiplierBps: Int = 12500,
        nextName: String? = "Platinum",
        nextThreshold: Long? = 100000L,
        perks: List<String> = listOf("25% bonus points"),
        available: Boolean = true,
    ) = RewardsStatus(
        tierId = tierId,
        name = name,
        lifetimePoints = lifetime,
        pointsMultiplierBps = multiplierBps,
        nextName = nextName,
        nextThresholdPoints = nextThreshold,
        perks = perks,
        available = available,
    )

    // ---- table integrity ----

    @Test
    fun table_hasSixAscendingTiers_matchingCanonicalThresholds() {
        val tiers = StatusTierMath.STATUS_TIERS
        assertEquals(6, tiers.size)
        assertEquals(listOf("member", "bronze", "silver", "gold", "platinum", "diamond"), tiers.map { it.id })
        assertEquals(listOf(0L, 1000L, 5000L, 25000L, 100000L, 500000L), tiers.map { it.thresholdPoints })
        assertEquals(listOf(10000, 10500, 11000, 12500, 15000, 20000), tiers.map { it.multiplierBps })
        // ascending, strictly
        val thresholds = tiers.map { it.thresholdPoints }
        assertEquals(thresholds.sorted(), thresholds)
    }

    // ---- statusTierForPoints ----

    @Test
    fun statusTierForPoints_floorTierAtZeroAndNegative() {
        assertEquals("member", StatusTierMath.statusTierForPoints(0L).id)
        assertEquals("member", StatusTierMath.statusTierForPoints(-999L).id)
        assertEquals("member", StatusTierMath.statusTierForPoints(999L).id)
    }

    @Test
    fun statusTierForPoints_exactThresholdReachesThatTier() {
        assertEquals("bronze", StatusTierMath.statusTierForPoints(1000L).id)
        assertEquals("silver", StatusTierMath.statusTierForPoints(5000L).id)
        assertEquals("gold", StatusTierMath.statusTierForPoints(25000L).id)
        assertEquals("platinum", StatusTierMath.statusTierForPoints(100000L).id)
        assertEquals("diamond", StatusTierMath.statusTierForPoints(500000L).id)
    }

    @Test
    fun statusTierForPoints_betweenThresholds_takesLowerTier() {
        assertEquals("bronze", StatusTierMath.statusTierForPoints(4999L).id)
        assertEquals("silver", StatusTierMath.statusTierForPoints(24999L).id)
        assertEquals("diamond", StatusTierMath.statusTierForPoints(999_999_999L).id)
    }

    // ---- nextStatusTier ----

    @Test
    fun nextStatusTier_returnsFollowingTier_andNullAtTop() {
        assertEquals("bronze", StatusTierMath.nextStatusTier("member")?.id)
        assertEquals("platinum", StatusTierMath.nextStatusTier("gold")?.id)
        assertNull(StatusTierMath.nextStatusTier("diamond"))
        // unknown id -> null (not a crash)
        assertNull(StatusTierMath.nextStatusTier("nonexistent"))
    }

    // ---- pointsToNextTier ----

    @Test
    fun pointsToNextTier_computesGapAndZeroAtTop() {
        // Member (0) with 250 pts -> needs 750 to Bronze (1000)
        assertEquals(750L, StatusTierMath.pointsToNextTier(250L))
        // Gold (25000) with 30000 -> needs 70000 to Platinum (100000)
        assertEquals(70000L, StatusTierMath.pointsToNextTier(30000L))
        // Diamond (top) -> 0
        assertEquals(0L, StatusTierMath.pointsToNextTier(600000L))
        // negative guarded
        assertEquals(1000L, StatusTierMath.pointsToNextTier(-5L))
    }

    // ---- progressToNextFraction ----

    @Test
    fun progressToNextFraction_boundsAndMidpoint() {
        // exactly at a threshold -> 0 progress toward the next
        assertEquals(0f, StatusTierMath.progressToNextFraction(1000L), 0.0001f)
        // halfway from Bronze(1000) to Silver(5000): span 4000, +2000 -> 0.5
        assertEquals(0.5f, StatusTierMath.progressToNextFraction(3000L), 0.0001f)
        // top tier -> 1.0
        assertEquals(1f, StatusTierMath.progressToNextFraction(500000L), 0.0001f)
        // below floor -> 0
        assertEquals(0f, StatusTierMath.progressToNextFraction(-100L), 0.0001f)
    }

    // ---- multiplierLabel ----

    @Test
    fun multiplierLabel_trimsTrailingZeros_andGuards() {
        assertEquals("1x", StatusTierMath.multiplierLabel(10000))
        assertEquals("1.05x", StatusTierMath.multiplierLabel(10500))
        assertEquals("1.1x", StatusTierMath.multiplierLabel(11000))
        assertEquals("1.25x", StatusTierMath.multiplierLabel(12500))
        assertEquals("1.5x", StatusTierMath.multiplierLabel(15000))
        assertEquals("2x", StatusTierMath.multiplierLabel(20000))
        // non-positive guards to 1x
        assertEquals("1x", StatusTierMath.multiplierLabel(0))
        assertEquals("1x", StatusTierMath.multiplierLabel(-500))
    }

    // ---- resolveStatus: client estimate ----

    @Test
    fun resolveStatus_estimate_whenNoAuthoritative() {
        val r = StatusTierMath.resolveStatus(lifetimePoints = 30000L, authoritative = null)
        assertEquals(StatusTierMath.Source.ESTIMATED, r.source)
        assertFalse(r.isAuthoritative)
        assertEquals("gold", r.tierId)
        assertEquals("Gold", r.name)
        assertEquals(12500, r.multiplierBps)
        assertEquals("Platinum", r.nextName)
        assertEquals(100000L, r.nextThreshold)
        assertEquals(70000L, r.pointsToNext)
        assertFalse(r.isTopTier)
        assertTrue(r.perks.isNotEmpty())
    }

    @Test
    fun resolveStatus_estimate_topTierHasNoNext() {
        val r = StatusTierMath.resolveStatus(lifetimePoints = 800000L, authoritative = null)
        assertEquals("diamond", r.tierId)
        assertNull(r.nextName)
        assertNull(r.nextThreshold)
        assertEquals(0L, r.pointsToNext)
        assertTrue(r.isTopTier)
        assertEquals(1f, r.progressFraction, 0.0001f)
    }

    @Test
    fun resolveStatus_estimate_whenAuthoritativeUnavailableOrZeroMultiplier() {
        val degraded = StatusTierMath.resolveStatus(6000L, RewardsStatus.unavailable())
        assertEquals(StatusTierMath.Source.ESTIMATED, degraded.source)
        assertEquals("silver", degraded.tierId)
        // available but non-positive multiplier / blank name -> falls back to client estimate
        val zeroMult = StatusTierMath.resolveStatus(6000L, authoritative(multiplierBps = 0))
        assertEquals(StatusTierMath.Source.ESTIMATED, zeroMult.source)
        val blankName = StatusTierMath.resolveStatus(6000L, authoritative(name = ""))
        assertEquals(StatusTierMath.Source.ESTIMATED, blankName.source)
    }

    // ---- resolveStatus: authoritative ----

    @Test
    fun resolveStatus_prefersAuthoritative_whenPresentAndSane() {
        // Authoritative overrides even a differing client computation from lifetime points.
        val a = authoritative(tierId = "platinum", name = "Platinum", lifetime = 120000L, multiplierBps = 15000, nextName = "Diamond", nextThreshold = 500000L, perks = listOf("Reduced fees"))
        val r = StatusTierMath.resolveStatus(lifetimePoints = 1L, authoritative = a)
        assertEquals(StatusTierMath.Source.AUTHORITATIVE, r.source)
        assertTrue(r.isAuthoritative)
        assertEquals("platinum", r.tierId)
        assertEquals("Platinum", r.name)
        assertEquals(120000L, r.lifetimePoints)
        assertEquals(15000, r.multiplierBps)
        assertEquals("Diamond", r.nextName)
        assertEquals(500000L, r.nextThreshold)
        assertEquals(380000L, r.pointsToNext)
        assertEquals(listOf("Reduced fees"), r.perks)
    }

    @Test
    fun resolveStatus_authoritative_topTierWhenNoNextTier() {
        val a = authoritative(tierId = "diamond", name = "Diamond", lifetime = 600000L, multiplierBps = 20000, nextName = null, nextThreshold = null, perks = listOf("Concierge support"))
        val r = StatusTierMath.resolveStatus(lifetimePoints = 0L, authoritative = a)
        assertEquals(StatusTierMath.Source.AUTHORITATIVE, r.source)
        assertNull(r.nextName)
        assertEquals(0L, r.pointsToNext)
        assertTrue(r.isTopTier)
    }

    @Test
    fun resolveStatus_authoritative_clampsNegativesAndFillsTierId() {
        val a = authoritative(tierId = "", name = "Gold", lifetime = -50L, multiplierBps = 12500, nextName = "Platinum", nextThreshold = -1L)
        val r = StatusTierMath.resolveStatus(lifetimePoints = 0L, authoritative = a)
        assertEquals(0L, r.lifetimePoints)
        // tierId back-filled from clamped lifetime points (0 -> member)
        assertEquals("member", r.tierId)
        // next threshold clamped to 0 -> pointsToNext 0
        assertNotNull(r.nextName)
        assertEquals(0L, r.pointsToNext)
    }
}
