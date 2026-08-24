package com.testlogon.android.feature.rewards

import com.testlogon.android.feature.rewards.RewardsCashMath.Validation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure rules for the DIRECT points->USD-cash redemption: canonical rate (100 pts = $1.00 -> 1 cent/pt),
 * $5.00 (500 pt) minimum, integer conversion both directions, and the redemption validation ladder
 * (not-positive -> below-min -> insufficient -> valid). No Android / Compose / Hilt.
 */
class RewardsCashMathTest {

    @Test
    fun canonicalRate_isOneCentPerPointAndFiveDollarMin() {
        assertEquals(1L, RewardsCashMath.CENTS_PER_POINT)
        assertEquals(500L, RewardsCashMath.MIN_REDEEM_POINTS)
        assertEquals(500L, RewardsCashMath.minRedeemCents())
    }

    @Test
    fun cashCentsForPoints_convertsAtCanonicalRate() {
        assertEquals(0L, RewardsCashMath.cashCentsForPoints(0L))
        assertEquals(500L, RewardsCashMath.cashCentsForPoints(500L))
        assertEquals(1000L, RewardsCashMath.cashCentsForPoints(1000L))
        assertEquals(1234L, RewardsCashMath.cashCentsForPoints(1234L))
    }

    @Test
    fun cashCentsForPoints_nonPositiveFloorsAtZero() {
        assertEquals(0L, RewardsCashMath.cashCentsForPoints(-1L))
        assertEquals(0L, RewardsCashMath.cashCentsForPoints(-999L))
    }

    @Test
    fun pointsForCashCents_roundsUpToCoverTarget() {
        assertEquals(0L, RewardsCashMath.pointsForCashCents(0L))
        assertEquals(500L, RewardsCashMath.pointsForCashCents(500L))   // $5.00
        assertEquals(1000L, RewardsCashMath.pointsForCashCents(1000L)) // $10.00
        assertEquals(0L, RewardsCashMath.pointsForCashCents(-5L))
    }

    @Test
    fun conversion_isInverseAtCanonicalRate() {
        val pts = 750L
        assertEquals(pts, RewardsCashMath.pointsForCashCents(RewardsCashMath.cashCentsForPoints(pts)))
    }

    @Test
    fun pointsAfterRedeem_flooredAtZero() {
        assertEquals(500L, RewardsCashMath.pointsAfterRedeem(1000L, 500L))
        assertEquals(0L, RewardsCashMath.pointsAfterRedeem(500L, 500L))
        assertEquals(0L, RewardsCashMath.pointsAfterRedeem(100L, 500L)) // never negative
    }

    @Test
    fun validate_notPositive() {
        assertEquals(Validation.NOT_POSITIVE, RewardsCashMath.validatePointsRedemption(0L, 10_000L))
        assertEquals(Validation.NOT_POSITIVE, RewardsCashMath.validatePointsRedemption(-50L, 10_000L))
    }

    @Test
    fun validate_belowMin() {
        assertEquals(Validation.BELOW_MIN, RewardsCashMath.validatePointsRedemption(1L, 10_000L))
        assertEquals(Validation.BELOW_MIN, RewardsCashMath.validatePointsRedemption(499L, 10_000L))
    }

    @Test
    fun validate_insufficientBalance() {
        assertEquals(Validation.INSUFFICIENT, RewardsCashMath.validatePointsRedemption(600L, 500L))
        assertEquals(Validation.INSUFFICIENT, RewardsCashMath.validatePointsRedemption(1L.let { 501L }, 500L))
    }

    @Test
    fun validate_valid_atMinAndAtFullBalance() {
        assertEquals(Validation.VALID, RewardsCashMath.validatePointsRedemption(500L, 500L))
        assertEquals(Validation.VALID, RewardsCashMath.validatePointsRedemption(1000L, 1000L))
        assertTrue(RewardsCashMath.canRedeem(500L, 500L))
        assertFalse(RewardsCashMath.canRedeem(499L, 500L))
    }

    @Test
    fun validate_belowMinTakesPrecedenceOverInsufficient() {
        // 300 points is both below the 500 min AND above a 200 balance; below-min is reported first.
        assertEquals(Validation.BELOW_MIN, RewardsCashMath.validatePointsRedemption(300L, 200L))
    }

    @Test
    fun maxRedeemablePoints_wholeBalanceWhenAtLeastMinElseZero() {
        assertEquals(0L, RewardsCashMath.maxRedeemablePoints(499L))
        assertEquals(500L, RewardsCashMath.maxRedeemablePoints(500L))
        assertEquals(12_345L, RewardsCashMath.maxRedeemablePoints(12_345L))
    }

    @Test
    fun rateLabel_mirrorsWebContract() {
        assertEquals("100 pts = $1.00", RewardsCashMath.rateLabel())
    }

    @Test
    fun formatting_delegatesToRewardsMath() {
        assertEquals("$5.00", RewardsCashMath.formatCentsUsd(500L))
        assertEquals("1,000 pts", RewardsCashMath.formatPoints(1000L))
    }
}
