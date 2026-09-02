package com.testlogon.android.data.adminfraud

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * FIN-015 - JVM unit tests for the PURE [FraudMath] logic (no Android / Moshi types). Covers score
 * clamping + bucketing (band boundaries), bucket labels, case-status normalization (unknown-safe),
 * case-resolvable + flag-reviewable gating, and freeze / unfreeze applicability.
 */
class FraudMathTest {

    @Test
    fun clampScore_boundsIntoValidRange() {
        assertEquals(0, FraudMath.clampScore(-10))
        assertEquals(0, FraudMath.clampScore(0))
        assertEquals(100, FraudMath.clampScore(100))
        assertEquals(100, FraudMath.clampScore(250))
        assertEquals(37, FraudMath.clampScore(37))
    }

    @Test
    fun bucket_mapsBandsAtBoundaries() {
        assertEquals(FraudMath.RiskBucket.LOW, FraudMath.bucket(0))
        assertEquals(FraudMath.RiskBucket.LOW, FraudMath.bucket(24))
        assertEquals(FraudMath.RiskBucket.MEDIUM, FraudMath.bucket(25))
        assertEquals(FraudMath.RiskBucket.MEDIUM, FraudMath.bucket(49))
        assertEquals(FraudMath.RiskBucket.HIGH, FraudMath.bucket(50))
        assertEquals(FraudMath.RiskBucket.HIGH, FraudMath.bucket(79))
        assertEquals(FraudMath.RiskBucket.CRITICAL, FraudMath.bucket(80))
        assertEquals(FraudMath.RiskBucket.CRITICAL, FraudMath.bucket(100))
    }

    @Test
    fun bucket_clampsOutOfRangeBeforeBanding() {
        assertEquals(FraudMath.RiskBucket.LOW, FraudMath.bucket(-5))
        assertEquals(FraudMath.RiskBucket.CRITICAL, FraudMath.bucket(999))
    }

    @Test
    fun bucketLabel_isStable() {
        assertEquals("Low", FraudMath.bucketLabel(FraudMath.RiskBucket.LOW))
        assertEquals("Medium", FraudMath.bucketLabel(FraudMath.RiskBucket.MEDIUM))
        assertEquals("High", FraudMath.bucketLabel(FraudMath.RiskBucket.HIGH))
        assertEquals("Critical", FraudMath.bucketLabel(FraudMath.RiskBucket.CRITICAL))
    }

    @Test
    fun scoreLabel_combinesBucketAndLabel() {
        assertEquals("Low", FraudMath.scoreLabel(10))
        assertEquals("Critical", FraudMath.scoreLabel(95))
    }

    @Test
    fun caseState_normalizesKnownTokens() {
        assertEquals(FraudMath.CaseState.OPEN, FraudMath.caseState("open"))
        assertEquals(FraudMath.CaseState.OPEN, FraudMath.caseState("  OPEN "))
        assertEquals(FraudMath.CaseState.INVESTIGATING, FraudMath.caseState("investigating"))
        assertEquals(FraudMath.CaseState.INVESTIGATING, FraudMath.caseState("in_progress"))
        assertEquals(FraudMath.CaseState.RESOLVED, FraudMath.caseState("resolved"))
        assertEquals(FraudMath.CaseState.RESOLVED, FraudMath.caseState("closed"))
    }

    @Test
    fun caseState_unknownAndBlankAreUnknown() {
        assertEquals(FraudMath.CaseState.UNKNOWN, FraudMath.caseState(null))
        assertEquals(FraudMath.CaseState.UNKNOWN, FraudMath.caseState(""))
        assertEquals(FraudMath.CaseState.UNKNOWN, FraudMath.caseState("weird_token"))
    }

    @Test
    fun isCaseResolvable_openWithoutTimestamp() {
        assertTrue(FraudMath.isCaseResolvable("open", null))
        assertTrue(FraudMath.isCaseResolvable("investigating", 0L))
    }

    @Test
    fun isCaseResolvable_falseWhenResolvedOrTimestamped() {
        assertFalse(FraudMath.isCaseResolvable("resolved", null))
        assertFalse(FraudMath.isCaseResolvable("open", 1_700_000_000L))
        assertFalse(FraudMath.isCaseResolvable("unknown_token", null))
    }

    @Test
    fun isFlagReviewable_onlyPending() {
        assertTrue(FraudMath.isFlagReviewable("pending"))
        assertTrue(FraudMath.isFlagReviewable("PENDING"))
        assertFalse(FraudMath.isFlagReviewable("approved"))
        assertFalse(FraudMath.isFlagReviewable("blocked"))
        assertFalse(FraudMath.isFlagReviewable(null))
    }

    @Test
    fun freezeGating_isComplementary() {
        assertTrue(FraudMath.canFreeze(false))
        assertFalse(FraudMath.canFreeze(true))
        assertTrue(FraudMath.canUnfreeze(true))
        assertFalse(FraudMath.canUnfreeze(false))
    }

    @Test
    fun thresholds_areOrdered() {
        assertTrue(FraudMath.MEDIUM_MIN < FraudMath.HIGH_MIN)
        assertTrue(FraudMath.HIGH_MIN < FraudMath.CRITICAL_MIN)
    }
}
