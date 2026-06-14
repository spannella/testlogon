package com.testlogon.android.data.broadcast.tips

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-282 — pure goal progress math + DTO->domain mapping (no Android/coroutines). */
class TipsDomainTest {

    @Test
    fun fraction_clampsAndComputesPercent() {
        val goal = Goal("g1", "s1", "mic", currentCents = 125000, targetCents = 200000, false, null, 0)
        assertEquals(0.625f, goal.fraction, 0.0001f)
        assertEquals(62, goal.percent)
    }

    @Test
    fun fraction_zeroTarget_isZero() {
        val goal = Goal("g1", "s1", "mic", currentCents = 500, targetCents = 0, false, null, 0)
        assertEquals(0f, goal.fraction, 0.0001f)
        assertEquals(0, goal.percent)
    }

    @Test
    fun fraction_overshoot_clampsToOne() {
        val goal = Goal("g1", "s1", "mic", currentCents = 300000, targetCents = 200000, false, null, 0)
        assertEquals(1f, goal.fraction, 0.0001f)
        assertEquals(100, goal.percent)
    }

    @Test
    fun isReached_prefersServerFlag_thenFallsBackToComparison() {
        val serverReached = Goal("g1", "s1", "mic", 0, 200000, reached = true, null, 0)
        assertTrue(serverReached.isReached)
        val localReached = Goal("g1", "s1", "mic", 200000, 200000, reached = false, null, 0)
        assertTrue(localReached.isReached)
        val notReached = Goal("g1", "s1", "mic", 100000, 200000, reached = false, null, 0)
        assertFalse(notReached.isReached)
    }

    @Test
    fun goalsList_sortsBySortOrderThenCreatedAt() {
        val dto = TipGoalsListDto(
            sessionId = "s1",
            goals = listOf(
                TipGoalDto("g2", "s1", "b", targetCents = 100, sortOrder = 1, createdAt = 5),
                TipGoalDto("g1", "s1", "a", targetCents = 100, sortOrder = 0, createdAt = 9),
                TipGoalDto("g3", "s1", "c", targetCents = 100, sortOrder = 0, createdAt = 2),
            ),
        )
        val ordered = dto.toDomain().map { it.goalId }
        assertEquals(listOf("g3", "g1", "g2"), ordered)
    }

    @Test
    fun summary_mapsCentsAndDefaultsCurrency() {
        val summary = TipSummaryDto(sessionId = "s1", totalCents = 999, tipCount = 3, currency = "").toDomain()
        assertEquals(999L, summary.totalCents)
        assertEquals("USD", summary.currency)
    }
}
