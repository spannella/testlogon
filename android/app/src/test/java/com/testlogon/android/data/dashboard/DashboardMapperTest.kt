package com.testlogon.android.data.dashboard

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-065 — mapper totality, epoch conversion, and warnings. */
class DashboardMapperTest {

    @Test
    fun happyPath_mapsAllFields() {
        val dto = DashboardSummaryDto(
            todayEarningsCents = 100,
            earningsBreakdown = DashboardEarningsBreakdownDto(subscriptions = 1, tips = 2, unlocks = 3, vodPurchases = 4, other = 5),
            periodViews = 10,
            periodRevenueCents = 20,
            totalSubscribers = 30,
            topContent = listOf(DashboardTopContentItemDto("c", "video", "T", 7, 8)),
            activeBroadcasts = listOf(DashboardActiveBroadcastDto("s", "live", "Show", "2026-06-05T12:00:00Z")),
            recentMilestones = listOf(DashboardMilestoneDto("m", "u", "subs", 100, 101, "fmt", 1748952000, false)),
            currency = "EUR",
            generatedAt = 1749126600,
            warnings = listOf("a"),
        )
        val d = dto.toDomain()
        assertEquals(100L, d.todayEarningsCents)
        assertEquals(5L, d.earningsBreakdown.other)
        assertEquals("video", d.topContent.single().contentType)
        // 2026-06-05T12:00:00Z = 1780660800 s = 1780660800000 ms.
        assertEquals(1780660800000L, d.activeBroadcasts.single().startedAtMillis)
        assertEquals(1748952000L * 1000L, d.recentMilestones.single().achievedAtMillis)
        assertEquals("EUR", d.currency)
        assertEquals(1749126600L * 1000L, d.generatedAtMillis)
        assertEquals(listOf("a"), d.warnings)
    }

    @Test
    fun totality_nullsAndUnparseable_doNotThrow() {
        val dto = DashboardSummaryDto(
            generatedAt = null,
            activeBroadcasts = listOf(DashboardActiveBroadcastDto("s", "live", null, "not-a-date")),
            recentMilestones = listOf(DashboardMilestoneDto(achievedAt = null)),
        )
        val d = dto.toDomain()
        assertNull(d.generatedAtMillis)
        assertNull(d.activeBroadcasts.single().startedAtMillis)
        assertNull(d.recentMilestones.single().achievedAtMillis)
    }

    @Test
    fun absentCollections_defaultEmpty() {
        val d = DashboardSummaryDto().toDomain()
        assertTrue(d.topContent.isEmpty())
        assertTrue(d.activeBroadcasts.isEmpty())
        assertTrue(d.recentMilestones.isEmpty())
        assertTrue(d.warnings.isEmpty())
    }

    @Test
    fun warnings_preserved() {
        val d = DashboardSummaryDto(warnings = listOf("Source X unavailable")).toDomain()
        assertEquals(listOf("Source X unavailable"), d.warnings)
    }

    @Test
    fun isEmpty_trueWhenAllZeroAndEmpty() {
        assertTrue(DashboardSummaryDto().toDomain().isEmpty)
    }

    @Test
    fun isEmpty_falseWhenMetricNonZero() {
        assertTrue(!DashboardSummaryDto(totalSubscribers = 1).toDomain().isEmpty)
    }
}
