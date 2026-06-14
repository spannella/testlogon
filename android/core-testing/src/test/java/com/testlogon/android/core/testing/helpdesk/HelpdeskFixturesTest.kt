package com.testlogon.android.core.testing.helpdesk

import com.testlogon.android.core.model.helpdesk.Availability
import com.testlogon.android.core.model.helpdesk.heartbeatStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-381 - self-test for the shared [HelpdeskFixtures] (spec AC-11 / FR-5): proves the consolidated
 * core-model-only helpdesk fixtures build the domain shapes the E49 suites need, and double as the
 * FR-2 round-trip-vs-builder assertions for [com.testlogon.android.core.model.helpdesk.HelpdeskMetrics]
 * (the all-zero EMPTY case, the time-metrics-null vs time-metrics-present cases, and an UNKNOWN
 * `deltas` key the consumer must tolerate without throwing).
 */
class HelpdeskFixturesTest {

    @Test
    fun populatedMetrics_isNotEmpty_andCarriesCounts() {
        val m = HelpdeskFixtures.metrics()
        assertEquals(5, m.openCount)
        assertEquals(2, m.unassignedCount)
        assertEquals(1, m.assignedToMeCount)
        assertEquals(1, m.slaAtRiskCount)
        assertEquals(HelpdeskFixtures.GENERATED_AT_EPOCH_SECONDS, m.generatedAtEpochSeconds)
        assertFalse(m.isEmpty)
    }

    @Test
    fun emptyMetrics_satisfiesIsEmptyContract() {
        val m = HelpdeskFixtures.emptyMetrics()
        assertEquals(0, m.openCount)
        assertEquals(0, m.unassignedCount)
        assertEquals(0, m.assignedToMeCount)
        assertEquals(0, m.slaAtRiskCount)
        assertEquals(null, m.avgFirstResponseSeconds)
        assertEquals(null, m.avgResolutionSeconds)
        assertEquals(null, m.resolvedByMeToday)
        assertTrue(m.deltas.isEmpty())
        assertTrue(m.isEmpty)
    }

    @Test
    fun timeMetrics_null_byDefault_butPopulatedFixtureCarriesThem() {
        // Default builder leaves the optional time/throughput metrics null (no client source, section 16).
        val plain = HelpdeskFixtures.metrics()
        assertEquals(null, plain.avgFirstResponseSeconds)
        assertEquals(null, plain.avgResolutionSeconds)
        assertEquals(null, plain.resolvedByMeToday)

        // The rich fixture carries them (a server-backed metrics source would).
        val rich = HelpdeskFixtures.metricsWithTimeAndDeltas()
        assertEquals(540L, rich.avgFirstResponseSeconds)
        assertEquals(7_200L, rich.avgResolutionSeconds)
        assertEquals(11, rich.resolvedByMeToday)
        assertFalse(rich.isEmpty)
    }

    @Test
    fun deltas_tolerateUnknownKey_withoutThrowing() {
        // FR-2: an unrecognized delta key must be tolerated as a plain map entry, never a throw.
        val deltas = HelpdeskFixtures.metricsWithTimeAndDeltas().deltas
        assertEquals(-4, deltas["open"])
        assertEquals(2, deltas["unassigned"])
        assertEquals(99, deltas["teleporting_metric"]) // forward-compat key preserved verbatim
        assertEquals(null, deltas["not_present"])
    }

    @Test
    fun availabilityRoster_coversBothStates_withHeartbeatVocabulary() {
        val roster = HelpdeskFixtures.availabilityRoster()
        assertEquals(listOf(Availability.ONLINE, Availability.AWAY), roster)
        assertEquals("available", Availability.ONLINE.heartbeatStatus())
        assertEquals("away", Availability.AWAY.heartbeatStatus())
    }

    @Test
    fun availabilityState_defaultsToAway() {
        assertEquals(Availability.AWAY, HelpdeskFixtures.availabilityState().availability)
        assertEquals(Availability.ONLINE, HelpdeskFixtures.availabilityState(Availability.ONLINE).availability)
    }
}
