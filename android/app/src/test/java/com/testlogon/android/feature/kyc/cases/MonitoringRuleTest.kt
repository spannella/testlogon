package com.testlogon.android.feature.kyc.cases

import com.testlogon.android.feature.kyc.cases.model.ReviewSchedule
import com.testlogon.android.feature.kyc.cases.model.TriggerEvent
import com.testlogon.android.feature.kyc.cases.model.monitoringActive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

/**
 * AND-329 - unit tests for the PURE [monitoringActive] reducer. The banner shows when the schedule status is
 * one of needs_review / grace_period / downgraded, OR when any trigger event is present. The steady "active"
 * schedule status does NOT raise the banner.
 */
class MonitoringRuleTest {

    private fun schedule(status: String) = ReviewSchedule(
        caseId = "case_1",
        status = status,
        nextReviewDate = Instant.ofEpochSecond(1_780_000_000L),
        graceDeadline = null,
        lastReviewDate = null,
    )

    private fun trigger() = TriggerEvent(
        eventId = "evt_1",
        triggerType = "periodic_review",
        caseId = "case_1",
        createdAt = Instant.ofEpochSecond(1_780_000_000L),
        note = "due",
    )

    @Test
    fun needsReview_raisesActiveBanner() {
        val state = monitoringActive(schedule("needs_review"), emptyList())
        assertTrue(state.active)
        assertEquals("needs_review", state.status)
        assertEquals("schedule:needs_review", state.message)
    }

    @Test
    fun gracePeriod_raisesActiveBanner() {
        assertTrue(monitoringActive(schedule("grace_period"), emptyList()).active)
    }

    @Test
    fun downgraded_raisesActiveBanner() {
        assertTrue(monitoringActive(schedule("downgraded"), emptyList()).active)
    }

    @Test
    fun activeStatus_doesNotRaiseBanner() {
        val state = monitoringActive(schedule("active"), emptyList())
        assertFalse(state.active)
        assertNull(state.message)
    }

    @Test
    fun triggersPresent_raiseActiveBanner_evenWhenScheduleSteady() {
        val state = monitoringActive(schedule("active"), listOf(trigger()))
        assertTrue(state.active)
        assertEquals("trigger", state.message)
        assertEquals("case_1", state.caseId)
    }

    @Test
    fun triggersPresent_withNullSchedule_raiseActiveBanner() {
        val state = monitoringActive(schedule = null, triggers = listOf(trigger()))
        assertTrue(state.active)
        assertEquals("trigger", state.message)
    }

    @Test
    fun noScheduleNoTriggers_isInactive() {
        val state = monitoringActive(schedule = null, triggers = emptyList())
        assertFalse(state.active)
    }
}
