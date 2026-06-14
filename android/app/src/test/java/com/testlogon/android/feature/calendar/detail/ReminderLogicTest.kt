package com.testlogon.android.feature.calendar.detail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

/**
 * AND-276 — pure reminder logic tests (JVM). Trigger computation (start - lead), the past-event /
 * unknown-start guard, and preset <-> minutes resolution.
 */
class ReminderLogicTest {

    private val start = Instant.parse("2026-06-10T15:00:00Z").toEpochMilli()

    @Test
    fun trigger_atStart_equalsStart() {
        assertEquals(start, ReminderLogic.triggerEpochMillis(start, ReminderLogic.Lead.AT_START))
    }

    @Test
    fun trigger_subtractsLead() {
        assertEquals(
            start - 30 * 60_000L,
            ReminderLogic.triggerEpochMillis(start, ReminderLogic.Lead.THIRTY_MIN),
        )
        assertEquals(
            start - 24 * 60 * 60_000L,
            ReminderLogic.triggerEpochMillis(start, ReminderLogic.Lead.ONE_DAY),
        )
    }

    @Test
    fun canSchedule_onlyFutureWithKnownStart() {
        val now = Instant.parse("2026-06-10T12:00:00Z").toEpochMilli()
        assertTrue(ReminderLogic.canSchedule(start, now))
        // Past event.
        assertFalse(ReminderLogic.canSchedule(start, Instant.parse("2026-06-10T16:00:00Z").toEpochMilli()))
        // Exactly now is not strictly future.
        assertFalse(ReminderLogic.canSchedule(start, start))
        // No known start (e.g. all-day with no instant).
        assertFalse(ReminderLogic.canSchedule(null, now))
    }

    @Test
    fun leadFromMinutes_resolvesPresets_andFallsBackToDefault() {
        assertEquals(ReminderLogic.Lead.FIFTEEN_MIN, ReminderLogic.leadFromMinutes(15))
        assertEquals(ReminderLogic.Lead.ONE_HOUR, ReminderLogic.leadFromMinutes(60))
        assertEquals(ReminderLogic.Lead.AT_START, ReminderLogic.leadFromMinutes(0))
        // Unknown minute count falls back to the default.
        assertEquals(ReminderLogic.DEFAULT_LEAD, ReminderLogic.leadFromMinutes(7))
        assertEquals(ReminderLogic.DEFAULT_LEAD, ReminderLogic.leadFromMinutes(null))
    }
}
