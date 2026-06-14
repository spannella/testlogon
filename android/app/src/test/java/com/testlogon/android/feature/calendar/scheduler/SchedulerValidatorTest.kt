package com.testlogon.android.feature.calendar.scheduler

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

/** AND-275 — pure validator tests (future-time grace, required fields, all-valid path). */
class SchedulerValidatorTest {

    private val now = Instant.ofEpochSecond(1_000_000L)

    @Test
    fun missingType_flagsActionType() {
        val errors = SchedulerValidator.validate(
            SchedulerForm(scheduledAt = now.plusSeconds(3600)), now,
        )
        assertTrue(errors.containsKey(SchedulerField.ActionType))
    }

    @Test
    fun pastTime_withinGrace_flagsScheduledAt() {
        val withinGrace = SchedulerForm(actionType = "post", scheduledAt = now.plusSeconds(30))
        assertTrue(SchedulerValidator.validate(withinGrace, now).containsKey(SchedulerField.ScheduledAt))

        val nullTime = SchedulerForm(actionType = "post", scheduledAt = null)
        assertTrue(SchedulerValidator.validate(nullTime, now).containsKey(SchedulerField.ScheduledAt))
    }

    @Test
    fun futureBeyondGrace_validType_isValid() {
        val form = SchedulerForm(actionType = "post", scheduledAt = now.plusSeconds(3600))
        assertEquals(emptyMap<SchedulerField, String>(), SchedulerValidator.validate(form, now))
    }

    @Test
    fun negativeNotify_flagged() {
        val form = SchedulerForm(
            actionType = "post",
            scheduledAt = now.plusSeconds(3600),
            notifyBeforeSeconds = -1,
        )
        assertTrue(SchedulerValidator.validate(form, now).containsKey(SchedulerField.NotifyBeforeSeconds))
    }
}
