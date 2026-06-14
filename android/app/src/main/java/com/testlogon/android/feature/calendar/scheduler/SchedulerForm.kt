package com.testlogon.android.feature.calendar.scheduler

import java.time.Instant

/**
 * AND-275 — scheduler form model + pure validation.
 *
 * Realigned to the verified ScheduledActionCreateIn/UpdateIn shapes: actionType, scheduledAt (epoch
 * seconds on the wire), title, description, payload, notifyBeforeSeconds. NO recurrence/timezone/
 * content_ref/edit-scope (those are the separate calendar Events API).
 */
data class SchedulerForm(
    val actionType: String? = null,
    val scheduledAt: Instant? = null,
    val title: String = "",
    val description: String = "",
    val payload: Map<String, Any?> = emptyMap(),
    val notifyBeforeSeconds: Int = 0,
)

/** The fields the validator / 422 mapping can flag inline. */
enum class SchedulerField { ActionType, ScheduledAt, Title, NotifyBeforeSeconds }

sealed interface SchedulerMode {
    data object Create : SchedulerMode
    data class Edit(val actionId: String) : SchedulerMode
}

/**
 * AND-275 — PURE, JVM-unit-testable validation. Empty map == valid.
 *
 * Rules (FR-4): an action_type is required; scheduled_at is required and must be strictly in the future
 * by more than [GRACE_SECONDS] (a 60-second grace); notify-before must be non-negative.
 */
object SchedulerValidator {

    const val GRACE_SECONDS = 60L

    fun validate(form: SchedulerForm, now: Instant): Map<SchedulerField, String> {
        val errors = LinkedHashMap<SchedulerField, String>()
        if (form.actionType.isNullOrBlank()) {
            errors[SchedulerField.ActionType] = "Choose an action type"
        }
        val at = form.scheduledAt
        if (at == null) {
            errors[SchedulerField.ScheduledAt] = "Choose a date and time"
        } else if (at.epochSecond <= now.epochSecond + GRACE_SECONDS) {
            errors[SchedulerField.ScheduledAt] = "Pick a time in the future"
        }
        if (form.notifyBeforeSeconds < 0) {
            errors[SchedulerField.NotifyBeforeSeconds] = "Reminder time can't be negative"
        }
        return errors
    }
}
