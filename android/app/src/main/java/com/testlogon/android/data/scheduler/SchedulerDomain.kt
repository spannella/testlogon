package com.testlogon.android.data.scheduler

import java.time.Instant

/**
 * AND-275 — scheduler-actions domain model (DTO-free).
 *
 * Mirrors the verified contract (reference openapi.index.txt lines 1834-1838: /ui/scheduler/actions
 * family; schema ScheduledActionOut; src/api/endpoints/scheduler.ts). KEY FACTS:
 *  - the model is an ACTION keyed by `action_type` + `scheduled_at` (epoch-SECONDS integer).
 *  - timestamps (scheduled_at/created_at/updated_at/completed_at) are epoch-SECONDS integers, NOT ISO
 *    strings -> modeled as [Instant], converted via Instant.ofEpochSecond.
 *  - there is NO recurrence, time zone, content_ref, or edit-scope (those are the separate calendar
 *    Events API). `action_type` is immutable after create (absent from the update schema).
 *  - action types: post|file_share|catalog_sale|message|broadcast (web SchedulerPage TYPE_LABELS).
 *  - statuses: pending|executing|completed|failed|cancelled.
 */
data class ScheduledAction(
    val actionId: String,
    val actionType: String,
    val status: String,
    val scheduledAt: Instant,
    val createdAt: Instant?,
    val updatedAt: Instant? = null,
    val completedAt: Instant? = null,
    val title: String = "",
    val description: String = "",
    val payload: Map<String, Any?> = emptyMap(),
    val error: String? = null,
    val retryCount: Int = 0,
    val maxRetries: Int = 0,
    val notifyBeforeSeconds: Int = 0,
    val reminderSent: Boolean = false,
)

/** The verified action-type vocabulary (web SchedulerPage TYPE_LABELS). */
object ActionTypes {
    const val POST = "post"
    const val FILE_SHARE = "file_share"
    const val CATALOG_SALE = "catalog_sale"
    const val MESSAGE = "message"
    const val BROADCAST = "broadcast"

    val ALL: List<String> = listOf(POST, FILE_SHARE, CATALOG_SALE, MESSAGE, BROADCAST)
}

/** Action statuses; "cancel" is offered only while pending (web guard). */
object ActionStatuses {
    const val PENDING = "pending"
    const val EXECUTING = "executing"
    const val COMPLETED = "completed"
    const val FAILED = "failed"
    const val CANCELLED = "cancelled"
}
