package com.testlogon.android.data.scheduler

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-275 — Moshi DTOs for the scheduler-actions contract, verified against
 * openapi.pretty.json (ScheduledActionOut / ScheduledActionCreateIn / ScheduledActionUpdateIn /
 * ScheduledActionListOut) and src/api/endpoints/scheduler.ts.
 *
 * Timestamps are epoch-SECONDS integers (Long), NOT ISO strings. `payload` is an open object
 * (additionalProperties: true) treated as opaque pass-through.
 */
@JsonClass(generateAdapter = true)
data class ScheduledActionOutDto(
    @Json(name = "action_id") val actionId: String,
    @Json(name = "action_type") val actionType: String,
    val status: String,
    @Json(name = "scheduled_at") val scheduledAt: Long,
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "updated_at") val updatedAt: Long? = null,
    @Json(name = "completed_at") val completedAt: Long? = null,
    val title: String = "",
    val description: String = "",
    val payload: Map<String, Any?> = emptyMap(),
    val error: String? = null,
    @Json(name = "retry_count") val retryCount: Int = 0,
    @Json(name = "max_retries") val maxRetries: Int = 0,
    @Json(name = "notify_before_seconds") val notifyBeforeSeconds: Int = 0,
    @Json(name = "reminder_sent") val reminderSent: Boolean = false,
)

/** POST /ui/scheduler/actions body. required: action_type, scheduled_at. */
@JsonClass(generateAdapter = true)
data class ScheduledActionCreateInDto(
    @Json(name = "action_type") val actionType: String,
    @Json(name = "scheduled_at") val scheduledAt: Long,
    val title: String? = null,
    val description: String? = null,
    val payload: Map<String, Any?>? = null,
    @Json(name = "notify_before_seconds") val notifyBeforeSeconds: Int? = null,
)

/** PATCH /ui/scheduler/actions/{id} body. All fields optional/nullable (partial update). No action_type. */
@JsonClass(generateAdapter = true)
data class ScheduledActionUpdateInDto(
    @Json(name = "scheduled_at") val scheduledAt: Long? = null,
    val title: String? = null,
    val description: String? = null,
    val payload: Map<String, Any?>? = null,
    @Json(name = "notify_before_seconds") val notifyBeforeSeconds: Int? = null,
)

/** GET /ui/scheduler/actions -> ScheduledActionListOut {actions, cursor}. */
@JsonClass(generateAdapter = true)
data class ScheduledActionListOutDto(
    val actions: List<ScheduledActionOutDto> = emptyList(),
    val cursor: String? = null,
)

/** DELETE /ui/scheduler/actions/{id} -> {ok, action_id, status}. */
@JsonClass(generateAdapter = true)
data class ScheduledActionDeleteOutDto(
    val ok: Boolean = false,
    @Json(name = "action_id") val actionId: String? = null,
    val status: String? = null,
)
