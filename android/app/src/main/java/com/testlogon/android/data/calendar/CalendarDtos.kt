package com.testlogon.android.data.calendar

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-270 — wire DTOs for the calendar domain.
 *
 * Shapes verified against reference/src/api/types.ts and openapi.index.txt (CalendarOut / EventOut /
 * RecurrenceRule / EventsPageOut / CalendarEventAttachment / OkResp). Field names are snake_case via
 * [Json]; absent optionals fall back to Kotlin defaults (lenient decode). Timestamps stay as ISO-8601
 * strings on the wire and are parsed to Instant in [toDomain] — there is no shared Instant Moshi
 * adapter in this project (the network Moshi uses the reflective Kotlin factory), so DTOs keep strings.
 */

/** CalendarOut. */
@JsonClass(generateAdapter = true)
data class CalendarDto(
    @Json(name = "calendar_id") val calendarId: String,
    @Json(name = "name") val name: String = "",
    @Json(name = "timezone") val timezone: String = "UTC",
    @Json(name = "owner_user_id") val ownerUserId: String = "",
    @Json(name = "conflict_detection") val conflictDetection: Boolean = false,
    @Json(name = "buffer_before_minutes") val bufferBeforeMinutes: Int = 0,
    @Json(name = "buffer_after_minutes") val bufferAfterMinutes: Int = 0,
    @Json(name = "created_at_utc") val createdAtUtc: String? = null,
)

/** EventOut (authenticated single event / list element). */
@JsonClass(generateAdapter = true)
data class CalendarEventDto(
    @Json(name = "event_id") val eventId: String,
    @Json(name = "calendar_id") val calendarId: String = "",
    @Json(name = "name") val name: String = "",
    @Json(name = "description") val description: String = "",
    @Json(name = "timezone") val timezone: String = "UTC",
    @Json(name = "start_utc") val startUtc: String? = null,
    @Json(name = "end_utc") val endUtc: String? = null,
    @Json(name = "all_day") val allDay: Boolean = false,
    @Json(name = "all_day_date") val allDayDate: String? = null,
    @Json(name = "attendees") val attendees: List<String>? = null,
    @Json(name = "booking_enabled") val bookingEnabled: Boolean = false,
    @Json(name = "approval_required") val approvalRequired: Boolean = false,
    @Json(name = "status") val status: String = "",
    @Json(name = "category") val category: String? = null,
    @Json(name = "recurrence_rule") val recurrenceRule: RecurrenceRuleDto? = null,
    @Json(name = "exdates_utc") val exdatesUtc: List<String>? = null,
    @Json(name = "created_at_utc") val createdAtUtc: String? = null,
    @Json(name = "sync_state") val syncState: String? = null,
    @Json(name = "sync_conflict_reason") val syncConflictReason: String? = null,
)

/** RecurrenceRule. */
@JsonClass(generateAdapter = true)
data class RecurrenceRuleDto(
    @Json(name = "freq") val freq: String? = null,
    @Json(name = "interval") val interval: Int = 1,
    @Json(name = "until_utc") val untilUtc: String? = null,
    @Json(name = "count") val count: Int? = null,
    @Json(name = "byday") val byday: List<String>? = null,
    @Json(name = "bymonthday") val bymonthday: List<Int>? = null,
    @Json(name = "bysetpos") val bysetpos: List<Int>? = null,
)

/** EventsPageOut = { events, next_cursor? }. */
@JsonClass(generateAdapter = true)
data class EventsPageDto(
    @Json(name = "events") val events: List<CalendarEventDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

/** CalendarEventAttachment — the REDUCED public-event payload (no attendees/recurrence/etc.). */
@JsonClass(generateAdapter = true)
data class PublicEventDto(
    @Json(name = "event_id") val eventId: String,
    @Json(name = "calendar_id") val calendarId: String = "",
    @Json(name = "name") val name: String = "",
    @Json(name = "start_utc") val startUtc: String? = null,
    @Json(name = "end_utc") val endUtc: String? = null,
    @Json(name = "all_day") val allDay: Boolean = false,
    @Json(name = "all_day_date") val allDayDate: String? = null,
    @Json(name = "timezone") val timezone: String = "UTC",
    @Json(name = "description") val description: String? = null,
    @Json(name = "owner") val owner: String? = null,
)

/** EventCreateIn / EventUpdateIn (PATCH sends a partial — every field omittable so nulls are dropped). */
@JsonClass(generateAdapter = true)
data class EventCreateReqDto(
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "timezone") val timezone: String? = null,
    @Json(name = "start_utc") val startUtc: String? = null,
    @Json(name = "end_utc") val endUtc: String? = null,
    @Json(name = "all_day") val allDay: Boolean? = null,
    @Json(name = "all_day_date") val allDayDate: String? = null,
    @Json(name = "attendees") val attendees: List<String>? = null,
    @Json(name = "booking_enabled") val bookingEnabled: Boolean? = null,
    @Json(name = "approval_required") val approvalRequired: Boolean? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "category") val category: String? = null,
    @Json(name = "recurrence_rule") val recurrenceRule: RecurrenceRuleDto? = null,
    @Json(name = "exdates_utc") val exdatesUtc: List<String>? = null,
)

/** CalendarCreateIn / CalendarUpdateIn. */
@JsonClass(generateAdapter = true)
data class CalendarCreateReqDto(
    @Json(name = "name") val name: String? = null,
    @Json(name = "timezone") val timezone: String? = null,
    @Json(name = "conflict_detection") val conflictDetection: Boolean? = null,
    @Json(name = "buffer_before_minutes") val bufferBeforeMinutes: Int? = null,
    @Json(name = "buffer_after_minutes") val bufferAfterMinutes: Int? = null,
)

/** OkResp — returned by deletes (`{ "ok": true }`). */
@JsonClass(generateAdapter = true)
data class OkRespDto(
    @Json(name = "ok") val ok: Boolean = false,
)
