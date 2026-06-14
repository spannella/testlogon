package com.testlogon.android.data.calendar

import java.time.Instant
import java.time.LocalDate

/**
 * AND-270 — canonical calendar domain models (DTO-free).
 *
 * Mirrors the verified backend contract (reference/src/api/types.ts: Calendar / CalendarEvent /
 * RecurrenceRule / EventsPage / CalendarEventAttachment; openapi.index.txt CalendarOut / EventOut /
 * RecurrenceRule / EventsPageOut). KEY FACTS the web reference confirms:
 *  - the id fields are `calendar_id` / `event_id` (NOT `id`); the title field is `name` (NOT `title`).
 *  - timed events carry `start_utc` / `end_utc` (both nullable); all-day events carry a single
 *    `all_day_date` (ISO date) and omit the timestamps. There is NO `start_date`/`end_date` pair.
 *  - there is NO RSVP concept (no endpoint, no field); attendees are a flat list of sub identifiers.
 *  - recurrence is fully STRUCTURED (freq DAILY|WEEKLY|MONTHLY, interval, until_utc, count, byday,
 *    bymonthday, bysetpos) — there is NO raw rrule string and NO YEARLY. Exception dates live at the
 *    EVENT level (`exdates_utc`); per-occurrence edits in `recurrence_overrides`.
 *  - the public event payload (CalendarEventAttachment) is a REDUCED shape: name/times/all-day/
 *    timezone/description/owner only (no attendees/recurrence/category/status).
 *
 * Timestamps are modeled as [Instant] on the domain (parsed from the wire ISO-8601 strings by the
 * mapper). Display formatting lives in [CalendarDateFormat]; pure month-grid/range date math lives in
 * [CalendarMath] (both JVM-unit-tested, no Android deps).
 */

/** A calendar the principal owns or can see (CalendarOut). */
data class Calendar(
    val calendarId: String,
    val name: String,
    val timezone: String,
    val ownerUserId: String,
    val conflictDetection: Boolean = false,
    val bufferBeforeMinutes: Int = 0,
    val bufferAfterMinutes: Int = 0,
    val createdAtUtc: Instant? = null,
)

/** A single calendar event (EventOut). */
data class CalendarEvent(
    val eventId: String,
    val calendarId: String,
    val name: String,
    val description: String = "",
    val timezone: String,
    val startAt: Instant? = null,
    val endAt: Instant? = null,
    val allDay: Boolean = false,
    val allDayDate: LocalDate? = null,
    val attendees: List<String> = emptyList(),
    val bookingEnabled: Boolean = false,
    val approvalRequired: Boolean = false,
    val status: String = "",
    val category: String? = null,
    val recurrence: Recurrence? = null,
    val exDatesUtc: List<Instant> = emptyList(),
    val createdAtUtc: Instant? = null,
    val syncState: String? = null,
    val syncConflictReason: String? = null,
    /** True when this came from the public (unauthenticated) endpoint — a reduced payload. */
    val isPublic: Boolean = false,
    /** Opaque owner identifier present only on the public payload. */
    val owner: String? = null,
)

/** Structured recurrence rule (RecurrenceRule). No raw rrule; no YEARLY. */
data class Recurrence(
    val freq: RecurrenceFreq,
    val interval: Int = 1,
    val untilUtc: Instant? = null,
    val count: Int? = null,
    val byDay: List<String> = emptyList(),
    val byMonthDay: List<Int> = emptyList(),
    val bySetPos: List<Int> = emptyList(),
)

/** Recurrence frequency. The backend only emits DAILY|WEEKLY|MONTHLY; unknown maps to UNKNOWN. */
enum class RecurrenceFreq { DAILY, WEEKLY, MONTHLY, UNKNOWN }

/** One cursor-paged page of events (EventsPageOut). */
data class EventsPage(
    val events: List<CalendarEvent> = emptyList(),
    val nextCursor: String? = null,
)
