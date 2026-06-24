package com.testlogon.android.data.calendar

import java.time.Instant
import java.time.LocalDate
import java.time.format.DateTimeParseException

/**
 * AND-270 — pure DTO -> domain mappers. Side-effect-free, never throw on recoverable shape variance:
 *  - unknown `freq` -> [RecurrenceFreq.UNKNOWN] (never throws);
 *  - absent optionals fall back to defaults / null;
 *  - all-day events (`start_utc` absent, `all_day_date` present) map to a null [CalendarEvent.startAt]
 *    and a non-null [CalendarEvent.allDayDate] — NO off-by-one, NO error on the absent start;
 *  - unparseable timestamps degrade to null rather than throwing (a contract-violating REQUIRED field
 *    that is genuinely missing fails earlier at the Moshi adapter, surfaced to AND-015/AND-018).
 */

internal fun parseInstantOrNull(value: String?): Instant? {
    if (value.isNullOrBlank()) return null
    return try {
        Instant.parse(value)
    } catch (_: DateTimeParseException) {
        null
    }
}

internal fun parseLocalDateOrNull(value: String?): LocalDate? {
    if (value.isNullOrBlank()) return null
    return try {
        LocalDate.parse(value)
    } catch (_: DateTimeParseException) {
        null
    }
}

internal fun String?.toRecurrenceFreq(): RecurrenceFreq = when (this?.uppercase()) {
    "DAILY" -> RecurrenceFreq.DAILY
    "WEEKLY" -> RecurrenceFreq.WEEKLY
    "MONTHLY" -> RecurrenceFreq.MONTHLY
    "YEARLY" -> RecurrenceFreq.YEARLY
    else -> RecurrenceFreq.UNKNOWN
}

fun RecurrenceRuleDto.toDomain(): Recurrence = Recurrence(
    freq = freq.toRecurrenceFreq(),
    interval = interval.takeIf { it > 0 } ?: 1,
    untilUtc = parseInstantOrNull(untilUtc),
    count = count,
    byDay = byday.orEmpty(),
    byMonthDay = bymonthday.orEmpty(),
    bySetPos = bysetpos.orEmpty(),
)

fun CalendarDto.toDomain(): Calendar = Calendar(
    calendarId = calendarId,
    name = name,
    timezone = timezone,
    ownerUserId = ownerUserId,
    conflictDetection = conflictDetection,
    bufferBeforeMinutes = bufferBeforeMinutes,
    bufferAfterMinutes = bufferAfterMinutes,
    createdAtUtc = parseInstantOrNull(createdAtUtc),
)

fun CalendarEventDto.toDomain(): CalendarEvent = CalendarEvent(
    eventId = eventId,
    calendarId = calendarId,
    name = name,
    description = description,
    timezone = timezone,
    startAt = parseInstantOrNull(startUtc),
    endAt = parseInstantOrNull(endUtc),
    allDay = allDay,
    allDayDate = parseLocalDateOrNull(allDayDate),
    attendees = attendees.orEmpty(),
    bookingEnabled = bookingEnabled,
    approvalRequired = approvalRequired,
    status = status,
    category = category,
    recurrence = recurrenceRule?.toDomain(),
    exDatesUtc = exdatesUtc.orEmpty().mapNotNull { parseInstantOrNull(it) },
    createdAtUtc = parseInstantOrNull(createdAtUtc),
    syncState = syncState,
    syncConflictReason = syncConflictReason,
    isPublic = false,
    owner = null,
)

fun EventsPageDto.toDomain(): EventsPage = EventsPage(
    events = events.map { it.toDomain() },
    nextCursor = nextCursor,
)

fun PublicEventDto.toDomain(): CalendarEvent = CalendarEvent(
    eventId = eventId,
    calendarId = calendarId,
    name = name,
    description = description.orEmpty(),
    timezone = timezone,
    startAt = parseInstantOrNull(startUtc),
    endAt = parseInstantOrNull(endUtc),
    allDay = allDay,
    allDayDate = parseLocalDateOrNull(allDayDate),
    attendees = emptyList(),
    recurrence = null,
    exDatesUtc = emptyList(),
    isPublic = true,
    owner = owner,
)
