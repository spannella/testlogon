package com.testlogon.android.data.contentcalendar

import java.time.Instant

/**
 * AND-274 — pure DTO->domain mappers. Unknown enum strings map to UNKNOWN (never throw); absent
 * optionals fall back to Kotlin defaults. `scheduled_at` is Unix epoch SECONDS (NOT an Instant string),
 * converted via [Instant.ofEpochSecond]; it does not flow through any Instant JSON adapter.
 */
fun ContentCalendarItemDto.toDomain(): ScheduledContent = ScheduledContent(
    id = id,
    type = type.toContentItemType(),
    title = title,
    status = status.toScheduledStatus(),
    scheduledAt = Instant.ofEpochSecond(scheduledAt),
    timezone = timezone,
    localTime = localTime,
    color = color,
    icon = icon,
    thumbnailUrl = thumbnailUrl,
    description = description,
    durationSeconds = durationSeconds,
)

fun String?.toScheduledStatus(): ScheduledStatus = when (this?.lowercase()) {
    "scheduled" -> ScheduledStatus.SCHEDULED
    "overdue" -> ScheduledStatus.OVERDUE
    "cancelled", "canceled" -> ScheduledStatus.CANCELLED
    else -> ScheduledStatus.UNKNOWN
}

fun String?.toContentItemType(): ContentItemType = when (this?.lowercase()) {
    "post" -> ContentItemType.POST
    "broadcast" -> ContentItemType.BROADCAST
    "vod" -> ContentItemType.VOD
    else -> ContentItemType.UNKNOWN
}
