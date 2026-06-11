package com.testlogon.android.data.contentcalendar

import java.time.Instant

/**
 * AND-274 — content-calendar domain models (DTO-free).
 *
 * Mirrors the verified web contract (reference/src/api/types.ts: ContentCalendarItem /
 * ContentCalendarResponse / ContentItemType, and openapi.index.txt GET /ui/content-calendar). KEY
 * FACTS the reference confirms:
 *  - the item is keyed by content `type` (post|broadcast|vod), NOT a delivery channel.
 *  - `status` vocabulary is scheduled|overdue|cancelled (NOT a publish lifecycle).
 *  - `scheduled_at` is a Unix epoch-SECONDS integer on the wire (NOT an RFC-3339 string, no
 *    `scheduled_date` ISO variant) -> the mapper uses Instant.ofEpochSecond.
 *  - the response envelope is {items, from_ts, to_ts, count, conflicts}; there is NO paging cursor.
 *
 * Timestamps are modeled as [Instant]; day bucketing onto the calendar grid is delegated to the pure
 * [com.testlogon.android.feature.calendar.CalendarMath] in the ViewModel (epoch-day, no java.time in
 * the bucketing math). The display zone resolves the [Instant] to an epoch day there.
 */

/** A scheduled content item (ContentCalendarItem). */
data class ScheduledContent(
    val id: String,
    val type: ContentItemType,
    val title: String,
    val status: ScheduledStatus,
    val scheduledAt: Instant,
    val timezone: String?,
    val localTime: String?,
    val color: String?,
    val icon: String?,
    val thumbnailUrl: String? = null,
    val description: String? = null,
    val durationSeconds: Long? = null,
)

/** Content kind. The backend emits post|broadcast|vod; unknown maps to UNKNOWN. */
enum class ContentItemType { POST, BROADCAST, VOD, UNKNOWN }

/** Schedule status. The backend emits scheduled|overdue|cancelled; unknown maps to UNKNOWN. */
enum class ScheduledStatus { SCHEDULED, OVERDUE, CANCELLED, UNKNOWN }

/** A half-open [from, to) instant range; from_ts/to_ts on the wire are epoch SECONDS. */
data class ContentDateRange(val from: Instant, val to: Instant)

/** Only `types` is a server-supported filter (comma-separated post,broadcast,vod). */
data class ContentFilter(
    val types: Set<ContentItemType> = emptySet(),
)

/** The wire id token for a content type (used to build the CSV `types` query). */
fun ContentItemType.wire(): String? = when (this) {
    ContentItemType.POST -> "post"
    ContentItemType.BROADCAST -> "broadcast"
    ContentItemType.VOD -> "vod"
    ContentItemType.UNKNOWN -> null
}
