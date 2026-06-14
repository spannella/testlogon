package com.testlogon.android.data.contentcalendar

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-274 — Moshi DTOs for the content-calendar contract, verified against
 * reference/src/api/types.ts: ContentCalendarItem / ContentCalendarResponse / ContentCalendarConflict.
 *
 * `scheduled_at` is a Unix epoch-SECONDS integer (Long), not an Instant string — the mapper converts via
 * Instant.ofEpochSecond. Type-specific optionals tolerate absence via Kotlin defaults; unknown enum
 * strings are tolerated by the mapper (never throw).
 */
@JsonClass(generateAdapter = true)
data class ContentCalendarItemDto(
    val id: String,
    val type: String? = null,
    val title: String,
    @Json(name = "scheduled_at") val scheduledAt: Long,
    val timezone: String? = null,
    @Json(name = "local_time") val localTime: String? = null,
    val status: String? = null,
    val color: String? = null,
    val icon: String? = null,
    // Post-specific (optional)
    @Json(name = "has_images") val hasImages: Boolean? = null,
    @Json(name = "has_video") val hasVideo: Boolean? = null,
    val visibility: String? = null,
    val locked: Boolean? = null,
    @Json(name = "unlock_price_cents") val unlockPriceCents: Int? = null,
    // Broadcast-specific (optional)
    val description: String? = null,
    @Json(name = "profile_id") val profileId: String? = null,
    @Json(name = "has_announcement") val hasAnnouncement: Boolean? = null,
    // VOD-specific (optional)
    @Json(name = "duration_seconds") val durationSeconds: Long? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
)

@JsonClass(generateAdapter = true)
data class ContentCalendarConflictDto(
    @Json(name = "item_a_id") val itemAId: String? = null,
    @Json(name = "item_a_type") val itemAType: String? = null,
    @Json(name = "item_b_id") val itemBId: String? = null,
    @Json(name = "item_b_type") val itemBType: String? = null,
    @Json(name = "gap_seconds") val gapSeconds: Long? = null,
    @Json(name = "gap_minutes") val gapMinutes: Long? = null,
)

/** Response envelope {items, from_ts, to_ts, count, conflicts}. No paging cursor exists. */
@JsonClass(generateAdapter = true)
data class ContentCalendarRespDto(
    val items: List<ContentCalendarItemDto> = emptyList(),
    @Json(name = "from_ts") val fromTs: Long? = null,
    @Json(name = "to_ts") val toTs: Long? = null,
    val count: Int? = null,
    val conflicts: List<ContentCalendarConflictDto> = emptyList(),
)
