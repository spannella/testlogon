package com.testlogon.android.feature.projects.ui

import android.text.format.DateUtils

/**
 * AND-374 - relative-time copy from an ISO-8601 timestamp String (this surface sends ISO strings, NOT epoch -
 * spec §5). UI-only (android.text.format), locale-aware via [DateUtils.getRelativeTimeSpanString]. Returns ""
 * for null / blank / unparseable input (the row simply omits the line). Mirrors the AND-372 relativeTime helper
 * but adapted for the ISO wire shape.
 *
 * Parsing is dependency-free: java.time.Instant.parse handles the common `...Z` / offset ISO forms; on any
 * parse failure we return "" rather than rendering the raw machine string.
 */
internal fun relativeTimeIso(iso: String?, nowMs: Long = System.currentTimeMillis()): String {
    if (iso.isNullOrBlank()) return ""
    val epochMs = runCatching { java.time.Instant.parse(iso).toEpochMilli() }.getOrNull() ?: return ""
    if (epochMs <= 0L) return ""
    return DateUtils.getRelativeTimeSpanString(
        epochMs,
        nowMs,
        DateUtils.MINUTE_IN_MILLIS,
    ).toString()
}
