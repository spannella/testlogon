package com.testlogon.android.feature.feed

import android.text.format.DateUtils

/**
 * AND-099 — relative-time copy from an epoch-SECONDS value. minSdk24-safe; uses android.text.format so
 * it is a UI-only helper (NOT referenced from JVM unit tests). Returns "" for unknown/epoch timestamps.
 */
internal fun relativeTime(epochSeconds: Long, nowMs: Long = System.currentTimeMillis()): String {
    if (epochSeconds <= 0L) return ""
    return DateUtils.getRelativeTimeSpanString(
        epochSeconds * 1000L,
        nowMs,
        DateUtils.MINUTE_IN_MILLIS,
    ).toString()
}
