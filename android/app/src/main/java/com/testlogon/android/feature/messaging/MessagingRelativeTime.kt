package com.testlogon.android.feature.messaging

import android.text.format.DateUtils

/**
 * Relative-time copy from an epoch-SECONDS value (minSdk24-safe via [DateUtils]).
 *
 * NOTE: uses android.text.format.DateUtils, so it is only called from @Composable rendering, NEVER
 * from JVM-unit-tested code (timestamps are passed around as Long until render).
 */
internal fun relativeTimeFromSeconds(
    epochSeconds: Long,
    nowMillis: Long = System.currentTimeMillis(),
): String {
    if (epochSeconds <= 0L) return ""
    val deltaMs = nowMillis - epochSeconds * 1000L
    // Within the last minute DateUtils renders the awkward "0 minutes ago"; show "Just now" instead.
    if (deltaMs in 0 until DateUtils.MINUTE_IN_MILLIS) return "Just now"
    return DateUtils.getRelativeTimeSpanString(
        epochSeconds * 1000L,
        nowMillis,
        DateUtils.MINUTE_IN_MILLIS,
    ).toString()
}
