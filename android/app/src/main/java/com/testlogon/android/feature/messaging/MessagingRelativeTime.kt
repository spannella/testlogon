package com.testlogon.android.feature.messaging

import android.text.format.DateUtils

/**
 * Relative-time copy from an epoch-SECONDS value (minSdk24-safe via [DateUtils]).
 *
 * NOTE: uses android.text.format.DateUtils, so it is only called from @Composable rendering, NEVER
 * from JVM-unit-tested code (timestamps are passed around as Long until render).
 */
internal fun relativeTimeFromSeconds(epochSeconds: Long): String {
    if (epochSeconds <= 0L) return ""
    return DateUtils.getRelativeTimeSpanString(
        epochSeconds * 1000L,
        System.currentTimeMillis(),
        DateUtils.MINUTE_IN_MILLIS,
    ).toString()
}
