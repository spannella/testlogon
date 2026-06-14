package com.testlogon.android.data.messaging

import java.util.Locale

/**
 * AND-137 — pure, JVM-testable countdown logic.
 *
 * Remaining time is always DERIVED from [targetEpochSeconds] and the current clock; it is never
 * stored as a mutable counter, so it self-corrects against the device clock after backgrounding,
 * rotation, and process death. The live ticker in the @Composable supplies `nowEpochSeconds` once
 * per second; everything here is a pure Long-epoch calculation (no java.time / API-26, no
 * android.text.format), so it runs in JVM unit tests.
 */
object CountdownLogic {

    private const val SECONDS_PER_MINUTE = 60L
    private const val SECONDS_PER_HOUR = 60L * 60L
    private const val SECONDS_PER_DAY = 24L * 60L * 60L

    /** Remaining whole seconds to the target, clamped to >= 0 (never negative). */
    fun remainingSeconds(targetEpochSeconds: Long, nowEpochSeconds: Long): Long =
        (targetEpochSeconds - nowEpochSeconds).coerceAtLeast(0L)

    /** True once the target has been reached/passed (remaining <= 0). */
    fun isDone(targetEpochSeconds: Long, nowEpochSeconds: Long): Boolean =
        remainingSeconds(targetEpochSeconds, nowEpochSeconds) <= 0L

    /**
     * Formats remaining seconds as "2d 04:12:09" (days shown only when >= 1 day) / "04:12:09" /
     * "00:00:09" / "00:00:00". Locale-safe (ROOT) zero-padded arithmetic; matches the web
     * CountdownCard treatment (days only when > 0).
     */
    fun format(remainingSeconds: Long): String {
        val total = remainingSeconds.coerceAtLeast(0L)
        val days = total / SECONDS_PER_DAY
        val hours = (total % SECONDS_PER_DAY) / SECONDS_PER_HOUR
        val minutes = (total % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE
        val seconds = total % SECONDS_PER_MINUTE
        val hms = String.format(Locale.ROOT, "%02d:%02d:%02d", hours, minutes, seconds)
        return if (days > 0L) "${days}d $hms" else hms
    }

    /** Coarse accessibility phrase (updated ~per minute by the caller, not per second). */
    fun accessibilityRemaining(remainingSeconds: Long): String {
        val total = remainingSeconds.coerceAtLeast(0L)
        if (total <= 0L) return "0 minutes"
        val days = total / SECONDS_PER_DAY
        val hours = (total % SECONDS_PER_DAY) / SECONDS_PER_HOUR
        val minutes = (total % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE
        val parts = buildList {
            if (days > 0L) add("$days ${plural(days, "day")}")
            if (hours > 0L) add("$hours ${plural(hours, "hour")}")
            if (days == 0L && minutes > 0L) add("$minutes ${plural(minutes, "minute")}")
        }
        return if (parts.isEmpty()) "less than a minute" else parts.joinToString(" ")
    }

    private fun plural(n: Long, unit: String): String = if (n == 1L) unit else "${unit}s"
}
