package com.testlogon.android.feature.gallery

/**
 * AND-201 — pure, JVM-testable formatters for the gallery card (no Android types). Mirrors the web
 * `formatCount` (1.2K / 3.4M) and the duration badge (mm:ss / h:mm:ss).
 */

/** Formats [totalSeconds] as mm:ss, or h:mm:ss when an hour or more. */
fun formatDuration(totalSeconds: Long): String {
    val s = totalSeconds.coerceAtLeast(0)
    val hours = s / 3600
    val minutes = (s % 3600) / 60
    val seconds = s % 60
    return if (hours > 0) {
        "%d:%02d:%02d".format(hours, minutes, seconds)
    } else {
        "%d:%02d".format(minutes, seconds)
    }
}

/** Formats a count as 1.2K / 3.4M (web `formatCount`); raw value under 1000. */
fun formatCount(count: Int): String {
    val c = count.coerceAtLeast(0)
    return when {
        c >= 1_000_000 -> trimOne(c / 1_000_000.0) + "M"
        c >= 1_000 -> trimOne(c / 1_000.0) + "K"
        else -> c.toString()
    }
}

/** One decimal place, dropping a trailing ".0" (e.g. 1.0 -> "1", 1.2 -> "1.2"). */
private fun trimOne(value: Double): String {
    val rounded = (value * 10).toLong() / 10.0
    return if (rounded % 1.0 == 0.0) rounded.toLong().toString() else "%.1f".format(rounded)
}
