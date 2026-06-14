package com.testlogon.android.feature.videos

import com.testlogon.android.feature.player.PlayerTimeFormat

/**
 * AND-189 / AND-191 — pure mm:ss / h:mm:ss badge formatting from a duration in SECONDS. Delegates to
 * the shared JVM-tested [PlayerTimeFormat] (works on Long ms, Locale.ROOT) so there is one formatter
 * and no android.text.format / java.time usage in unit-tested code.
 */
object VideoDurationFormat {

    /** Formats [seconds] as "m:ss" (or "h:mm:ss" past an hour); null/non-positive -> null (no badge). */
    fun badge(seconds: Int?): String? {
        if (seconds == null || seconds <= 0) return null
        return PlayerTimeFormat.format(seconds.toLong() * 1000L)
    }
}
