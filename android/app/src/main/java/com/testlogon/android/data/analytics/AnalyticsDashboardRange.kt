package com.testlogon.android.data.analytics

import com.testlogon.android.data.earnings.isoDateFromEpochDay

/**
 * AND-399 - selectable analytics dashboard date-range presets. CORRECTED per spec FR-2 / section 16 #9:
 * the web RANGE_PRESETS are 7 / 30 / 90 / 365 with DEFAULT = 30 (NOT the draft's 7/28/90 default 28).
 * Each preset converts client-side to an inclusive from_date / to_date pair; the backend has no `range`
 * param. The engagement endpoint instead takes [days] verbatim as period_days.
 */
enum class AnalyticsDashboardRange(val apiKey: String, val days: Int) {
    LAST_7("7", 7),
    LAST_30("30", 30),
    LAST_90("90", 90),
    LAST_365("365", 365),
    ;

    companion object {
        val DEFAULT = LAST_30

        /** Lenient parse of a persisted / deep-link key; unknown -> [DEFAULT]. */
        fun fromKey(key: String?): AnalyticsDashboardRange =
            entries.firstOrNull { it.apiKey.equals(key, ignoreCase = true) } ?: DEFAULT
    }
}

/** Inclusive ISO YYYY-MM-DD from/to window for a range. */
data class AnalyticsDateWindow(val fromDate: String, val toDate: String)

/**
 * Pure date-window math given "today" as an epoch-DAY (days since 1970). Inclusive window:
 * to = today, from = today - (days - 1). No java.time -> JVM-unit-testable and API < 26 safe (reuses
 * the AND-252 isoDateFromEpochDay converter).
 */
fun AnalyticsDashboardRange.toDateWindow(todayEpochDay: Long): AnalyticsDateWindow {
    val to = todayEpochDay
    val from = todayEpochDay - (days - 1).toLong()
    return AnalyticsDateWindow(
        fromDate = isoDateFromEpochDay(from),
        toDate = isoDateFromEpochDay(to),
    )
}
