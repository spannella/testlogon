package com.testlogon.android.feature.calendar.detail

import com.testlogon.android.data.calendar.Recurrence
import com.testlogon.android.data.calendar.RecurrenceFreq

/**
 * AND-272 — PURE, JVM-testable recurrence summary builder. Produces a short, non-localized base label
 * for a [Recurrence] (e.g. "Daily", "Every 2 weeks on MO, WE"). The screen wraps it with a localized
 * prefix; this helper avoids java.time and Android so it is unit-testable. Unknown freq -> null (the row
 * is hidden).
 */
object RecurrenceSummary {

    fun build(recurrence: Recurrence): String? {
        val base = when (recurrence.freq) {
            RecurrenceFreq.DAILY -> if (recurrence.interval > 1) "Every ${recurrence.interval} days" else "Daily"
            RecurrenceFreq.WEEKLY -> if (recurrence.interval > 1) "Every ${recurrence.interval} weeks" else "Weekly"
            RecurrenceFreq.MONTHLY -> if (recurrence.interval > 1) "Every ${recurrence.interval} months" else "Monthly"
            RecurrenceFreq.UNKNOWN -> return null
        }
        val days = if (recurrence.byDay.isNotEmpty()) " on ${recurrence.byDay.joinToString(", ")}" else ""
        val limit = when {
            recurrence.count != null -> ", ${recurrence.count} times"
            else -> ""
        }
        return base + days + limit
    }
}
