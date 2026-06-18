package com.testlogon.android.feature.groups

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * AND-355 (sub-pages) - tiny framework-free formatters shared by the group sub-pages. NO java.time:
 * timestamps use SimpleDateFormat per the codebase convention. Money is integer cents.
 */

/** Formats integer [cents] as a major-unit amount with the (already-uppercased) [currency] suffix. */
internal fun formatMoney(cents: Long, currency: String?): String {
    val major = cents / 100.0
    val code = currency?.takeIf { it.isNotBlank() }?.uppercase(Locale.US) ?: "USD"
    return String.format(Locale.US, "%,.2f %s", major, code)
}

private val DATE_FORMAT = SimpleDateFormat("MMM d, yyyy", Locale.US)

/** Formats an epoch-SECONDS [epochSeconds] as a short date, or null when absent. */
internal fun formatEpochSeconds(epochSeconds: Long?): String? {
    val secs = epochSeconds ?: return null
    return DATE_FORMAT.format(Date(secs * 1000L))
}
