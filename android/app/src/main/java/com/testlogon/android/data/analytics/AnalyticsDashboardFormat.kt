package com.testlogon.android.data.analytics

import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

/**
 * AND-399 - pure, JVM-testable analytics-dashboard formatting (no Android / Compose types). Units are
 * pinned by the spec (sections 5 / 16): revenue is integer CENTS, watch time is integer SECONDS,
 * top-content engagement_rate is a 0..1 FRACTION (rendered (rate*100)), audience percentage is already
 * a 0..100 number (rendered verbatim - NO extra *100). All numbers are locale-aware (NumberFormat).
 */

const val ANALYTICS_PLACEHOLDER = "—" // em dash

/** Locale-formatted integer count, e.g. 184320 -> "184,320" (US). */
fun formatCount(value: Long, locale: Locale = Locale.getDefault()): String =
    NumberFormat.getIntegerInstance(locale).format(value)

/**
 * Integer cents -> a localized currency string, e.g. 188200 + "USD" -> "$1,882.00". Falls back to the
 * locale default currency when [currencyCode] is blank/unknown.
 */
fun formatCents(cents: Long, currencyCode: String, locale: Locale = Locale.getDefault()): String {
    val nf = NumberFormat.getCurrencyInstance(locale)
    runCatching { Currency.getInstance(currencyCode.trim().uppercase(Locale.ROOT)) }
        .getOrNull()
        ?.let { nf.currency = it }
    return nf.format(cents / 100.0)
}

/**
 * Integer seconds -> a compact "Hh Mm" duration, e.g. 318400 -> "88h 26m"; under an hour -> "26m";
 * exactly zero -> "0m". Seconds are dropped (the dashboard shows hour/minute granularity).
 */
fun formatWatchTime(totalSeconds: Long, locale: Locale = Locale.getDefault()): String {
    val safe = totalSeconds.coerceAtLeast(0L)
    val hours = safe / 3600L
    val minutes = (safe % 3600L) / 60L
    val nf = NumberFormat.getIntegerInstance(locale)
    return if (hours > 0L) {
        "${nf.format(hours)}h ${nf.format(minutes)}m"
    } else {
        "${nf.format(minutes)}m"
    }
}

/**
 * A 0..1 engagement FRACTION -> a percentage string, e.g. 0.0613 -> "6.1%" (one decimal, matching the
 * web (rate*100).toFixed(1)). Multiplies by 100.
 */
fun formatFractionPercent(fraction: Double, locale: Locale = Locale.getDefault()): String {
    val nf = NumberFormat.getNumberInstance(locale).apply {
        minimumFractionDigits = 1
        maximumFractionDigits = 1
    }
    return nf.format(fraction * 100.0) + "%"
}

/**
 * An already-0..100 percentage NUMBER -> a percentage string, e.g. 38.0 -> "38%". NO extra scaling
 * (audience country/device percentages arrive 0..100; spec section 16 #7).
 */
fun formatPercentNumber(value: Double, locale: Locale = Locale.getDefault()): String {
    val nf = NumberFormat.getNumberInstance(locale).apply {
        minimumFractionDigits = 0
        maximumFractionDigits = 1
    }
    return nf.format(value) + "%"
}
