package com.testlogon.android.feature.analytics.engagement

import java.text.NumberFormat
import java.util.Locale

/**
 * AND-254 — pure, JVM-testable engagement formatting (no Android types). Percentages and counts are
 * locale-aware (NumberFormat); no hard-coded `%` glyph or `.`-decimal assumption in the data layer.
 * A null rate renders as the localized em-dash placeholder.
 */

const val ENGAGEMENT_PLACEHOLDER = "—" // em dash

/** Locale-formatted percentage, e.g. 9.83 -> "9.83%". Null -> em-dash placeholder. */
fun formatEngagementPercent(value: Double?, locale: Locale = Locale.getDefault()): String {
    if (value == null) return ENGAGEMENT_PLACEHOLDER
    val nf = NumberFormat.getNumberInstance(locale).apply {
        minimumFractionDigits = 2
        maximumFractionDigits = 2
    }
    return nf.format(value) + "%"
}

/** Signed locale-formatted delta in percentage points, e.g. 1.17 -> "+1.17", -0.5 -> "-0.50". */
fun formatEngagementDelta(value: Double?, locale: Locale = Locale.getDefault()): String {
    if (value == null) return ENGAGEMENT_PLACEHOLDER
    val sign = if (value > 0.0) "+" else if (value < 0.0) "-" else ""
    val nf = NumberFormat.getNumberInstance(locale).apply {
        minimumFractionDigits = 2
        maximumFractionDigits = 2
    }
    return sign + nf.format(kotlin.math.abs(value))
}

/** Locale-formatted integer count, e.g. 18450 -> "18,450" (US) / "18.450" (de). */
fun formatEngagementCount(value: Int, locale: Locale = Locale.getDefault()): String =
    NumberFormat.getIntegerInstance(locale).format(value.toLong())
