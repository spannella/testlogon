package com.testlogon.android.feature.affiliates

import com.testlogon.android.data.affiliates.AffiliateLink
import com.testlogon.android.feature.charts.ChartGeometryCore
import com.testlogon.android.feature.charts.SeriesGeometry
import java.text.NumberFormat
import java.util.Locale

/**
 * AND-265 — pure, JVM-testable affiliate formatting + chart mapping (no Android types).
 *
 * Reuses the JVM-tested [ChartGeometryCore] to build a per-link commission-earned trend (one bucket per
 * link, value = commission cents). This is the same reusable chart math/renderer the earnings dashboard
 * and engagement trend use — affiliates plots per-link commission instead of a date series.
 */

/** Per-link commission cents -> reusable [SeriesGeometry] (empty when there is no non-zero commission). */
fun List<AffiliateLink>.commissionSeriesGeometry(): SeriesGeometry =
    ChartGeometryCore.compute(map { it.commissionEarned.cents })

/** Formats an integer percentage value like `10%` (display-only; never the money graph). Locale-aware. */
fun formatPercent(value: Double, locale: Locale = Locale.getDefault()): String {
    val nf = NumberFormat.getNumberInstance(locale).apply { maximumFractionDigits = 1 }
    return "${nf.format(value)}%"
}

/** Locale-aware integer count formatting (clicks/conversions). */
fun formatCount(value: Long, locale: Locale = Locale.getDefault()): String =
    NumberFormat.getIntegerInstance(locale).format(value)

/** Truncates a URL to a compact display form, keeping the leading origin + an ellipsis tail. */
fun displayUrl(fullUrl: String, max: Int = 40): String =
    if (fullUrl.length <= max) fullUrl else fullUrl.take(max - 1) + "…"
