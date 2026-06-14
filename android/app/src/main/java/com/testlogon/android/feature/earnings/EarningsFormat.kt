package com.testlogon.android.feature.earnings

import com.testlogon.android.data.earnings.EarningsBreakdown
import com.testlogon.android.data.earnings.isoDateFromEpochDay
import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

/**
 * AND-252/253 — pure, JVM-testable earnings money + label formatting (no Android types), mirroring the
 * AND-243 InvoiceFormat helpers. Money is integer cents; an unrecognized currency code falls back to a
 * plain "<major> <CODE>" form (never crashes).
 */

/** Locale-formatted currency for integer [cents] + ISO-4217 [currency]. Falls back on unknown codes. */
fun formatEarningsMoney(
    cents: Long,
    currency: String,
    locale: Locale = Locale.getDefault(),
): String {
    val amount = cents / 100.0
    return try {
        val format = NumberFormat.getCurrencyInstance(locale)
        format.currency = Currency.getInstance(currency.uppercase(Locale.ROOT))
        format.format(amount)
    } catch (_: IllegalArgumentException) {
        "%.2f %s".format(locale, amount, currency.uppercase(Locale.ROOT))
    }
}

/** A bucket source key (stable, locale-agnostic) used by the breakdown UI to look up a localized label. */
enum class EarningsSource { SUBSCRIPTIONS, TIPS, UNLOCKS, VOD_PURCHASES, OTHER }

/** A computed breakdown row: source, raw cents, and integer-percent share of the total. */
data class BreakdownRow(
    val source: EarningsSource,
    val cents: Long,
    /** Percent share 0..100, computed in integer cents (round(source/total*100)). */
    val sharePct: Int,
)

/**
 * Pure breakdown computation (AND-252 FR-4): turns the fixed-key breakdown into rows sorted descending
 * by amount, dropping zero rows (web filters v > 0). Share = round(cents / total * 100) where total is
 * the SUM of the breakdown sources (so shares sum to ~100 even if it diverges from summary.total_cents).
 */
fun EarningsBreakdown.toRows(): List<BreakdownRow> {
    val raw = listOf(
        EarningsSource.SUBSCRIPTIONS to subscriptions,
        EarningsSource.TIPS to tips,
        EarningsSource.UNLOCKS to unlocks,
        EarningsSource.VOD_PURCHASES to vodPurchases,
        EarningsSource.OTHER to other,
    )
    val total = raw.sumOf { it.second }
    return raw
        .filter { it.second > 0L }
        .map { (source, cents) ->
            val pct = if (total > 0L) {
                Math.round(cents.toDouble() / total.toDouble() * 100.0).toInt()
            } else {
                0
            }
            BreakdownRow(source = source, cents = cents, sharePct = pct)
        }
        .sortedByDescending { it.cents }
}

/**
 * Formats a series bucket's X-axis label. A parseable [dateEpochDay] -> "MM-DD" short label; otherwise
 * the raw backend label (e.g. weekly "2026-W18") is shown verbatim. Pure / java.time-free.
 */
fun formatBucketLabel(dateEpochDay: Long?, rawDate: String): String {
    if (dateEpochDay == null) return rawDate
    val iso = isoDateFromEpochDay(dateEpochDay) // YYYY-MM-DD
    // Show MM-DD to keep axis labels compact; full date stays available via the raw label/tooltip.
    return if (iso.length == 10) iso.substring(5) else iso
}

/** Epoch-seconds -> localized medium date string, or null when [epochSeconds] is null/0 (unknown). */
fun formatPublishedDate(epochSeconds: Long?, locale: Locale = Locale.getDefault()): String? {
    if (epochSeconds == null || epochSeconds <= 0L) return null
    return java.text.DateFormat
        .getDateInstance(java.text.DateFormat.MEDIUM, locale)
        .format(java.util.Date(epochSeconds * 1000L))
}
