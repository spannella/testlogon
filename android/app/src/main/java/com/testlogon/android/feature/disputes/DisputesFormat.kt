package com.testlogon.android.feature.disputes

import com.testlogon.android.R
import com.testlogon.android.data.disputes.DisputeMoney
import com.testlogon.android.data.disputes.DisputeStatus
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Currency
import java.util.Date
import java.util.Locale

/**
 * AND-245 — pure, JVM-testable dispute money/date/status formatting (no Android UI types). Money is
 * integer cents; unknown currencies fall back to "<major> <CODE>". Dates use [DateFormat]/[Date].
 */

/** Locale-formatted currency for a [DisputeMoney] (cents/100). Falls back on an unknown currency code. */
fun formatDisputeMoney(money: DisputeMoney, locale: Locale = Locale.getDefault()): String {
    val amount = money.cents / 100.0
    return try {
        val format = NumberFormat.getCurrencyInstance(locale)
        format.currency = Currency.getInstance(money.currency.uppercase(Locale.ROOT))
        format.format(amount)
    } catch (_: IllegalArgumentException) {
        "%.2f %s".format(locale, amount, money.currency.uppercase(Locale.ROOT))
    }
}

/** Epoch-seconds -> localized medium date string, or null when [epochSeconds] is null. */
fun formatDisputeDate(epochSeconds: Long?, locale: Locale = Locale.getDefault()): String? {
    if (epochSeconds == null) return null
    return DateFormat.getDateInstance(DateFormat.MEDIUM, locale).format(Date(epochSeconds * 1000L))
}

/** Stable string-resource id for a dispute status label (text, never color-only). */
fun disputeStatusLabelRes(status: DisputeStatus): Int = when (status) {
    DisputeStatus.OPEN -> R.string.disputes_status_open
    DisputeStatus.UNDER_REVIEW -> R.string.disputes_status_under_review
    DisputeStatus.RESOLVED -> R.string.disputes_status_resolved
    DisputeStatus.UNKNOWN -> R.string.disputes_status_unknown
}
