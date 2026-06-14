package com.testlogon.android.feature.refunds

import com.testlogon.android.R
import com.testlogon.android.data.refunds.RefundMoney
import com.testlogon.android.data.refunds.RefundStatus
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Currency
import java.util.Date
import java.util.Locale

/**
 * AND-244 — pure, JVM-testable refund money/date/status formatting (no Android UI types), mirroring the
 * AND-243 InvoiceFormat helpers. Money is integer cents; unknown currencies fall back to "<major> <CODE>".
 * Dates use [DateFormat]/[Date] (NOT java.time, API26+).
 */

/** Locale-formatted currency for a [RefundMoney] (cents/100). Falls back on an unknown currency code. */
fun formatRefundMoney(money: RefundMoney, locale: Locale = Locale.getDefault()): String {
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
fun formatRefundDate(epochSeconds: Long?, locale: Locale = Locale.getDefault()): String? {
    if (epochSeconds == null) return null
    return DateFormat.getDateInstance(DateFormat.MEDIUM, locale).format(Date(epochSeconds * 1000L))
}

/** Stable string-resource id for a refund status label (text, never color-only). */
fun refundStatusLabelRes(status: RefundStatus): Int = when (status) {
    RefundStatus.PENDING -> R.string.refunds_status_pending
    RefundStatus.APPROVED -> R.string.refunds_status_approved
    RefundStatus.COMPLETED -> R.string.refunds_status_completed
    RefundStatus.DENIED -> R.string.refunds_status_denied
    RefundStatus.UNKNOWN -> R.string.refunds_status_unknown
}
