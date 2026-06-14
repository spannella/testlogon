package com.testlogon.android.feature.payouts

import com.testlogon.android.R
import com.testlogon.android.data.payouts.PayoutMethodType
import com.testlogon.android.data.payouts.PayoutMoney
import com.testlogon.android.data.payouts.PayoutStatus
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Currency
import java.util.Date
import java.util.Locale

/**
 * AND-260 — pure, JVM-testable payout money/date/label formatting (no Android types beyond R ids),
 * mirroring InvoiceFormat. Money is integer cents; an unrecognized currency falls back to a plain
 * "<major> <CODE>" form. Dates use [DateFormat]/[Date] (NOT java.time, API26+).
 */

/** Locale-formatted currency for a [PayoutMoney] (cents/100). Falls back on an unknown currency code. */
fun formatPayoutMoney(money: PayoutMoney, locale: Locale = Locale.getDefault()): String {
    val amount = money.cents / 100.0
    return try {
        val format = NumberFormat.getCurrencyInstance(locale)
        format.currency = Currency.getInstance(money.currency.uppercase(Locale.ROOT))
        format.format(amount)
    } catch (_: IllegalArgumentException) {
        "%.2f %s".format(locale, amount, money.currency.uppercase(Locale.ROOT))
    }
}

/** Epoch-seconds -> localized medium date string, or null when [epochSeconds] is null/zero. */
fun formatPayoutDate(epochSeconds: Long?, locale: Locale = Locale.getDefault()): String? {
    if (epochSeconds == null || epochSeconds <= 0L) return null
    return DateFormat.getDateInstance(DateFormat.MEDIUM, locale).format(Date(epochSeconds * 1000L))
}

/** String-resource id for a payout [PayoutStatus] chip label (TalkBack reads "Status: <label>"). */
fun payoutStatusLabelRes(status: PayoutStatus): Int = when (status) {
    PayoutStatus.REQUESTED -> R.string.payout_status_requested
    PayoutStatus.APPROVED -> R.string.payout_status_approved
    PayoutStatus.PROCESSING -> R.string.payout_status_processing
    PayoutStatus.COMPLETED -> R.string.payout_status_completed
    PayoutStatus.REJECTED -> R.string.payout_status_rejected
    PayoutStatus.CANCELLED -> R.string.payout_status_cancelled
    PayoutStatus.UNKNOWN -> R.string.payout_status_unknown
}

/** String-resource id for a payout [PayoutMethodType] label, derived from the raw `method` string. */
fun payoutMethodLabelRes(method: String): Int = when (PayoutMethodType.from(method)) {
    PayoutMethodType.BANK_TRANSFER -> R.string.payout_method_bank_transfer
    PayoutMethodType.PAYPAL -> R.string.payout_method_paypal
    PayoutMethodType.CARD -> R.string.payout_method_card
    PayoutMethodType.UNKNOWN -> R.string.payout_method_unknown
}
