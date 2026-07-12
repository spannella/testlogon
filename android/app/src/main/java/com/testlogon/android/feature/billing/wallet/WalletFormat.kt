package com.testlogon.android.feature.billing.wallet

import com.testlogon.android.data.billing.BillingMoney
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Currency
import java.util.Date
import java.util.Locale

/**
 * PW18 — pure, JVM-testable wallet money/date formatting (no Android types), mirroring the AND-243
 * InvoiceFormat helpers. Money is integer cents; an unrecognized currency code falls back to a plain
 * "<major> <CODE>" form (never crashes). Dates use [DateFormat]/[Date] (NOT java.time, API26-safe).
 */

/** Locale-formatted currency for a [BillingMoney] (cents/100). Falls back on an unknown currency code. */
fun formatWalletMoney(money: BillingMoney, locale: Locale = Locale.getDefault()): String {
    val amount = money.cents / 100.0
    return try {
        val format = NumberFormat.getCurrencyInstance(locale)
        format.currency = Currency.getInstance(money.currency.uppercase(Locale.ROOT))
        format.format(amount)
    } catch (_: IllegalArgumentException) {
        "%.2f %s".format(locale, amount, money.currency.uppercase(Locale.ROOT))
    }
}

/**
 * Signed transaction amount for a ledger row: credits show a leading "+", debits a leading "-". The
 * sign is derived from the ledger entry `type` ("credit"/"debit"); any other type renders unsigned.
 */
fun formatLedgerAmount(type: String, money: BillingMoney, locale: Locale = Locale.getDefault()): String {
    val base = formatWalletMoney(money, locale)
    return when (type.lowercase(Locale.ROOT)) {
        "credit" -> "+$base"
        "debit" -> "-$base"
        else -> base
    }
}

/** Epoch-seconds -> localized medium date+time string, or null when [epochSeconds] is null. */
fun formatLedgerDate(epochSeconds: Long?, locale: Locale = Locale.getDefault()): String? {
    if (epochSeconds == null) return null
    return DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, locale)
        .format(Date(epochSeconds * 1000L))
}
