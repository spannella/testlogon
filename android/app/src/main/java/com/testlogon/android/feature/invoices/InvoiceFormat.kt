package com.testlogon.android.feature.invoices

import com.testlogon.android.data.invoices.InvoiceMoney
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Currency
import java.util.Date
import java.util.Locale

/**
 * AND-243 — pure, JVM-testable invoice money/date formatting (no Android types), mirroring the AND-235
 * SubscriptionFormat helpers. Money is integer cents; an unrecognized currency code falls back to a
 * plain "<major> <CODE>" form (never crashes). Dates use [DateFormat]/[Date] (NOT java.time, API26+).
 */

/** Locale-formatted currency for an [InvoiceMoney] (cents/100). Falls back on an unknown currency code. */
fun formatInvoiceMoney(money: InvoiceMoney, locale: Locale = Locale.getDefault()): String {
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
fun formatInvoiceDate(epochSeconds: Long?, locale: Locale = Locale.getDefault()): String? {
    if (epochSeconds == null) return null
    return DateFormat.getDateInstance(DateFormat.MEDIUM, locale).format(Date(epochSeconds * 1000L))
}
