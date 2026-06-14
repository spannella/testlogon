package com.testlogon.android.feature.taxforms

import com.testlogon.android.data.taxforms.Form1099Money
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Currency
import java.util.Date
import java.util.Locale

/**
 * AND-247 — pure, JVM-testable 1099 money/date/filename formatting (no Android types), mirroring the
 * AND-243 InvoiceFormat helpers. Money is integer cents; an unknown currency code falls back to a plain
 * "<major> <CODE>" form (never crashes). Dates use [DateFormat]/[Date] (NOT java.time / API26+).
 */

/** Locale-formatted currency for a [Form1099Money] (cents/100). Falls back on an unknown currency code. */
fun formatForm1099Money(money: Form1099Money, locale: Locale = Locale.getDefault()): String {
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
fun formatForm1099Date(epochSeconds: Long?, locale: Locale = Locale.getDefault()): String? {
    if (epochSeconds == null) return null
    return DateFormat.getDateInstance(DateFormat.MEDIUM, locale).format(Date(epochSeconds * 1000L))
}

/**
 * AND-247 FR-6 — the downloaded-file name for a 1099-NEC. Form type is always NEC and the tax year
 * uniquely identifies the form per user, so there is no type/formId segment, e.g.
 * `TestLogon_1099-NEC_2025.pdf`.
 */
fun form1099FileName(taxYear: Int): String = "TestLogon_1099-NEC_$taxYear.pdf"
