package com.testlogon.android.feature.purchases

import com.testlogon.android.data.purchases.Money
import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

/**
 * AND-219 / AND-220 — pure, JVM-testable money + date formatting for the purchases surface (no Android
 * types so it stays unit-testable). Mirrors AND-205 CatalogFormat's NumberFormat/Currency approach, but
 * the purchases `amount` is a major-unit decimal ([Money.amount] BigDecimal) — NOT integer cents — so it
 * formats the decimal directly (do NOT divide by 100). An unrecognized currency code falls back to a
 * plain "<amount> <CODE>" form so an exotic/unknown currency never crashes the UI.
 */
fun formatMoney(money: Money, locale: Locale = Locale.getDefault()): String {
    return try {
        val format = NumberFormat.getCurrencyInstance(locale)
        format.currency = Currency.getInstance(money.currency)
        format.format(money.amount)
    } catch (_: IllegalArgumentException) {
        "${money.amount.toPlainString()} ${money.currency}"
    }
}

/**
 * AND-219 / AND-220 — formats a Long epoch-SECONDS timestamp to a locale medium date. Uses
 * java.text.DateFormat / Date (JVM-available; avoids the API-26 java.time gate and stays unit-testable).
 */
fun formatEpochSeconds(epochSec: Long, locale: Locale = Locale.getDefault()): String {
    val date = java.util.Date(epochSec * 1000L)
    return java.text.DateFormat.getDateInstance(java.text.DateFormat.MEDIUM, locale).format(date)
}
