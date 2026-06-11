package com.testlogon.android.feature.taxdocs

import com.testlogon.android.data.taxdocs.TaxMoney
import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

/**
 * AND-246 — pure, JVM-testable tax money formatting (no Android UI types). Money is integer cents; an
 * unknown currency code falls back to "<major> <CODE>".
 */
fun formatTaxMoney(money: TaxMoney, locale: Locale = Locale.getDefault()): String {
    val amount = money.cents / 100.0
    return try {
        val format = NumberFormat.getCurrencyInstance(locale)
        format.currency = Currency.getInstance(money.currency.uppercase(Locale.ROOT))
        format.format(amount)
    } catch (_: IllegalArgumentException) {
        "%.2f %s".format(locale, amount, money.currency.uppercase(Locale.ROOT))
    }
}
