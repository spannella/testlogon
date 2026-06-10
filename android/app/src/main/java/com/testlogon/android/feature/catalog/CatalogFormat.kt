package com.testlogon.android.feature.catalog

import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

/**
 * AND-205 — pure, JVM-testable price formatter (no Android types). Maps integer minor units
 * (price_cents) + an ISO-4217 currency code into a locale-formatted label via
 * NumberFormat.getCurrencyInstance, e.g. (1999, "USD", en-US) -> "$19.99".
 *
 * A currency code the JVM does not recognize falls back to a plain "<major>.<minor> <CODE>" form so the
 * UI never crashes on an exotic/unknown currency.
 */
fun formatPrice(priceCents: Long, currency: String, locale: Locale = Locale.getDefault()): String {
    val amount = priceCents / 100.0
    return try {
        val format = NumberFormat.getCurrencyInstance(locale)
        format.currency = Currency.getInstance(currency)
        format.format(amount)
    } catch (_: IllegalArgumentException) {
        "%.2f %s".format(locale, amount, currency)
    }
}
