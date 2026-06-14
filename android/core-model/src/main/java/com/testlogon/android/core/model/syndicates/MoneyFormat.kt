package com.testlogon.android.core.model.syndicates

import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

/**
 * AND-356 - pure, JVM-testable money formatter for the syndicate treasury / split surfaces.
 *
 * Maps integer minor units (*_cents) + an ISO-4217 currency code into a locale-formatted label via
 * NumberFormat.getCurrencyInstance, e.g. (1999, "USD", en-US) -> "$19.99". An exotic / unrecognized
 * currency falls back to a plain "<major>.<minor> CODE" form so the UI never crashes (mirrors the AND-205
 * formatPrice helper, lifted to core-model since the syndicate surface lives across modules and core-model
 * has no Android dependency).
 *
 * The currency code is upper-cased defensively (the wire ships lowercase ISO; the mapper already
 * upper-cases, but this keeps the helper self-contained).
 */
fun formatCents(cents: Int, currency: String, locale: Locale = Locale.getDefault()): String =
    formatCents(cents.toLong(), currency, locale)

/**
 * AND-364 - overflow-proof [Long] overload (the content-boost / ads surface ships *_cents as Long to avoid
 * Int overflow). [currency] defaults to USD because the boost contract bills implicitly in integer USD
 * cents (no currency field on the wire). Same locale-aware formatting + plain-string fallback as the Int
 * form; the Int overload now delegates here so both share one implementation.
 */
fun formatCents(cents: Long, currency: String = "USD", locale: Locale = Locale.getDefault()): String {
    val amount = cents / 100.0
    val code = currency.trim().uppercase(Locale.ROOT)
    return try {
        val format = NumberFormat.getCurrencyInstance(locale)
        format.currency = Currency.getInstance(code)
        format.format(amount)
    } catch (_: IllegalArgumentException) {
        "%.2f %s".format(locale, amount, code)
    }
}
