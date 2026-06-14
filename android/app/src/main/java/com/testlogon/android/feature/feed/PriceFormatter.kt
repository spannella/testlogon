package com.testlogon.android.feature.feed

import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

/**
 * AND-101 — formats integer minor units (cents) as a locale-aware currency string. The wire carries no
 * currency code; USD is assumed (web parity). Pure / JVM-unit-testable. Returns null for an unusable
 * input so the UI can fall back to a generic "Unlock" CTA (FR-4 graceful degradation).
 */
object PriceFormatter {

    fun format(amountMinor: Int?, currencyCode: String = "USD", locale: Locale = Locale.US): String? {
        if (amountMinor == null) return null
        return try {
            val currency = Currency.getInstance(currencyCode)
            val nf = NumberFormat.getCurrencyInstance(locale)
            nf.currency = currency
            nf.format(amountMinor / 100.0)
        } catch (_: Exception) {
            null
        }
    }
}
