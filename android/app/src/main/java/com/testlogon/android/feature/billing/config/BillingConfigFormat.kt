package com.testlogon.android.feature.billing.config

import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

/**
 * AND-248 — pure, JVM-testable billing-config formatting (no Android UI types).
 *
 *  - bps -> percent: `bps / 100` to one decimal, e.g. 250 -> "2.5%" (matches web `bpsToPct`).
 *  - cents -> locale currency via [NumberFormat.getCurrencyInstance] over `cents / 100`, seeded from the
 *    config's default currency; an unknown ISO code falls back to "<major> <CODE>" (never crashes).
 */

/** Basis points -> a one-decimal percentage string, e.g. 250 -> "2.5%". */
fun formatBps(bps: Int, locale: Locale = Locale.getDefault()): String {
    val pct = bps / 100.0
    return "%.1f%%".format(locale, pct)
}

/** Integer cents -> locale currency seeded from [currencyCode] (ISO-4217). Falls back on unknown codes. */
fun formatConfigCents(cents: Long, currencyCode: String, locale: Locale = Locale.getDefault()): String {
    val amount = cents / 100.0
    return try {
        val format = NumberFormat.getCurrencyInstance(locale)
        format.currency = Currency.getInstance(currencyCode.uppercase(Locale.ROOT))
        format.format(amount)
    } catch (_: IllegalArgumentException) {
        "%.2f %s".format(locale, amount, currencyCode.uppercase(Locale.ROOT))
    }
}
