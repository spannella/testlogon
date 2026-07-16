package com.testlogon.android.feature.subscriptions

import com.testlogon.android.data.subscriptions.BillingInterval
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Currency
import java.util.Date
import java.util.Locale

/**
 * AND-235 — pure, JVM-testable subscription price/interval formatting (no Android types).
 *
 * Mirrors the catalog's [com.testlogon.android.feature.catalog.formatPrice] (NumberFormat with the
 * currency forced to the tier's ISO-4217 code), with two Android product choices:
 *  - a `priceCents == 0` tier renders the localized "Free" label (the web client has no Free case);
 *  - an unrecognized currency code falls back to a plain "<major> <CODE>" form (never crashes).
 */

/** Locale-formatted price, or [freeLabel] when [priceCents] is 0. */
fun formatTierPrice(
    priceCents: Long,
    currency: String,
    freeLabel: String,
    locale: Locale = Locale.getDefault(),
): String {
    if (priceCents == 0L) return freeLabel
    val amount = priceCents / 100.0
    return try {
        val format = NumberFormat.getCurrencyInstance(locale)
        format.currency = Currency.getInstance(currency)
        format.format(amount)
    } catch (_: IllegalArgumentException) {
        "%.2f %s".format(locale, amount, currency)
    }
}

/**
 * SUBX-24 — monthly-equivalent price (cents) for cross-interval up/downgrade classification: a $50/yr
 * plan should NOT be labelled an "upgrade" over an $8/mo plan by raw price. Yearly /12, weekly *52/12,
 * monthly/unknown as-is. Pure + JVM-testable (mirrors the backend M5 monthly-equiv fix).
 */
fun monthlyEquivCents(priceCents: Long, interval: BillingInterval): Long = when (interval) {
    BillingInterval.YEAR -> priceCents / 12
    BillingInterval.WEEK -> (priceCents * 52) / 12
    BillingInterval.MONTH, BillingInterval.UNKNOWN -> priceCents
}

/** Suffix label for a billing interval, e.g. "/month". Empty for free tiers / unknown intervals. */
fun intervalSuffix(interval: BillingInterval, monthLabel: String, yearLabel: String, weekLabel: String): String =
    when (interval) {
        BillingInterval.MONTH -> monthLabel
        BillingInterval.YEAR -> yearLabel
        BillingInterval.WEEK -> weekLabel
        BillingInterval.UNKNOWN -> ""
    }

/**
 * AND-237 — pure, JVM-testable epoch-seconds -> localized medium date string (renewal / period-end).
 *
 * Uses [DateFormat] / [Date] (NOT java.time, which is API26+) so this stays runnable in plain JVM unit
 * tests. Returns null when [epochSeconds] is null so callers can render a fallback label.
 */
fun formatEpochDate(epochSeconds: Long?, locale: Locale = Locale.getDefault()): String? {
    if (epochSeconds == null) return null
    val df = DateFormat.getDateInstance(DateFormat.MEDIUM, locale)
    return df.format(Date(epochSeconds * 1000L))
}
