package com.testlogon.android.feature.broadcast.privateshow

import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

/**
 * AND-315 — locale-aware money + elapsed formatting for the private-show surfaces (no hardcoded $ strings in
 * the UI). Mirrors the host manage screen's [formatCents] idiom; kept package-local so no shared helper is
 * touched.
 */

/** Locale-aware cents -> currency string; falls back to a plain amount on an unusable currency code. */
internal fun formatCents(
    cents: Long,
    currencyCode: String = "USD",
    locale: Locale = Locale.getDefault(),
): String = runCatching {
    val nf = NumberFormat.getCurrencyInstance(locale)
    nf.currency = Currency.getInstance(currencyCode)
    nf.format(cents / 100.0)
}.getOrElse { (cents / 100.0).toString() }

/** Formats elapsed seconds as HH:MM:SS (or MM:SS under an hour). */
internal fun formatElapsed(totalSeconds: Long): String {
    val s = if (totalSeconds < 0) 0 else totalSeconds
    val hours = s / 3600
    val minutes = (s % 3600) / 60
    val seconds = s % 60
    return if (hours > 0) {
        "%02d:%02d:%02d".format(hours, minutes, seconds)
    } else {
        "%02d:%02d".format(minutes, seconds)
    }
}
