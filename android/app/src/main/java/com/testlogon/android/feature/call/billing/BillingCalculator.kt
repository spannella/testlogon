package com.testlogon.android.feature.call.billing

/**
 * AND-301 — pure (android-free, JVM-testable) money helpers for the 1:1 call billing layer.
 *
 * No android.*, no Compose, no java.time. Money is Int CENTS, USD. [formatCents] builds the currency
 * string MANUALLY (cents/100 dollars + zero-padded cents) so it is locale-agnostic and does not depend on
 * android.icu / a Locale-dependent currency formatter that would break plain JVM unit tests.
 */
object BillingCalculator {

    /**
     * The LOCAL running-cost estimate bridging server heartbeats: ceil(elapsedSeconds / 60) * rate.
     * Returns 0 when [rateCentsPerMinute] <= 0 (free call) or [elapsedSeconds] <= 0.
     */
    fun estimateCents(elapsedSeconds: Long, rateCentsPerMinute: Int): Int {
        if (rateCentsPerMinute <= 0 || elapsedSeconds <= 0L) return 0
        val minutes = (elapsedSeconds + 59L) / 60L // ceil(elapsed / 60)
        return (minutes * rateCentsPerMinute).toInt()
    }

    /** Formats CENTS as locale-agnostic USD, e.g. 5 -> "$0.05", 120 -> "$1.20", 0 -> "$0.00". */
    fun formatCents(cents: Int): String {
        val safe = if (cents < 0) 0 else cents
        val dollars = safe / 100
        val remainder = safe % 100
        return "$" + dollars.toString() + "." + remainder.toString().padStart(2, '0')
    }
}
