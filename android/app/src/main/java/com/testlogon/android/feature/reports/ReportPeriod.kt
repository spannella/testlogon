package com.testlogon.android.feature.reports

import com.testlogon.android.data.exchange.FillFee
import com.testlogon.android.data.exchange.FundingPayment
import com.testlogon.android.data.exchange.Liquidation

/**
 * PURE period scoping for the Export & Reporting surface. A [ReportPeriod] is a rolling look-back
 * window (24h / 7d / 30d) or ALL; [filterFills] (and the sibling helpers) drop any event whose
 * nanosecond tick falls before [cutoffNs] computed from a caller-supplied 'now'. ALL keeps everything.
 *
 * Keeping this pure (no clock, no Android) makes the window boundary unit-testable: the caller passes
 * the reference 'now' in nanoseconds so tests are deterministic.
 */
enum class ReportPeriod(val label: String, private val lookbackNs: Long?) {
    DAY("24h", 24L * 60L * 60L * 1_000_000_000L),
    WEEK("7d", 7L * 24L * 60L * 60L * 1_000_000_000L),
    MONTH("30d", 30L * 24L * 60L * 60L * 1_000_000_000L),
    ALL("All", null);

    /** The inclusive lower-bound tick for this window relative to [nowNs], or 0 for [ALL]. */
    fun cutoffNs(nowNs: Long): Long {
        val lb = lookbackNs ?: return 0L
        val c = nowNs - lb
        return if (c < 0L) 0L else c
    }

    /** True when [tsNs] falls inside this window relative to [nowNs]. */
    fun contains(tsNs: Long, nowNs: Long): Boolean = tsNs >= cutoffNs(nowNs)
}

/** Keep only fills at/after the period cutoff (ALL keeps everything). */
fun filterFills(fills: List<FillFee>, period: ReportPeriod, nowNs: Long): List<FillFee> {
    if (period == ReportPeriod.ALL) return fills
    val cutoff = period.cutoffNs(nowNs)
    return fills.filter { it.tsNs >= cutoff }
}

/** Keep only liquidations at/after the period cutoff. */
fun filterLiquidations(events: List<Liquidation>, period: ReportPeriod, nowNs: Long): List<Liquidation> {
    if (period == ReportPeriod.ALL) return events
    val cutoff = period.cutoffNs(nowNs)
    return events.filter { it.tsNs >= cutoff }
}

/** Keep only funding payments at/after the period cutoff. */
fun filterFunding(payments: List<FundingPayment>, period: ReportPeriod, nowNs: Long): List<FundingPayment> {
    if (period == ReportPeriod.ALL) return payments
    val cutoff = period.cutoffNs(nowNs)
    return payments.filter { it.tsNs >= cutoff }
}

/** Current wall-clock time as a nanosecond tick (epoch millis * 1e6). */
fun nowTicksNs(): Long = System.currentTimeMillis() * 1_000_000L
