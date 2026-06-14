package com.testlogon.android.data.earnings

/**
 * AND-252 — the combined dashboard snapshot (quick-stats + summary) for one [range].
 *
 * [fetchedAtEpochMs] is the client fetch time (the backend supplies no `as_of` field). [isStale] is
 * set when this snapshot is served from cache after a failed refresh.
 */
data class EarningsDashboard(
    val range: EarningsRange,
    val quickStats: EarningsQuickStats,
    val summary: EarningsSummary,
    val currency: String,
    val fetchedAtEpochMs: Long,
    val isStale: Boolean = false,
) {
    /** True when there is no revenue at all in this window (zero total + empty/all-zero series). */
    val isEmpty: Boolean
        get() = summary.total.cents == 0L && summary.series.all { it.totalCents == 0L }

    fun asStale(): EarningsDashboard = copy(isStale = true)
}
