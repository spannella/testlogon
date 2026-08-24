package com.testlogon.android.feature.rewards

import com.testlogon.android.data.rewards.PointsExpiryLot
import com.testlogon.android.data.rewards.RewardsHistoryEntry

/**
 * UI state for the POINTS STATEMENT + EXPIRY screen (feature/rewards). The screen shows the current
 * points balance, an "expiring soon" banner (authoritative from GET me/rewards/expiry when present,
 * else client-computed FIFO from the rewards history with an "Est." badge), the 12-month expiry-policy
 * note, a running-balance statement table with a period filter + Share/Copy CSV, and the upcoming
 * expirations list. Reads degrade-on-404 to an honest empty state; a transport failure is retryable.
 */
data class PointsStatementUiState(
    val loading: Boolean = true,
    /** False when the rewards balance read degraded (404 / undeployed) — the screen shows coming-soon. */
    val available: Boolean = true,
    /** Current points balance (server-authoritative from GET me/rewards). */
    val points: Long = 0L,
    /** Lifetime points earned (server-authoritative), shown as context. */
    val lifetimePoints: Long = 0L,
    /** The full history the statement + client expiry are computed from. */
    val history: List<RewardsHistoryEntry> = emptyList(),
    /** All statement rows (newest first), before the period filter. */
    val allRows: List<PointsExpiryMath.StatementRow> = emptyList(),
    /** The currently-selected statement period (All / This year / This month). */
    val period: PointsExpiryMath.StatementPeriod = PointsExpiryMath.StatementPeriod.ALL,
    /** The rows actually shown = [allRows] filtered by [period]. */
    val rows: List<PointsExpiryMath.StatementRow> = emptyList(),
    /** The resolved expiry picture (authoritative when present, else client estimate). */
    val expiryPolicyMonths: Int = PointsExpiryMath.EXPIRY_MONTHS,
    val expiringSoonPoints: Long = 0L,
    val nextExpiryTs: Long = 0L,
    val nextExpiryPoints: Long = 0L,
    /** Upcoming per-lot expirations (soonest first). */
    val upcoming: List<PointsExpiryLot> = emptyList(),
    /** True when the expiry picture came from the CLIENT computation (badge "Est."), false when authoritative. */
    val expiryEstimated: Boolean = true,
    /** CSV for the currently-shown (period-filtered) statement, ready for the share sheet / clipboard. */
    val csv: String = "",
    val csvName: String = "points-statement",
    val errorMessage: String? = null,
    val offline: Boolean = false,
) {
    /** True when there is a non-zero expiring-soon total worth surfacing in the banner. */
    val hasExpiringSoon: Boolean get() = expiringSoonPoints > 0L && nextExpiryTs > 0L

    /** True when the shown statement has at least one row (post period filter). */
    val hasRows: Boolean get() = rows.isNotEmpty()

    /** Honest "nothing yet" state: available, not loading/offline, and no activity at all. */
    val isEmpty: Boolean
        get() = available && !loading && !offline && errorMessage == null && allRows.isEmpty()
}

/** One-shot side effects handled by the Route (never replayed on rotation). */
sealed interface PointsStatementEffect {
    data class CopyCsv(val text: String) : PointsStatementEffect
}
