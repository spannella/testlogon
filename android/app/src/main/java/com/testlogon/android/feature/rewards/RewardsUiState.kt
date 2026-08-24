package com.testlogon.android.feature.rewards

import com.testlogon.android.data.rewards.CatalogReward
import com.testlogon.android.data.rewards.LeaderboardEntry
import com.testlogon.android.data.rewards.LeaderboardPeriod
import com.testlogon.android.data.rewards.ReferralLeaderboard
import com.testlogon.android.data.rewards.Rewards
import com.testlogon.android.data.rewards.RewardsHistoryEntry
import com.testlogon.android.data.rewards.ReferralSummary
import com.testlogon.android.data.rewards.ReferredUser

/**
 * UI state + one-shot effects for the REFERRALS and REWARDS screens (feature/rewards). Both screens
 * degrade-on-404 to an honest "coming soon" empty state (available=false), surface a transport failure
 * as a retryable error, and gate the (money-moving) redeem behind a confirm in the UI.
 */

// ---- Referral screen ----

data class ReferralHubUiState(
    val loading: Boolean = true,
    /** False when GET me/referral degraded (404 / undeployed) — the screen shows a coming-soon state. */
    val available: Boolean = true,
    val summary: ReferralSummary = ReferralSummary.unavailable(),
    val referrals: List<ReferredUser> = emptyList(),
    val errorMessage: String? = null,
    val offline: Boolean = false,
) {
    /** There is something worth sharing when the read succeeded and a code/link exists. */
    val hasShareable: Boolean get() = available && (summary.link.isNotBlank() || summary.code.isNotBlank())
}

// ---- Referral leaderboard screen ----

data class ReferralLeaderboardUiState(
    val loading: Boolean = true,
    /** The currently-selected time window (All-time / This month). */
    val period: LeaderboardPeriod = LeaderboardPeriod.ALL,
    /** False when GET me/referral/leaderboard degraded (404 / undeployed) — the screen shows coming-soon. */
    val available: Boolean = true,
    val board: ReferralLeaderboard = ReferralLeaderboard.unavailable(),
    /** The top-N slice actually rendered (server-ranked, repaired for order). */
    val shown: List<LeaderboardEntry> = emptyList(),
    /** The pinned "Your rank: #N" row when the caller falls outside [shown]; null otherwise. */
    val youRow: LeaderboardEntry? = null,
    val errorMessage: String? = null,
    val offline: Boolean = false,
) {
    /** True when the board has at least one visible row (top slice or the pinned own-rank row). */
    val hasRows: Boolean get() = shown.isNotEmpty() || youRow != null
    val updatedTs: Long get() = board.updatedTs
}

// ---- Rewards screen ----

data class RewardsUiState(
    val loading: Boolean = true,
    /** False when GET me/rewards degraded (404 / undeployed) — the screen shows a coming-soon state. */
    val available: Boolean = true,
    val rewards: Rewards = Rewards.unavailable(),
    val catalog: List<CatalogReward> = emptyList(),
    val history: List<RewardsHistoryEntry> = emptyList(),
    val redeeming: Boolean = false,
    val errorMessage: String? = null,
    val successMessage: String? = null,
    val offline: Boolean = false,
) {
    val points: Long get() = rewards.points
}

/** One-shot side effects handled by the Route (never replayed on rotation). */
sealed interface RewardsEffect {
    data class ShareText(val text: String) : RewardsEffect
    data class CopyText(val text: String) : RewardsEffect
    data class Toast(val message: String) : RewardsEffect
}
