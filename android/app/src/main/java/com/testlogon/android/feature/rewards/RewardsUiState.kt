package com.testlogon.android.feature.rewards

import com.testlogon.android.data.rewards.CatalogReward
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
