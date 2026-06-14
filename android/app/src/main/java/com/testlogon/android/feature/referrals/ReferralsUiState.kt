package com.testlogon.android.feature.referrals

import androidx.annotation.StringRes
import com.testlogon.android.data.referrals.ReferralDashboard

/**
 * AND-264 — single render-ready referrals state.
 *
 * One immutable data class (not a sealed hierarchy) so content persists across refresh — e.g. show the
 * prior [dashboard] while [isRefreshing]. [phase] enumerates the mutually-exclusive top-level surfaces.
 */
data class ReferralsUiState(
    val phase: Phase = Phase.Loading,
    val dashboard: ReferralDashboard? = null,
    /** Public web origin used to build per-code share links (build constant). */
    val webOrigin: String = "",
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val isCreatingCode: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Ineligible, SessionExpired, Error, Offline }

    val canRetry: Boolean get() = phase == Phase.Error || phase == Phase.Offline
}

/**
 * One-shot side effects (AND-264). Channel-backed (see ReferralsViewModel) so they are not replayed on
 * rotation. Clipboard/share carry the already-built link string; messages are [StringRes] ids to keep
 * the ViewModel locale-agnostic (resolved in composable scope).
 */
sealed interface ReferralsEffect {
    data class CopyLink(val link: String) : ReferralsEffect
    data class Share(val link: String) : ReferralsEffect
    data class ShowMessage(@StringRes val resId: Int) : ReferralsEffect
}
