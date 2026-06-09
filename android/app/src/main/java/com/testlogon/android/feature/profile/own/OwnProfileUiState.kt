package com.testlogon.android.feature.profile.own

import androidx.annotation.StringRes
import com.testlogon.android.core.model.profile.Profile

/**
 * AND-071 / AND-075 — single render-ready own-profile state.
 *
 * One immutable data class (not a sealed hierarchy) so content persists across refresh transitions
 * (show stale [profile] while [isRefreshing]). [phase] enumerates the mutually-exclusive surfaces.
 */
data class OwnProfileUiState(
    val phase: Phase = Phase.Loading,
    val profile: Profile? = null,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }
}

/** One-shot side effects (Channel-backed so they are not replayed on rotation). */
sealed interface OwnProfileEffect {
    data object NavigateToEdit : OwnProfileEffect
    data class ShowMessage(@StringRes val resId: Int) : OwnProfileEffect
}
