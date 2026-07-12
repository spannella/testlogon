package com.testlogon.android.feature.alerts

import androidx.annotation.StringRes
import com.testlogon.android.data.alerts.AlertsPage

/**
 * Single render-ready state for the alerts inbox. One immutable data class (not a sealed hierarchy) so
 * content persists across refresh (show the prior [page] while [isRefreshing]). [phase] enumerates the
 * mutually-exclusive top-level surfaces.
 */
data class AlertsUiState(
    val phase: Phase = Phase.Loading,
    val page: AlertsPage? = null,
    val unreadOnly: Boolean = false,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val isMutating: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Empty, SessionExpired, Error, Offline }

    val unreadCount: Int get() = page?.unreadCount ?: 0
    val hasUnread: Boolean get() = unreadCount > 0
}

/** One-shot side effects (Channel-backed so they are not replayed on rotation). */
sealed interface AlertsEffect {
    data class ShowMessage(@StringRes val resId: Int) : AlertsEffect
}
