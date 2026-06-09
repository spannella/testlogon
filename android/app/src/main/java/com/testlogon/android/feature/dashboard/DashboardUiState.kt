package com.testlogon.android.feature.dashboard

import androidx.annotation.StringRes
import com.testlogon.android.core.model.Dashboard

/** Client-defined quick links (server provides no quick-link list). */
enum class QuickLink { Profile, Sessions, Settings, More }

/**
 * AND-068 — single render-ready dashboard state.
 *
 * A single immutable data class (rather than a sealed hierarchy) so content persists across refresh
 * transitions — e.g. show stale [dashboard] while [isRefreshing]. [phase] enumerates the mutually
 * exclusive top-level surfaces.
 */
data class DashboardUiState(
    val phase: Phase = Phase.Loading,
    val dashboard: Dashboard? = null,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Empty, Error }

    /** Cached content shown because the live fetch failed. */
    val isOffline: Boolean get() = isStale && dashboard != null

    val canRetry: Boolean get() = phase == Phase.Error || phase == Phase.Empty
}

/**
 * One-shot side effects (AND-068). Channel-backed (see [DashboardViewModel]) so they are not
 * replayed on rotation. Messages are carried as [StringRes] ids to keep the ViewModel
 * locale-agnostic.
 */
sealed interface DashboardEffect {
    data class ShowMessage(@StringRes val resId: Int) : DashboardEffect
}
