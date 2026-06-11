package com.testlogon.android.feature.earnings

import androidx.annotation.StringRes
import com.testlogon.android.data.earnings.EarningsDashboard
import com.testlogon.android.data.earnings.EarningsRange

/** Chart presentation toggle (session-only). */
enum class ChartType { LINE, BAR }

/**
 * AND-252 — single render-ready earnings-dashboard state.
 *
 * A single immutable data class (rather than a sealed hierarchy) so content persists across refresh /
 * range transitions — e.g. show the prior [dashboard] while [isRefreshing]. [phase] enumerates the
 * mutually-exclusive top-level surfaces.
 */
data class EarningsUiState(
    val range: EarningsRange = EarningsRange.DEFAULT,
    val phase: Phase = Phase.Loading,
    val dashboard: EarningsDashboard? = null,
    val chartType: ChartType = ChartType.LINE,
    val selectedPoint: Int? = null,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Empty, Error, Offline }

    val canRetry: Boolean get() = phase == Phase.Error || phase == Phase.Offline
}

/**
 * One-shot side effects (AND-252). Channel-backed (see EarningsViewModel) so they are not replayed on
 * rotation. Messages are carried as [StringRes] ids to keep the ViewModel locale-agnostic.
 */
sealed interface EarningsEffect {
    data class ShowMessage(@StringRes val resId: Int) : EarningsEffect
}
