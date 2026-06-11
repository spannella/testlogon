package com.testlogon.android.feature.affiliates

import androidx.annotation.StringRes
import com.testlogon.android.data.affiliates.AffiliateDashboard

/**
 * AND-265 — single render-ready affiliates-dashboard state.
 *
 * One immutable data class so content persists across refresh. [phase] enumerates the mutually-exclusive
 * top-level surfaces. [selectedChartIndex] drives the reusable chart's tooltip selection.
 */
data class AffiliatesUiState(
    val phase: Phase = Phase.Loading,
    val dashboard: AffiliateDashboard? = null,
    /** Public web origin used to build shareable URLs (build constant). */
    val webOrigin: String = "",
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val selectedChartIndex: Int? = null,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Empty, Error, Offline }

    val canRetry: Boolean get() = phase == Phase.Error || phase == Phase.Offline
}

/** One-shot side effects (AND-265). Channel-backed so they are not replayed on rotation. */
sealed interface AffiliatesEffect {
    data class CopyUrl(val url: String) : AffiliatesEffect
    data class ShareUrl(val url: String) : AffiliatesEffect
    data class ShowMessage(@StringRes val resId: Int) : AffiliatesEffect
}
