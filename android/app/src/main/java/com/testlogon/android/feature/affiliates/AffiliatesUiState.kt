package com.testlogon.android.feature.affiliates

import androidx.annotation.StringRes
import com.testlogon.android.data.affiliates.AffiliateDashboard

/**
 * AND-265 — single render-ready affiliates-dashboard state.
 *
 * One immutable data class so content persists across refresh. [phase] enumerates the mutually-exclusive
 * top-level surfaces. [selectedChartIndex] drives the reusable chart's tooltip selection. [createForm]
 * (non-null while the create sheet is open) and [pendingDelete] (non-null while a delete confirm is
 * shown) model the two mutations the dashboard now exposes.
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
    val createForm: CreateForm? = null,
    val pendingDelete: PendingDelete? = null,
) {
    enum class Phase { Loading, Content, Empty, Error, Offline }

    val canRetry: Boolean get() = phase == Phase.Error || phase == Phase.Offline

    /** Editable create-link form. [errorRes] surfaces client-side validation / server errors inline. */
    data class CreateForm(
        val targetType: String = "",
        val targetId: String = "",
        val commissionPercent: String = "",
        val customCode: String = "",
        val submitting: Boolean = false,
        @StringRes val errorRes: Int? = null,
    ) {
        val canSubmit: Boolean get() = !submitting && targetId.isNotBlank()
    }

    /** A link awaiting delete confirmation. */
    data class PendingDelete(val linkId: String, val label: String, val deleting: Boolean = false)
}

/** One-shot side effects (AND-265). Channel-backed so they are not replayed on rotation. */
sealed interface AffiliatesEffect {
    data class CopyUrl(val url: String) : AffiliatesEffect
    data class ShareUrl(val url: String) : AffiliatesEffect
    data class ShowMessage(@StringRes val resId: Int) : AffiliatesEffect
}
