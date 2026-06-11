package com.testlogon.android.feature.promo

import androidx.annotation.StringRes
import com.testlogon.android.data.promo.PromoCode

/**
 * AND-266 — single render-ready promo-codes state.
 *
 * The list is a non-paged in-memory list (the endpoint is not paginated). [phase] enumerates the
 * mutually-exclusive list surfaces; transient create-sheet/submit/banner concerns live alongside.
 */
data class PromoCodesUiState(
    val phase: Phase = Phase.Loading,
    val codes: List<PromoCode> = emptyList(),
    val isRefreshing: Boolean = false,
    val isSheetOpen: Boolean = false,
    val isSubmitting: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Empty, Error, Offline }

    val canRetry: Boolean get() = phase == Phase.Error || phase == Phase.Offline
}

/** One-shot side effects (AND-266). Channel-backed so they are not replayed on rotation. */
sealed interface PromoCodesEffect {
    data class ShowMessage(@StringRes val resId: Int) : PromoCodesEffect
    /** A server/validation message already resolved to a human-readable string. */
    data class ShowError(val message: String) : PromoCodesEffect
}
