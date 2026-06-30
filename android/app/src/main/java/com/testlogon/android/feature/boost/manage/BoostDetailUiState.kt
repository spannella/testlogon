package com.testlogon.android.feature.boost.manage

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ads.ContentBoost

/**
 * Hoisted UI state for the BOOST DETAIL screen (web parity: ContentBoostDetail.tsx).
 *
 *  - [Loading] - the boost load is in flight.
 *  - [Error]   - a fatal load failure (e.g. boost not found); retryable.
 *  - [Content] - the loaded [boost]. [canCancel] is true only while the boost is active (Cancel + refund).
 *    [cancelling] / [refreshing] drive progress affordances; [actionError] surfaces a transient
 *    cancel/refresh failure without leaving the detail view; [cancelledRefundCents] holds the refund amount
 *    after a successful cancel (shown as a confirmation).
 */
sealed interface BoostDetailUiState {

    data object Loading : BoostDetailUiState

    data class Error(val error: ApiError) : BoostDetailUiState

    data class Content(
        val boost: ContentBoost,
        val canCancel: Boolean = false,
        val cancelling: Boolean = false,
        val refreshing: Boolean = false,
        val actionError: String? = null,
        val cancelledRefundCents: Long? = null,
    ) : BoostDetailUiState
}
