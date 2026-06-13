package com.testlogon.android.feature.kyc.liveness

import com.testlogon.android.feature.kyc.liveness.model.LivenessCall

// AND-324 - UI state for the KYC scheduled liveness (video-verification) call screen.

/**
 * The single immutable UI state for the liveness-call flow (a plain MutableStateFlow drives it; there is
 * NO poll / delay loop — status is refreshed only on explicit refresh / pull-to-refresh).
 *
 * - [Loading]  the initial single list fetch is in flight.
 * - [Ready]    the user's calls plus the schedule-form sub-state ([scheduling] guards the debounce;
 *              [formError] surfaces a 422 / validation message inline on the form).
 * - [Error]    a non-form-level failure (e.g. blank caseId, or a list-load failure); [recoverable]
 *              drives whether a retry affordance is shown.
 */
sealed interface LivenessUiState {

    data object Loading : LivenessUiState

    data class Ready(
        val calls: List<LivenessCall> = emptyList(),
        val scheduling: Boolean = false,
        val formError: String? = null,
    ) : LivenessUiState

    data class Error(
        val message: String,
        val recoverable: Boolean,
    ) : LivenessUiState
}
