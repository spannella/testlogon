package com.testlogon.android.feature.boost

import com.testlogon.android.core.model.ads.ContentBoost

/**
 * AND-364 - hoisted UI state for the content-boost screen. Four variants:
 *  - [Loading] - the initial cache lookup (Form vs. Status) is in flight.
 *  - [Form]    - pick a total budget + duration, then submit.
 *  - [Status]  - watch the created boost; Cancel + refund offered only while [canCancel].
 *  - [Error]   - a fatal load problem (e.g. no post id); retryable.
 */
sealed interface BoostUiState {

    data object Loading : BoostUiState

    /**
     * The budget / duration entry form. [budgetText] / [durationMinutesText] are the raw user entries;
     * [budgetCents] (USD -> cents) and [durationSeconds] (minutes -> seconds) are the parsed values that go
     * on the wire. [canSubmit] is true only when there is a post id and both parsed values are at least 1.
     */
    data class Form(
        val budgetText: String,
        val durationMinutesText: String,
        val budgetCents: Long,
        val durationSeconds: Long,
        val canSubmit: Boolean = false,
        val submitting: Boolean = false,
        val error: String? = null,
    ) : BoostUiState

    /**
     * The status view for a created [boost]. [refreshing] covers a manual refresh / cancel / poll tick in
     * flight; [canCancel] is true only while the boost is active (Cancel + refund). [error] surfaces a
     * non-fatal refresh / cancel failure without leaving the status view.
     */
    data class Status(
        val boost: ContentBoost,
        val refreshing: Boolean = false,
        val canCancel: Boolean = false,
        val error: String? = null,
    ) : BoostUiState

    /** A fatal, retryable load error (message already user-facing). */
    data class Error(val message: String) : BoostUiState
}
