package com.testlogon.android.feature.appeals

import androidx.annotation.StringRes
import com.testlogon.android.data.appeals.AppealsPage

/**
 * Single render-ready state for the "My appeals" screen. One immutable data class (not a sealed
 * hierarchy) so content persists across refresh (show the prior [page] while [isRefreshing]). [phase]
 * enumerates the mutually-exclusive top-level surfaces; [submit] carries the bottom-sheet/dialog form
 * state for filing a new appeal.
 */
data class AppealsUiState(
    val phase: Phase = Phase.Loading,
    val page: AppealsPage? = null,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val isMutating: Boolean = false,
    val errorMessage: String? = null,
    val submit: SubmitFormState = SubmitFormState(),
) {
    enum class Phase { Loading, Content, Empty, SessionExpired, Error, Offline }
}

/**
 * State for the submit-appeal form. [isOpen] drives the dialog; [enforcementId] / [appealText] are the
 * two fields; [isSubmitting] disables the form during the POST. [canSubmit] gates the confirm button.
 */
data class SubmitFormState(
    val isOpen: Boolean = false,
    val enforcementId: String = "",
    val appealText: String = "",
    val isSubmitting: Boolean = false,
) {
    val canSubmit: Boolean
        get() = !isSubmitting && enforcementId.isNotBlank() && appealText.isNotBlank()
}

/** One-shot side effects (Channel-backed so they are not replayed on rotation). */
sealed interface AppealsEffect {
    data class ShowMessage(@StringRes val resId: Int) : AppealsEffect
}
