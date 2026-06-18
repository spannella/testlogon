package com.testlogon.android.feature.ideas

import androidx.annotation.StringRes
import com.testlogon.android.data.ideas.IdeasPage

/**
 * Single render-ready state for the "Ideas" screen. One immutable data class (not a sealed hierarchy)
 * so content persists across refresh (show the prior [page] while [isRefreshing]). [phase] enumerates
 * the mutually-exclusive top-level surfaces; [submit] carries the dialog-form state for filing a new
 * idea. Mirrors the web ideas/submit page (a submit form + a list of the member's own ideas).
 */
data class IdeasUiState(
    val phase: Phase = Phase.Loading,
    val page: IdeasPage? = null,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val errorMessage: String? = null,
    val submit: SubmitFormState = SubmitFormState(),
) {
    enum class Phase { Loading, Content, Empty, SessionExpired, Error, Offline }
}

/**
 * State for the submit-idea form. [isOpen] drives the dialog; [title] / [description] are the two
 * fields; [isSubmitting] disables the form during the POST. [canSubmit] gates the confirm button and
 * mirrors the web validation (title >= 3 chars, description >= 10 chars, both trimmed).
 */
data class SubmitFormState(
    val isOpen: Boolean = false,
    val title: String = "",
    val description: String = "",
    val isSubmitting: Boolean = false,
) {
    val canSubmit: Boolean
        get() = !isSubmitting && title.trim().length >= MIN_TITLE && description.trim().length >= MIN_DESCRIPTION

    private companion object {
        private const val MIN_TITLE = 3
        private const val MIN_DESCRIPTION = 10
    }
}

/** One-shot side effects (Channel-backed so they are not replayed on rotation). */
sealed interface IdeasEffect {
    data class ShowMessage(@StringRes val resId: Int) : IdeasEffect
}
