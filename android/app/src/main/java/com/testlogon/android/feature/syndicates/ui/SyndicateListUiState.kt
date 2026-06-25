package com.testlogon.android.feature.syndicates.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.syndicates.SyndicateListItem

/**
 * Batch-7 - render-ready state for the "syndicates the caller belongs to" LIST screen.
 *
 * A real list endpoint now exists (GET ui/syndicates -> a bare array), so this surfaces
 * Content / Empty / Error (the legacy [NotAvailable] is retained only for backward source-compat and is no
 * longer emitted). The create-syndicate dialog is carried as an independent [CreateSyndicateFormState] in
 * the ViewModel, NOT in this sealed surface.
 *
 * Sealed so the screen renders mutually-exclusive surfaces; a new variant forces an exhaustive `when`.
 */
sealed interface SyndicateListUiState {

    /** Initial / first-load-with-no-content surface. */
    data object Loading : SyndicateListUiState

    /** Loaded syndicates. [isRefreshing] is true while a pull-to-refresh re-read is in flight. */
    data class Content(
        val items: List<SyndicateListItem>,
        val isRefreshing: Boolean = false,
        val staleError: ApiError? = null,
    ) : SyndicateListUiState

    /** The read succeeded but the caller belongs to no syndicate. */
    data object Empty : SyndicateListUiState

    /** Retained for source-compat with older tests; no longer emitted now a list endpoint exists. */
    data object NotAvailable : SyndicateListUiState

    /** Terminal first-load failure (no content to show). */
    data class Error(val error: ApiError) : SyndicateListUiState
}

/**
 * Batch-7 - the create-syndicate dialog sub-state. [isValid] enforces the server's 2..100 char name;
 * description is optional.
 */
data class CreateSyndicateFormState(
    val visible: Boolean = false,
    val name: String = "",
    val description: String = "",
    val submitting: Boolean = false,
    val nameError: String? = null,
    val submitError: String? = null,
) {
    val isValid: Boolean get() = name.trim().length in 2..100
}
