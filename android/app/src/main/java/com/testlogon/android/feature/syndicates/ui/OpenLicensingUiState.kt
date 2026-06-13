package com.testlogon.android.feature.syndicates.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.syndicates.LicensingContentType
import com.testlogon.android.core.model.syndicates.OpenLicensingContent

/**
 * AND-357 - render-ready state for the open-licensing sub-screen (a sub-surface of the AND-356 syndicate
 * overview).
 *
 * The list is NOT paginated (a single bounded {items} page), so [Content] carries the whole list in-memory;
 * [Content.isRefreshing] drives the pull-to-refresh spinner. Sealed so the screen renders mutually-exclusive
 * surfaces and a new variant forces an exhaustive `when`.
 *
 * The register FORM is a SEPARATE sub-state ([RegisterFormState]) carried on the same UiState so the form can
 * stay open over a list reload: on a successful register the form closes + [RegisterFormState.lastResult]
 * holds licenses_created and the list is REFETCHED (never optimistically prepended); on a 422 the form stays
 * open with per-field inline errors mapped by the FastAPI detail loc tail; on any other failure the form stays
 * open with a single retryable [RegisterFormState.submitError].
 */
sealed interface OpenLicensingUiState {

    /** The register-form sub-state, surfaced on every variant so the form survives a list reload. */
    val form: RegisterFormState

    /** Initial first-load surface (no list yet). */
    data class Loading(
        override val form: RegisterFormState = RegisterFormState(),
    ) : OpenLicensingUiState

    /** Loaded list of open-licensing content rows; [isRefreshing] drives pull-to-refresh. */
    data class Content(
        val items: List<OpenLicensingContent>,
        val isRefreshing: Boolean = false,
        override val form: RegisterFormState = RegisterFormState(),
    ) : OpenLicensingUiState

    /** Loaded but the syndicate has NO open-licensing content yet (prominent register CTA). */
    data class Empty(
        override val form: RegisterFormState = RegisterFormState(),
    ) : OpenLicensingUiState

    /** Terminal first-load failure of the list (no list to show). */
    data class Error(
        val error: ApiError,
        override val form: RegisterFormState = RegisterFormState(),
    ) : OpenLicensingUiState
}

/**
 * AND-357 - the register-content form sub-state.
 *
 * [visible] gates the dialog / sheet. [isValid] gates the submit button (a non-blank content id AND a chosen
 * type). [submitting] shows the spinner. [contentIdError] / [contentTypeError] are inline per-field messages
 * (populated from a 422 detail by loc tail). [submitError] is the single retryable banner for any non-422
 * failure. [lastResult] holds the licenses_created count from the most recent successful register (success
 * feedback); it is set ONLY on success.
 */
data class RegisterFormState(
    val visible: Boolean = false,
    val contentId: String = "",
    val contentType: LicensingContentType? = null,
    val submitting: Boolean = false,
    val contentIdError: String? = null,
    val contentTypeError: String? = null,
    val submitError: String? = null,
    val lastResult: Int? = null,
) {
    /** Submit is enabled only with a non-blank content id AND a chosen content type (and not submitting). */
    val isValid: Boolean
        get() = contentId.trim().isNotEmpty() && contentType != null
}
