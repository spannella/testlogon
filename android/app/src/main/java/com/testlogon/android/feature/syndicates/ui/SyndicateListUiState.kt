package com.testlogon.android.feature.syndicates.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.syndicates.SyndicateOverview

/**
 * AND-361 - render-ready state for the "syndicates the caller belongs to" LIST screen (FR-6).
 *
 * IMPORTANT - NO LIST ENDPOINT: the [com.testlogon.android.core.network.syndicates.SyndicateApi] (AND-356 /
 * AND-357) exposes ONLY by-id reads (GET ui/syndicates/{syndicateId} and its sub-resources); there is NO
 * "list my syndicates" endpoint and the OpenAPI surface for this wave does not define one. The overview is
 * reached by id (via a stub). Rather than INVENT a network endpoint, this state-holder surfaces
 * [NotAvailable] - a first-class "no list endpoint" surface - so the screen can render an informative
 * placeholder. [Content] / [Empty] / [Error] are kept so this contract is ready to light up unchanged the
 * moment a real list endpoint ships (see SyndicateListViewModel KDoc).
 *
 * Sealed so the screen renders mutually-exclusive surfaces; a new variant forces an exhaustive `when`.
 */
sealed interface SyndicateListUiState {

    /** Initial / first-load-with-no-content surface. */
    data object Loading : SyndicateListUiState

    /**
     * Loaded syndicates. Reserved for when a real list endpoint exists; [isRefreshing] is true while a
     * pull-to-refresh re-read is in flight over the already-shown list.
     */
    data class Content(
        val items: List<SyndicateOverview>,
        val isRefreshing: Boolean = false,
    ) : SyndicateListUiState

    /** The read succeeded but the caller belongs to no syndicate (reserved for a real list endpoint). */
    data object Empty : SyndicateListUiState

    /**
     * Terminal surface for THIS wave: the API has no "list my syndicates" endpoint, so a list cannot be
     * fetched. This is NOT an error or an empty roster - it is a known capability gap. FLAG: remove this
     * variant (and switch the ViewModel to the real call) once a GET ui/syndicates list endpoint exists.
     */
    data object NotAvailable : SyndicateListUiState

    /** Terminal failure with no content to show (reserved for a real list endpoint). */
    data class Error(val error: ApiError) : SyndicateListUiState
}
