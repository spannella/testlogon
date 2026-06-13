package com.testlogon.android.feature.orgs

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.orgs.Org

/**
 * AND-361 - render-ready state for the caller's ORGANIZATIONS LIST screen (FR-1).
 *
 * Sealed so the screen renders mutually-exclusive surfaces; a new variant forces an exhaustive `when`.
 * [Content] carries the caller's organizations (from listOrgs / GET ui/orgs - the OrgOut row also carries
 * the caller's role). [Empty] is DISTINCT from [Error]: Empty means the read succeeded but the caller
 * belongs to NO organization, whereas Error is a terminal read failure with no content to show.
 *
 * REUSE: this is the genuinely-missing LIST state-holder. The OVERVIEW hub (single org, member count,
 * caller role) is OrgOverviewUiState [AND-354] and is NOT duplicated here.
 */
sealed interface OrgListUiState {

    /** Initial / first-load-with-no-content surface. */
    data object Loading : OrgListUiState

    /**
     * Loaded organizations. [isRefreshing] is true while a pull-to-refresh re-read is in flight over the
     * already-shown list (the prior [orgs] stay visible under the refresh indicator).
     */
    data class Content(
        val orgs: List<Org>,
        val isRefreshing: Boolean = false,
    ) : OrgListUiState

    /** The read succeeded but the caller belongs to no organization (distinct from [Error]). */
    data object Empty : OrgListUiState

    /** Terminal failure with no content to show. */
    data class Error(val error: ApiError) : OrgListUiState
}
