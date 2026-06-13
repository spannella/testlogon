package com.testlogon.android.feature.groups

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.groups.Group

/**
 * AND-355 - render-ready state for the social-groups LIST screen (group discovery).
 *
 * Sealed so the screen renders mutually-exclusive surfaces; a new variant forces an exhaustive `when`.
 * [Content] keeps the last-loaded list across a pull-to-refresh; a refresh failure does NOT drop the list
 * - it surfaces a [staleError] banner over the cached content instead (FR resilience).
 */
sealed interface GroupsListUiState {

    /** Initial / first-load surface (no cached content yet). */
    data object Loading : GroupsListUiState

    /** Loaded list of the caller's groups. */
    data class Content(
        val groups: List<Group>,
        /** True while a pull-to-refresh is in flight over already-shown content. */
        val isRefreshing: Boolean = false,
        /** A non-fatal refresh failure surfaced as a banner over the cached list, or null. */
        val staleError: ApiError? = null,
    ) : GroupsListUiState

    /** Loaded successfully but the caller belongs to no groups. */
    data object Empty : GroupsListUiState

    /** Terminal first-load failure (no content to show). */
    data class Error(val error: ApiError) : GroupsListUiState
}
