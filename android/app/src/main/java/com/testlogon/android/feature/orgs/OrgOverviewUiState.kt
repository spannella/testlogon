package com.testlogon.android.feature.orgs

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.orgs.Org
import com.testlogon.android.core.model.orgs.OrgRole

/**
 * AND-354 - render-ready state for the org OVERVIEW hub screen.
 *
 * Sealed so the screen renders mutually-exclusive surfaces; a new variant forces an exhaustive `when`.
 * [Content] is derived from listOrgs (the OrgOut row -> [org] + the caller's [callerRole]) plus
 * listMembers().size ([memberCount]); there is NO GET ui/orgs/{orgId} detail endpoint - the overview is
 * composed CLIENT-side from the two list reads.
 *
 * Resilience (FR-9): when a refresh fails but cached content is still in hand, the ViewModel keeps the
 * [Content] surface and flips [isStale] = true so the screen can show a stale banner over the content.
 */
sealed interface OrgOverviewUiState {

    /** Initial / reloading-with-no-content surface. */
    data object Loading : OrgOverviewUiState

    /** Loaded org overview. [memberCount] is null when the roster read failed but the org row resolved. */
    data class Content(
        val org: Org,
        val memberCount: Int?,
        val callerRole: OrgRole,
        /** True when content is cached and a refresh failed (stale banner). */
        val isStale: Boolean = false,
    ) : OrgOverviewUiState {
        /** True when the caller may manage members (owner/admin) - gates manager-only affordances. */
        val canManage: Boolean get() = callerRole.isManager
    }

    /** No org could be resolved (the caller belongs to no organization). */
    data object Empty : OrgOverviewUiState

    /** Terminal failure (no content to show). */
    data class Error(val error: ApiError) : OrgOverviewUiState
}
