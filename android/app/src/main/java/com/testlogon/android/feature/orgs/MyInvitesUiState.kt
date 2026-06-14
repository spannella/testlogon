package com.testlogon.android.feature.orgs

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.orgs.OrgInvite

/**
 * AND-354 - render-ready state for the MY-INVITES screen (the CURRENT USER's own pending invitations from
 * GET ui/orgs/invites/pending, across all orgs).
 *
 * Sealed so the screen renders mutually-exclusive surfaces; a new variant forces an exhaustive `when`.
 * [Content.actingInviteId] marks the row whose accept/decline is in flight (disable + spinner). There is
 * NO org-scoped outstanding-invites list and NO inviter-side revoke here - this surface is purely the
 * recipient responding to their own invites.
 */
sealed interface MyInvitesUiState {

    /** Initial / reloading-with-no-content surface. */
    data object Loading : MyInvitesUiState

    /** Loaded pending invites. */
    data class Content(
        val invites: List<OrgInvite>,
        /** The invite whose accept/decline is in flight, or null when idle. */
        val actingInviteId: String? = null,
        /** A transient, already-resolved user-facing message (e.g. an action failure), or null. */
        val notice: String? = null,
    ) : MyInvitesUiState

    /** No pending invites for the caller. */
    data object Empty : MyInvitesUiState

    /** Terminal failure (no content to show). */
    data class Error(val error: ApiError) : MyInvitesUiState
}
