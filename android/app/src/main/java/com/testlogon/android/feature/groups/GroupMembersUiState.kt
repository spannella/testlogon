package com.testlogon.android.feature.groups

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.groups.GroupMember
import com.testlogon.android.core.model.groups.GroupRole

/**
 * AND-355 - render-ready state for the social-group MEMBERS screen (roster + pending invites + role-gated
 * management).
 *
 * Sealed so the screen renders mutually-exclusive surfaces; a new variant forces an exhaustive `when`.
 * [Content] splits the roster into [members] (active) and [pending] (status=="invited"), carries the
 * derived [viewerRole] / [canManage] permission gate, and the in-flight [mutatingUserId] (so one row
 * shows a spinner / is disabled during an optimistic role-change or removal). [notice] is a transient,
 * already-resolved user-facing message (e.g. a 403 "no permission" snackbar).
 */
sealed interface GroupMembersUiState {

    /** Initial / reloading surface. */
    data object Loading : GroupMembersUiState

    /** Loaded roster + pending invites. */
    data class Content(
        /** Active members (status != "invited"). */
        val members: List<GroupMember>,
        /** Pending invites (status == "invited"). */
        val pending: List<GroupMember>,
        val viewerRole: GroupRole,
        /** True when the viewer may invite / change-role / remove (viewerRole.canManage). */
        val canManage: Boolean,
        /** The member currently being mutated (role-change / remove), or null when idle. */
        val mutatingUserId: String? = null,
        /** True while an invite POST is in flight. */
        val isInviting: Boolean = false,
        /** A transient, already-resolved user-facing message, or null. */
        val notice: String? = null,
    ) : GroupMembersUiState

    /** Terminal failure (no content to show). */
    data class Error(val error: ApiError) : GroupMembersUiState
}
