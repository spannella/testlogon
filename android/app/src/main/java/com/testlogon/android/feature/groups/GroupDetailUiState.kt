package com.testlogon.android.feature.groups

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.groups.Group

/**
 * AND-355 - render-ready state for the social-group DETAIL screen (GET ui/groups/{groupId}).
 *
 * Sealed so the screen renders mutually-exclusive surfaces; a new variant forces an exhaustive `when`.
 * [Content] carries the group plus the derived [canLeave] gate (the viewer is a member AND is NOT the
 * owner). Dissolve is OUT OF SCOPE.
 */
sealed interface GroupDetailUiState {

    /** Initial / reloading surface. */
    data object Loading : GroupDetailUiState

    /** Loaded group detail. */
    data class Content(
        val group: Group,
        /** True when the viewer may leave (a member who is NOT the owner). */
        val canLeave: Boolean,
        /** PAR-10 - True when the viewer is NOT yet a member and may join. */
        val canJoin: Boolean = false,
        /** True while a leave POST is in flight. */
        val isLeaving: Boolean = false,
        /** PAR-10 - True while a join POST is in flight. */
        val isJoining: Boolean = false,
    ) : GroupDetailUiState

    /** Terminal failure (no content to show). */
    data class Error(val error: ApiError) : GroupDetailUiState
}

/** AND-355 - a one-shot effect emitted after a successful leave (pop the detail + drop from cache). */
sealed interface GroupDetailEffect {
    /** The viewer successfully left [groupId]; the host should pop back to the list. */
    data class LeftGroup(val groupId: String) : GroupDetailEffect

    /** PAR-10 - a transient user-facing message (e.g. a 409 already-member on join). */
    data class ShowMessage(val message: String) : GroupDetailEffect
}
