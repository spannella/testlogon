package com.testlogon.android.feature.orgs

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.orgs.Org
import com.testlogon.android.core.model.orgs.OrgInvite
import com.testlogon.android.core.model.orgs.OrgMember
import com.testlogon.android.core.model.orgs.OrgRole

/**
 * AND-353 - render-ready state for the org members/roles screen.
 *
 * Sealed so the screen renders mutually-exclusive surfaces; a new variant forces an exhaustive `when`.
 * [Content] carries everything the roster needs, including the derived [callerRole] / [canManage]
 * permission gate and the in-flight [mutatingMemberSub] (so that one row shows a spinner / is disabled
 * during an optimistic role-change or removal).
 */
sealed interface OrgMembersUiState {

    /** Initial / reloading-with-no-content surface. */
    data object Loading : OrgMembersUiState

    /** Loaded roster + pending invites. */
    data class Content(
        val org: Org,
        val members: List<OrgMember>,
        val pendingInvites: List<OrgInvite>,
        val callerRole: OrgRole,
        /** True when the caller may invite / change-role / remove (callerRole.isManager). */
        val canManage: Boolean,
        /** The member currently being mutated (role-change / remove), or null when idle. */
        val mutatingMemberSub: String? = null,
        /** True while an invite POST is in flight. */
        val isInviting: Boolean = false,
        /** A transient, already-resolved user-facing message (e.g. self-protection block), or null. */
        val notice: String? = null,
    ) : OrgMembersUiState {

        /**
         * Self-protection (FR-7): the caller may not remove THEMSELF and may not demote the SOLE owner.
         * These are CLIENT-side guards (the server stays authoritative); they disable the affordance and
         * surface an explanatory notice.
         */
        fun canRemove(member: OrgMember, callerUserSub: String?): Boolean =
            canManage && member.userSub != callerUserSub

        /** True when [member] is the only OWNER in the roster (demoting them is blocked). */
        fun isSoleOwner(member: OrgMember): Boolean =
            member.role == OrgRole.OWNER && members.count { it.role == OrgRole.OWNER } <= 1

        fun canChangeRole(member: OrgMember): Boolean =
            canManage && !isSoleOwner(member)
    }

    /** Terminal failure (no content to show). */
    data class Error(val error: ApiError) : OrgMembersUiState
}
