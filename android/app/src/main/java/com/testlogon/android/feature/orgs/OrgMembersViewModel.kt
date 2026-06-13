package com.testlogon.android.feature.orgs

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.orgs.Org
import com.testlogon.android.core.model.orgs.OrgMember
import com.testlogon.android.core.model.orgs.OrgRole
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.feature.orgs.data.OrgsRepository
import com.testlogon.android.feature.orgs.data.SelectedOrgStore
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-353 - drives the single [OrgMembersUiState] for the org members/roles screen.
 *
 * load(orgId) fetches the roster (listMembers) + the pending invites (listPendingInvites), resolves the
 * [Org] from listOrgs, and derives the caller's role (FR-6) by matching [AuthStateStore.userSub] to a
 * member row -> canManage = callerRole.isManager. When no orgId is supplied the SELECTED org id is used
 * (DataStore), defaulting to the caller's PRIMARY org (the first listOrgs entry) when unset.
 *
 * changeRole is OPTIMISTIC with rollback on failure (FR-4); removeMember drops the row on success (FR-5);
 * inviteMember inserts the 201 result into pendingInvites - NOT the member roster (the invite is a
 * pending invite, not a member). Self-protection (FR-7) blocks removing SELF and demoting the SOLE owner
 * CLIENT-side (the server stays authoritative). There is NO poll loop.
 */
@HiltViewModel
class OrgMembersViewModel @Inject constructor(
    private val repository: OrgsRepository,
    private val selectedOrgStore: SelectedOrgStore,
    private val authStateStore: AuthStateStore,
) : ViewModel() {

    private val _uiState = MutableStateFlow<OrgMembersUiState>(OrgMembersUiState.Loading)
    val uiState: StateFlow<OrgMembersUiState> = _uiState.asStateFlow()

    /** The caller's user_sub, used to gate self-protection. Snapshot read by the screen for canRemove. */
    val callerUserSub: String? get() = authStateStore.userSub.value

    init {
        load(orgId = null)
    }

    /** Loads (or reloads) the roster for [orgId]; null -> the selected org (default: primary org). */
    fun load(orgId: String?) {
        _uiState.value = OrgMembersUiState.Loading
        viewModelScope.launch {
            val resolved = orgId ?: resolveOrgId() ?: run {
                // No org could be resolved (listOrgs failed or empty) - reflect the orgs failure/empty.
                reduceNoOrg()
                return@launch
            }
            if (orgId != null) selectedOrgStore.setSelectedOrgId(resolved)
            loadRoster(resolved)
        }
    }

    fun onRetry() = load(orgId = currentOrgId())

    /** Resolves the org id to show: the selected one, else the caller's primary (first listOrgs) entry. */
    private suspend fun resolveOrgId(): String? {
        selectedOrgStore.selectedOrgId.first()?.let { return it }
        return when (val orgs = repository.listOrgs()) {
            is ApiResult.Success -> orgs.data.firstOrNull()?.orgId
            else -> null
        }
    }

    private suspend fun reduceNoOrg() {
        _uiState.value = when (val orgs = repository.listOrgs()) {
            is ApiResult.Success -> OrgMembersUiState.Content(
                org = Org(orgId = "", name = null, callerRole = OrgRole.UNKNOWN),
                members = emptyList(),
                pendingInvites = emptyList(),
                callerRole = OrgRole.UNKNOWN,
                canManage = false,
            )
            is ApiResult.Failure -> OrgMembersUiState.Error(orgs.error)
            is ApiResult.NetworkError -> OrgMembersUiState.Error(
                ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK),
            )
        }
    }

    private suspend fun loadRoster(orgId: String) {
        // Resolve the org metadata + caller role from listOrgs (best-effort; falls back to UNKNOWN).
        val org = when (val orgs = repository.listOrgs()) {
            is ApiResult.Success ->
                orgs.data.firstOrNull { it.orgId == orgId }
                    ?: Org(orgId = orgId, name = null, callerRole = OrgRole.UNKNOWN)
            else -> Org(orgId = orgId, name = null, callerRole = OrgRole.UNKNOWN)
        }

        when (val members = repository.listMembers(orgId)) {
            is ApiResult.Success -> {
                val invites = (repository.listPendingInvites() as? ApiResult.Success)?.data
                    .orEmpty()
                    .filter { it.orgId == null || it.orgId == orgId }
                val callerRole = deriveCallerRole(org, members.data)
                _uiState.value = OrgMembersUiState.Content(
                    org = org.copy(callerRole = callerRole),
                    members = members.data,
                    pendingInvites = invites,
                    callerRole = callerRole,
                    canManage = callerRole.isManager,
                )
            }
            is ApiResult.Failure -> _uiState.value = OrgMembersUiState.Error(members.error)
            is ApiResult.NetworkError -> _uiState.value = OrgMembersUiState.Error(
                ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK),
            )
        }
    }

    /**
     * Derives the caller's role (FR-6): match the caller's user_sub to a member row; if not present, fall
     * back to the org's callerRole from listOrgs.
     */
    private fun deriveCallerRole(org: Org, members: List<OrgMember>): OrgRole {
        val sub = callerUserSub
        val fromRow = members.firstOrNull { it.userSub == sub }?.role
        return when {
            fromRow != null && fromRow != OrgRole.UNKNOWN -> fromRow
            org.callerRole != OrgRole.UNKNOWN -> org.callerRole
            else -> fromRow ?: OrgRole.UNKNOWN
        }
    }

    /**
     * Optimistically changes [memberSub]'s role to [newRole], rolling back on failure (FR-4). owner is
     * NOT assignable here, and the SOLE owner cannot be demoted (self-protection).
     */
    fun changeRole(memberSub: String, newRole: OrgRole) {
        val content = _uiState.value as? OrgMembersUiState.Content ?: return
        if (!content.canManage || newRole == OrgRole.OWNER || newRole == OrgRole.UNKNOWN) return
        val target = content.members.firstOrNull { it.userSub == memberSub } ?: return
        if (content.isSoleOwner(target)) {
            _uiState.value = content.copy(notice = SOLE_OWNER_BLOCKED)
            return
        }
        val previousRole = target.role
        // Optimistic update + mark the row as mutating.
        _uiState.value = content.copy(
            members = content.members.map {
                if (it.userSub == memberSub) it.copy(role = newRole) else it
            },
            mutatingMemberSub = memberSub,
            notice = null,
        )
        viewModelScope.launch {
            val result = repository.changeRole(content.org.orgId, memberSub, newRole)
            val now = _uiState.value as? OrgMembersUiState.Content ?: return@launch
            _uiState.value = when (result) {
                is ApiResult.Success -> now.copy(mutatingMemberSub = null)
                else -> now.copy(
                    // Rollback to the previous role.
                    members = now.members.map {
                        if (it.userSub == memberSub) it.copy(role = previousRole) else it
                    },
                    mutatingMemberSub = null,
                    notice = ROLE_CHANGE_FAILED,
                )
            }
        }
    }

    /** Removes [memberSub] on success (FR-5). Blocks removing SELF (self-protection / FR-7). */
    fun removeMember(memberSub: String) {
        val content = _uiState.value as? OrgMembersUiState.Content ?: return
        if (!content.canManage) return
        if (memberSub == callerUserSub) {
            _uiState.value = content.copy(notice = SELF_REMOVE_BLOCKED)
            return
        }
        _uiState.value = content.copy(mutatingMemberSub = memberSub, notice = null)
        viewModelScope.launch {
            val result = repository.removeMember(content.org.orgId, memberSub)
            val now = _uiState.value as? OrgMembersUiState.Content ?: return@launch
            _uiState.value = when (result) {
                is ApiResult.Success -> now.copy(
                    members = now.members.filterNot { it.userSub == memberSub },
                    mutatingMemberSub = null,
                )
                else -> now.copy(mutatingMemberSub = null, notice = REMOVE_FAILED)
            }
        }
    }

    /**
     * Invites [email] with [role] (admin|member|viewer; owner NOT invitable). On 201 the returned PENDING
     * invite is inserted into pendingInvites - NOT the member roster.
     */
    fun inviteMember(email: String, role: OrgRole) {
        val content = _uiState.value as? OrgMembersUiState.Content ?: return
        if (!content.canManage || content.isInviting) return
        val safeRole = role.takeIf { it != OrgRole.OWNER && it != OrgRole.UNKNOWN }
        _uiState.value = content.copy(isInviting = true, notice = null)
        viewModelScope.launch {
            val result = repository.inviteMember(content.org.orgId, email, safeRole)
            val now = _uiState.value as? OrgMembersUiState.Content ?: return@launch
            _uiState.value = when (result) {
                is ApiResult.Success -> now.copy(
                    pendingInvites = now.pendingInvites + result.data,
                    isInviting = false,
                    notice = INVITE_SENT,
                )
                else -> now.copy(isInviting = false, notice = INVITE_FAILED)
            }
        }
    }

    /** Clears a transient notice after it has been surfaced. */
    fun consumeNotice() {
        val content = _uiState.value as? OrgMembersUiState.Content ?: return
        if (content.notice != null) _uiState.value = content.copy(notice = null)
    }

    private fun currentOrgId(): String? =
        (_uiState.value as? OrgMembersUiState.Content)?.org?.orgId?.takeIf { it.isNotBlank() }

    private companion object {
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
        const val ROLE_CHANGE_FAILED = "Couldn't change the role. Please try again."
        const val REMOVE_FAILED = "Couldn't remove the member. Please try again."
        const val INVITE_SENT = "Invite sent."
        const val INVITE_FAILED = "Couldn't send the invite. Please try again."
        const val SELF_REMOVE_BLOCKED = "You can't remove yourself from the organization."
        const val SOLE_OWNER_BLOCKED = "You can't change the role of the only owner."
    }
}
