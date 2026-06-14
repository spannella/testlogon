package com.testlogon.android.feature.groups

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.groups.GroupMember
import com.testlogon.android.core.model.groups.GroupRole
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.feature.groups.data.GroupsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-355 - drives the [GroupMembersUiState] for the social-group MEMBERS screen.
 *
 * groupId arrives as a nav arg via [SavedStateHandle]; the viewer's own user_id comes from
 * [AuthStateStore.userSub]. load() reads the roster (GET ui/groups/{groupId}/members, the {members,count}
 * ENVELOPE), splits it into ACTIVE members vs PENDING invites (status=="invited"), and derives the
 * viewer's role (the viewer's own member row, falling back to the group's my_role) -> canManage =
 * viewerRole.canManage (admin only).
 *
 * invite(userId) is PESSIMISTIC (awaits the server) - on success the invitee appears as a PENDING entry
 * (the roster is re-fetched). changeRole(userId, role[moderator|member]) and removeMember(userId) are
 * OPTIMISTIC with rollback on failure. A 403 from any mutation surfaces a non-fatal snackbar (mapping the
 * detail.code "role_required" to friendly copy) and reverts. There is NO poll loop.
 */
@HiltViewModel
class GroupMembersViewModel @Inject constructor(
    private val repository: GroupsRepository,
    private val authStateStore: AuthStateStore,
    savedState: SavedStateHandle,
) : ViewModel() {

    val groupId: String = checkNotNull(savedState[ARG_GROUP_ID]) { "missing $ARG_GROUP_ID nav arg" }

    private val _uiState = MutableStateFlow<GroupMembersUiState>(GroupMembersUiState.Loading)
    val uiState: StateFlow<GroupMembersUiState> = _uiState.asStateFlow()

    /** The viewer's own user_id; used to derive the viewer role from the roster. */
    val viewerUserId: String? get() = authStateStore.userSub.value

    init {
        load()
    }

    /** Loads (or reloads) the roster; splits active vs pending and derives the viewer's role. */
    fun load() {
        _uiState.value = GroupMembersUiState.Loading
        viewModelScope.launch { fetchRoster() }
    }

    fun onRetry() = load()

    private suspend fun fetchRoster() {
        _uiState.value = when (val result = repository.listMembers(groupId)) {
            is ApiResult.Success -> reduceRoster(result.data)
            is ApiResult.Failure -> GroupMembersUiState.Error(result.error)
            is ApiResult.NetworkError -> GroupMembersUiState.Error(networkError())
        }
    }

    private fun reduceRoster(roster: List<GroupMember>): GroupMembersUiState.Content {
        val (pending, active) = roster.partition { it.isPending }
        val viewerRole = deriveViewerRole(active)
        return GroupMembersUiState.Content(
            members = active,
            pending = pending,
            viewerRole = viewerRole,
            canManage = viewerRole.canManage,
        )
    }

    /** The viewer's role is taken from their own active member row (UNKNOWN when absent). */
    private fun deriveViewerRole(active: List<GroupMember>): GroupRole {
        val me = viewerUserId
        return active.firstOrNull { it.userId == me }?.role ?: GroupRole.UNKNOWN
    }

    /**
     * Invites [userId] (PESSIMISTIC - awaits the server). On success the invitee appears as a PENDING
     * entry (the roster is re-fetched so the new status="invited" row shows). A 403 surfaces a friendly
     * snackbar.
     */
    fun invite(userId: String) {
        val content = _uiState.value as? GroupMembersUiState.Content ?: return
        if (!content.canManage || content.isInviting || userId.isBlank()) return
        _uiState.value = content.copy(isInviting = true, notice = null)
        viewModelScope.launch {
            when (val result = repository.invite(groupId, userId)) {
                is ApiResult.Success -> {
                    // Re-fetch so the invitee shows as a pending (status="invited") entry.
                    when (val roster = repository.listMembers(groupId)) {
                        is ApiResult.Success ->
                            _uiState.value = reduceRoster(roster.data).copy(notice = INVITE_SENT)
                        else -> {
                            val now = _uiState.value as? GroupMembersUiState.Content ?: return@launch
                            _uiState.value = now.copy(isInviting = false, notice = INVITE_SENT)
                        }
                    }
                }
                is ApiResult.Failure -> {
                    val now = _uiState.value as? GroupMembersUiState.Content ?: return@launch
                    _uiState.value = now.copy(isInviting = false, notice = noticeForFailure(result.error))
                }
                is ApiResult.NetworkError -> {
                    val now = _uiState.value as? GroupMembersUiState.Content ?: return@launch
                    _uiState.value = now.copy(isInviting = false, notice = INVITE_FAILED)
                }
            }
        }
    }

    /**
     * Optimistically changes [userId]'s role to [newRole] (moderator|member ONLY; admin is NOT assignable),
     * rolling back on failure. A 403 surfaces a friendly "no permission" snackbar + revert.
     */
    fun changeRole(userId: String, newRole: GroupRole) {
        val content = _uiState.value as? GroupMembersUiState.Content ?: return
        if (!content.canManage || newRole == GroupRole.ADMIN || newRole == GroupRole.UNKNOWN) return
        val target = content.members.firstOrNull { it.userId == userId } ?: return
        val previousRole = target.role
        _uiState.value = content.copy(
            members = content.members.map {
                if (it.userId == userId) it.copy(role = newRole) else it
            },
            mutatingUserId = userId,
            notice = null,
        )
        viewModelScope.launch {
            val result = repository.changeRole(groupId, userId, newRole)
            val now = _uiState.value as? GroupMembersUiState.Content ?: return@launch
            _uiState.value = when (result) {
                is ApiResult.Success -> now.copy(mutatingUserId = null)
                is ApiResult.Failure -> now.copy(
                    members = now.members.map {
                        if (it.userId == userId) it.copy(role = previousRole) else it
                    },
                    mutatingUserId = null,
                    notice = noticeForFailure(result.error),
                )
                is ApiResult.NetworkError -> now.copy(
                    members = now.members.map {
                        if (it.userId == userId) it.copy(role = previousRole) else it
                    },
                    mutatingUserId = null,
                    notice = ROLE_CHANGE_FAILED,
                )
            }
        }
    }

    /** Optimistically removes [userId], rolling back on failure. A 403 surfaces a friendly snackbar. */
    fun removeMember(userId: String) {
        val content = _uiState.value as? GroupMembersUiState.Content ?: return
        if (!content.canManage) return
        val removed = content.members.firstOrNull { it.userId == userId } ?: return
        val removedIndex = content.members.indexOf(removed)
        _uiState.value = content.copy(
            members = content.members.filterNot { it.userId == userId },
            mutatingUserId = userId,
            notice = null,
        )
        viewModelScope.launch {
            val result = repository.removeMember(groupId, userId)
            val now = _uiState.value as? GroupMembersUiState.Content ?: return@launch
            _uiState.value = when (result) {
                is ApiResult.Success -> now.copy(mutatingUserId = null)
                is ApiResult.Failure -> now.copy(
                    members = restore(now.members, removed, removedIndex),
                    mutatingUserId = null,
                    notice = noticeForFailure(result.error),
                )
                is ApiResult.NetworkError -> now.copy(
                    members = restore(now.members, removed, removedIndex),
                    mutatingUserId = null,
                    notice = REMOVE_FAILED,
                )
            }
        }
    }

    /** Clears a transient notice after it has been surfaced. */
    fun consumeNotice() {
        val content = _uiState.value as? GroupMembersUiState.Content ?: return
        if (content.notice != null) _uiState.value = content.copy(notice = null)
    }

    /** Re-inserts a rolled-back removal at its original position (best-effort). */
    private fun restore(
        members: List<GroupMember>,
        removed: GroupMember,
        index: Int,
    ): List<GroupMember> {
        if (members.any { it.userId == removed.userId }) return members
        val safeIndex = index.coerceIn(0, members.size)
        return members.toMutableList().apply { add(safeIndex, removed) }
    }

    /** Maps a mutation failure to friendly copy (a 403 / role_required becomes the no-permission message). */
    private fun noticeForFailure(error: ApiError): String = when {
        error.status == 403 || error.code == CODE_ROLE_REQUIRED -> NO_PERMISSION
        else -> MUTATION_FAILED
    }

    private fun networkError(): ApiError =
        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    companion object {
        const val ARG_GROUP_ID = "groupId"

        private const val CODE_ROLE_REQUIRED = "role_required"
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
        private const val NO_PERMISSION = "You don't have permission to do that."
        private const val MUTATION_FAILED = "Couldn't complete that action. Please try again."
        private const val ROLE_CHANGE_FAILED = "Couldn't change the role. Please try again."
        private const val REMOVE_FAILED = "Couldn't remove the member. Please try again."
        private const val INVITE_SENT = "Invite sent."
        private const val INVITE_FAILED = "Couldn't send the invite. Please try again."
    }
}
