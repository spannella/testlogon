package com.testlogon.android.feature.groups

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.groups.Group
import com.testlogon.android.core.model.groups.GroupRole
import com.testlogon.android.feature.groups.data.GroupsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-355 - drives the [GroupDetailUiState] for the social-group DETAIL screen (GET ui/groups/{groupId}).
 *
 * groupId arrives as a nav arg via [SavedStateHandle] (survives process death). load() reads the group
 * and derives [GroupDetailUiState.Content.canLeave] = the viewer is a member (my_role is known) AND is NOT
 * the owner (userId != admin_user_id). leave() POSTs ui/groups/{groupId}/leave and, on success, emits a
 * one-shot [GroupDetailEffect.LeftGroup] over a Channel (so rotation cannot replay it) for the host to
 * pop + drop the group from the list cache. Dissolve is OUT OF SCOPE. There is NO poll loop.
 */
@HiltViewModel
class GroupDetailViewModel @Inject constructor(
    private val repository: GroupsRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val groupId: String = checkNotNull(savedState[ARG_GROUP_ID]) { "missing $ARG_GROUP_ID nav arg" }

    private val _uiState = MutableStateFlow<GroupDetailUiState>(GroupDetailUiState.Loading)
    val uiState: StateFlow<GroupDetailUiState> = _uiState.asStateFlow()

    private val _effects = Channel<GroupDetailEffect>(Channel.BUFFERED)
    val effects: Flow<GroupDetailEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    /** Loads (or reloads) the group detail. */
    fun load() {
        _uiState.value = GroupDetailUiState.Loading
        viewModelScope.launch {
            _uiState.value = when (val result = repository.getGroup(groupId)) {
                is ApiResult.Success -> GroupDetailUiState.Content(
                    group = result.data,
                    canLeave = deriveCanLeave(result.data),
                    canJoin = deriveCanJoin(result.data),
                )
                is ApiResult.Failure -> GroupDetailUiState.Error(result.error)
                is ApiResult.NetworkError -> GroupDetailUiState.Error(networkError())
            }
        }
    }

    fun onRetry() = load()

    /**
     * Leaves the group. Guarded against double-tap (no-op while a leave is in flight or when the viewer
     * cannot leave). On success emits a one-shot [GroupDetailEffect.LeftGroup]; on failure restores the
     * content (the host surfaces the snackbar).
     */
    fun leave() {
        val content = _uiState.value as? GroupDetailUiState.Content ?: return
        if (!content.canLeave || content.isLeaving) return
        _uiState.value = content.copy(isLeaving = true)
        viewModelScope.launch {
            when (repository.leave(groupId)) {
                is ApiResult.Success -> _effects.send(GroupDetailEffect.LeftGroup(groupId))
                else -> _uiState.value = content.copy(isLeaving = false)
            }
        }
    }

    /**
     * PAR-10 - joins the group. Guarded against double-tap and only when the viewer is not already a member.
     * On a successful public join, reloads the detail so the role / affordances reflect the new membership; a
     * 409 (already a member / pending / invited) surfaces a one-shot snackbar; other failures restore content.
     */
    fun join() {
        val content = _uiState.value as? GroupDetailUiState.Content ?: return
        if (!content.canJoin || content.isJoining) return
        _uiState.value = content.copy(isJoining = true)
        viewModelScope.launch {
            when (val result = repository.join(groupId)) {
                is ApiResult.Success -> load()
                is ApiResult.Failure -> {
                    _uiState.value = content.copy(isJoining = false)
                    _effects.send(
                        GroupDetailEffect.ShowMessage(
                            if (result.error.status == HTTP_CONFLICT) ALREADY_MEMBER else result.error.message,
                        ),
                    )
                }
                is ApiResult.NetworkError -> {
                    _uiState.value = content.copy(isJoining = false)
                    _effects.send(GroupDetailEffect.ShowMessage(OFFLINE_FALLBACK))
                }
            }
        }
    }

    /**
     * canLeave = the viewer is a member (my_role is known) AND is NOT the owner. ASSUMPTION: the detail
     * payload does not echo the viewer's own user_id, so the viewer cannot be compared to admin_user_id
     * directly; ownership is inferred from my_role == admin (the admin IS the owner in this model), so an
     * admin viewer is treated as the owner and cannot leave.
     */
    private fun deriveCanLeave(group: Group): Boolean {
        val isMember = group.myRole != GroupRole.UNKNOWN
        return isMember && group.myRole != GroupRole.ADMIN
    }

    /** canJoin = the viewer is NOT already a member (my_role is UNKNOWN for a group they have not joined). */
    private fun deriveCanJoin(group: Group): Boolean = group.myRole == GroupRole.UNKNOWN

    private fun networkError(): ApiError =
        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    companion object {
        const val ARG_GROUP_ID = "groupId"

        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
        private const val HTTP_CONFLICT = 409
        private const val ALREADY_MEMBER = "You're already a member of this group."
    }
}
