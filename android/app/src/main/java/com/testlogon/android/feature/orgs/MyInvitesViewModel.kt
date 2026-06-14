package com.testlogon.android.feature.orgs

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.orgs.OrgInvite
import com.testlogon.android.feature.orgs.data.OrgsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-354 - drives the [MyInvitesUiState] for the MY-INVITES screen (the caller's own pending invites).
 *
 * load() reads listPendingInvites. accept(inviteId, token) / decline(inviteId) OPTIMISTICALLY remove the
 * row on success and ROLL BACK (re-insert the row) + surface a snackbar on failure. The accept token comes
 * from the [OrgInvite.token] carried on the row; when the wire row omits a token the accept is sent with an
 * EMPTY token (the server stays authoritative - see the open assumption).
 */
@HiltViewModel
class MyInvitesViewModel @Inject constructor(
    private val repository: OrgsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<MyInvitesUiState>(MyInvitesUiState.Loading)
    val uiState: StateFlow<MyInvitesUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    /** Loads (or reloads) the caller's pending invites. */
    fun load() {
        _uiState.value = MyInvitesUiState.Loading
        viewModelScope.launch {
            _uiState.value = when (val result = repository.listPendingInvites()) {
                is ApiResult.Success ->
                    if (result.data.isEmpty()) {
                        MyInvitesUiState.Empty
                    } else {
                        MyInvitesUiState.Content(invites = result.data)
                    }
                is ApiResult.Failure -> MyInvitesUiState.Error(result.error)
                is ApiResult.NetworkError -> MyInvitesUiState.Error(networkError())
            }
        }
    }

    fun onRetry() = load()

    /** Accepts [inviteId] using the row's token (empty when absent). Optimistic remove + rollback. */
    fun accept(inviteId: String) {
        val content = _uiState.value as? MyInvitesUiState.Content ?: return
        if (content.actingInviteId != null) return
        val target = content.invites.firstOrNull { it.inviteId == inviteId } ?: return
        val token = target.token.orEmpty()
        mutateOptimistically(content, target) { repository.acceptInvite(inviteId, token) }
    }

    /** Declines [inviteId]. Optimistic remove + rollback. */
    fun decline(inviteId: String) {
        val content = _uiState.value as? MyInvitesUiState.Content ?: return
        if (content.actingInviteId != null) return
        val target = content.invites.firstOrNull { it.inviteId == inviteId } ?: return
        mutateOptimistically(content, target) { repository.declineInvite(inviteId) }
    }

    /**
     * Optimistically removes [target] from the list, marks it acting, runs [action], and either keeps the
     * removal (success) or re-inserts the row at its original index + surfaces a notice (failure).
     */
    private fun mutateOptimistically(
        content: MyInvitesUiState.Content,
        target: OrgInvite,
        action: suspend () -> ApiResult<Unit>,
    ) {
        val originalIndex = content.invites.indexOf(target)
        _uiState.value = content.copy(
            invites = content.invites.filterNot { it.inviteId == target.inviteId },
            actingInviteId = target.inviteId,
            notice = null,
        )
        viewModelScope.launch {
            val result = action()
            val now = _uiState.value as? MyInvitesUiState.Content ?: return@launch
            _uiState.value = when (result) {
                is ApiResult.Success ->
                    if (now.invites.isEmpty()) {
                        MyInvitesUiState.Empty
                    } else {
                        now.copy(actingInviteId = null)
                    }
                else -> {
                    // Rollback: re-insert the row at its original position (clamped).
                    val restored = now.invites.toMutableList().apply {
                        val idx = originalIndex.coerceIn(0, size)
                        add(idx, target)
                    }
                    now.copy(
                        invites = restored,
                        actingInviteId = null,
                        notice = ACTION_FAILED,
                    )
                }
            }
        }
    }

    /** Clears a transient notice after it has been surfaced. */
    fun consumeNotice() {
        val content = _uiState.value as? MyInvitesUiState.Content ?: return
        if (content.notice != null) _uiState.value = content.copy(notice = null)
    }

    private fun networkError(): ApiError =
        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    private companion object {
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
        const val ACTION_FAILED = "Couldn't update the invite. Please try again."
    }
}
