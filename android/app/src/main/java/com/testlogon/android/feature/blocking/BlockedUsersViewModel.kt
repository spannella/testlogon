package com.testlogon.android.feature.blocking

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.blocking.BlockedUser
import com.testlogon.android.data.blocking.BlockingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * P0-BLOCK — drives the Blocked Users management screen.
 *
 * A single GET ([BlockingRepository.refreshBlockList]) loads the caller's blocked users (also seeds
 * the shared blocked-id set used for client-side suppression). Pull-to-refresh re-reads but, on a
 * non-401 failure, KEEPS the last-good list and flips isStale. Unblock is a confirm-gated mutation:
 * the row is staged into [BlockedUsersUiState.Content.pendingUnblock] (confirm dialog), and on confirm
 * the repository optimistically removes it; on failure the item is restored via a full refresh and a
 * transient message is emitted. Any 200 from unblock maps to success (idempotent, FR-6).
 */
@HiltViewModel
class BlockedUsersViewModel @Inject constructor(
    private val repository: BlockingRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<BlockedUsersUiState>(BlockedUsersUiState.Loading)
    val uiState: StateFlow<BlockedUsersUiState> = _uiState.asStateFlow()

    private val _effects = Channel<BlockedUsersEffect>(Channel.BUFFERED)
    val effects: Flow<BlockedUsersEffect> = _effects.receiveAsFlow()

    private var loadJob: Job? = null

    init {
        load()
    }

    fun load() {
        if (loadJob?.isActive == true) return
        _uiState.value = BlockedUsersUiState.Loading
        fetch(isRefresh = false)
    }

    fun onRetry() = load()

    fun refresh() {
        if (loadJob?.isActive == true) return
        val current = _uiState.value
        if (current is BlockedUsersUiState.Content) {
            _uiState.value = current.copy(isRefreshing = true)
        }
        fetch(isRefresh = true)
    }

    private fun fetch(isRefresh: Boolean) {
        loadJob = viewModelScope.launch {
            when (val result = repository.refreshBlockList()) {
                is ApiResult.Success -> {
                    val items = result.data
                    _uiState.value = if (items.isEmpty()) {
                        BlockedUsersUiState.Empty
                    } else {
                        BlockedUsersUiState.Content(items = items, isStale = false, isRefreshing = false)
                    }
                }
                is ApiResult.Failure -> emitFailure(isRefresh, result.error.message)
                is ApiResult.NetworkError -> emitFailure(isRefresh, OFFLINE_FALLBACK)
            }
        }
    }

    /** Overflow / row Unblock → stage the confirm dialog. */
    fun onUnblockRequested(user: BlockedUser) {
        val current = _uiState.value as? BlockedUsersUiState.Content ?: return
        if (current.unblockingId != null) return
        _uiState.value = current.copy(pendingUnblock = user, actionError = null)
    }

    /** User dismissed the confirm dialog. */
    fun onUnblockDismissed() {
        val current = _uiState.value as? BlockedUsersUiState.Content ?: return
        _uiState.value = current.copy(pendingUnblock = null)
    }

    /** User confirmed the unblock. */
    fun onUnblockConfirmed() {
        val current = _uiState.value as? BlockedUsersUiState.Content ?: return
        val target = current.pendingUnblock ?: return
        if (current.unblockingId != null) return
        _uiState.value = current.copy(pendingUnblock = null, unblockingId = target.userId, actionError = null)
        viewModelScope.launch {
            when (repository.unblock(target.userId)) {
                is ApiResult.Success -> {
                    val now = _uiState.value as? BlockedUsersUiState.Content ?: return@launch
                    val remaining = now.items.filterNot { it.userId == target.userId }
                    _uiState.value = if (remaining.isEmpty()) {
                        BlockedUsersUiState.Empty
                    } else {
                        now.copy(items = remaining, unblockingId = null)
                    }
                }
                else -> {
                    // Repository already rolled back its optimistic set; surface a transient message.
                    val now = _uiState.value as? BlockedUsersUiState.Content
                    if (now != null) _uiState.value = now.copy(unblockingId = null)
                    _effects.send(BlockedUsersEffect.ShowMessage(R.string.block_update_failed))
                }
            }
        }
    }

    private fun emitFailure(isRefresh: Boolean, message: String) {
        val prior = _uiState.value as? BlockedUsersUiState.Content
        _uiState.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, isStale = true)
        } else {
            BlockedUsersUiState.Error(message = message, retryable = true)
        }
    }

    private companion object {
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
