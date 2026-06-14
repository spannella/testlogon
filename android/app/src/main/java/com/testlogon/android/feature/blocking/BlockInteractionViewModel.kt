package com.testlogon.android.feature.blocking

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.blocking.BlockRelationship
import com.testlogon.android.data.blocking.BlockingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-382 - drives the reusable block / unblock interaction embedded in the profile and message-thread
 * screens.
 *
 * The viewed counterpart is supplied via [hydrate] (NOT the ctor): Hilt cannot honor a non-primitive
 * runtime arg through the constructor, so the host screen calls hydrate(userId, handle) once the route
 * arg is known, which reads the relationship from the server inside the load coroutine.
 *
 * Block / unblock are optimistic at the repository layer (the blocked-id set updates immediately for
 * cross-screen suppression). On failure the optimistic change is reverted by the repository and a
 * non-blocking "couldn't update - tap to retry" message is emitted (no auto-retry of the POST). An
 * in-flight guard disables the action and prevents double-submit. Re-block / re-unblock map any 200 to
 * success (FR-6). A generic 403 from a contact attempt (race) is folded in via [onContactRejected].
 */
@HiltViewModel
class BlockInteractionViewModel @Inject constructor(
    private val repository: BlockingRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(BlockInteractionUiState())
    val uiState: StateFlow<BlockInteractionUiState> = _uiState.asStateFlow()

    private val _effects = Channel<BlockInteractionEffect>(Channel.BUFFERED)
    val effects: Flow<BlockInteractionEffect> = _effects.receiveAsFlow()

    /**
     * Bind the screen's counterpart and read the current relationship. Idempotent: re-hydrating the
     * same user re-reads status (cheap GET). The blocked-by-me direction also falls back to the local
     * cached set so suppression survives an offline status read (fail-safe: still hide blocked content).
     */
    fun hydrate(userId: String, handle: String) {
        if (userId.isBlank()) return
        val cachedBlocked = repository.isBlocked(userId)
        _uiState.update {
            it.copy(
                targetUserId = userId,
                targetHandle = handle,
                relationship = if (cachedBlocked) BlockRelationship.BlockedByMe else it.relationship,
            )
        }
        viewModelScope.launch {
            when (val result = repository.blockStatus(userId)) {
                is ApiResult.Success ->
                    _uiState.update { it.copy(relationship = result.data) }
                // On a failed status read, keep the fail-safe cached relationship already set above.
                is ApiResult.Failure, is ApiResult.NetworkError -> Unit
            }
        }
    }

    /** Overflow -> Block: show the confirmation dialog. */
    fun onBlockRequested() {
        if (!_uiState.value.canBlock) return
        _uiState.update { it.copy(confirmVisible = true) }
    }

    /** User dismissed the confirm dialog without blocking. */
    fun onBlockDismissed() {
        _uiState.update { it.copy(confirmVisible = false) }
    }

    /** User confirmed the block in the dialog. */
    fun onBlockConfirmed() {
        val target = _uiState.value.targetUserId
        if (target.isEmpty() || _uiState.value.inFlight) return
        _uiState.update { it.copy(confirmVisible = false, inFlight = true) }
        viewModelScope.launch {
            when (repository.block(target)) {
                is ApiResult.Success ->
                    _uiState.update {
                        it.copy(relationship = BlockRelationship.BlockedByMe, inFlight = false)
                    }
                else -> {
                    // Repository already rolled back the optimistic set; reflect Normal + notify.
                    _uiState.update { it.copy(inFlight = false) }
                    _effects.send(BlockInteractionEffect.ShowMessage(R.string.block_update_failed))
                }
            }
        }
    }

    /** Unblock from the profile placeholder. */
    fun onUnblock() {
        val target = _uiState.value.targetUserId
        if (target.isEmpty() || _uiState.value.inFlight) return
        _uiState.update { it.copy(inFlight = true) }
        viewModelScope.launch {
            when (repository.unblock(target)) {
                is ApiResult.Success ->
                    _uiState.update {
                        it.copy(relationship = BlockRelationship.Normal, inFlight = false)
                    }
                else -> {
                    _uiState.update { it.copy(inFlight = false) }
                    _effects.send(BlockInteractionEffect.ShowMessage(R.string.block_update_failed))
                }
            }
        }
    }

    /**
     * A contact attempt slipped through and the server returned a generic 403 (race / stale state).
     * Reflect the block locally so the composer disables and re-renders. We do NOT require the
     * unverified `user_blocked` detail code (citation audit sec.16 #17): any 403 from the thread's send
     * path routes here.
     */
    fun onContactRejected() {
        _uiState.update {
            // Treat as blocked-me (the counterpart blocked us) unless we already know we blocked them.
            val next = if (it.relationship == BlockRelationship.BlockedByMe) {
                it.relationship
            } else {
                BlockRelationship.BlockedMe
            }
            it.copy(relationship = next)
        }
    }
}
