package com.testlogon.android.feature.fanclub

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.fanclub.FanClubMessage
import com.testlogon.android.data.fanclub.FanClubRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

/** AND-239 — send lifecycle of an optimistic outgoing message. */
enum class SendState { Sending, Sent, Failed }

/**
 * AND-239 — a UI-layer message item: either a confirmed server [Real] message or an optimistic
 * [Pending] outgoing text. Pending entries live outside Paging (server-truthed) and are merged in the
 * Composable; on post success the pager is invalidated so the confirmed row supersedes the pending one.
 */
sealed interface MessageItemUi {
    val id: String

    data class Real(val message: FanClubMessage) : MessageItemUi {
        override val id: String get() = message.id
    }

    data class Pending(
        val localId: String,
        val text: String,
        val sendState: SendState,
    ) : MessageItemUi {
        override val id: String get() = localId
    }
}

/** AND-239 — screen-level (non-list) state. The paged timeline drives its own load states. */
data class ChannelMessagesUiState(
    val channelId: String,
    val channelName: String?,
    val currentUserId: String? = null,
    val composerText: String = "",
    val canPost: Boolean = true,
    val pending: List<MessageItemUi.Pending> = emptyList(),
    /** Message ids removed optimistically (delete) — hidden until the pager refresh confirms. */
    val deletedIds: Set<String> = emptySet(),
)

/** AND-239 — one-shot effects (Channel-delivered). */
sealed interface ChannelMessagesEvent {
    data class ShowMessage(val message: String) : ChannelMessagesEvent
}

/**
 * AND-239 — channel message thread presentation logic.
 *
 * Owns a cached Paging 3 stream of confirmed messages + optimistic overlays (pending sends + a
 * deleted-id set) merged at the UI layer. Posting is optimistic (Pending/Sending -> Sent or Failed with
 * retry); on success the pager is invalidated so the server row replaces the pending entry. Reaction and
 * delete are optimistic with rollback on failure (a transient snackbar). 403 on send sets canPost=false.
 *
 * REALTIME: this reuses NO second realtime stack — there is no fan-club SSE topic in the contract and the
 * web reference polls; new messages arrive via pull-to-refresh / pager invalidation (poll/refresh).
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class ChannelMessagesViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repository: FanClubRepository,
) : ViewModel() {

    private val channelId: String = checkNotNull(savedStateHandle[ARG_CHANNEL_ID]) {
        "ChannelMessagesViewModel requires a '$ARG_CHANNEL_ID' nav argument"
    }

    private val refreshTrigger = MutableStateFlow(0L)

    val pagedMessages: Flow<PagingData<FanClubMessage>> =
        refreshTrigger
            .flatMapLatest {
                Pager(
                    config = PagingConfig(
                        pageSize = PAGE_SIZE,
                        prefetchDistance = PREFETCH_DISTANCE,
                        initialLoadSize = PAGE_SIZE,
                        enablePlaceholders = false,
                    ),
                    pagingSourceFactory = { ChannelMessagesPagingSource(repository, channelId) },
                ).flow
            }
            .cachedIn(viewModelScope)

    private val _uiState = MutableStateFlow(
        ChannelMessagesUiState(
            channelId = channelId,
            channelName = savedStateHandle.get<String?>(ARG_CHANNEL_NAME)?.takeIf { it.isNotBlank() },
            composerText = savedStateHandle.get<String?>(KEY_COMPOSER).orEmpty(),
        ),
    )
    val uiState: StateFlow<ChannelMessagesUiState> = _uiState.asStateFlow()

    private val _events = Channel<ChannelMessagesEvent>(Channel.BUFFERED)
    val events: Flow<ChannelMessagesEvent> = _events.receiveAsFlow()

    private val savedState = savedStateHandle

    init {
        viewModelScope.launch {
            _uiState.update { it.copy(currentUserId = repository.currentUserId()) }
        }
    }

    fun onComposerChange(text: String) {
        _uiState.update { it.copy(composerText = text) }
        savedState[KEY_COMPOSER] = text
    }

    fun onRefresh() {
        refreshTrigger.value = refreshTrigger.value + 1L
    }

    fun onSend() {
        val text = _uiState.value.composerText.trim()
        if (text.isEmpty() || !_uiState.value.canPost) return
        val localId = "pending_${UUID.randomUUID()}"
        _uiState.update {
            it.copy(
                composerText = "",
                pending = it.pending + MessageItemUi.Pending(localId, text, SendState.Sending),
            )
        }
        savedState[KEY_COMPOSER] = ""
        sendPending(localId, text)
    }

    /** AND-239 — retry a previously-failed pending send (safe: retry only fires after a real failure). */
    fun onRetryPending(localId: String) {
        val pending = _uiState.value.pending.firstOrNull { it.localId == localId } ?: return
        if (pending.sendState != SendState.Failed) return
        setPendingState(localId, SendState.Sending)
        sendPending(localId, pending.text)
    }

    private fun sendPending(localId: String, text: String) {
        viewModelScope.launch {
            when (val result = repository.postText(channelId, text)) {
                is ApiResult.Success -> {
                    // Confirmed: drop the pending entry and invalidate so the server row appears.
                    _uiState.update { it.copy(pending = it.pending.filterNot { p -> p.localId == localId }) }
                    onRefresh()
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_FORBIDDEN) {
                        _uiState.update {
                            it.copy(
                                canPost = false,
                                pending = it.pending.filterNot { p -> p.localId == localId },
                            )
                        }
                        emit(result.error.message)
                    } else {
                        setPendingState(localId, SendState.Failed)
                        emit(result.error.message)
                    }
                }
                is ApiResult.NetworkError -> {
                    setPendingState(localId, SendState.Failed)
                    emit(OFFLINE_MESSAGE)
                }
            }
        }
    }

    fun onToggleReaction(messageId: String, emoji: String) {
        viewModelScope.launch {
            when (val result = repository.toggleReaction(channelId, messageId, emoji)) {
                is ApiResult.Success -> onRefresh() // reconcile derived counts from the server
                is ApiResult.Failure -> emit(result.error.message)
                is ApiResult.NetworkError -> emit(OFFLINE_MESSAGE)
            }
        }
    }

    fun onDelete(messageId: String) {
        // Optimistic removal; restore on failure.
        _uiState.update { it.copy(deletedIds = it.deletedIds + messageId) }
        viewModelScope.launch {
            when (val result = repository.deleteMessage(channelId, messageId)) {
                is ApiResult.Success -> onRefresh()
                is ApiResult.Failure -> {
                    restore(messageId)
                    emit(result.error.message)
                }
                is ApiResult.NetworkError -> {
                    restore(messageId)
                    emit(OFFLINE_MESSAGE)
                }
            }
        }
    }

    /** AND-239 — delete is offered only on the current user's own messages (server is authoritative). */
    fun canDelete(message: FanClubMessage): Boolean {
        val me = _uiState.value.currentUserId ?: return false
        return !message.deleted && message.senderId == me
    }

    private fun setPendingState(localId: String, state: SendState) {
        _uiState.update {
            it.copy(
                pending = it.pending.map { p -> if (p.localId == localId) p.copy(sendState = state) else p },
            )
        }
    }

    private fun restore(messageId: String) {
        _uiState.update { it.copy(deletedIds = it.deletedIds - messageId) }
    }

    private suspend fun emit(message: String) {
        _events.send(ChannelMessagesEvent.ShowMessage(message))
    }

    companion object {
        const val ARG_CHANNEL_ID = "channelId"
        const val ARG_CHANNEL_NAME = "channelName"
        const val KEY_COMPOSER = "fanclub_composer_draft"

        private const val PAGE_SIZE = 30
        private const val PREFETCH_DISTANCE = 10
        private const val HTTP_FORBIDDEN = 403
        private const val OFFLINE_MESSAGE = "You're offline"
    }
}
