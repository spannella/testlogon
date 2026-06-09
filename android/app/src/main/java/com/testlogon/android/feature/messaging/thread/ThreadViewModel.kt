package com.testlogon.android.feature.messaging.thread

import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.messaging.Message
import com.testlogon.android.data.messaging.MessagingRepository
import com.testlogon.android.data.messaging.ShareableVideo
import com.testlogon.android.data.messaging.realtime.MessagingEvent
import com.testlogon.android.data.messaging.realtime.MessagingEventStream
import com.testlogon.android.data.messaging.realtime.MessagingStreamEvent
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

/** One-shot effects for the thread screen. */
sealed interface ThreadEvent {
    data object ScrollToBottom : ThreadEvent

    /** AND-130 — open the full-screen image viewer for [url]. */
    data class OpenImageViewer(val url: String) : ThreadEvent
}

/**
 * AND-123 / AND-124 — thread presentation logic.
 *
 * Source of truth is the Room-backed [MessagingRepository.observeThread] (history ∪ outbox), mapped
 * to [ThreadMessageUi] with self/other alignment derived from the current user_sub
 * ([AuthStateStore.userSub]). Reverse history is loaded page-by-page via the `before` cursor (the
 * oldest loaded message id). Sends are optimistic (outbox insert -> POST -> reconcile / FAILED).
 * Inbound realtime new-message events for THIS conversation are merged through the cache.
 *
 * One-shot effects (scroll-to-bottom) use a Channel + receiveAsFlow.
 */
@HiltViewModel
class ThreadViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repository: MessagingRepository,
    private val authStateStore: AuthStateStore,
    private val eventStream: MessagingEventStream,
) : ViewModel() {

    /** Epoch-seconds clock; overridable in tests for deterministic optimistic timestamps. */
    internal var clock: () -> Long = { System.currentTimeMillis() / 1000L }

    private val conversationId: String =
        requireNotNull(savedStateHandle.get<String>(ARG_CONVERSATION_ID)) {
            "missing $ARG_CONVERSATION_ID"
        }

    private val _state = MutableStateFlow(ThreadUiState(conversationId = conversationId))
    val state: StateFlow<ThreadUiState> = _state.asStateFlow()

    private val _events = Channel<ThreadEvent>(Channel.BUFFERED)
    val events: Flow<ThreadEvent> = _events.receiveAsFlow()

    /** Oldest message id we have loaded, used as the next `before` cursor. */
    private var oldestLoadedId: String? = null

    /**
     * AND-125 — newest message known to the client (server id + created_at), used as the read marker.
     * Updated from every thread emission so mark-read targets the latest message.
     */
    private var newestMessageId: String? = null
    private var newestMessageEpochSeconds: Long? = null

    /** AND-125 — in-session guard: don't re-POST read for an already-read thread (FR-2). */
    private var readMarked: Boolean = false

    init {
        observeThread()
        observeRealtime()
        loadInitial()
    }

    private fun observeThread() {
        viewModelScope.launch {
            val currentUser = authStateStore.userSub.value
            repository.observeThread(conversationId).collect { messages ->
                val self = authStateStore.userSub.value ?: currentUser
                // Track the newest CONFIRMED (server id present) message as the read marker (AND-125).
                messages.lastOrNull { it.id != null }?.let {
                    newestMessageId = it.id
                    newestMessageEpochSeconds = it.createdAtEpochSeconds
                }
                _state.update { prior ->
                    prior.copy(messages = messages.map { it.toUi(self) })
                }
            }
        }
    }

    /**
     * AND-125 — called when the thread becomes visible (ON_START). Marks the conversation read once
     * per session; the optimistic local clear + POST is owned by the repository. Re-arms when a new
     * inbound message arrives while the thread is open (see [observeRealtime]).
     */
    fun onThreadVisible() {
        if (readMarked) return
        readMarked = true
        viewModelScope.launch {
            repository.markRead(
                conversationId,
                lastReadMessageId = newestMessageId,
                lastReadAtEpochSeconds = newestMessageEpochSeconds,
            )
        }
    }

    fun loadInitial() {
        viewModelScope.launch {
            _state.update { it.copy(isLoadingInitial = it.messages.isEmpty(), errorMessage = null) }
            when (val result = repository.loadHistory(conversationId, before = null, limit = PAGE_SIZE)) {
                is ApiResult.Success -> {
                    oldestLoadedId = result.data.minByOrNull { it.createdAtEpochSeconds }?.id ?: oldestLoadedId
                    _state.update {
                        it.copy(
                            isLoadingInitial = false,
                            endOfHistory = result.data.size < PAGE_SIZE,
                            errorMessage = null,
                        )
                    }
                    _events.trySend(ThreadEvent.ScrollToBottom)
                }
                is ApiResult.Failure -> reduceLoadFailure(result.error.message)
                is ApiResult.NetworkError -> reduceLoadFailure(OFFLINE_MESSAGE)
            }
        }
    }

    fun loadOlder() {
        val before = oldestLoadedId ?: return
        if (_state.value.isLoadingOlder || _state.value.endOfHistory) return
        viewModelScope.launch {
            _state.update { it.copy(isLoadingOlder = true) }
            when (val result = repository.loadHistory(conversationId, before = before, limit = PAGE_SIZE)) {
                is ApiResult.Success -> {
                    val newOldest = result.data.minByOrNull { it.createdAtEpochSeconds }?.id
                    if (newOldest != null) oldestLoadedId = newOldest
                    _state.update {
                        it.copy(isLoadingOlder = false, endOfHistory = result.data.size < PAGE_SIZE)
                    }
                }
                is ApiResult.Failure, is ApiResult.NetworkError ->
                    _state.update { it.copy(isLoadingOlder = false) }
            }
        }
    }

    fun retry() = loadInitial()

    // ---- Composer / send ----

    fun onDraftChange(text: String) {
        _state.update {
            it.copy(
                composer = it.composer.copy(
                    draft = text,
                    charCount = text.length,
                    overLimit = text.length > ComposerState.MAX_LENGTH,
                ),
            )
        }
    }

    fun onSend() {
        val composer = _state.value.composer
        val body = composer.draft.trim()
        if (body.isEmpty() || composer.overLimit) return
        val clientId = UUID.randomUUID().toString()
        // Clear the draft immediately.
        _state.update { it.copy(composer = ComposerState()) }
        viewModelScope.launch {
            repository.enqueueOptimistic(conversationId, clientId, body, clock())
            _events.trySend(ThreadEvent.ScrollToBottom)
            repository.sendOutbox(conversationId, clientId, body)
        }
    }

    fun onRetry(clientId: String) {
        val failed = _state.value.messages.firstOrNull { it.key == clientId } ?: return
        viewModelScope.launch {
            // Re-enqueue as SENDING (same clientId) then re-fire. No server idempotency key exists,
            // so a retry after an uncertain failure may duplicate — retry stays manual.
            if (failed.isImage) {
                val uri = imageDrafts[clientId] ?: return@launch
                repository.enqueueOptimisticImage(conversationId, clientId, uri, clock())
                repository.sendImageOutbox(conversationId, clientId, uri)
            } else {
                repository.enqueueOptimistic(conversationId, clientId, failed.text, clock())
                repository.sendOutbox(conversationId, clientId, failed.text)
            }
        }
    }

    // ---- AND-130: image messages ----

    /** Tracks picked image uris by local clientId so a retry can re-run without re-picking. */
    private val imageDrafts = mutableMapOf<String, String>()

    fun onImagePicked(uri: Uri) {
        val clientId = UUID.randomUUID().toString()
        val localUri = uri.toString()
        imageDrafts[clientId] = localUri
        viewModelScope.launch {
            repository.enqueueOptimisticImage(conversationId, clientId, localUri, clock())
            _events.trySend(ThreadEvent.ScrollToBottom)
            repository.sendImageOutbox(conversationId, clientId, localUri)
        }
    }

    fun onOpenImage(url: String) {
        _events.trySend(ThreadEvent.OpenImageViewer(url))
    }

    // ---- AND-131: video-share ----

    fun onOpenVideoPicker() {
        _state.update { it.copy(videoPicker = it.videoPicker.copy(visible = true, loading = true, errorMessage = null)) }
        viewModelScope.launch {
            when (val result = repository.listShareableVideos()) {
                is ApiResult.Success -> _state.update {
                    it.copy(
                        videoPicker = it.videoPicker.copy(
                            loading = false,
                            videos = result.data.map { v ->
                                ShareableVideoUi(v.videoId, v.title, v.thumbnailUrl, v.durationSeconds)
                            },
                        ),
                    )
                }
                is ApiResult.Failure -> _state.update {
                    it.copy(videoPicker = it.videoPicker.copy(loading = false, errorMessage = result.error.message))
                }
                is ApiResult.NetworkError -> _state.update {
                    it.copy(videoPicker = it.videoPicker.copy(loading = false, errorMessage = OFFLINE_MESSAGE))
                }
            }
        }
    }

    fun onDismissVideoPicker() {
        _state.update { it.copy(videoPicker = VideoPickerState()) }
    }

    fun onShareVideo(videoId: String) {
        _state.update { it.copy(videoPicker = VideoPickerState()) }
        viewModelScope.launch {
            repository.sendVideoShare(conversationId, videoId, caption = null)
            _events.trySend(ThreadEvent.ScrollToBottom)
        }
    }

    private fun reduceLoadFailure(message: String) {
        _state.update {
            if (it.messages.isNotEmpty()) {
                it.copy(isLoadingInitial = false) // keep cached content
            } else {
                it.copy(isLoadingInitial = false, errorMessage = message)
            }
        }
    }

    private fun observeRealtime() {
        viewModelScope.launch {
            eventStream.events().collect { streamEvent ->
                if (streamEvent is MessagingStreamEvent.Event) {
                    val event = streamEvent.event
                    if (event is MessagingEvent.NewMessage && event.conversationId == conversationId) {
                        repository.applyInboundMessage(event)
                        _events.trySend(ThreadEvent.ScrollToBottom)
                        // AND-125 FR-2: a new inbound message re-arms the read trigger; since the
                        // thread is open and visible, mark it read again straight away.
                        readMarked = false
                        onThreadVisible()
                    }
                }
            }
        }
    }

    companion object {
        const val ARG_CONVERSATION_ID = "conversationId"
        const val PAGE_SIZE = 30
        private const val OFFLINE_MESSAGE = "You're offline. Showing saved messages."
    }
}

internal fun Message.toUi(currentUserSub: String?): ThreadMessageUi = ThreadMessageUi(
    key = id ?: clientId,
    text = text,
    // Outbox rows have an empty senderId; they are always the current user's.
    isOwn = senderId.isEmpty() || senderId == currentUserSub,
    createdAtEpochSeconds = createdAtEpochSeconds,
    sendStatus = sendStatus,
    media = media,
)
