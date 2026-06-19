package com.testlogon.android.feature.messaging.thread

import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.messaging.AssociatedEventType
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.data.messaging.CountdownDraft
import com.testlogon.android.data.messaging.DownloadProgress
import com.testlogon.android.data.messaging.GifResult
import com.testlogon.android.data.messaging.GifSendPayload
import com.testlogon.android.data.messaging.MeetingPoll
import com.testlogon.android.data.messaging.MeetingPollDraft
import com.testlogon.android.data.messaging.Message
import com.testlogon.android.data.messaging.MessageMedia
import com.testlogon.android.data.messaging.MessageMonetization
import com.testlogon.android.data.messaging.MessagingRepository
import com.testlogon.android.data.messaging.ShareableVideo
import com.testlogon.android.data.messaging.SlotVote
import com.testlogon.android.data.messaging.StickerPick
import com.testlogon.android.data.messaging.realtime.MessageReceipt
import com.testlogon.android.data.messaging.realtime.MessageViewer
import com.testlogon.android.data.messaging.realtime.MessagingEvent
import com.testlogon.android.data.messaging.realtime.MessagingEventStream
import com.testlogon.android.data.messaging.realtime.MessagingStreamEvent
import com.testlogon.android.data.messaging.realtime.ReceiptReducer
import com.testlogon.android.data.messaging.realtime.ReceiptStatus
import com.testlogon.android.data.messaging.typing.TypingRepository
import com.testlogon.android.feature.messaging.typing.TypingConfig
import com.testlogon.android.feature.messaging.typing.TypingInput
import com.testlogon.android.feature.messaging.typing.TypingReducer
import com.testlogon.android.feature.messaging.typing.TypingSignalController
import com.testlogon.android.feature.messaging.typing.TypingUiUser
import com.testlogon.android.feature.messaging.voice.RecorderLimits
import com.testlogon.android.feature.messaging.voice.RecorderState
import com.testlogon.android.feature.messaging.voice.VoicePlayerController
import com.testlogon.android.feature.messaging.voice.VoicePlayerFactory
import com.testlogon.android.feature.messaging.voice.VoiceRecorder
import com.testlogon.android.feature.messaging.voice.VoiceRecorderFactory
import com.testlogon.android.feature.messaging.voice.Waveform
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.transformLatest
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.io.File
import java.util.UUID
import javax.inject.Inject

/** One-shot effects for the thread screen. */
sealed interface ThreadEvent {
    data object ScrollToBottom : ThreadEvent

    /** AND-140 — scroll the thread to a specific message (jump-to-pinned). */
    data class ScrollToMessage(val messageKey: String) : ThreadEvent

    /** AND-130 — open the full-screen image viewer for [url]. */
    data class OpenImageViewer(val url: String) : ThreadEvent

    /** AND-132 — open a downloaded file via FileProvider + ACTION_VIEW (UI launches the intent). */
    data class OpenFile(val localPath: String, val mimeType: String?) : ThreadEvent
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
    private val savedStateHandle: SavedStateHandle,
    private val repository: MessagingRepository,
    private val authStateStore: AuthStateStore,
    private val eventStream: MessagingEventStream,
    @dagger.hilt.android.qualifiers.ApplicationContext private val appContext: android.content.Context,
    private val recorderFactory: VoiceRecorderFactory,
    private val playerFactory: VoicePlayerFactory,
    private val billing: BillingAuthorizer,
    private val draftRepository: com.testlogon.android.data.messaging.DraftRepository,
    private val typingRepository: TypingRepository,
) : ViewModel() {

    /**
     * AND-133 — lifecycle-scoped recorder/player, created PER-VM on first use (not eagerly) and
     * released in [onCleared]. Backing nullables let [onCleared] release only what was actually
     * created, so closing a thread that never used voice never spins up a MediaRecorder/ExoPlayer.
     */
    private var recorderOrNull: VoiceRecorder? = null
    private val recorder: VoiceRecorder
        get() = recorderOrNull ?: recorderFactory.create().also { recorderOrNull = it }

    private var voicePlayerOrNull: VoicePlayerController? = null
    val voicePlayer: VoicePlayerController
        get() = voicePlayerOrNull ?: playerFactory.create().also { voicePlayerOrNull = it }

    private var recorderObserver: kotlinx.coroutines.Job? = null
    private var capturedPeaks: List<Float> = emptyList()

    /** Epoch-seconds clock; overridable in tests for deterministic optimistic timestamps. */
    internal var clock: () -> Long = { System.currentTimeMillis() / 1000L }

    private val conversationId: String =
        requireNotNull(savedStateHandle.get<String>(ARG_CONVERSATION_ID)) {
            "missing $ARG_CONVERSATION_ID"
        }

    /** AND-152 — deep-link target message to scroll to on open (consumed once, then cleared). */
    private var focusMessageId: String? = savedStateHandle.get<String>(ARG_FOCUS_MESSAGE_ID)

    private val _state = MutableStateFlow(ThreadUiState(conversationId = conversationId))
    val state: StateFlow<ThreadUiState> = _state.asStateFlow()

    private val _events = Channel<ThreadEvent>(Channel.BUFFERED)
    val events: Flow<ThreadEvent> = _events.receiveAsFlow()

    // ---- AND-151: in-conversation search ----

    /** AND-151 — owns the debounced in-conversation search lifecycle (state isolated from the thread). */
    private val searchController = ThreadSearchController(
        conversationId = conversationId,
        repository = repository,
        saved = savedStateHandle,
        scope = viewModelScope,
    )

    /** AND-151 — search UI state (active/query/phase/matches/cursor) for the Thread search bar. */
    val searchState: StateFlow<ThreadSearchUiState> = searchController.state

    fun onOpenSearch() = searchController.open()
    fun onCloseSearch() = searchController.close()
    fun onSearchQueryChange(query: String) = searchController.onQueryChange(query)
    fun onSearchNext() = searchController.next()
    fun onSearchPrev() = searchController.prev()

    // ---- AND-146: typing indicators ----

    private val typing = MutableStateFlow<Map<String, TypingUiUser>>(emptyMap())

    /** Per-user TTL expiry jobs; a fresh typing event cancels+replaces the user's pending expiry. */
    private val typingExpiryJobs = mutableMapOf<String, kotlinx.coroutines.Job>()

    /** Remote typers in this conversation (excludes self), ordered by display name. */
    val typingUsers: StateFlow<List<TypingUiUser>> =
        typing
            .map { TypingReducer.ordered(it) }
            .stateIn(viewModelScope, kotlinx.coroutines.flow.SharingStarted.Eagerly, emptyList())

    /** Send-side debounced typing controller. */
    private val typingController: TypingSignalController by lazy {
        TypingSignalController(conversationId, typingRepository)
    }

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

    /**
     * AND-147 — locally-known viewers per OWN message id (from live message:viewed events + the roster
     * fetch). Drives the live "seen" marker and the roster sheet; the server fields remain authoritative
     * on the next list fetch. The local user is never added (FR-6).
     */
    private val viewersByMessage = mutableMapOf<String, List<MessageViewer>>()

    /** AND-147 — server message ids already reported viewed this VM lifetime (once-guard, FR-1/AC-2). */
    private val reportedViews = mutableSetOf<String>()

    // AND-141: drafts. Declared BEFORE init{} so observeDraftSaver()'s Main.immediate launch (which
    // touches draftSaver synchronously) doesn't hit it before initialization — that NPE crashed the
    // thread screen on open.
    private val draftSaver = kotlinx.coroutines.flow.MutableSharedFlow<String>(extraBufferCapacity = 64)

    init {
        observeThread()
        observeRealtime()
        loadInitial()
        restoreDraft()
        observeDraftSaver()
        startTyping()
    }

    /** AND-146 — run the debounced typing send controller. */
    private fun startTyping() {
        viewModelScope.launch { typingController.run() }
    }

    private fun observeThread() {
        viewModelScope.launch {
            val currentUser = authStateStore.userSub.value
            repository.observeThread(conversationId).collect { messages ->
                val self = authStateStore.userSub.value ?: currentUser
                // AND-140 — hidden-for-me messages are dropped from the rendered thread.
                val visible = messages.filterNot { it.isHiddenLocal }
                // Track the newest CONFIRMED (server id present) message as the read marker (AND-125).
                visible.lastOrNull { it.id != null }?.let {
                    newestMessageId = it.id
                    newestMessageEpochSeconds = it.createdAtEpochSeconds
                }
                _state.update { prior ->
                    prior.copy(
                        messages = visible.map { it.toUi(self) },
                        receipts = computeReceipts(visible, self),
                        peerUserSub = prior.peerUserSub
                            ?: visible.firstOrNull { it.senderId.isNotEmpty() && it.senderId != self && it.senderId != "system" }?.senderId,
                    )
                }
                // AND-152 — once the deep-link target message is loaded, scroll to it (once).
                val target = focusMessageId
                if (target != null && visible.any { it.id == target || it.clientId == target }) {
                    focusMessageId = null
                    savedStateHandle[ARG_FOCUS_MESSAGE_ID] = null
                    _events.trySend(ThreadEvent.ScrollToMessage(target))
                }
            }
        }
    }

    /**
     * AND-147 — derive the receipt state for the local user's OWN confirmed messages from the payload
     * counts (delivered_to_count / read_by_count) plus any live-known viewers. Pure mapping via the
     * tested [ReceiptReducer]; only own, server-confirmed rows get an entry.
     */
    private fun computeReceipts(
        messages: List<Message>,
        self: String?,
    ): Map<String, MessageReceipt> {
        val out = mutableMapOf<String, MessageReceipt>()
        for (m in messages) {
            val id = m.id ?: continue
            val isOwn = m.senderId.isEmpty() || m.senderId == self
            if (!isOwn) continue
            out[id] = ReceiptReducer.derive(
                sendStatus = m.sendStatus.toReceiptStatus(),
                deliveredToCount = m.deliveredToCount,
                deliveredToUserIds = null,
                readByCount = m.readByCount,
                readByUserIds = m.readByUserIds,
                viewers = viewersByMessage[id].orEmpty(),
                selfUserId = self,
            )
        }
        return out
    }

    private fun com.testlogon.android.data.messaging.SendStatus.toReceiptStatus(): ReceiptStatus =
        when (this) {
            com.testlogon.android.data.messaging.SendStatus.SENDING -> ReceiptStatus.SENDING
            com.testlogon.android.data.messaging.SendStatus.FAILED -> ReceiptStatus.FAILED
            com.testlogon.android.data.messaging.SendStatus.SENT -> ReceiptStatus.SENT
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

    /**
     * AND-147 — called by the thread when an inbound (NOT own) message crosses the visibility
     * threshold. Reports the view at most once per VM lifetime ([reportedViews] guard); own/optimistic
     * messages (no server id, or authored by me) are never reported (FR-1/FR-6 / AC-2/AC-5).
     */
    fun onMessageVisible(messageId: String, authoredByMe: Boolean) {
        if (authoredByMe) return
        if (!reportedViews.add(messageId)) return
        viewModelScope.launch { repository.reportView(conversationId, messageId) }
    }

    /** AND-147 — open the "Seen by" roster sheet for [messageId] and fetch the (single-shot) roster. */
    fun openViewers(messageId: String) {
        _state.update { it.copy(viewerRoster = ViewerRosterUiState(messageId = messageId, loading = true)) }
        viewModelScope.launch {
            when (val r = repository.getViewers(conversationId, messageId)) {
                is ApiResult.Success -> {
                    viewersByMessage[messageId] = r.data
                    _state.update {
                        if (it.viewerRoster.messageId != messageId) it
                        else it.copy(viewerRoster = it.viewerRoster.copy(loading = false, viewers = r.data.sortedByDescending { v -> v.viewedAtEpochSeconds }, error = null))
                    }
                    recomputeReceiptsNow()
                }
                is ApiResult.Failure -> setRosterError(messageId, r.error.message)
                is ApiResult.NetworkError -> setRosterError(messageId, OFFLINE_MESSAGE)
            }
        }
    }

    fun closeViewers() {
        _state.update { it.copy(viewerRoster = ViewerRosterUiState()) }
    }

    private fun setRosterError(messageId: String, message: String) {
        _state.update {
            if (it.viewerRoster.messageId != messageId) it
            else it.copy(viewerRoster = it.viewerRoster.copy(loading = false, error = message))
        }
    }

    /** AND-147 — re-derive receipts from the current messages + the latest viewer map. */
    private fun recomputeReceiptsNow() {
        val self = authStateStore.userSub.value
        // Re-derive from the domain rows the repository last emitted (mirrored in receipts keys).
        _state.update { st ->
            val updated = st.receipts.mapValues { (id, prior) ->
                ReceiptReducer.derive(
                    sendStatus = prior.status,
                    deliveredToCount = prior.deliveredCount,
                    deliveredToUserIds = null,
                    readByCount = prior.seenCount,
                    readByUserIds = null,
                    viewers = viewersByMessage[id].orEmpty(),
                    selfUserId = self,
                )
            }
            st.copy(receipts = updated)
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
        // AND-141 — persist the composer draft (debounced; empty -> delete).
        draftSaver.tryEmit(text)
        // AND-146 — drive the debounced typing signal from composer activity.
        typingController.onInput(if (text.isBlank()) TypingInput.Cleared else TypingInput.Keystroke)
    }

    /** AND-146 — called from the screen on ON_STOP / leaving so a final typing stop is sent. */
    fun onScreenStopped() {
        typingController.onInput(TypingInput.Left)
    }

    fun onSend() {
        val composer = _state.value.composer
        val body = composer.draft.trim()
        if (body.isEmpty() || composer.overLimit) return
        val clientId = UUID.randomUUID().toString()
        val replyToId = composer.replyingTo?.messageId
        val opts = composer.options
        // AND-146 — sending the message ends the typing signal.
        typingController.onInput(TypingInput.Sent)
        // Clear the composer + the persisted draft immediately (AND-141 FR-4).
        _state.update { it.copy(composer = ComposerState(), hasDraft = false, draftSyncState = DraftSyncState.Idle) }
        // Cancel any pending debounced save from the last keystroke (coalesces to a clear), so a
        // queued save can't re-create the draft after we've sent + cleared it.
        draftSaver.tryEmit("")
        viewModelScope.launch {
            repository.enqueueOptimistic(conversationId, clientId, body, clock())
            _events.trySend(ThreadEvent.ScrollToBottom)
            val result = repository.sendOutbox(
                conversationId, clientId, body, replyToId,
                viewOnce = opts.viewOnce,
                lockPriceCents = opts.lockPriceCents,
                lockDescription = opts.lockDescription,
                sendAtEpochSeconds = opts.scheduledAtEpochSeconds,
                expiresInSeconds = opts.expiresInSeconds,
            )
            // AND-141 — clear the draft on a successful send.
            if (result is ApiResult.Success) draftRepository.clearDraft(conversationId)
        }
    }

    // ---- Send-options (view-once / locked / scheduled) ----

    fun openMessageOptions() {
        _state.update { it.copy(messageOptionsVisible = true) }
    }

    fun closeMessageOptions() {
        _state.update { it.copy(messageOptionsVisible = false) }
    }

    fun setViewOnce(enabled: Boolean) {
        _state.update {
            it.copy(composer = it.composer.copy(options = it.composer.options.copy(viewOnce = enabled)))
        }
    }

    fun setLockPrice(dollars: String) {
        val cents = parseDollarsToCents(dollars)
        _state.update {
            it.copy(
                composer = it.composer.copy(
                    options = it.composer.options.copy(
                        lockPriceCents = cents,
                        lockDescription = if (cents != null) "Unlock to view" else null,
                    ),
                ),
            )
        }
    }

    fun setScheduledAt(epochSeconds: Long?) {
        _state.update {
            it.copy(composer = it.composer.copy(options = it.composer.options.copy(scheduledAtEpochSeconds = epochSeconds)))
        }
    }

    fun setExpiresIn(seconds: Long?) {
        _state.update {
            it.copy(composer = it.composer.copy(options = it.composer.options.copy(expiresInSeconds = seconds)))
        }
    }

    fun clearMessageOptions() {
        _state.update { it.copy(composer = it.composer.copy(options = MessageOptions()), messageOptionsVisible = false) }
    }

    private fun startReply(messageId: String) {
        val msg = _state.value.messages.firstOrNull { it.key == messageId } ?: return
        if (msg.isTombstone) return
        val preview = msg.text.ifBlank {
            when {
                msg.isImage -> "Photo"
                msg.isVideo -> "Video"
                msg.isVoice || msg.isVoicemail -> "Voice message"
                msg.isGif -> "GIF"
                msg.isSticker -> "Sticker"
                else -> "Message"
            }
        }.take(80)
        val label = if (msg.isOwn) "yourself" else "them"
        _state.update {
            it.copy(composer = it.composer.copy(replyingTo = ReplyDraft(messageId, preview, label)))
        }
        _events.trySend(ThreadEvent.ScrollToBottom)
    }

    fun onRetry(clientId: String) {
        val failed = _state.value.messages.firstOrNull { it.key == clientId } ?: return
        viewModelScope.launch {
            // Re-enqueue as SENDING (same clientId) then re-fire. No server idempotency key exists,
            // so a retry after an uncertain failure may duplicate — retry stays manual.
            when {
                failed.isImage -> {
                    val uri = imageDrafts[clientId] ?: return@launch
                    repository.enqueueOptimisticImage(conversationId, clientId, uri, clock())
                    repository.sendImageOutbox(conversationId, clientId, uri)
                }
                failed.isFile -> {
                    val (uri, name, mime) = fileDrafts[clientId] ?: return@launch
                    val file = failed.media as? MessageMedia.File
                    repository.enqueueOptimisticFile(
                        conversationId, clientId, uri, name, file?.sizeBytes ?: 0L, mime, clock(),
                    )
                    repository.sendFileOutbox(conversationId, clientId, uri, name, mime)
                }
                else -> {
                    repository.enqueueOptimistic(conversationId, clientId, failed.text, clock())
                    repository.sendOutbox(conversationId, clientId, failed.text)
                }
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

    // ---- AND-132: file messages ----

    /** Tracks picked file uris by clientId so a retry can re-run without re-picking. */
    private val fileDrafts = mutableMapOf<String, Triple<String, String, String>>() // uri, name, mime

    fun onFilePicked(uri: android.net.Uri, fileName: String, sizeBytes: Long, mimeType: String) {
        val clientId = UUID.randomUUID().toString()
        val localUri = uri.toString()
        fileDrafts[clientId] = Triple(localUri, fileName, mimeType)
        viewModelScope.launch {
            repository.enqueueOptimisticFile(
                conversationId, clientId, localUri, fileName, sizeBytes, mimeType, clock(),
            )
            _events.trySend(ThreadEvent.ScrollToBottom)
            repository.sendFileOutbox(conversationId, clientId, localUri, fileName, mimeType)
        }
    }

    /** AND-132 — download (grant -> consume? -> GET) a received file, tracking per-message progress. */
    fun onDownloadFile(message: ThreadMessageUi) {
        val messageId = message.key
        val file = message.media as? MessageMedia.File ?: return
        val existing = _state.value.downloads[messageId]
        if (existing is FileDownloadUi.Downloading) return
        if (existing is FileDownloadUi.Downloaded) {
            _events.trySend(ThreadEvent.OpenFile(existing.localPath, file.mimeType))
            return
        }
        setDownload(messageId, FileDownloadUi.Downloading(0f))
        viewModelScope.launch {
            repository.downloadAttachment(
                conversationId, messageId, file.fileName, file.consumptionPolicy,
            ).collect { progress ->
                when (progress) {
                    is DownloadProgress.Downloading -> setDownload(messageId, FileDownloadUi.Downloading(progress.fraction))
                    is DownloadProgress.Done -> {
                        setDownload(messageId, FileDownloadUi.Downloaded(progress.file.absolutePath))
                        _events.trySend(ThreadEvent.OpenFile(progress.file.absolutePath, file.mimeType))
                    }
                    is DownloadProgress.Failed ->
                        setDownload(messageId, FileDownloadUi.Failed("Download failed"))
                }
            }
        }
    }

    private fun setDownload(messageId: String, state: FileDownloadUi) {
        _state.update { it.copy(downloads = it.downloads + (messageId to state)) }
    }

    // ---- AND-133: voice messages ----

    /** Called once RECORD_AUDIO is granted; starts capturing into a fresh cache temp file. */
    fun onStartRecording() {
        val dir = File(appContext.cacheDir, "voice").apply { mkdirs() }
        val outFile = File(dir, "${UUID.randomUUID()}.m4a")
        capturedPeaks = emptyList()
        observeRecorder()
        recorder.start(outFile)
        _state.update { it.copy(voice = VoiceComposerUiState.Recording(0L, emptyList(), null)) }
    }

    fun onPermissionDenied(permanently: Boolean) {
        _state.update { it.copy(voice = VoiceComposerUiState.PermissionRequired(permanently)) }
    }

    private fun observeRecorder() {
        recorderObserver?.cancel()
        recorderObserver = viewModelScope.launch {
            recorder.amplitudes.collect { amp ->
                // Append a coarse normalized peak for the live waveform (full-scale 0..1).
                capturedPeaks = (capturedPeaks + (amp / 32767f).coerceIn(0f, 1f)).takeLast(MAX_LIVE_PEAKS)
                val st = recorder.state.value
                if (st is RecorderState.Recording) {
                    _state.update {
                        it.copy(
                            voice = VoiceComposerUiState.Recording(
                                elapsedMs = st.elapsedMs,
                                peaks = capturedPeaks,
                                countdownSeconds = RecorderLimits.countdownSeconds(st.elapsedMs),
                            ),
                        )
                    }
                } else if (st is RecorderState.Stopped) {
                    // Auto-stop (max duration) reached on the recorder ticker.
                    reduceStopped(st)
                }
            }
        }
    }

    /** Finish a tap/locked recording; transitions to Preview, or back to Idle if too short. */
    fun onStopRecording() {
        val result = recorder.stop()
        recorderObserver?.cancel()
        if (result == null) {
            _state.update { it.copy(voice = VoiceComposerUiState.Idle) }
            return
        }
        reduceStopped(RecorderState.Stopped(result))
    }

    private fun reduceStopped(stopped: RecorderState.Stopped) {
        val result = stopped.result
        val peaks = Waveform.resample(
            Waveform.normalize(result.amplitudes),
        )
        capturedPeaks = peaks
        currentClipPath = result.file.absolutePath
        currentClipDurationMs = result.durationMs
        currentClipRawAmplitudes = result.amplitudes
        _state.update {
            it.copy(voice = VoiceComposerUiState.Preview(durationMs = result.durationMs, peaks = peaks))
        }
    }

    private var currentClipPath: String? = null
    private var currentClipDurationMs: Long = 0L
    private var currentClipRawAmplitudes: List<Int> = emptyList()

    fun onCancelRecording() {
        recorder.cancel()
        recorderObserver?.cancel()
        currentClipPath?.let { File(it).delete() }
        currentClipPath = null
        _state.update { it.copy(voice = VoiceComposerUiState.Idle) }
    }

    fun onSendVoice() {
        val path = currentClipPath ?: return
        val durationSeconds = currentClipDurationMs / 1000.0
        // Downsample to the wire waveform (10..200 floats 0..1), clamped to the min the API accepts.
        val wire = Waveform.normalize(currentClipRawAmplitudes, Waveform.DEFAULT_BUCKETS)
        val clientId = UUID.randomUUID().toString()
        _state.update { it.copy(voice = VoiceComposerUiState.Sending(0f)) }
        viewModelScope.launch {
            repository.enqueueOptimisticVoice(conversationId, clientId, path, durationSeconds, wire, clock())
            _events.trySend(ThreadEvent.ScrollToBottom)
            val result = repository.sendVoiceOutbox(conversationId, clientId, path, durationSeconds, wire)
            _state.update {
                it.copy(
                    voice = if (result is ApiResult.Success) {
                        VoiceComposerUiState.Idle
                    } else {
                        VoiceComposerUiState.Failed("Couldn't send voice message")
                    },
                )
            }
            if (result is ApiResult.Success) {
                currentClipPath = null
            }
        }
    }

    /** AND-133 — toggle playback of a received/sent voice bubble (one clip at a time). */
    fun onToggleVoice(messageId: String, audioUrl: String?) {
        val url = audioUrl ?: return
        voicePlayer.toggle(messageId, url)
    }

    fun onSeekVoice(messageId: String, fraction: Float) {
        voicePlayer.seekTo(messageId, fraction)
    }

    // ---- AND-135: GIF / sticker / custom-emoji picker ----

    private var gifSearchJob: kotlinx.coroutines.Job? = null
    private val pollObservers = mutableSetOf<String>()

    init {
        observeCustomEmoji()
        observePollsInThread()
    }

    private fun observeCustomEmoji() {
        viewModelScope.launch {
            repository.observeCustomEmoji().collect { catalog ->
                _state.update {
                    it.copy(customEmoji = catalog, mediaPicker = it.mediaPicker.copy(emoji = catalog))
                }
            }
        }
        // Stale-first: surface cached rows immediately, then refresh in the background.
        viewModelScope.launch { repository.refreshCustomEmoji() }
    }

    fun openMediaPicker() {
        _state.update { it.copy(mediaPicker = it.mediaPicker.copy(visible = true)) }
        // Lazy-load the default tab content.
        onGifQueryChange(_state.value.mediaPicker.gifQuery)
        loadStickerCollections()
    }

    fun closeMediaPicker() {
        gifSearchJob?.cancel()
        _state.update { it.copy(mediaPicker = it.mediaPicker.copy(visible = false)) }
    }

    fun selectMediaTab(tab: MediaTab) {
        _state.update { it.copy(mediaPicker = it.mediaPicker.copy(tab = tab)) }
        if (tab == MediaTab.STICKERS && _state.value.mediaPicker.collections.isEmpty()) {
            loadStickerCollections()
        }
    }

    fun onGifQueryChange(query: String) {
        _state.update { it.copy(mediaPicker = it.mediaPicker.copy(gifQuery = query, gifLoading = true)) }
        gifSearchJob?.cancel()
        gifSearchJob = viewModelScope.launch {
            kotlinx.coroutines.delay(GIF_DEBOUNCE_MS) // empty query => trending
            when (val r = repository.searchGifs(query)) {
                is ApiResult.Success -> _state.update {
                    it.copy(mediaPicker = it.mediaPicker.copy(gifLoading = false, gifResults = r.data, gifError = null))
                }
                is ApiResult.Failure -> _state.update {
                    it.copy(mediaPicker = it.mediaPicker.copy(gifLoading = false, gifError = r.error.message))
                }
                is ApiResult.NetworkError -> _state.update {
                    it.copy(mediaPicker = it.mediaPicker.copy(gifLoading = false, gifError = OFFLINE_MESSAGE))
                }
            }
        }
    }

    private fun loadStickerCollections() {
        if (_state.value.mediaPicker.collectionsLoading) return
        _state.update { it.copy(mediaPicker = it.mediaPicker.copy(collectionsLoading = true, collectionsError = null)) }
        viewModelScope.launch {
            when (val r = repository.stickerCollections()) {
                is ApiResult.Success -> _state.update {
                    it.copy(
                        mediaPicker = it.mediaPicker.copy(
                            collectionsLoading = false,
                            collections = r.data,
                            selectedCollectionId = it.mediaPicker.selectedCollectionId ?: r.data.firstOrNull()?.collectionId,
                        ),
                    )
                }
                is ApiResult.Failure -> _state.update {
                    it.copy(mediaPicker = it.mediaPicker.copy(collectionsLoading = false, collectionsError = r.error.message))
                }
                is ApiResult.NetworkError -> _state.update {
                    it.copy(mediaPicker = it.mediaPicker.copy(collectionsLoading = false, collectionsError = OFFLINE_MESSAGE))
                }
            }
        }
    }

    fun onSelectCollection(collectionId: String) {
        _state.update { it.copy(mediaPicker = it.mediaPicker.copy(selectedCollectionId = collectionId)) }
    }

    /** AND-135 — selecting a GIF sends immediately and closes the sheet. */
    fun onGifSelected(gif: GifResult) {
        closeMediaPicker()
        val clientId = UUID.randomUUID().toString()
        viewModelScope.launch {
            _events.trySend(ThreadEvent.ScrollToBottom)
            repository.sendGif(
                conversationId,
                clientId,
                GifSendPayload(gif.url, gif.altText, gif.width, gif.height),
            )
        }
    }

    /** AND-135 — selecting a sticker sends immediately and closes the sheet. */
    fun onStickerSelected(collectionId: String, stickerId: String, url: String, altText: String?) {
        closeMediaPicker()
        val clientId = UUID.randomUUID().toString()
        viewModelScope.launch {
            _events.trySend(ThreadEvent.ScrollToBottom)
            repository.sendSticker(conversationId, clientId, StickerPick(stickerId, collectionId, url, altText))
        }
    }

    /** AND-135 — inserting a custom emoji adds its ":shortcode:" token to the draft (does NOT send). */
    fun onCustomEmojiSelected(shortcode: String) {
        _state.update {
            val current = it.composer.draft
            val next = "$current:$shortcode:"
            it.copy(composer = it.composer.copy(draft = next, charCount = next.length, overLimit = next.length > ComposerState.MAX_LENGTH))
        }
    }

    // ---- AND-134: voicemail ----

    /**
     * AND-134 — send the just-recorded clip as a voicemail tied to [callId]. Reuses the AND-133
     * recorder pipeline (currentClipPath/Duration/Amplitudes); audio mode by default.
     */
    fun onSendVoicemail(callId: String, isVideo: Boolean = false) {
        val path = currentClipPath ?: return
        val durationSeconds = currentClipDurationMs / 1000.0
        val wire = Waveform.normalize(currentClipRawAmplitudes, Waveform.DEFAULT_BUCKETS)
        val clientId = UUID.randomUUID().toString()
        val contentType = if (isVideo) "video/mp4" else VOICEMAIL_AUDIO_CONTENT_TYPE
        _state.update { it.copy(voice = VoiceComposerUiState.Sending(0f)) }
        viewModelScope.launch {
            repository.enqueueOptimisticVoicemail(conversationId, clientId, path, durationSeconds, wire, isVideo, clock())
            _events.trySend(ThreadEvent.ScrollToBottom)
            val result = repository.sendVoicemailOutbox(
                conversationId, clientId, callId, path, durationSeconds, wire, contentType, isVideo,
            )
            _state.update {
                it.copy(
                    voice = if (result is ApiResult.Success) VoiceComposerUiState.Idle
                    else VoiceComposerUiState.Failed("Couldn't send voicemail"),
                )
            }
            if (result is ApiResult.Success) currentClipPath = null
        }
    }

    // ---- AND-136: meeting poll ----

    /** Observe poll state for every meeting-poll message currently in the thread. */
    private fun observePollsInThread() {
        viewModelScope.launch {
            state.collect { st ->
                val me = authStateStore.userSub.value
                st.messages.forEach { ui ->
                    val poll = ui.media as? MessageMedia.MeetingPoll ?: return@forEach
                    if (poll.pollId.isNotBlank() && pollObservers.add(poll.pollId)) {
                        observeOnePoll(poll.pollId, me)
                        // Hydrate canonical counts.
                        viewModelScope.launch { repository.refreshMeetingPoll(conversationId, poll.pollId) }
                    }
                }
            }
        }
    }

    private fun observeOnePoll(pollId: String, currentUser: String?) {
        viewModelScope.launch {
            repository.observeMeetingPoll(pollId).collect { poll ->
                if (poll == null) return@collect
                _state.update {
                    val prior = it.polls[pollId]
                    it.copy(
                        polls = it.polls + (
                            pollId to (prior?.copy(poll = poll, canManage = poll.creatorId == currentUser)
                                ?: MeetingPollCardUiState(poll = poll, canManage = poll.creatorId == currentUser))
                            ),
                    )
                }
            }
        }
    }

    fun onOpenPollComposer() { _state.update { it.copy(pollComposerVisible = true) } }
    fun onDismissPollComposer() { _state.update { it.copy(pollComposerVisible = false) } }

    fun onCreatePoll(draft: MeetingPollDraft) {
        _state.update { it.copy(pollComposerVisible = false) }
        viewModelScope.launch {
            repository.createMeetingPoll(conversationId, draft)
            _events.trySend(ThreadEvent.ScrollToBottom)
        }
    }

    fun onPollVote(pollId: String, slotId: String, vote: SlotVote?) {
        setPollMutating(pollId, true)
        viewModelScope.launch {
            val result = repository.voteMeetingPoll(conversationId, pollId, slotId, vote)
            _state.update {
                val prior = it.polls[pollId] ?: return@update it
                it.copy(
                    polls = it.polls + (
                        pollId to prior.copy(
                            isMutating = false,
                            inlineError = if (result is ApiResult.Success) null else "Couldn't save your vote — tap to retry",
                        )
                        ),
                )
            }
        }
    }

    fun onPollConfirm(pollId: String, slotId: String) {
        setPollMutating(pollId, true)
        viewModelScope.launch {
            val result = repository.confirmMeetingPoll(conversationId, pollId, slotId)
            _state.update {
                val prior = it.polls[pollId] ?: return@update it
                it.copy(
                    polls = it.polls + (
                        pollId to prior.copy(
                            isMutating = false,
                            inlineError = if (result is ApiResult.Success) null else "Couldn't confirm — tap to retry",
                        )
                        ),
                )
            }
        }
    }

    private fun setPollMutating(pollId: String, mutating: Boolean) {
        _state.update {
            val prior = it.polls[pollId] ?: return@update it
            it.copy(polls = it.polls + (pollId to prior.copy(isMutating = mutating, inlineError = null)))
        }
    }

    // ---- AND-137: countdown ----

    fun onOpenCountdownPicker() {
        _state.update { it.copy(countdownPicker = CountdownPickerState(visible = true)) }
    }

    fun onDismissCountdownPicker() {
        _state.update { it.copy(countdownPicker = CountdownPickerState()) }
    }

    fun onCountdownTitleChange(title: String) {
        _state.update { it.copy(countdownPicker = it.countdownPicker.copy(title = title, error = null)) }
    }

    /** [target] is UTC epoch seconds chosen in the picker (device zone -> UTC done in the UI). */
    fun onCountdownTargetChange(targetEpochSeconds: Long?) {
        _state.update {
            it.copy(countdownPicker = it.countdownPicker.copy(targetEpochSeconds = targetEpochSeconds, error = null))
        }
    }

    fun onSendCountdown() {
        val picker = _state.value.countdownPicker
        val title = picker.title.trim()
        val target = picker.targetEpochSeconds
        // Validate: 1..200 chars + strictly-future target.
        if (title.isEmpty() || title.length > 200) {
            _state.update { it.copy(countdownPicker = it.countdownPicker.copy(error = "Enter a title (1–200 characters)")) }
            return
        }
        if (target == null || target <= clock()) {
            _state.update { it.copy(countdownPicker = it.countdownPicker.copy(error = "Pick a future time")) }
            return
        }
        val clientId = UUID.randomUUID().toString()
        val draft = CountdownDraft(title = title, targetEpochSeconds = target, associatedEventType = AssociatedEventType.CUSTOM)
        _state.update { it.copy(countdownPicker = CountdownPickerState()) }
        viewModelScope.launch {
            // Optimistic countdown bubble through the shared outbox (renders + ticks immediately).
            repository.enqueueOptimisticCountdown(conversationId, clientId, title, target, clock())
            _events.trySend(ThreadEvent.ScrollToBottom)
            repository.sendCountdown(conversationId, clientId, draft)
        }
    }

    // ---- AND-139: tips / paid-unlockable / lottery ----

    /** AND-139 — unlock entry point (FIXED runs billing-authorize; LOTTERY is a single server call). */
    fun onUnlockClick(messageKey: String) {
        val msg = _state.value.messages.firstOrNull { it.key == messageKey } ?: return
        val paid = (msg.media as? MessageMedia.Paid)?.monetization ?: return
        if (paid.unlocked || msg.isOwn) return
        when (paid.type) {
            com.testlogon.android.data.messaging.UnlockType.LOTTERY -> unlockLottery(messageKey)
            com.testlogon.android.data.messaging.UnlockType.FIXED -> unlockFixed(messageKey, paid)
        }
    }

    private fun unlockFixed(messageKey: String, paid: MessageMonetization) {
        setUnlock(messageKey, UnlockUiState(UnlockPhase.AUTHORIZING))
        viewModelScope.launch {
            when (val auth = billing.authorize(paid.priceMinorUnits ?: 0L, paid.currency)) {
                is BillingResult.Authorized -> {
                    setUnlock(messageKey, UnlockUiState(UnlockPhase.UNLOCKING))
                    when (repository.unlockMessage(conversationId, messageKey, auth.paymentMethodId)) {
                        is ApiResult.Success -> clearUnlock(messageKey)
                        else -> setUnlock(messageKey, UnlockUiState(UnlockPhase.FAILED, "Couldn't unlock — tap to retry"))
                    }
                }
                BillingResult.Cancelled -> clearUnlock(messageKey)
                is BillingResult.Declined ->
                    setUnlock(messageKey, UnlockUiState(UnlockPhase.FAILED, "Payment declined: ${auth.reason}"))
                is BillingResult.Failed ->
                    setUnlock(messageKey, UnlockUiState(UnlockPhase.FAILED, "Payment failed — tap to retry"))
                BillingResult.NotConfigured ->
                    // STOP-AND-FLAG: no payment provider wired (AND-031). Never call the server / fake a charge.
                    setUnlock(messageKey, UnlockUiState(UnlockPhase.FAILED, "Payments are not available yet"))
            }
        }
    }

    private fun unlockLottery(messageKey: String) {
        // No client-side billing-authorize for lottery: the server draws + reveals atomically.
        setUnlock(messageKey, UnlockUiState(UnlockPhase.UNLOCKING))
        viewModelScope.launch {
            when (repository.unlockLottery(conversationId, messageKey)) {
                is ApiResult.Success -> clearUnlock(messageKey)
                else -> setUnlock(messageKey, UnlockUiState(UnlockPhase.FAILED, "Unlock failed — tap to retry"))
            }
        }
    }

    private fun setUnlock(messageKey: String, state: UnlockUiState) {
        _state.update { it.copy(unlocks = it.unlocks + (messageKey to state)) }
    }

    private fun clearUnlock(messageKey: String) {
        _state.update { it.copy(unlocks = it.unlocks - messageKey) }
    }

    fun onTipOpen(messageKey: String) {
        val msg = _state.value.messages.firstOrNull { it.key == messageKey } ?: return
        if (msg.isOwn) return // FR-10: never tip your own message.
        _state.update { it.copy(tipSheet = TipSheetState(messageId = messageKey)) }
    }

    fun onTipDismiss() {
        _state.update { it.copy(tipSheet = TipSheetState()) }
    }

    fun onTipPresetSelect(cents: Long) {
        _state.update {
            it.copy(tipSheet = it.tipSheet.copy(selectedCents = cents, customInput = "", amountError = null))
        }
    }

    fun onTipCustomChange(text: String) {
        _state.update {
            it.copy(tipSheet = it.tipSheet.copy(customInput = text, selectedCents = null, amountError = null))
        }
    }

    fun onTipNoteChange(text: String) {
        _state.update { it.copy(tipSheet = it.tipSheet.copy(note = text)) }
    }

    fun onTipConfirm() {
        val sheet = _state.value.tipSheet
        val messageId = sheet.messageId ?: return
        val cents = sheet.amountCents
        if (cents == null || cents !in TipSheetState.MIN_TIP_CENTS..TipSheetState.MAX_TIP_CENTS) {
            _state.update { it.copy(tipSheet = it.tipSheet.copy(amountError = "Enter an amount between \$0.01 and \$1000.00")) }
            return
        }
        _state.update { it.copy(tipSheet = it.tipSheet.copy(submitting = true, amountError = null)) }
        viewModelScope.launch {
            when (val auth = billing.authorize(cents, TIP_CURRENCY)) {
                is BillingResult.Authorized -> {
                    val result = repository.tipMessage(
                        conversationId, messageId, cents, TIP_CURRENCY,
                        note = sheet.note.takeIf { it.isNotBlank() },
                        paymentMethodId = auth.paymentMethodId,
                    )
                    when (result) {
                        is ApiResult.Success ->
                            _state.update { it.copy(tipSheet = TipSheetState(), transientMessage = "Tip sent") }
                        else ->
                            _state.update {
                                it.copy(tipSheet = it.tipSheet.copy(submitting = false, amountError = "Couldn't send tip — try again"))
                            }
                    }
                }
                BillingResult.Cancelled ->
                    _state.update { it.copy(tipSheet = it.tipSheet.copy(submitting = false)) }
                is BillingResult.Declined ->
                    _state.update { it.copy(tipSheet = it.tipSheet.copy(submitting = false, amountError = "Payment declined: ${auth.reason}")) }
                is BillingResult.Failed ->
                    _state.update { it.copy(tipSheet = it.tipSheet.copy(submitting = false, amountError = "Payment failed — try again")) }
                BillingResult.NotConfigured ->
                    _state.update { it.copy(tipSheet = it.tipSheet.copy(submitting = false, amountError = "Payments are not available yet")) }
            }
        }
    }

    fun onTransientMessageShown() {
        _state.update { it.copy(transientMessage = null) }
    }

    // ---- AND-140: per-message actions ----

    /** Dispatches a long-press action intent on viewModelScope. */
    fun onAction(action: ThreadAction) {
        when (action) {
            is ThreadAction.ToggleReaction -> toggleReaction(action.messageId, action.emoji)
            is ThreadAction.OpenReactionDetails -> openReactionDetails(action.messageId)
            is ThreadAction.SetPinned -> setPinned(action.messageId, action.pinned)
            ThreadAction.OpenPinsList -> openPinsList()
            is ThreadAction.Reply -> startReply(action.messageId)
            ThreadAction.CancelReply ->
                _state.update { it.copy(composer = it.composer.copy(replyingTo = null)) }
            is ThreadAction.StartEdit -> startEdit(action.messageId)
            is ThreadAction.SubmitEdit -> submitEdit(action.messageId, action.body)
            ThreadAction.CancelEdit -> updateActions { it.copy(editing = null) }
            is ThreadAction.OpenEditHistory -> openEditHistory(action.messageId)
            is ThreadAction.Delete -> deleteMessage(action.messageId)
            is ThreadAction.Revoke -> revokeMessage(action.messageId)
            is ThreadAction.SetHidden -> setHidden(action.messageId, action.hidden)
            // AND-163 — the report flow is owned by the separate ReportViewModel/ReportSheet hosted by
            // the screen (like Delete/Revoke confirms in MessageActionsHost), so the thread VM ignores it.
            is ThreadAction.Report -> Unit
            ThreadAction.DismissSheets -> updateActions {
                it.copy(
                    pinsSheetVisible = false,
                    reactionDetailsVisible = false,
                    editHistoryVisible = false,
                )
            }
        }
    }

    private fun toggleReaction(messageId: String, emoji: String) {
        val msg = _state.value.messages.firstOrNull { it.key == messageId } ?: return
        val add = msg.reactions.none { it.emoji == emoji && it.reactedByMe }
        viewModelScope.launch {
            val result = repository.toggleReaction(conversationId, messageId, emoji, add)
            if (result is ApiResult.Failure) {
                updateActions { it.copy(transientError = result.error.message) }
            } else if (result is ApiResult.NetworkError) {
                updateActions { it.copy(transientError = OFFLINE_MESSAGE) }
            }
        }
    }

    private fun openReactionDetails(messageId: String) {
        updateActions { it.copy(reactionDetails = Async.Loading, reactionDetailsVisible = true) }
        viewModelScope.launch {
            when (val r = repository.reactionDetails(conversationId, messageId)) {
                is ApiResult.Success -> updateActions { it.copy(reactionDetails = Async.Success(r.data)) }
                is ApiResult.Failure -> updateActions { it.copy(reactionDetails = Async.Error(r.error.message)) }
                is ApiResult.NetworkError -> updateActions { it.copy(reactionDetails = Async.Error(OFFLINE_MESSAGE)) }
            }
        }
    }

    private fun setPinned(messageId: String, pinned: Boolean) {
        viewModelScope.launch {
            when (val r = repository.setPinned(conversationId, messageId, pinned)) {
                is ApiResult.Failure -> updateActions { it.copy(transientError = r.error.message) }
                is ApiResult.NetworkError -> updateActions { it.copy(transientError = OFFLINE_MESSAGE) }
                else -> Unit
            }
        }
    }

    private fun openPinsList() {
        updateActions { it.copy(pinned = Async.Loading, pinsSheetVisible = true) }
        viewModelScope.launch {
            val self = authStateStore.userSub.value
            when (val r = repository.pinnedMessages(conversationId)) {
                is ApiResult.Success ->
                    updateActions { it.copy(pinned = Async.Success(r.data.map { m -> m.toUi(self) })) }
                is ApiResult.Failure -> updateActions { it.copy(pinned = Async.Error(r.error.message)) }
                is ApiResult.NetworkError -> updateActions { it.copy(pinned = Async.Error(OFFLINE_MESSAGE)) }
            }
        }
    }

    /** AND-140 — jump the thread to a pinned message (if loaded). */
    fun onJumpToPinned(messageKey: String) {
        updateActions { it.copy(pinsSheetVisible = false) }
        _events.trySend(ThreadEvent.ScrollToMessage(messageKey))
    }

    /** AND-151 — scroll the thread to a search-match message id, reusing the jump-to-message effect. */
    fun onJumpToSearchMatch(messageId: String) {
        _events.trySend(ThreadEvent.ScrollToMessage(messageId))
    }

    private fun startEdit(messageId: String) {
        val msg = _state.value.messages.firstOrNull { it.key == messageId } ?: return
        if (!msg.isOwn || msg.isTombstone) return
        updateActions { it.copy(editing = EditTarget(messageId, msg.text)) }
    }

    private fun submitEdit(messageId: String, body: String) {
        val trimmed = body.trim()
        if (trimmed.isEmpty()) return
        updateActions { it.copy(editing = null) }
        viewModelScope.launch {
            when (val r = repository.editMessage(conversationId, messageId, trimmed)) {
                is ApiResult.Failure -> updateActions { it.copy(transientError = r.error.message) }
                is ApiResult.NetworkError -> updateActions { it.copy(transientError = OFFLINE_MESSAGE) }
                else -> Unit
            }
        }
    }

    private fun openEditHistory(messageId: String) {
        updateActions { it.copy(editHistory = Async.Loading, editHistoryVisible = true) }
        viewModelScope.launch {
            when (val r = repository.editHistory(conversationId, messageId)) {
                is ApiResult.Success -> updateActions { it.copy(editHistory = Async.Success(r.data)) }
                is ApiResult.Failure -> updateActions { it.copy(editHistory = Async.Error(r.error.message)) }
                is ApiResult.NetworkError -> updateActions { it.copy(editHistory = Async.Error(OFFLINE_MESSAGE)) }
            }
        }
    }

    private fun deleteMessage(messageId: String) {
        viewModelScope.launch {
            when (val r = repository.deleteMessage(conversationId, messageId)) {
                is ApiResult.Failure -> updateActions { it.copy(transientError = r.error.message) }
                is ApiResult.NetworkError -> updateActions { it.copy(transientError = OFFLINE_MESSAGE) }
                else -> Unit
            }
        }
    }

    private fun revokeMessage(messageId: String) {
        viewModelScope.launch {
            when (val r = repository.revokeMessage(conversationId, messageId)) {
                is ApiResult.Failure -> updateActions {
                    // 403 = outside the revoke window: surface a precise message.
                    val message = if (r.error.status == HTTP_FORBIDDEN) "Revoke window expired" else r.error.message
                    it.copy(transientError = message)
                }
                is ApiResult.NetworkError -> updateActions { it.copy(transientError = OFFLINE_MESSAGE) }
                else -> Unit
            }
        }
    }

    private fun setHidden(messageId: String, hidden: Boolean) {
        viewModelScope.launch {
            when (val r = repository.setHidden(conversationId, messageId, hidden)) {
                is ApiResult.Failure -> updateActions { it.copy(transientError = r.error.message) }
                is ApiResult.NetworkError -> updateActions { it.copy(transientError = OFFLINE_MESSAGE) }
                else -> Unit
            }
        }
    }

    fun onActionErrorShown() {
        updateActions { it.copy(transientError = null) }
    }

    private inline fun updateActions(transform: (MessageActionsUiState) -> MessageActionsUiState) {
        _state.update { it.copy(actions = transform(it.actions)) }
    }

    // ---- AND-141: drafts ----

    private fun restoreDraft() {
        viewModelScope.launch {
            when (val r = draftRepository.loadAndReconcile(conversationId)) {
                is ApiResult.Success -> {
                    val draft = r.data
                    if (draft != null && draft.text.isNotBlank()) {
                        _state.update {
                            it.copy(
                                composer = it.composer.copy(
                                    draft = draft.text,
                                    charCount = draft.text.length,
                                    overLimit = draft.text.length > ComposerState.MAX_LENGTH,
                                ),
                                hasDraft = true,
                                draftSyncState = if (draft.pendingSync) DraftSyncState.SavedLocal else DraftSyncState.Synced,
                            )
                        }
                    }
                }
                else -> Unit
            }
            // Push any pending-sync rows on open.
            draftRepository.flushPending()
        }
    }

    private fun observeDraftSaver() {
        viewModelScope.launch {
            draftSaver
                .debounceCompat(DRAFT_DEBOUNCE_MS)
                .collect { text -> persistDraft(text) }
        }
    }

    private suspend fun persistDraft(text: String) {
        if (text.isBlank()) {
            draftRepository.clearDraft(conversationId)
            _state.update { it.copy(hasDraft = false, draftSyncState = DraftSyncState.Idle) }
        } else {
            _state.update { it.copy(draftSyncState = DraftSyncState.Saving) }
            val r = draftRepository.saveDraft(conversationId, text)
            _state.update {
                it.copy(
                    hasDraft = true,
                    draftSyncState = when {
                        r is ApiResult.Success && !r.data.pendingSync -> DraftSyncState.Synced
                        else -> DraftSyncState.SavedLocal
                    },
                )
            }
        }
    }

    /** AND-141 — flush the buffered draft edit immediately (ON_STOP / leaving the screen). */
    fun flushDraft() {
        val text = _state.value.composer.draft
        viewModelScope.launch { persistDraft(text) }
    }

    /** AND-141 — discard the draft (composer overflow action). */
    fun onDiscardDraft() {
        _state.update { it.copy(composer = ComposerState(), hasDraft = false, draftSyncState = DraftSyncState.Idle) }
        draftSaver.tryEmit("") // cancel any pending debounced save
        viewModelScope.launch { draftRepository.clearDraft(conversationId) }
    }

    override fun onCleared() {
        super.onCleared()
        recorderOrNull?.release()
        voicePlayerOrNull?.release()
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

    /**
     * AND-146 — merge a typing event into the typing map. `is_typing:false` removes the user
     * immediately; `is_typing:true` (re)adds them and (re)arms a relative TTL expiry job so the entry
     * self-clears after [TypingConfig.TTL_MS] of silence even if a stop frame is dropped (FR-5).
     * Display names resolve from the loaded roster; unknown ids fall back to a generic label.
     */
    private fun applyTyping(event: MessagingEvent.Typing) {
        typingExpiryJobs.remove(event.userId)?.cancel()
        if (!event.isTyping) {
            typing.update { it - event.userId }
            return
        }
        typing.update { current ->
            current + (event.userId to TypingUiUser(
                userId = event.userId,
                displayName = resolveSenderName(event.userId) ?: TYPING_FALLBACK_NAME,
                expiresAtMillis = 0L, // expiry is enforced by the per-user job below
            ))
        }
        typingExpiryJobs[event.userId] = viewModelScope.launch {
            delay(TypingConfig.TTL_MS)
            typing.update { it - event.userId }
            typingExpiryJobs.remove(event.userId)
        }
    }

    /** Best-effort display name from the loaded roster; null when unknown (UI uses the fallback). */
    private fun resolveSenderName(userId: String): String? =
        // The thread model exposes only sender ids today; surface the id itself as a stable label
        // until a participant roster with names is wired (FR-4 fallback path).
        userId.takeIf { it.isNotBlank() }

    private fun observeRealtime() {
        viewModelScope.launch {
            eventStream.events().collect { streamEvent ->
                // AND-147 FR-8 / AND-149 — on (re)connect, retry any view reports that failed offline.
                if (streamEvent is MessagingStreamEvent.State &&
                    streamEvent.state == com.testlogon.android.data.messaging.realtime.StreamConnectionState.CONNECTED
                ) {
                    viewModelScope.launch { repository.retryPendingViews() }
                }
                if (streamEvent is MessagingStreamEvent.Event) {
                    when (val event = streamEvent.event) {
                        is MessagingEvent.NewMessage ->
                            if (event.conversationId == conversationId) {
                                repository.applyInboundMessage(event)
                                _events.trySend(ThreadEvent.ScrollToBottom)
                                // AND-125 FR-2: a new inbound message re-arms the read trigger; since the
                                // thread is open and visible, mark it read again straight away.
                                readMarked = false
                                onThreadVisible()
                            }
                        // AND-140 — reaction/edit/revoke on an existing message: reconcile for live reflection.
                        is MessagingEvent.MessageMutated ->
                            if (event.conversationId == conversationId) {
                                repository.applyMessageMutation(event)
                            }
                        // AND-146 — fold typing events for THIS conversation into the typing map,
                        // excluding self-echo.
                        is MessagingEvent.Typing ->
                            if (event.conversationId == conversationId &&
                                event.userId != authStateStore.userSub.value
                            ) {
                                applyTyping(event)
                            }
                        // AND-147 — a counterpart viewed a message: fold into the live roster + seen
                        // marker for THIS conversation, excluding self-echo (FR-3/FR-6 / AC-1).
                        is MessagingEvent.MessageViewed ->
                            if (event.conversationId == conversationId &&
                                event.viewerId != authStateStore.userSub.value
                            ) {
                                applyViewed(event)
                            }
                        else -> Unit
                    }
                }
            }
        }
    }

    /**
     * AND-147 — fold a live message:viewed event into the per-message viewer roster (idempotent via
     * the tested [ReceiptReducer.applyViewed]) and re-derive the seen marker without a refetch (AC-1).
     */
    private fun applyViewed(event: MessagingEvent.MessageViewed) {
        val self = authStateStore.userSub.value
        val merged = ReceiptReducer.applyViewed(viewersByMessage[event.messageId].orEmpty(), event, self)
        viewersByMessage[event.messageId] = merged
        _state.update { st ->
            val prior = st.receipts[event.messageId]
            // Only own messages carry a receipt entry; derive SEEN live from the new roster.
            val receipts = if (prior != null) {
                st.receipts + (event.messageId to ReceiptReducer.derive(
                    sendStatus = if (prior.status == ReceiptStatus.SENDING || prior.status == ReceiptStatus.FAILED) {
                        prior.status
                    } else {
                        ReceiptStatus.SENT
                    },
                    deliveredToCount = prior.deliveredCount,
                    deliveredToUserIds = null,
                    readByCount = prior.seenCount,
                    readByUserIds = null,
                    viewers = merged,
                    selfUserId = self,
                ))
            } else {
                st.receipts
            }
            val roster = if (st.viewerRoster.messageId == event.messageId) {
                st.viewerRoster.copy(viewers = merged.sortedByDescending { v -> v.viewedAtEpochSeconds })
            } else {
                st.viewerRoster
            }
            st.copy(receipts = receipts, viewerRoster = roster)
        }
    }

    companion object {
        const val ARG_CONVERSATION_ID = "conversationId"

        /** AND-152 — optional deep-link arg: scroll the thread to this message id on open. */
        const val ARG_FOCUS_MESSAGE_ID = "focusMessageId"
        const val PAGE_SIZE = 30
        private const val OFFLINE_MESSAGE = "You're offline. Showing saved messages."

        /** AND-133 — cap the live-waveform peak buffer so the overlay scrolls a fixed window. */
        private const val MAX_LIVE_PEAKS = 64

        /** AND-135 — debounce window for GIF search keystrokes. */
        private const val GIF_DEBOUNCE_MS = 300L

        /** AND-134 — AAC-LC / M4A audio voicemail MIME (matches the presign content-type pattern). */
        private const val VOICEMAIL_AUDIO_CONTENT_TYPE = "audio/mp4"

        /** AND-139 — tip currency (USD per the SendTipIn default; future: per-conversation currency). */
        private const val TIP_CURRENCY = "USD"

        /** AND-140 — HTTP 403 (revoke window expired / not allowed). */
        private const val HTTP_FORBIDDEN = 403

        /** AND-141 — debounce window for composer draft saves (ms). */
        private const val DRAFT_DEBOUNCE_MS = 800L

        /** AND-146 — label used when a typer's display name can't be resolved. */
        private const val TYPING_FALLBACK_NAME = "Someone"
    }
}

/**
 * AND-141 — debounce a Flow without relying on the FlowPreview `debounce` API: emit the latest value
 * only after [millis] of quiescence. Built on [transformLatest], which cancels the pending delay on a
 * new upstream value (the coalescing behaviour we want for composer keystrokes). JVM-testable.
 */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
internal fun <T> Flow<T>.debounceCompat(millis: Long): Flow<T> =
    transformLatest { value ->
        delay(millis)
        emit(value)
    }

internal fun Message.toUi(currentUserSub: String?): ThreadMessageUi = ThreadMessageUi(
    key = id ?: clientId,
    text = text,
    // Outbox rows have an empty senderId; they are always the current user's.
    isOwn = senderId.isEmpty() || senderId == currentUserSub,
    createdAtEpochSeconds = createdAtEpochSeconds,
    sendStatus = sendStatus,
    media = media,
    reactions = reactions,
    isPinned = isPinned,
    lifecycle = lifecycle,
    isEdited = lifecycle == com.testlogon.android.data.messaging.MessageLifecycle.EDITED || editedAtEpochSeconds != null,
    deliveredCount = deliveredToCount,
    seenCount = readByCount,
    replyToMessageId = replyToMessageId,
    expiresAtEpochSeconds = expiresAtEpochSeconds,
    serverExpired = expired,
)
