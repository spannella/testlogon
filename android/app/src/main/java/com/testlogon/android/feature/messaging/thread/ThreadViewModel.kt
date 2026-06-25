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
    private val displayNames: com.testlogon.android.data.profile.DisplayNameResolver,
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
    fun onSelectSearchMatch(messageId: String) = searchController.selectMatch(messageId)

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
        // MSG — receiver-side decrypted plaintext for encrypted messages, keyed by message UI key
    // (transient; never persisted). Set after a correct passphrase.
    private val decryptedMessages = mutableMapOf<String, String>()
    // MSG — view-once messages consumed locally this session (hidden immediately on close, even before
    // the server reflects the consumption). Keyed by message UI key.
    private val locallyConsumed = mutableSetOf<String>()
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
        observePeerPhoto()
    }

    /**
     * ID15 - resolve the DM peer's profile photo (via the shared display-name/photo resolver) once
     * [ThreadUiState.peerUserSub] is known, so the thread header avatar can show the person's photo.
     */
    private fun observePeerPhoto() {
        // Resolve MY own profile (name+photo) once for the #15 overlapping DM avatar pair.
        authStateStore.userSub.value?.let { displayNames.resolve(it) }
        viewModelScope.launch {
            _state.collect { st ->
                val peer = st.peerUserSub ?: return@collect
                // Resolve the peer's name (header title + #18 outgoing-call peerName) and photo.
                if (st.peerPhotoUrl == null || st.title.isBlank()) displayNames.resolve(peer)
            }
        }
        viewModelScope.launch {
            // Re-resolve names so the peer title fills in even if only the name (not photo) arrives.
            displayNames.names.collect { names ->
                val st = _state.value
                val self = authStateStore.userSub.value
                val peerName = st.peerUserSub?.let { names[it] }
                val myName = self?.let { names[it] }
                if ((peerName != null && st.title.isBlank()) ||
                    (myName != null && st.myName != myName)
                ) {
                    _state.update {
                        it.copy(
                            title = if (peerName != null && it.title.isBlank()) peerName else it.title,
                            myName = myName ?: it.myName,
                        )
                    }
                }
            }
        }
        viewModelScope.launch {
            displayNames.photos.collect { photos ->
                val st = _state.value
                val self = authStateStore.userSub.value
                val peerPhoto = st.peerUserSub?.let { photos[it] }
                val myPhoto = self?.let { photos[it] }
                if ((peerPhoto != null && st.peerPhotoUrl != peerPhoto) ||
                    (myPhoto != null && st.myPhotoUrl != myPhoto)
                ) {
                    _state.update {
                        it.copy(
                            peerPhotoUrl = peerPhoto ?: it.peerPhotoUrl,
                            myPhotoUrl = myPhoto ?: it.myPhotoUrl,
                        )
                    }
                }
            }
        }
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
                // MSG — a consumed view-once message is permanently hidden for the recipient (not the sender).
                val visible = messages.filterNot { m ->
                    m.isHiddenLocal ||
                        ((m.id ?: m.clientId) in locallyConsumed) ||
                        (m.consumed && m.senderId.isNotEmpty() && m.senderId != self)
                }
                // Track the newest CONFIRMED (server id present) message as the read marker (AND-125).
                visible.lastOrNull { it.id != null }?.let {
                    newestMessageId = it.id
                    newestMessageEpochSeconds = it.createdAtEpochSeconds
                }
                // #15 — distinct non-self, non-system senders. A 1:1 DM has at most one (renders the
                // overlapping two-circle avatar); two or more => a group thread.
                val otherSenders = visible
                    .map { it.senderId }
                    .filter { it.isNotEmpty() && it != self && it != "system" }
                    .distinct()
                _state.update { prior ->
                    prior.copy(
                        messages = visible.map { msg ->
                            val ui = msg.toUi(self)
                            ui.copy(decryptedText = decryptedMessages[ui.key])
                        },
                        receipts = computeReceipts(visible, self),
                        peerUserSub = prior.peerUserSub ?: otherSenders.firstOrNull(),
                        // Once messages exist, lock isDm from the distinct-sender count.
                        isDm = if (visible.isEmpty()) prior.isDm else otherSenders.size <= 1,
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
        // C5/C6/C7 — staged media takes priority. Multiple images -> ONE gallery message; a single
        // image -> an image message; a video -> an inline video message. Text is the caption.
        val stagedImages = composer.stagedImageUris
        val stagedVideo = composer.stagedVideoUri
        if (stagedImages.isNotEmpty() || stagedVideo != null) {
            if (composer.overLimit) return
            val opts = composer.options
            val caption = body.ifBlank { null }
            typingController.onInput(TypingInput.Sent)
            _state.update { it.copy(composer = ComposerState(), hasDraft = false, draftSyncState = DraftSyncState.Idle) }
            draftSaver.tryEmit("")
            when {
                stagedVideo != null -> sendStagedVideo(stagedVideo, caption, opts)
                stagedImages.size == 1 -> sendStagedImage(stagedImages.first(), caption, opts)
                else -> sendStagedGallery(stagedImages, caption, opts)
            }
            viewModelScope.launch { draftRepository.clearDraft(conversationId) }
            return
        }
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
            val result = if (opts.encrypted) {
                // MSG — encrypted text: derive a real AES-256-GCM envelope from the passphrase; no plaintext
                // (and no passphrase) ever leaves the device. The receiver decrypts with the same passphrase.
                repository.sendEncryptedText(
                    conversationId, clientId,
                    envelope = com.testlogon.android.data.messaging.MessageCrypto.encrypt(body, opts.encryptionPassphrase),
                    replyToMessageId = replyToId,
                )
            } else {
                repository.sendOutbox(
                    conversationId, clientId, body, replyToId,
                    viewOnce = opts.viewOnce,
                    lockPriceCents = opts.lockPriceCents,
                    lockDescription = opts.lockDescription,
                    sendAtEpochSeconds = opts.scheduledAtEpochSeconds,
                    expiresInSeconds = opts.expiresInSeconds,
                )
            }
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

    /** MSG — toggle client-side encryption for the next text message. */
    fun setEncrypted(enabled: Boolean) {
        _state.update {
            it.copy(composer = it.composer.copy(options = it.composer.options.copy(encrypted = enabled)))
        }
    }

    /** MSG — set the passphrase used to encrypt the next message (kept client-side only). */
    fun setEncryptionPassphrase(passphrase: String) {
        _state.update {
            it.copy(composer = it.composer.copy(options = it.composer.options.copy(encryptionPassphrase = passphrase)))
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

    // ---- #8 Scheduled-messages manager (list / edit / remove pending scheduled sends) ----

    /** Open the scheduled-messages manager and (re)load the pending list. */
    fun openScheduledManager() {
        _state.update { it.copy(scheduledManager = it.scheduledManager.copy(visible = true)) }
        refreshScheduledMessages()
    }

    fun closeScheduledManager() {
        _state.update { it.copy(scheduledManager = ScheduledManagerUiState()) }
    }

    fun onScheduledManagerErrorShown() {
        _state.update { it.copy(scheduledManager = it.scheduledManager.copy(error = null)) }
    }

    /** Re-fetch the caller's pending scheduled messages for this conversation. */
    fun refreshScheduledMessages() {
        _state.update { it.copy(scheduledManager = it.scheduledManager.copy(loading = true)) }
        viewModelScope.launch {
            when (val r = repository.listScheduledMessages(conversationId)) {
                is ApiResult.Success -> _state.update {
                    it.copy(scheduledManager = it.scheduledManager.copy(loading = false, items = r.data))
                }
                is ApiResult.Failure -> _state.update {
                    it.copy(scheduledManager = it.scheduledManager.copy(loading = false, error = "Couldn't load scheduled messages."))
                }
                is ApiResult.NetworkError -> _state.update {
                    it.copy(scheduledManager = it.scheduledManager.copy(loading = false, error = "You're offline. Try again."))
                }
            }
        }
    }

    /** Open the edit dialog for a scheduled message (prefills its current body + due time). */
    fun openScheduledEdit(messageId: String) {
        val item = _state.value.scheduledManager.items.firstOrNull { it.id == messageId } ?: return
        _state.update {
            it.copy(
                scheduledManager = it.scheduledManager.copy(
                    editing = ScheduledEditState(
                        messageId = item.id,
                        textEditable = item.isTextEditable,
                        draftText = item.text,
                        draftDeliverAtEpochSeconds = item.deliverAtEpochSeconds,
                    ),
                ),
            )
        }
    }

    fun closeScheduledEdit() {
        _state.update { it.copy(scheduledManager = it.scheduledManager.copy(editing = null)) }
    }

    fun onScheduledEditTextChange(text: String) {
        _state.update {
            val e = it.scheduledManager.editing ?: return@update it
            it.copy(scheduledManager = it.scheduledManager.copy(editing = e.copy(draftText = text)))
        }
    }

    fun onScheduledEditTimeChange(epochSeconds: Long) {
        _state.update {
            val e = it.scheduledManager.editing ?: return@update it
            it.copy(scheduledManager = it.scheduledManager.copy(editing = e.copy(draftDeliverAtEpochSeconds = epochSeconds)))
        }
    }

    /** Commit the edit dialog: PATCH the new text/time, then refresh the list. */
    fun saveScheduledEdit() {
        val editing = _state.value.scheduledManager.editing ?: return
        // Server requires send_at >= now+5s; clamp to a small safe margin.
        val minSendAt = (System.currentTimeMillis() / 1000L) + 10L
        val sendAt = maxOf(editing.draftDeliverAtEpochSeconds, minSendAt)
        val text = if (editing.textEditable) editing.draftText.trim().ifBlank { null } else null
        _state.update {
            it.copy(scheduledManager = it.scheduledManager.copy(editing = editing.copy(saving = true)))
        }
        viewModelScope.launch {
            when (val r = repository.rescheduleMessage(conversationId, editing.messageId, text = text, sendAtEpochSeconds = sendAt)) {
                is ApiResult.Success -> {
                    _state.update { it.copy(scheduledManager = it.scheduledManager.copy(editing = null)) }
                    refreshScheduledMessages()
                }
                is ApiResult.Failure -> _state.update {
                    it.copy(scheduledManager = it.scheduledManager.copy(
                        editing = editing.copy(saving = false),
                        error = "Couldn't update the scheduled message.",
                    ))
                }
                is ApiResult.NetworkError -> _state.update {
                    it.copy(scheduledManager = it.scheduledManager.copy(
                        editing = editing.copy(saving = false),
                        error = "You're offline. Try again.",
                    ))
                }
            }
        }
    }

    /** Cancel/remove a pending scheduled message, then refresh the list. */
    fun cancelScheduledMessage(messageId: String) {
        viewModelScope.launch {
            when (val r = repository.cancelScheduledMessage(conversationId, messageId)) {
                is ApiResult.Success -> {
                    // Optimistically drop it, then refetch to be authoritative.
                    _state.update {
                        it.copy(scheduledManager = it.scheduledManager.copy(
                            items = it.scheduledManager.items.filterNot { m -> m.id == messageId },
                        ))
                    }
                    refreshScheduledMessages()
                }
                is ApiResult.Failure -> _state.update {
                    it.copy(scheduledManager = it.scheduledManager.copy(error = "Couldn't remove the scheduled message."))
                }
                is ApiResult.NetworkError -> _state.update {
                    it.copy(scheduledManager = it.scheduledManager.copy(error = "You're offline. Try again."))
                }
            }
        }
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
                // C6/C7 — a gallery or video draft is matched by clientId first (both reuse the
                // image/file optimistic kind, so check the draft maps before isImage/isFile).
                galleryDrafts.containsKey(clientId) -> {
                    val draft = galleryDrafts[clientId] ?: return@launch
                    repository.enqueueOptimisticGallery(conversationId, clientId, draft.uris.first(), draft.uris.size, clock())
                    repository.sendGalleryOutbox(
                        conversationId, clientId, draft.uris,
                        caption = draft.caption,
                        expiresInSeconds = draft.options.expiresInSeconds,
                        sendAtEpochSeconds = draft.options.scheduledAtEpochSeconds,
                    )
                }
                videoDrafts.containsKey(clientId) -> {
                    val draft = videoDrafts[clientId] ?: return@launch
                    repository.enqueueOptimisticVideoClip(conversationId, clientId, draft.uri, clock())
                    repository.sendVideoClipOutbox(
                        conversationId, clientId, draft.uri,
                        caption = draft.caption,
                        viewOnce = draft.options.viewOnce,
                        lockPriceCents = draft.options.lockPriceCents,
                        expiresInSeconds = draft.options.expiresInSeconds,
                        sendAtEpochSeconds = draft.options.scheduledAtEpochSeconds,
                    )
                }
                failed.isImage -> {
                    val draft = imageDrafts[clientId] ?: return@launch
                    repository.enqueueOptimisticImage(conversationId, clientId, draft.uri, clock())
                    repository.sendImageOutbox(
                        conversationId, clientId, draft.uri,
                        caption = draft.caption,
                        viewOnce = draft.options.viewOnce,
                        lockPriceCents = draft.options.lockPriceCents,
                        expiresInSeconds = draft.options.expiresInSeconds,
                        sendAtEpochSeconds = draft.options.scheduledAtEpochSeconds,
                        encryptionPassphrase = if (draft.options.encrypted) draft.options.encryptionPassphrase else null,
                    )
                }
                failed.isFile -> {
                    val draft = fileDrafts[clientId] ?: return@launch
                    val file = failed.media as? MessageMedia.File
                    repository.enqueueOptimisticFile(
                        conversationId, clientId, draft.uri, draft.name, file?.sizeBytes ?: 0L, draft.mime, clock(),
                    )
                    repository.sendFileOutbox(
                        conversationId, clientId, draft.uri, draft.name, draft.mime,
                        viewOnce = draft.options.viewOnce,
                        lockPriceCents = draft.options.lockPriceCents,
                        lockDescription = draft.options.lockDescription,
                        expiresInSeconds = draft.options.expiresInSeconds,
                        sendAtEpochSeconds = draft.options.scheduledAtEpochSeconds,
                    )
                }
                else -> {
                    repository.enqueueOptimistic(conversationId, clientId, failed.text, clock())
                    repository.sendOutbox(conversationId, clientId, failed.text)
                }
            }
        }
    }

    // ---- AND-130: image messages ----

    /** C5 — a picked image + its caption/options, retained by clientId for retry. */
    private data class ImageDraft(
        val uri: String,
        val caption: String?,
        val options: MessageOptions,
    )

    /** Tracks staged/sent image drafts by local clientId so a retry can re-run without re-picking. */
    private val imageDrafts = mutableMapOf<String, ImageDraft>()

    /** C6 — a staged gallery (multi-image) draft, retained by clientId for retry. */
    private data class GalleryDraft(
        val uris: List<String>,
        val caption: String?,
        val options: MessageOptions,
    )
    private val galleryDrafts = mutableMapOf<String, GalleryDraft>()

    /** C7 — max allowed short-video size; larger picks are rejected with a hint (no transcode). */
    private val maxVideoBytes = 50L * 1024L * 1024L

    /**
     * C5/C6 — STAGE the picked image(s) in the composer instead of sending immediately. The user can
     * then type a caption (the text field) and toggle send-options before tapping Send. One image
     * sends as an image message; several send as ONE gallery message. Picking image(s) clears any
     * staged video (one media kind at a time).
     */
    fun onImagePicked(uri: Uri) = onImagesPicked(listOf(uri))

    fun onImagesPicked(uris: List<Uri>) {
        if (uris.isEmpty()) return
        // Server caps free_images at 20; cap the pick to keep one message valid.
        val capped = uris.take(20).map { it.toString() }
        _state.update {
            it.copy(composer = it.composer.copy(stagedImageUris = capped, stagedVideoUri = null))
        }
        _events.trySend(ThreadEvent.ScrollToBottom)
    }

    /**
     * C7 — STAGE a picked SHORT video. Guarded by [maxVideoBytes]; an oversized clip is rejected with
     * an action error instead of staging. Staging a video clears any staged images.
     */
    fun onVideoPicked(uri: Uri, sizeBytes: Long) {
        if (sizeBytes in 1..maxVideoBytes || sizeBytes == 0L) {
            // sizeBytes==0 means the picker didn't report a size; allow and let the upload guard catch it.
            _state.update {
                it.copy(composer = it.composer.copy(stagedVideoUri = uri.toString(), stagedImageUris = emptyList()))
            }
            _events.trySend(ThreadEvent.ScrollToBottom)
        } else {
            _state.update { it.copy(transientMessage = "That video is too large. Pick a clip under 50 MB.") }
        }
    }

    /** C5/C6 — remove one staged image by index, or all when index < 0 (the x on a preview thumbnail). */
    fun onRemoveStagedImage(index: Int = -1) {
        _state.update {
            val current = it.composer.stagedImageUris
            val next = if (index < 0) emptyList() else current.filterIndexed { i, _ -> i != index }
            it.copy(composer = it.composer.copy(stagedImageUris = next))
        }
    }

    /** C7 — remove the staged video. */
    fun onRemoveStagedVideo() {
        _state.update { it.copy(composer = it.composer.copy(stagedVideoUri = null)) }
    }

    /** C5 — actually send a single staged image with the current caption + armed options. */
    private fun sendStagedImage(localUri: String, caption: String?, opts: MessageOptions) {
        val clientId = UUID.randomUUID().toString()
        imageDrafts[clientId] = ImageDraft(localUri, caption, opts)
        viewModelScope.launch {
            repository.enqueueOptimisticImage(conversationId, clientId, localUri, clock())
            _events.trySend(ThreadEvent.ScrollToBottom)
            repository.sendImageOutbox(
                conversationId, clientId, localUri,
                caption = caption,
                viewOnce = opts.viewOnce,
                lockPriceCents = opts.lockPriceCents,
                expiresInSeconds = opts.expiresInSeconds,
                sendAtEpochSeconds = opts.scheduledAtEpochSeconds,
                encryptionPassphrase = if (opts.encrypted) opts.encryptionPassphrase else null,
            )
        }
    }

    /** C6 — send multiple staged images as ONE gallery message. */
    private fun sendStagedGallery(localUris: List<String>, caption: String?, opts: MessageOptions) {
        val clientId = UUID.randomUUID().toString()
        galleryDrafts[clientId] = GalleryDraft(localUris, caption, opts)
        viewModelScope.launch {
            repository.enqueueOptimisticGallery(conversationId, clientId, localUris.first(), localUris.size, clock())
            _events.trySend(ThreadEvent.ScrollToBottom)
            repository.sendGalleryOutbox(
                conversationId, clientId, localUris,
                caption = caption,
                // Gallery create only supports expiry + schedule (no view-once/lock on the free path).
                expiresInSeconds = opts.expiresInSeconds,
                sendAtEpochSeconds = opts.scheduledAtEpochSeconds,
            )
        }
    }

    /** C7 — send a staged short video inline (kind=video), reusing the image outbox transport. */
    private fun sendStagedVideo(localUri: String, caption: String?, opts: MessageOptions) {
        val clientId = UUID.randomUUID().toString()
        videoDrafts[clientId] = VideoDraft(localUri, caption, opts)
        viewModelScope.launch {
            repository.enqueueOptimisticVideoClip(conversationId, clientId, localUri, clock())
            _events.trySend(ThreadEvent.ScrollToBottom)
            repository.sendVideoClipOutbox(
                conversationId, clientId, localUri,
                caption = caption,
                viewOnce = opts.viewOnce,
                lockPriceCents = opts.lockPriceCents,
                expiresInSeconds = opts.expiresInSeconds,
                sendAtEpochSeconds = opts.scheduledAtEpochSeconds,
            )
        }
    }

    /** C7 — a staged short-video draft, retained by clientId for retry. */
    private data class VideoDraft(
        val uri: String,
        val caption: String?,
        val options: MessageOptions,
    )
    private val videoDrafts = mutableMapOf<String, VideoDraft>()

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

    /** C9 — a picked file + its gating options, retained by clientId for retry. */
    private data class FileDraft(
        val uri: String,
        val name: String,
        val mime: String,
        val options: MessageOptions,
    )

    /** Tracks picked files by clientId so a retry can re-run without re-picking. */
    private val fileDrafts = mutableMapOf<String, FileDraft>()

    fun onFilePicked(uri: android.net.Uri, fileName: String, sizeBytes: Long, mimeType: String) {
        val clientId = UUID.randomUUID().toString()
        val localUri = uri.toString()
        // C9 — apply any armed send-options (view-once / locked / expiring / scheduled) to this file,
        // then clear them so they don't leak onto the next message (mirrors the text/image path).
        val opts = _state.value.composer.options
        fileDrafts[clientId] = FileDraft(localUri, fileName, mimeType, opts)
        _state.update {
            it.copy(composer = it.composer.copy(options = MessageOptions()), messageOptionsVisible = false)
        }
        viewModelScope.launch {
            repository.enqueueOptimisticFile(
                conversationId, clientId, localUri, fileName, sizeBytes, mimeType, clock(),
            )
            _events.trySend(ThreadEvent.ScrollToBottom)
            repository.sendFileOutbox(
                conversationId, clientId, localUri, fileName, mimeType,
                viewOnce = opts.viewOnce,
                lockPriceCents = opts.lockPriceCents,
                lockDescription = opts.lockDescription,
                expiresInSeconds = opts.expiresInSeconds,
                sendAtEpochSeconds = opts.scheduledAtEpochSeconds,
            )
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
        // Apply armed send-options (the once-toggle maps to listen-once for audio) + clear them.
        val opts = _state.value.composer.options
        _state.update {
            it.copy(voice = VoiceComposerUiState.Sending(0f), composer = it.composer.copy(options = MessageOptions()))
        }
        viewModelScope.launch {
            repository.enqueueOptimisticVoice(conversationId, clientId, path, durationSeconds, wire, clock())
            _events.trySend(ThreadEvent.ScrollToBottom)
            val result = repository.sendVoiceOutbox(
                conversationId, clientId, path, durationSeconds, wire,
                consumptionPolicy = if (opts.viewOnce) "listen_once" else "none",
                sendAtEpochSeconds = opts.scheduledAtEpochSeconds,
            )
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
        val msg = _state.value.messages.firstOrNull { it.key == messageId }
        val voice = msg?.media as? MessageMedia.Voice
        // Listen-once audio: must be consumed so it can't be replayed. Pull the bytes via the
        // grant -> GET -> consume flow, play the local clip once, then hide the bubble.
        if (voice?.consumptionPolicy == "listen_once" && msg?.isOwn != true && messageId !in locallyConsumed) {
            locallyConsumed.add(messageId)
            // Listen-once audio: the url is exposed, so play it directly (resolved), record the
            // consumption server-side, then hide the bubble so it can't be replayed.
            audioUrl?.let { raw ->
                val u = if (raw.startsWith("/")) {
                    com.testlogon.android.BuildConfig.API_BASE_URL.trimEnd('/') + raw
                } else {
                    raw
                }
                voicePlayer.toggle(messageId, u)
            }
            viewModelScope.launch {
                repository.consumeOnceMedia(conversationId, messageId, "play")
                _state.update { it.copy(messages = it.messages.filterNot { m -> m.key == messageId }) }
            }
            return
        }
        val raw = audioUrl ?: return
        // The backend serves audio at a server-RELATIVE /mock url; ExoPlayer needs an absolute URL,
        // so resolve it against the configured API origin (same idea as Coil's RelativeUrlMapper for
        // images). Without this, every received voice clip fails to play.
        val url = if (raw.startsWith("/")) {
            com.testlogon.android.BuildConfig.API_BASE_URL.trimEnd('/') + raw
        } else {
            raw
        }
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

    // ---- MSG: new in-app composers ----

    fun onAttachLottery() { _state.update { it.copy(lotteryComposerVisible = true) } }
    fun onDismissLotteryComposer() { _state.update { it.copy(lotteryComposerVisible = false) } }

    /**
     * [outcomes] are (label, revealedText) pairs from the composer (2..4). [imageUri] is an optional
     * cover image (C10) uploaded before the lottery is created.
     */
    fun onSendLottery(
        outcomes: List<com.testlogon.android.data.messaging.LotteryOutcomeDraft>,
        imageUri: String? = null,
    ) {
        if (outcomes.size < 2) return
        _state.update { it.copy(lotteryComposerVisible = false) }
        viewModelScope.launch {
            // #13 — a media outcome arrives with payloadType image|video and mediaAssetId carrying the
            // picked LOCAL uri; upload each via the conversation image-presign transport and swap in the
            // resolved "bucket:key" media_asset_id before creating the lottery. A failed upload demotes
            // that option to text so the lottery still sends.
            val resolved = outcomes.map { o ->
                val isMedia = (o.payloadType == "image" || o.payloadType == "video")
                val localUri = o.mediaAssetId
                if (isMedia && !localUri.isNullOrBlank()) {
                    val assetId = repository.uploadLotteryOptionMedia(
                        conversationId,
                        localUri,
                        isVideo = o.payloadType == "video",
                    )
                    if (assetId != null) {
                        o.copy(mediaAssetId = assetId)
                    } else {
                        o.copy(payloadType = "text", mediaAssetId = null, text = o.text.ifBlank { "Prize" })
                    }
                } else {
                    o
                }
            }
            val imageRef = imageUri?.let { repository.uploadLotteryImage(conversationId, it) }
            repository.sendLottery(conversationId, resolved, image = imageRef)
            _events.trySend(ThreadEvent.ScrollToBottom)
        }
    }

    fun onAttachFindDateTime() { _state.update { it.copy(findDateTimeComposerVisible = true) } }
    fun onDismissFindDateTimeComposer() { _state.update { it.copy(findDateTimeComposerVisible = false) } }

    fun onSendFindDateTime(draft: com.testlogon.android.data.messaging.FindDateTimeDraft) {
        _state.update { it.copy(findDateTimeComposerVisible = false) }
        viewModelScope.launch {
            repository.createFindDateTime(conversationId, draft)
            _events.trySend(ThreadEvent.ScrollToBottom)
        }
    }

    // ---- calendar-event share ----
    fun onAttachCalendarEvent() {
        _state.update { it.copy(calendarEventComposer = CalendarPickerState(visible = true, loading = true)) }
        loadCalendars(forEvent = true)
    }
    fun onDismissCalendarEventComposer() { _state.update { it.copy(calendarEventComposer = CalendarPickerState()) } }

    fun onSelectCalendarForEvent(calendarId: String) {
        _state.update {
            it.copy(calendarEventComposer = it.calendarEventComposer.copy(selectedCalendarId = calendarId, eventsLoading = true, events = emptyList()))
        }
        viewModelScope.launch {
            when (val r = repository.listCalendarEvents(calendarId)) {
                is ApiResult.Success -> _state.update {
                    it.copy(calendarEventComposer = it.calendarEventComposer.copy(eventsLoading = false, events = r.data))
                }
                else -> _state.update {
                    it.copy(calendarEventComposer = it.calendarEventComposer.copy(eventsLoading = false, error = "Couldn't load events"))
                }
            }
        }
    }

    fun onSendCalendarEvent(calendarId: String, eventId: String) {
        _state.update { it.copy(calendarEventComposer = CalendarPickerState()) }
        viewModelScope.launch {
            repository.shareCalendarEvent(conversationId, calendarId, eventId, text = null)
            _events.trySend(ThreadEvent.ScrollToBottom)
        }
    }

    // ---- calendar share ----
    fun onAttachCalendarShare() {
        _state.update { it.copy(calendarShareComposer = CalendarPickerState(visible = true, loading = true)) }
        loadCalendars(forEvent = false)
    }
    fun onDismissCalendarShareComposer() { _state.update { it.copy(calendarShareComposer = CalendarPickerState()) } }

    fun onSelectCalendarForShare(calendarId: String) {
        _state.update { it.copy(calendarShareComposer = it.calendarShareComposer.copy(selectedCalendarId = calendarId)) }
    }

    fun onSendCalendarShare(calendarId: String, permission: String, includeBookingLink: Boolean) {
        _state.update { it.copy(calendarShareComposer = CalendarPickerState()) }
        viewModelScope.launch {
            repository.shareCalendar(conversationId, calendarId, permission, includeBookingLink, text = null)
            _events.trySend(ThreadEvent.ScrollToBottom)
        }
    }

    private fun loadCalendars(forEvent: Boolean) {
        viewModelScope.launch {
            val r = repository.listCalendars()
            _state.update {
                if (forEvent) {
                    when (r) {
                        is ApiResult.Success -> it.copy(calendarEventComposer = it.calendarEventComposer.copy(loading = false, calendars = r.data))
                        else -> it.copy(calendarEventComposer = it.calendarEventComposer.copy(loading = false, error = "Couldn't load calendars"))
                    }
                } else {
                    when (r) {
                        is ApiResult.Success -> it.copy(calendarShareComposer = it.calendarShareComposer.copy(loading = false, calendars = r.data))
                        else -> it.copy(calendarShareComposer = it.calendarShareComposer.copy(loading = false, error = "Couldn't load calendars"))
                    }
                }
            }
        }
    }

    // ---- file-manager share ----
    fun onAttachFileShare() {
        _state.update { it.copy(fileShareComposer = FilePickerState(visible = true, loading = true)) }
        viewModelScope.launch {
            when (val r = repository.listFiles("/")) {
                is ApiResult.Success -> _state.update {
                    it.copy(fileShareComposer = it.fileShareComposer.copy(loading = false, files = r.data))
                }
                else -> _state.update {
                    it.copy(fileShareComposer = it.fileShareComposer.copy(loading = false, error = "Couldn't load files"))
                }
            }
        }
    }
    fun onDismissFileShareComposer() { _state.update { it.copy(fileShareComposer = FilePickerState()) } }

    fun onSendFileShare(filePath: String) {
        _state.update { it.copy(fileShareComposer = FilePickerState()) }
        viewModelScope.launch {
            repository.shareFile(conversationId, filePath, permission = "read", text = null)
            _events.trySend(ThreadEvent.ScrollToBottom)
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

    // ---- MSG: encrypted-message receiver-side unlock (passphrase -> decrypt inline) ----

    /** Open the passphrase dialog for an encrypted message bubble tap. */
    fun openEncryptUnlock(messageKey: String) {
        _state.update { it.copy(encryptUnlock = EncryptUnlockState(messageKey = messageKey)) }
    }

    fun onEncryptPassphraseChange(passphrase: String) {
        _state.update { it.copy(encryptUnlock = it.encryptUnlock.copy(passphrase = passphrase, error = null)) }
    }

    fun dismissEncryptUnlock() {
        _state.update { it.copy(encryptUnlock = EncryptUnlockState()) }
    }

    /** Try to decrypt the targeted message with the entered passphrase; reveal inline on success. */
    fun submitEncryptUnlock() {
        val target = _state.value.encryptUnlock.messageKey ?: return
        val passphrase = _state.value.encryptUnlock.passphrase
        val msg = _state.value.messages.firstOrNull { it.key == target } ?: return
        val envelope = msg.encryption
        if (envelope == null) {
            _state.update { it.copy(encryptUnlock = it.encryptUnlock.copy(error = "No encryption envelope on this message")) }
            return
        }
        // Encrypted IMAGE: the envelope has no inline ciphertext (it lives in storage). Download the
        // ciphertext, decrypt the bytes, and show the image in the media viewer (no consume).
        val encImage = msg.media as? MessageMedia.Image
        if (encImage?.url != null && envelope.ciphertextB64 == null) {
            val url = encImage.url
            viewModelScope.launch {
                val cipher = repository.fetchEncryptedImageBytes(url)
                val plain = cipher?.let {
                    com.testlogon.android.data.messaging.MessageCrypto.decryptBytes(it, envelope, passphrase)
                }
                if (plain == null) {
                    _state.update { it.copy(encryptUnlock = it.encryptUnlock.copy(error = "Wrong passphrase \u2014 try again")) }
                } else {
                    val f = java.io.File(appContext.cacheDir, "dec_" + target.replace('/', '_') + ".jpg")
                        .apply { writeBytes(plain) }
                    _state.update {
                        it.copy(
                            encryptUnlock = EncryptUnlockState(),
                            viewOnceViewer = ViewOnceViewerState(
                                messageKey = target,
                                imageFile = f.absolutePath,
                                title = "Encrypted image",
                                consumeOnDismiss = false,
                            ),
                        )
                    }
                }
            }
            return
        }
        val plaintext = com.testlogon.android.data.messaging.MessageCrypto.decrypt(envelope, passphrase)
        if (plaintext == null) {
            _state.update { it.copy(encryptUnlock = it.encryptUnlock.copy(error = "Wrong passphrase — try again")) }
            return
        }
        decryptedMessages[target] = plaintext
        _state.update { st ->
            st.copy(
                encryptUnlock = EncryptUnlockState(),
                messages = st.messages.map { if (it.key == target) it.copy(decryptedText = plaintext) else it },
            )
        }
    }

    // ---- MSG: view-once receiver-side reveal-then-consume ----

    /** Open the view-once content popup, then report the view (consume) so it is permanently hidden. */
    fun openViewOnce(messageKey: String) {
        val msg = _state.value.messages.firstOrNull { it.key == messageKey } ?: return
        val content = msg.decryptedText ?: msg.text
        if (content.isNotBlank()) {
            // View-once TEXT: the body is already present; show it inline (consume on close).
            _state.update { it.copy(viewOnceViewer = ViewOnceViewerState(messageKey = messageKey, text = content)) }
            return
        }
        // View-once MEDIA (image): the server withholds the url until consumed, so pull the bytes via
        // the grant -> consume -> GET attachment flow and display the downloaded file once.
        _state.update { it.copy(viewOnceViewer = ViewOnceViewerState(messageKey = messageKey, loading = true)) }
        viewModelScope.launch {
            repository.downloadAttachment(conversationId, messageKey, "view_once.jpg", "view_once")
                .collect { progress ->
                    _state.update { st ->
                        if (st.viewOnceViewer.messageKey != messageKey) return@update st
                        when (progress) {
                            is DownloadProgress.Done ->
                                st.copy(viewOnceViewer = st.viewOnceViewer.copy(loading = false, imageFile = progress.file.absolutePath))
                            is DownloadProgress.Failed ->
                                st.copy(viewOnceViewer = st.viewOnceViewer.copy(loading = false, error = true))
                            is DownloadProgress.Downloading -> st
                        }
                    }
                }
        }
    }

    /** Close the view-once popup, consuming the message so it can never be shown again. */
    fun dismissViewOnce() {
        val vo = _state.value.viewOnceViewer
        if (!vo.consumeOnDismiss) {
            // Encrypted-image preview: just close; the message stays (re-viewable).
            _state.update { it.copy(viewOnceViewer = ViewOnceViewerState()) }
            return
        }
        val key = vo.messageKey
        if (key != null) locallyConsumed.add(key)
        _state.update {
            it.copy(
                viewOnceViewer = ViewOnceViewerState(),
                // Hide the consumed view-once bubble immediately (optimistic; server consume follows).
                messages = it.messages.filterNot { m -> m.key == key },
            )
        }
        if (key != null) {
            viewModelScope.launch { repository.reportView(conversationId, key) }
        }
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

    /** M11 — jump the thread to the original message a reply quotes (no-op if not currently loaded). */
    fun onJumpToMessage(messageId: String) {
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
                                // MSG — re-arm the read trigger only AFTER the inbound bubble has had
                                // time to render + scroll into view, so the receiver visibly RECEIVES
                                // the message before the sender flips to "read" (no read-before-received).
                                viewModelScope.launch {
                                    kotlinx.coroutines.delay(1500)
                                    readMarked = false
                                    onThreadVisible()
                                }
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

/**
 * MSG — build a minimal valid [MessageEncryptionEnvelopeDto] for the encrypted-text demo. The server
 * only validates structure (16-byte salt, 12-byte iv, ciphertext+tag >16 bytes, valid base64); for
 * the two-phone demo we derive deterministic-but-non-empty binary fields from the plaintext so the
 * envelope is well-formed without shipping a real KDF/cipher. The receiver renders a lock indicator.
 */
internal fun buildDemoEncryptionEnvelope(plaintext: String): com.testlogon.android.data.messaging.MessageEncryptionEnvelopeDto {
    val b64 = java.util.Base64.getEncoder()
    val salt = ByteArray(16) { (it * 7 + 1).toByte() }
    val iv = ByteArray(12) { (it * 11 + 3).toByte() }
    // ciphertext: a deterministic >16-byte blob (plaintext bytes padded with a 16-byte mock GCM tag).
    val body = plaintext.toByteArray(Charsets.UTF_8)
    val padded = ByteArray((body.size).coerceAtLeast(1) + 16)
    body.copyInto(padded)
    for (i in 0 until 16) padded[padded.size - 16 + i] = (i * 13 + 5).toByte()
    return com.testlogon.android.data.messaging.MessageEncryptionEnvelopeDto(
        version = 1,
        alg = "AES-256-GCM",
        kdf = "PBKDF2-SHA256",
        iterations = 100_000,
        saltB64 = b64.encodeToString(salt),
        ivB64 = b64.encodeToString(iv),
        ciphertextB64 = b64.encodeToString(padded),
    )
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
    isEncrypted = isEncrypted,
    encryption = encryption,
    viewOnce = viewOnce,
    consumed = consumed,
    lockPriceCents = lockPriceCents,
    lockCurrency = lockCurrency,
)
