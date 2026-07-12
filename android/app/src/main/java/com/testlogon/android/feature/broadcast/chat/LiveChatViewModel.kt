package com.testlogon.android.feature.broadcast.chat

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.chat.BroadcastChatRepository
import com.testlogon.android.data.broadcast.chat.ChatComposeOptions
import com.testlogon.android.data.broadcast.chat.ChatConnectionState
import com.testlogon.android.data.broadcast.chat.ChatMessage
import com.testlogon.android.data.broadcast.chat.ChatReaction
import com.testlogon.android.data.broadcast.chat.ChatStreamEvent
import com.testlogon.android.data.broadcast.chat.ChatStreamSignal
import com.testlogon.android.data.broadcast.chat.DeliveryState
import dagger.assisted.Assisted
import dagger.assisted.AssistedFactory
import dagger.assisted.AssistedInject
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.UUID

/** AND-281 — live-chat connection status surfaced to the panel. */
enum class ConnectionStatus { LIVE, RECONNECTING, OFFLINE }

/** AND-281 — the live-chat panel view-state. */
sealed interface LiveChatUiState {
    data object Connecting : LiveChatUiState
    data class Content(
        val messages: List<ChatMessage>, // capped at MAX_RETAINED, oldest-first
        val connection: ConnectionStatus,
        val composerText: String,
        val canSend: Boolean,
        val pinnedToBottom: Boolean,
        // ---- BCAST-016 composer state ----
        val options: ChatComposeOptions = ChatComposeOptions(),
        val replyTo: ChatMessage? = null,
        val attaching: Boolean = false,
    ) : LiveChatUiState

    data class Error(val retryable: Boolean) : LiveChatUiState
}

/**
 * AND-281 / BCAST-016 — live-chat presentation logic for a single broadcast session.
 *
 * Folds the [BroadcastChatRepository] SSE signals + send/react/unlock/view mutations into a single
 * reducer. Optimistic send inserts a SENDING entry keyed by a LOCAL-ONLY clientNonce; the SSE echo / POST
 * response reconciles it to SENT. The in-memory list is capped at [MAX_RETAINED]. Built with
 * AssistedInject so the sessionId is supplied at the call site (the panel composes into the viewer AND
 * the host live screen).
 *
 * TRANSPORT DECOUPLE: the long-lived SSE does not connect on-device, so the repository also drives a POLL
 * backstop that emits [ChatStreamSignal.PollAlive] + re-delivered frames; send-enablement keys off a
 * WORKING TRANSPORT (SSE LIVE **or** the poll being alive), NOT strictly the SSE being LIVE.
 *
 * BCAST-016: the composer now stages reply + gating options ([ChatComposeOptions]) and media (image/video
 * uploaded via the repository), and the reducer supports react / unlock (pay-to-reveal) / view-once
 * consume. Mutation-in-place events (react/unlock/expiry/view-once) that carry no new sort_key are
 * reconciled here from the react/unlock POST responses + a history re-fetch (the on-device poll dedups by
 * message_id and would otherwise skip them).
 */
@HiltViewModel(assistedFactory = LiveChatViewModel.Factory::class)
class LiveChatViewModel @AssistedInject constructor(
    @Assisted private val sessionId: String,
    private val repo: BroadcastChatRepository,
) : ViewModel() {

    @AssistedFactory
    interface Factory {
        fun create(sessionId: String): LiveChatViewModel
    }

    private val _uiState = MutableStateFlow<LiveChatUiState>(LiveChatUiState.Connecting)
    val uiState: StateFlow<LiveChatUiState> = _uiState.asStateFlow()

    private var streamJob: Job? = null

    private var sseStatus: ConnectionStatus = ConnectionStatus.RECONNECTING
    private var pollAlive: Boolean = false

    init {
        loadHistory()
        onResumeStreaming()
    }

    /** (Re)starts SSE collection; safe to call repeatedly (cancels the prior subscription). */
    fun onResumeStreaming() {
        streamJob?.cancel()
        streamJob = viewModelScope.launch {
            repo.chatEvents(sessionId).collect { signal -> reduce(signal) }
        }
    }

    fun onComposerTextChange(text: String) {
        _uiState.update { state ->
            (state as? LiveChatUiState.Content)?.copy(
                composerText = text,
                canSend = canSendNow(text, state),
            ) ?: state
        }
    }

    // ---- BCAST-016 composer options ----

    fun onReplyTo(message: ChatMessage) {
        _uiState.update { state ->
            val c = state as? LiveChatUiState.Content ?: return@update state
            c.copy(
                replyTo = message,
                options = c.options.copy(
                    replyToMessageId = message.id,
                    replyPreviewSender = message.senderDisplayName,
                    replyPreviewText = message.text,
                ),
            )
        }
    }

    fun onClearReply() {
        _uiState.update { state ->
            val c = state as? LiveChatUiState.Content ?: return@update state
            c.copy(
                replyTo = null,
                options = c.options.copy(
                    replyToMessageId = null,
                    replyPreviewSender = null,
                    replyPreviewText = null,
                ),
            )
        }
    }

    fun onSetViewOnce(enabled: Boolean) = updateOptions { it.copy(viewOnce = enabled) }

    fun onSetLock(priceCents: Long?, description: String?) =
        updateOptions { it.copy(lockPriceCents = priceCents, lockDescription = description) }

    fun onSetExpiry(seconds: Long?) = updateOptions { it.copy(expiresInSeconds = seconds) }

    fun onSetScheduled(epochSeconds: Long?) = updateOptions { it.copy(sendAtEpochSeconds = epochSeconds) }

    fun onClearGating() = updateOptions {
        it.copy(viewOnce = false, lockPriceCents = null, lockDescription = null, expiresInSeconds = null, sendAtEpochSeconds = null)
    }

    private fun updateOptions(transform: (ChatComposeOptions) -> ChatComposeOptions) {
        _uiState.update { state ->
            val c = state as? LiveChatUiState.Content ?: return@update state
            c.copy(options = transform(c.options))
        }
    }

    // ---- send ----

    fun send() {
        val content = _uiState.value as? LiveChatUiState.Content ?: return
        val text = content.composerText.trim()
        if (text.isEmpty() || !transportUp()) return
        val options = content.options
        val nonce = enqueueOptimistic(text = text, options = options)
        clearComposer()
        dispatchSend(nonce, text = text, options = options, imageUrl = null, videoUrl = null, thumbnailUrl = null)
    }

    /** BCAST-016 — upload a picked image, then send it as an image_url message (with staged options). */
    fun onPickImage(localUri: String) {
        val content = _uiState.value as? LiveChatUiState.Content ?: return
        val options = content.options
        setAttaching(true)
        viewModelScope.launch {
            when (val up = repo.uploadImage(localUri)) {
                is ApiResult.Success -> {
                    setAttaching(false)
                    val nonce = enqueueOptimistic(text = null, options = options, imageUrl = up.data)
                    clearComposer()
                    dispatchSend(nonce, text = null, options = options, imageUrl = up.data, videoUrl = null, thumbnailUrl = null)
                }
                else -> setAttaching(false)
            }
        }
    }

    /** BCAST-016 — upload a picked video via the VOD pipeline, then send it as a video_url message. */
    fun onPickVideo(localUri: String) {
        val content = _uiState.value as? LiveChatUiState.Content ?: return
        val options = content.options
        setAttaching(true)
        viewModelScope.launch {
            when (val up = repo.uploadVideo(localUri)) {
                is ApiResult.Success -> {
                    setAttaching(false)
                    val nonce = enqueueOptimistic(text = null, options = options, videoUrl = up.data.videoUrl, thumbnailUrl = up.data.thumbnailUrl)
                    clearComposer()
                    dispatchSend(nonce, text = null, options = options, imageUrl = null, videoUrl = up.data.videoUrl, thumbnailUrl = up.data.thumbnailUrl)
                }
                else -> setAttaching(false)
            }
        }
    }

    fun retrySend(clientNonce: String) {
        val content = _uiState.value as? LiveChatUiState.Content ?: return
        val msg = content.messages.firstOrNull { it.clientNonce == clientNonce } ?: return
        setDeliveryState(clientNonce, DeliveryState.SENDING)
        val options = ChatComposeOptions(replyToMessageId = msg.replyToMessageId)
        dispatchSend(clientNonce, text = msg.text, options = options, imageUrl = msg.imageUrl, videoUrl = msg.videoUrl, thumbnailUrl = msg.thumbnailUrl)
    }

    private fun enqueueOptimistic(
        text: String?,
        options: ChatComposeOptions,
        imageUrl: String? = null,
        videoUrl: String? = null,
        thumbnailUrl: String? = null,
    ): String {
        val nonce = UUID.randomUUID().toString()
        val optimistic = ChatMessage(
            id = nonce,
            clientNonce = nonce,
            sessionId = sessionId,
            senderId = repo.selfId() ?: SELF_PLACEHOLDER,
            senderDisplayName = "",
            isSelf = true,
            text = text,
            kind = when {
                videoUrl != null -> "video"
                imageUrl != null -> "image"
                else -> "text"
            },
            createdAtEpochSeconds = System.currentTimeMillis() / 1000L,
            deliveryState = DeliveryState.SENDING,
            replyToMessageId = options.replyToMessageId,
            replyPreviewSender = options.replyPreviewSender,
            replyPreviewText = options.replyPreviewText,
            imageUrl = imageUrl,
            videoUrl = videoUrl,
            thumbnailUrl = thumbnailUrl,
            mediaKind = if (videoUrl != null) "video" else if (imageUrl != null) "image" else null,
            lockPriceCents = options.lockPriceCents,
            lockDescription = options.lockDescription,
            isUnlocked = true, // own message is always unlocked to the sender
            viewOnce = options.viewOnce,
            scheduled = options.sendAtEpochSeconds != null,
            sendAtEpochSeconds = options.sendAtEpochSeconds,
        )
        _uiState.update { state ->
            (state as? LiveChatUiState.Content)?.copy(
                messages = (state.messages + optimistic).takeLast(MAX_RETAINED),
            ) ?: state
        }
        return nonce
    }

    private fun clearComposer() {
        _uiState.update { state ->
            (state as? LiveChatUiState.Content)?.copy(
                composerText = "",
                canSend = false,
                options = ChatComposeOptions(),
                replyTo = null,
            ) ?: state
        }
    }

    private fun setAttaching(attaching: Boolean) {
        _uiState.update { state -> (state as? LiveChatUiState.Content)?.copy(attaching = attaching) ?: state }
    }

    // ---- reactions ----

    fun reactToMessage(messageId: String, emoji: String) {
        viewModelScope.launch {
            when (val result = repo.reactToMessage(sessionId, messageId, emoji)) {
                is ApiResult.Success -> applyReactionCounts(messageId, result.data, toggledEmoji = emoji)
                else -> Unit
            }
        }
    }

    // ---- unlock (PPV) ----

    fun unlock(messageId: String) {
        viewModelScope.launch {
            when (val result = repo.unlock(sessionId, messageId, DEFAULT_PAYMENT_METHOD)) {
                is ApiResult.Success -> {
                    applyUnlocked(messageId, result.data)
                    reconcileFromHistory(messageId)
                }
                else -> Unit
            }
        }
    }

    // ---- view-once ----

    fun revealViewOnce(messageId: String) {
        // Show the content this session immediately, then record the one-view server-side.
        _uiState.update { current ->
            val content = current.asContent()
            content.copy(messages = content.messages.map { if (it.id == messageId) it.copy(locallyRevealed = true) else it })
        }
        viewModelScope.launch { repo.consumeView(sessionId, messageId) }
    }

    fun onScrolledToBottom(atBottom: Boolean) {
        _uiState.update { (it as? LiveChatUiState.Content)?.copy(pinnedToBottom = atBottom) ?: it }
    }

    fun retry() {
        loadHistory()
        onResumeStreaming()
    }

    // ---- transport ----

    private fun transportUp(): Boolean = sseStatus == ConnectionStatus.LIVE || pollAlive

    private fun canSendNow(text: String, state: LiveChatUiState.Content): Boolean =
        transportUp() && !state.attaching && text.isNotBlank()

    private fun effectiveConnection(): ConnectionStatus =
        if (transportUp()) ConnectionStatus.LIVE else sseStatus

    private fun recomputeTransport() {
        _uiState.update { current ->
            val content = current.asContent()
            content.copy(
                connection = effectiveConnection(),
                canSend = transportUp() && !content.attaching && content.composerText.isNotBlank(),
            )
        }
    }

    // ---- reducer ----

    private fun reduce(signal: ChatStreamSignal) {
        when (signal) {
            is ChatStreamSignal.Connection -> applyConnection(signal.state)
            is ChatStreamSignal.Decoded -> applyEvent(signal.event)
            is ChatStreamSignal.PollAlive -> {
                pollAlive = signal.alive
                recomputeTransport()
            }
        }
    }

    private fun applyConnection(state: ChatConnectionState) {
        if (state == ChatConnectionState.CONNECTING &&
            _uiState.value is LiveChatUiState.Connecting && !pollAlive
        ) {
            return
        }
        sseStatus = when (state) {
            ChatConnectionState.LIVE -> ConnectionStatus.LIVE
            ChatConnectionState.CONNECTING, ChatConnectionState.RECONNECTING -> ConnectionStatus.RECONNECTING
            ChatConnectionState.OFFLINE -> ConnectionStatus.OFFLINE
        }
        recomputeTransport()
    }

    private fun applyEvent(event: ChatStreamEvent) {
        when (event) {
            is ChatStreamEvent.MessageReceived -> appendOrReconcile(event.message)
            is ChatStreamEvent.MessageDeleted -> removeMessage(event.messageId)
            is ChatStreamEvent.ReactionUpdated -> applyReactionCounts(event.messageId, event.counts)
            is ChatStreamEvent.MessageUnlocked -> unlockText(event.messageId, event.text)
            ChatStreamEvent.Unknown -> Unit
        }
    }

    private fun appendOrReconcile(incoming: ChatMessage) {
        _uiState.update { current ->
            val content = current.asContent()
            val messages = content.messages
            // If we already have this server message, MERGE any newer server fields (reactions/unlock/
            // expiry updates ride the same message_id when the poll re-reads the recent window).
            val existingIdx = messages.indexOfFirst { it.id == incoming.id && it.clientNonce == null }
            if (existingIdx >= 0) {
                val merged = messages.toMutableList().apply {
                    val prev = this[existingIdx]
                    this[existingIdx] = incoming.copy(
                        isSelf = prev.isSelf || incoming.isSelf,
                        locallyRevealed = prev.locallyRevealed,
                    )
                }
                return@update content.copy(messages = merged)
            }
            // Reconcile an optimistic SENDING/FAILED self entry by senderId + text (media -> both null).
            val matchIndex = messages.indexOfFirst {
                it.clientNonce != null &&
                    it.deliveryState != DeliveryState.SENT &&
                    it.senderId == incoming.senderId &&
                    it.text == incoming.text
            }
            val next = if (matchIndex >= 0) {
                messages.toMutableList().apply {
                    this[matchIndex] = incoming.copy(deliveryState = DeliveryState.SENT, isSelf = true)
                }
            } else {
                messages + incoming
            }
            content.copy(messages = next.takeLast(MAX_RETAINED))
        }
    }

    private fun removeMessage(messageId: String) {
        _uiState.update { current ->
            val content = current.asContent()
            content.copy(messages = content.messages.filterNot { it.id == messageId })
        }
    }

    private fun applyReactionCounts(messageId: String, counts: Map<String, Int>, toggledEmoji: String? = null) {
        _uiState.update { current ->
            val content = current.asContent()
            content.copy(
                messages = content.messages.map { msg ->
                    if (msg.id != messageId) {
                        msg
                    } else {
                        val mine = msg.reactions.filter { it.reactedBySelf }.map { it.emoji }.toMutableSet()
                        // Optimistically toggle the self-flag for the emoji this viewer just tapped.
                        if (toggledEmoji != null) {
                            if (toggledEmoji in mine) mine.remove(toggledEmoji) else mine.add(toggledEmoji)
                        }
                        msg.copy(
                            reactions = counts.filterValues { it > 0 }.map { (emoji, count) ->
                                ChatReaction(emoji, count, reactedBySelf = emoji in mine)
                            },
                        )
                    }
                },
            )
        }
    }

    private fun applyUnlocked(messageId: String, revealed: ChatMessage?) {
        _uiState.update { current ->
            val content = current.asContent()
            content.copy(
                messages = content.messages.map { msg ->
                    if (msg.id != messageId) {
                        msg
                    } else {
                        msg.copy(
                            isUnlocked = true,
                            text = revealed?.text ?: msg.text,
                            imageUrl = revealed?.imageUrl ?: msg.imageUrl,
                            videoUrl = revealed?.videoUrl ?: msg.videoUrl,
                            thumbnailUrl = revealed?.thumbnailUrl ?: msg.thumbnailUrl,
                        )
                    }
                },
            )
        }
    }

    private fun unlockText(messageId: String, text: String) {
        _uiState.update { current ->
            val content = current.asContent()
            content.copy(
                messages = content.messages.map {
                    if (it.id == messageId) it.copy(text = text, isUnlocked = true) else it
                },
            )
        }
    }

    /** Re-fetch history and merge fresh server fields for [messageId] (unlock/view/expiry reconcile). */
    private fun reconcileFromHistory(messageId: String) {
        viewModelScope.launch {
            when (val result = repo.loadHistory(sessionId)) {
                is ApiResult.Success -> {
                    val fresh = result.data.firstOrNull { it.id == messageId } ?: return@launch
                    _uiState.update { current ->
                        val content = current.asContent()
                        content.copy(
                            messages = content.messages.map { msg ->
                                if (msg.id != messageId) msg
                                else fresh.copy(isSelf = msg.isSelf || fresh.isSelf, locallyRevealed = msg.locallyRevealed)
                            },
                        )
                    }
                }
                else -> Unit
            }
        }
    }

    private fun dispatchSend(
        nonce: String,
        text: String?,
        options: ChatComposeOptions,
        imageUrl: String?,
        videoUrl: String?,
        thumbnailUrl: String?,
    ) {
        viewModelScope.launch {
            when (val result = repo.send(sessionId, text, options, imageUrl, videoUrl, thumbnailUrl)) {
                is ApiResult.Success -> reconcileSent(nonce, result.data)
                else -> setDeliveryState(nonce, DeliveryState.FAILED)
            }
        }
    }

    private fun reconcileSent(nonce: String, server: ChatMessage) {
        _uiState.update { current ->
            val content = current.asContent()
            val idx = content.messages.indexOfFirst { it.clientNonce == nonce }
            if (idx < 0) {
                if (content.messages.any { it.id == server.id }) return@update content
                content.copy(messages = (content.messages + server).takeLast(MAX_RETAINED))
            } else {
                content.copy(
                    messages = content.messages.toMutableList().apply {
                        this[idx] = server.copy(deliveryState = DeliveryState.SENT, isSelf = true)
                    },
                )
            }
        }
    }

    private fun setDeliveryState(nonce: String, deliveryState: DeliveryState) {
        _uiState.update { current ->
            val content = current.asContent()
            content.copy(
                messages = content.messages.map {
                    if (it.clientNonce == nonce) it.copy(deliveryState = deliveryState) else it
                },
            )
        }
    }

    private fun loadHistory() {
        viewModelScope.launch {
            when (val result = repo.loadHistory(sessionId)) {
                is ApiResult.Success -> _uiState.update { current ->
                    val content = current.asContent()
                    if (content.messages.isEmpty()) content.copy(messages = result.data.takeLast(MAX_RETAINED))
                    else content
                }
                else -> Unit
            }
        }
    }

    private fun LiveChatUiState.asContent(): LiveChatUiState.Content = when (this) {
        is LiveChatUiState.Content -> this
        else -> LiveChatUiState.Content(
            messages = emptyList(),
            connection = effectiveConnection(),
            composerText = "",
            canSend = false,
            pinnedToBottom = true,
        )
    }

    override fun onCleared() {
        streamJob?.cancel()
    }

    companion object {
        const val MAX_RETAINED = 500
        private const val SELF_PLACEHOLDER = "self"
        // BCAST-016 FLAG: unlock captures against a saved payment method; a real pm id is required for a
        // successful charge. We pass a best-effort default (mirrors the DM PPV unlock, which also accepts a
        // caller-supplied method); on accounts without a saved method the unlock POST will fail server-side.
        private const val DEFAULT_PAYMENT_METHOD = "default"
    }
}
