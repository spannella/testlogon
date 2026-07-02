package com.testlogon.android.feature.broadcast.chat

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.chat.BroadcastChatRepository
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
    ) : LiveChatUiState

    data class Error(val retryable: Boolean) : LiveChatUiState
}

/**
 * AND-281 — live-chat presentation logic for a single broadcast session.
 *
 * Folds the [BroadcastChatRepository] SSE signals + send/react mutations into a single reducer.
 * Optimistic send inserts a SENDING entry keyed by a LOCAL-ONLY clientNonce; the SSE echo / POST
 * response reconciles it to SENT by matching senderId+text (then adopting the server message_id), since
 * the wire carries no client_id (FR-5). The in-memory list is capped at [MAX_RETAINED]. Built with
 * AssistedInject so the sessionId is supplied at the call site (the panel composes into the viewer AND
 * the host live screen).
 *
 * TRANSPORT DECOUPLE: the long-lived SSE does not connect on-device (same failure documented for the
 * messaging /events/stream), so the repository also drives a POLL backstop that emits
 * [ChatStreamSignal.PollAlive] + re-delivered [ChatStreamEvent.MessageReceived] frames. Send-enablement
 * therefore keys off a WORKING TRANSPORT (SSE LIVE **or** the poll being alive), NOT strictly the SSE
 * connection being LIVE — otherwise canSend would never become true when the SSE is stuck RECONNECTING.
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

    // The raw SSE connection status and the poll-backstop liveness are tracked separately so the
    // effective (displayed + send-gating) transport can be either one.
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
                canSend = text.isNotBlank() && transportUp(),
            ) ?: state
        }
    }

    fun send() {
        val content = _uiState.value as? LiveChatUiState.Content ?: return
        val text = content.composerText.trim()
        if (text.isEmpty() || !transportUp()) return
        val nonce = UUID.randomUUID().toString()
        val optimistic = ChatMessage(
            id = nonce,
            clientNonce = nonce,
            sessionId = sessionId,
            senderId = repo.selfId() ?: SELF_PLACEHOLDER,
            senderDisplayName = "",
            isSelf = true,
            text = text,
            createdAtEpochSeconds = System.currentTimeMillis() / 1000L,
            deliveryState = DeliveryState.SENDING,
        )
        _uiState.update { state ->
            (state as? LiveChatUiState.Content)?.copy(
                messages = (state.messages + optimistic).takeLast(MAX_RETAINED),
                composerText = "",
                canSend = false,
            ) ?: state
        }
        dispatchSend(nonce, text)
    }

    fun retrySend(clientNonce: String) {
        val content = _uiState.value as? LiveChatUiState.Content ?: return
        val msg = content.messages.firstOrNull { it.clientNonce == clientNonce } ?: return
        val text = msg.text ?: return
        setDeliveryState(clientNonce, DeliveryState.SENDING)
        dispatchSend(clientNonce, text)
    }

    fun reactToMessage(messageId: String, emoji: String) {
        viewModelScope.launch {
            when (val result = repo.reactToMessage(sessionId, messageId, emoji)) {
                is ApiResult.Success -> applyReactionCounts(messageId, result.data)
                else -> Unit // best-effort; the chat:reaction SSE frame also broadcasts counts
            }
        }
    }

    fun onScrolledToBottom(atBottom: Boolean) {
        _uiState.update { (it as? LiveChatUiState.Content)?.copy(pinnedToBottom = atBottom) ?: it }
    }

    fun retry() {
        loadHistory()
        onResumeStreaming()
    }

    // ---- transport ----

    /** True when a working transport exists: the SSE is LIVE, OR the poll backstop is delivering. */
    private fun transportUp(): Boolean = sseStatus == ConnectionStatus.LIVE || pollAlive

    /**
     * The status shown to the user: LIVE when either transport is up, otherwise the raw SSE status. This
     * keeps the panel from showing a scary "Reconnecting" banner while the poll backstop is happily
     * delivering messages + accepting sends.
     */
    private fun effectiveConnection(): ConnectionStatus =
        if (transportUp()) ConnectionStatus.LIVE else sseStatus

    /** Recompute the displayed connection + canSend after either transport signal changes. */
    private fun recomputeTransport() {
        _uiState.update { current ->
            val content = current.asContent()
            content.copy(
                connection = effectiveConnection(),
                canSend = transportUp() && content.composerText.isNotBlank(),
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
        // Stay on the pure Connecting state until the first Open (LIVE) or a frame/poll arrives — unless
        // the poll backstop has already made the transport usable, in which case we materialize Content.
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
            // AND-313 — the chat:delete frame reconciles a moderator's optimistic delete (the moderation VM
            // issues the DELETE; this reducer removes the row when the server echoes chat:delete). There are
            // NO SSE frames for mute / ban / pin, so those are NOT reconciled here.
            is ChatStreamEvent.MessageDeleted -> removeMessage(event.messageId)
            is ChatStreamEvent.ReactionUpdated -> applyReactionCounts(event.messageId, event.counts)
            is ChatStreamEvent.MessageUnlocked -> unlockMessage(event.messageId, event.text)
            ChatStreamEvent.Unknown -> Unit
        }
    }

    private fun appendOrReconcile(incoming: ChatMessage) {
        _uiState.update { current ->
            val content = current.asContent()
            val messages = content.messages
            // Guard: server message_id already present -> ignore (dedup).
            if (messages.any { it.id == incoming.id && it.clientNonce == null }) return@update content
            // Reconcile an optimistic SENDING/FAILED self entry by senderId+text.
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

    private fun applyReactionCounts(messageId: String, counts: Map<String, Int>) {
        _uiState.update { current ->
            val content = current.asContent()
            content.copy(
                messages = content.messages.map { msg ->
                    if (msg.id != messageId) {
                        msg
                    } else {
                        val mine = msg.reactions.filter { it.reactedBySelf }.map { it.emoji }.toSet()
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

    private fun unlockMessage(messageId: String, text: String) {
        _uiState.update { current ->
            val content = current.asContent()
            content.copy(messages = content.messages.map { if (it.id == messageId) it.copy(text = text) else it })
        }
    }

    private fun dispatchSend(nonce: String, text: String) {
        viewModelScope.launch {
            when (val result = repo.send(sessionId, text)) {
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
                // The SSE echo already reconciled it; ignore the POST response to avoid a duplicate.
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
                    // Seed only if we have not already accumulated live messages.
                    if (content.messages.isEmpty()) content.copy(messages = result.data.takeLast(MAX_RETAINED))
                    else content
                }
                else -> Unit // history is a best-effort seed; the live stream still drives the panel
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
    }
}
