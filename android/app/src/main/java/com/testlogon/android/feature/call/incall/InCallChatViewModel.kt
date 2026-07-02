package com.testlogon.android.feature.call.incall

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.messaging.Message
import com.testlogon.android.data.messaging.MessagingRepository
import com.testlogon.android.data.messaging.SendStatus
import com.testlogon.android.data.messaging.realtime.MessagingEvent
import com.testlogon.android.data.messaging.realtime.MessagingEventStream
import com.testlogon.android.data.messaging.realtime.MessagingStreamEvent
import com.testlogon.android.feature.call.domain.CallManager
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import javax.inject.Inject

/**
 * FIX C — in-call chat drawer view model.
 *
 * Rides the SAME DM as the active call (the call carries a [conversationId]) so in-call chat reuses the
 * messaging data layer end-to-end: history via [MessagingRepository.loadHistory], the live thread via
 * [MessagingRepository.observeThread] (Room history union outbox, so optimistic sends show instantly),
 * sends via enqueueOptimistic -> sendOutbox (identical to [com.testlogon.android.feature.messaging.thread.ThreadViewModel]),
 * and realtime inbound via the cold [MessagingEventStream] poll (/messaging/events/poll). The
 * conversation id is read from [CallManager] (the active call), so the drawer needs no nav args.
 *
 * Deliberately minimal (text bubbles only) — it is an overlay on the call, not the full thread screen.
 */
@HiltViewModel
class InCallChatViewModel @Inject constructor(
    private val repository: MessagingRepository,
    private val eventStream: MessagingEventStream,
    private val authStateStore: AuthStateStore,
    private val callManager: CallManager,
) : ViewModel() {

    private val _state = MutableStateFlow(InCallChatUiState())
    val state: StateFlow<InCallChatUiState> = _state.asStateFlow()

    private var conversationId: String? = null
    private var threadJob: Job? = null
    private var realtimeJob: Job? = null

    init {
        // The call may adopt/place slightly after this VM is created; bind to the conversation id the
        // moment the active call exposes one, and (re)start the thread + realtime collectors once.
        viewModelScope.launch {
            callManager.state.collect { session ->
                val cid = session.call?.conversationId
                if (!cid.isNullOrEmpty() && cid != conversationId) {
                    conversationId = cid
                    _state.update { it.copy(conversationId = cid) }
                    start(cid)
                }
            }
        }
    }

    private fun start(cid: String) {
        threadJob?.cancel()
        realtimeJob?.cancel()
        threadJob = viewModelScope.launch {
            repository.observeThread(cid).collect { messages ->
                val self = authStateStore.userSub.value
                _state.update { st -> st.copy(messages = messages.filterNot { it.isHiddenLocal }.map { it.toChatUi(self) }) }
            }
        }
        // Realtime inbound for THIS conversation: fold new messages into the cache so observeThread emits
        // them live (mirrors ThreadViewModel.observeRealtime, scoped to the call conversation).
        realtimeJob = viewModelScope.launch {
            eventStream.events().collect { streamEvent ->
                if (streamEvent is MessagingStreamEvent.Event) {
                    val event = streamEvent.event
                    if (event is MessagingEvent.NewMessage && event.conversationId == cid) {
                        repository.applyInboundMessage(event)
                    }
                }
            }
        }
        // Seed the newest page of history.
        viewModelScope.launch { repository.loadHistory(cid, before = null, limit = PAGE_SIZE) }
    }

    fun onDraftChange(text: String) = _state.update { it.copy(draft = text) }

    fun onSend() {
        val cid = conversationId ?: return
        val body = _state.value.draft.trim()
        if (body.isEmpty()) return
        val clientId = UUID.randomUUID().toString()
        _state.update { it.copy(draft = "") }
        viewModelScope.launch {
            repository.enqueueOptimistic(cid, clientId, body, System.currentTimeMillis() / 1000L)
            repository.sendOutbox(cid, clientId, body)
        }
    }

    private fun Message.toChatUi(self: String?): InCallChatMessage = InCallChatMessage(
        key = id ?: clientId,
        text = text,
        // Outbox rows have an empty senderId; they are always the current user's.
        isOwn = senderId.isEmpty() || senderId == self,
        timeLabel = TIME_FMT.format(Date(createdAtEpochSeconds * 1000L)),
        sending = sendStatus == SendStatus.SENDING,
        failed = sendStatus == SendStatus.FAILED,
    )

    companion object {
        private const val PAGE_SIZE = 30
        private val TIME_FMT = SimpleDateFormat("HH:mm", Locale.getDefault())
    }
}

/** Minimal, overlay-friendly chat state for the in-call drawer. */
data class InCallChatUiState(
    val conversationId: String? = null,
    val messages: List<InCallChatMessage> = emptyList(),
    val draft: String = "",
)

/** One text bubble in the in-call chat drawer. */
data class InCallChatMessage(
    val key: String,
    val text: String,
    val isOwn: Boolean,
    val timeLabel: String,
    val sending: Boolean = false,
    val failed: Boolean = false,
)
