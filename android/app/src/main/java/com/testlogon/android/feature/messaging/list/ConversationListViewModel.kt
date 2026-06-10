package com.testlogon.android.feature.messaging.list

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.Conversation
import com.testlogon.android.data.messaging.MessagingRepository
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
import kotlinx.coroutines.launch
import javax.inject.Inject

/** One-shot effects consumed by the conversation-list screen. */
sealed interface ConversationListEvent {
    data class ShowSnackbar(val message: String) : ConversationListEvent
}

/**
 * AND-121 / AND-122 — conversation-list presentation logic.
 *
 * Source of truth is the Room-backed [MessagingRepository.observeConversations] stream; a network
 * [refresh] upserts the cache. Inbound realtime events trigger a silent re-refresh so unread counts
 * and last-message previews stay live. The screen never re-implements data logic.
 *
 * One-shot effects use a Channel + receiveAsFlow (never distinctUntilChanged on a StateFlow).
 */
@HiltViewModel
class ConversationListViewModel @Inject constructor(
    private val repository: MessagingRepository,
    private val eventStream: MessagingEventStream,
) : ViewModel() {

    private val _state = MutableStateFlow<ConversationListUiState>(ConversationListUiState.Loading)
    val state: StateFlow<ConversationListUiState> = _state.asStateFlow()

    private val _events = Channel<ConversationListEvent>(Channel.BUFFERED)
    val events: Flow<ConversationListEvent> = _events.receiveAsFlow()

    private var cached: List<ConversationRow> = emptyList()
    private var firstRefreshSucceeded = false

    init {
        observeCache()
        observeRealtime()
        refresh(initial = true)
    }

    fun refresh(initial: Boolean = false) {
        viewModelScope.launch {
            val prior = _state.value as? ConversationListUiState.Content
            if (initial && prior == null && cached.isEmpty()) {
                _state.value = ConversationListUiState.Loading
            } else if (prior != null) {
                _state.value = prior.copy(isRefreshing = true)
            }
            when (val result = repository.refreshConversations()) {
                is ApiResult.Success -> {
                    firstRefreshSucceeded = true
                    renderCache() // resolves Loading -> Content/Empty
                }
                is ApiResult.Failure -> reduceFailure(message = result.error.message, offline = false)
                is ApiResult.NetworkError -> reduceFailure(message = OFFLINE_MESSAGE, offline = true)
            }
        }
    }

    fun retry() = refresh(initial = true)

    private fun observeCache() {
        viewModelScope.launch {
            repository.observeConversations().collect { conversations ->
                cached = conversations.map(Conversation::toRow)
                renderCache()
            }
        }
    }

    private fun renderCache() {
        val prior = _state.value
        _state.value = when {
            cached.isNotEmpty() ->
                ConversationListUiState.Content(
                    rows = cached,
                    isRefreshing = false,
                    staleReason = (prior as? ConversationListUiState.Content)?.staleReason,
                )
            // Only show Empty once the first network refresh has resolved successfully.
            firstRefreshSucceeded -> ConversationListUiState.Empty
            // Otherwise keep whatever we had (Loading on cold start).
            prior is ConversationListUiState.Content -> ConversationListUiState.Empty
            else -> prior
        }
    }

    private fun reduceFailure(message: String, offline: Boolean) {
        if (cached.isNotEmpty()) {
            _state.value = ConversationListUiState.Content(
                rows = cached,
                isRefreshing = false,
                staleReason = if (offline) StaleReason.OFFLINE else StaleReason.SERVER_ERROR,
            )
            _events.trySend(ConversationListEvent.ShowSnackbar(REFRESH_FAILED))
        } else {
            _state.value = ConversationListUiState.Error(message = message, offline = offline)
        }
    }

    private fun observeRealtime() {
        viewModelScope.launch {
            eventStream.events().collect { streamEvent ->
                if (streamEvent is MessagingStreamEvent.Event) {
                    when (streamEvent.event) {
                        is MessagingEvent.NewMessage,
                        is MessagingEvent.ConversationUpdated,
                        is MessagingEvent.MessageMutated,
                        is MessagingEvent.Other,
                        -> refresh()
                        // AND-145/146/147 — presence, typing, and read receipts don't change list
                        // summaries; ignored here (presence -> PresenceRepository; typing + receipts ->
                        // the open thread VM).
                        is MessagingEvent.PresenceUpdate,
                        is MessagingEvent.Typing,
                        is MessagingEvent.MessageViewed,
                        -> Unit
                    }
                }
            }
        }
    }

    private companion object {
        const val OFFLINE_MESSAGE = "You're offline. Showing saved conversations."
        const val REFRESH_FAILED = "Couldn't refresh — showing older conversations."
    }
}
