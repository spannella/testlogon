package com.testlogon.android.feature.tickets.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.feature.tickets.data.TicketsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-372 - drives the READ-ONLY [TicketThreadUiState] for the ticket THREAD (screen 3).
 *
 * spaceId + ticketId arrive as nav args via [SavedStateHandle] (survive process death). [load] fetches the
 * ticket (named {ticket} envelope unwrap) whose embedded messages are the thread (oldest-first). [currentSub]
 * is the viewer's own user_sub (from [AuthStateStore]) so the screen distinguishes the viewer's own messages
 * (sender_sub == currentSub) visually. A loaded ticket with NO messages -> Empty.
 *
 * STALE (in-memory only): [refresh] re-reads but, on a NON-401 failure, KEEPS the last-good Content and flips
 * isStale true (the snapshot lives only in this StateFlow - NOT persisted; Room persistence is DEFERRED, no
 * migration this wave). A TERMINAL 401 -> one-shot [TicketsEffect.NavigateToLogin] (re-auth handoff), NOT a
 * generic error. There is NO poll loop and NO composer (replying is AND-373).
 */
@HiltViewModel
class TicketThreadViewModel @Inject constructor(
    private val repository: TicketsRepository,
    savedState: SavedStateHandle,
    authStateStore: AuthStateStore,
) : ViewModel() {

    val spaceId: String =
        checkNotNull(savedState[ARG_SPACE_ID]) { "missing $ARG_SPACE_ID nav arg" }
    val ticketId: String =
        checkNotNull(savedState[ARG_TICKET_ID]) { "missing $ARG_TICKET_ID nav arg" }

    /** The viewer's own user_sub (may be null when unresolved); used to align the viewer's own bubbles. */
    val currentSub: String? = authStateStore.userSub.value?.takeIf { it.isNotBlank() }

    private val _uiState = MutableStateFlow<TicketThreadUiState>(TicketThreadUiState.Loading)
    val uiState: StateFlow<TicketThreadUiState> = _uiState.asStateFlow()

    private val _effects = Channel<TicketsEffect>(Channel.BUFFERED)
    val effects: Flow<TicketsEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    /** First load (no cached content): goes through Loading and may resolve to Empty / Error / NavigateToLogin. */
    fun load() {
        _uiState.value = TicketThreadUiState.Loading
        fetch(isRefresh = false)
    }

    fun onRetry() = load()

    /** Pull-to-refresh. On a non-401 failure the last-good Content is kept with isStale=true. */
    fun refresh() = fetch(isRefresh = true)

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val result = repository.getTicket(spaceId, ticketId)) {
                is ApiResult.Success -> {
                    val ticket = result.data
                    _uiState.value = if (ticket.messages.isEmpty()) {
                        TicketThreadUiState.Empty
                    } else {
                        TicketThreadUiState.Content(
                            ticket = ticket,
                            currentSub = currentSub,
                            isStale = false,
                        )
                    }
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _effects.send(TicketsEffect.NavigateToLogin)
                    } else {
                        emitFailure(isRefresh, result.error)
                    }
                }
                is ApiResult.NetworkError ->
                    emitFailure(
                        isRefresh,
                        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK),
                    )
            }
        }
    }

    /** A non-401 failure: keep stale content on a refresh that has prior content, else surface Error. */
    private fun emitFailure(isRefresh: Boolean, error: ApiError) {
        val prior = _uiState.value as? TicketThreadUiState.Content
        _uiState.value = if (isRefresh && prior != null) {
            prior.copy(isStale = true)
        } else {
            TicketThreadUiState.Error(error)
        }
    }

    companion object {
        const val ARG_SPACE_ID = "spaceId"
        const val ARG_TICKET_ID = "ticketId"

        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
