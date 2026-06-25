package com.testlogon.android.feature.support.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.support.data.SupportRepository
import com.testlogon.android.feature.support.data.SupportTicket
import com.testlogon.android.navigation.SupportTicketDetailDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B-SUP (batch 7) — one ticket: messages thread + a reply composer. Shared by both roles (the SAME thread).
 * Admin-only status/assign controls are exposed via [isAdmin]; for a USER they are hidden and the server
 * would 403 anyway. [isAdmin] is passed in from the nav arg (resolved once at the Support landing).
 */
data class SupportTicketDetailUiState(
    val loading: Boolean = true,
    val ticket: SupportTicket? = null,
    val error: String? = null,
    val reply: String = "",
    val sending: Boolean = false,
    val actionError: String? = null,
    val actionInFlight: Boolean = false,
    val isAdmin: Boolean = false,
    // B8 #15 — owner close/cancel
    val closing: Boolean = false,
) {
    val canSend: Boolean
        get() = reply.trim().length in SupportRepository.REPLY_MIN..SupportRepository.REPLY_MAX && !sending

    /** B8 #15 — a USER may close/cancel their own ticket while it is not already terminal. */
    val canClose: Boolean
        get() = !isAdmin && ticket != null && !ticket.isTerminal && !closing && !actionInFlight
}

@HiltViewModel
class SupportTicketDetailViewModel @Inject constructor(
    private val repository: SupportRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val ticketId: String =
        savedStateHandle.get<String>(SupportTicketDetailDest.ARG_TICKET_ID).orEmpty()

    private val _uiState = MutableStateFlow(
        SupportTicketDetailUiState(
            isAdmin = savedStateHandle.get<Boolean>(SupportTicketDetailDest.ARG_IS_ADMIN) ?: false,
        ),
    )
    val uiState: StateFlow<SupportTicketDetailUiState> = _uiState.asStateFlow()

    val statusOptions = listOf("open", "in_progress", "waiting_on_user", "done", "reopened")

    init { load() }

    fun load() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(loading = true, error = null)
            when (val r = repository.getTicket(ticketId)) {
                is ApiResult.Success ->
                    _uiState.value = _uiState.value.copy(loading = false, ticket = r.data, error = null)
                is ApiResult.Failure ->
                    _uiState.value = _uiState.value.copy(loading = false, error = r.error.message)
                is ApiResult.NetworkError ->
                    _uiState.value = _uiState.value.copy(loading = false, error = "You appear to be offline.")
            }
        }
    }

    fun onReplyChange(v: String) { _uiState.value = _uiState.value.copy(reply = v) }

    fun sendReply() {
        val s = _uiState.value
        if (!s.canSend) return
        viewModelScope.launch {
            _uiState.value = s.copy(sending = true, actionError = null)
            when (val r = repository.addMessage(ticketId, s.reply)) {
                is ApiResult.Success ->
                    _uiState.value = _uiState.value.copy(sending = false, reply = "", ticket = r.data)
                is ApiResult.Failure ->
                    _uiState.value = _uiState.value.copy(sending = false, actionError = r.error.message)
                is ApiResult.NetworkError ->
                    _uiState.value = _uiState.value.copy(sending = false, actionError = "You appear to be offline.")
            }
        }
    }

    /** ADMIN-only. */
    fun setStatus(status: String) {
        if (!_uiState.value.isAdmin) return
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(actionInFlight = true, actionError = null)
            when (val r = repository.setStatus(ticketId, status)) {
                is ApiResult.Success ->
                    _uiState.value = _uiState.value.copy(actionInFlight = false, ticket = r.data)
                is ApiResult.Failure ->
                    _uiState.value = _uiState.value.copy(actionInFlight = false, actionError = r.error.message)
                is ApiResult.NetworkError ->
                    _uiState.value = _uiState.value.copy(actionInFlight = false, actionError = "You appear to be offline.")
            }
        }
    }

    /**
     * B8 #15 — the OWNER closes ("close" -> done) or cancels ("cancel" -> cancelled) their own ticket via
     * POST /tickets/{id}/close. The returned ticket carries the new terminal status so the detail reflects
     * it immediately; the Support landing re-pulls on resume so the list updates too.
     */
    fun closeTicket(action: String) {
        val s = _uiState.value
        if (s.isAdmin || s.ticket == null || s.ticket.isTerminal || s.closing) return
        viewModelScope.launch {
            _uiState.value = s.copy(closing = true, actionError = null)
            when (val r = repository.closeTicket(ticketId, action)) {
                is ApiResult.Success ->
                    _uiState.value = _uiState.value.copy(closing = false, ticket = r.data)
                is ApiResult.Failure ->
                    _uiState.value = _uiState.value.copy(closing = false, actionError = r.error.message)
                is ApiResult.NetworkError ->
                    _uiState.value = _uiState.value.copy(closing = false, actionError = "You appear to be offline.")
            }
        }
    }

    fun clearActionError() { _uiState.value = _uiState.value.copy(actionError = null) }
}
