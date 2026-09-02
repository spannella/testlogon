package com.testlogon.android.feature.agents.feedback.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.agents.feedback.data.FeedbackRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AGENTS-BASICS (web-parity) - drives the FEEDBACK list (web /agents/feedback). A single GET loads all feedback
 * requests; pull-to-refresh re-reads. Per-item respond / skip set an [actioningId] flag and re-load on success.
 * A terminal 401 -> [FeedbackEffect.NavigateToLogin]. No poll loop (the web page polls; we re-read on refresh).
 *
 * [dialogState] is a SEPARATE flow for the create-request + terminal-log dialogs so they work from the empty
 * state too. [create] mirrors web createFeedbackRequest; [loadTerminal] mirrors web getTerminalLog.
 */
@HiltViewModel
class FeedbackViewModel @Inject constructor(
    private val repo: FeedbackRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<FeedbackUiState>(FeedbackUiState.Loading)
    val uiState: StateFlow<FeedbackUiState> = _uiState.asStateFlow()

    private val _dialogState = MutableStateFlow(FeedbackDialogState())
    val dialogState: StateFlow<FeedbackDialogState> = _dialogState.asStateFlow()

    private val _effects = Channel<FeedbackEffect>(Channel.BUFFERED)
    val effects: Flow<FeedbackEffect> = _effects.receiveAsFlow()

    private var loadJob: Job? = null

    init { load() }

    fun load() {
        if (loadJob?.isActive == true) return
        _uiState.value = FeedbackUiState.Loading
        fetch(isRefresh = false)
    }

    fun onRetry() = load()

    fun refresh() {
        if (loadJob?.isActive == true) return
        (_uiState.value as? FeedbackUiState.Content)?.let { _uiState.value = it.copy(isRefreshing = true) }
        fetch(isRefresh = true)
    }

    private fun fetch(isRefresh: Boolean) {
        loadJob = viewModelScope.launch {
            when (val result = repo.list()) {
                is ApiResult.Success ->
                    _uiState.value = if (result.data.isEmpty()) FeedbackUiState.Empty
                    else FeedbackUiState.Content(items = result.data)
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _effects.send(FeedbackEffect.NavigateToLogin); clearRefreshing()
                    } else emitFailure(isRefresh, result.error.message)
                }
                is ApiResult.NetworkError -> emitFailure(isRefresh, OFFLINE)
            }
        }
    }

    fun respond(workerId: String, requestId: String, text: String) {
        if (text.isBlank()) return
        act(requestId) { repo.respond(workerId, requestId, text.trim()) }
    }

    fun skip(workerId: String, requestId: String) = act(requestId) { repo.skip(workerId, requestId) }

    private fun act(requestId: String, block: suspend () -> ApiResult<*>) {
        val current = _uiState.value as? FeedbackUiState.Content ?: return
        if (current.actioningId != null) return
        _uiState.value = current.copy(actioningId = requestId, actionError = null)
        viewModelScope.launch {
            when (val result = block()) {
                is ApiResult.Success -> reloadAfterAction()
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(FeedbackEffect.NavigateToLogin)
                    clearActioning(result.error.message)
                }
                is ApiResult.NetworkError -> clearActioning(OFFLINE)
            }
        }
    }

    // ---- Create feedback request (web createFeedbackRequest) ----

    fun openCreate() { _dialogState.value = _dialogState.value.copy(create = CreateFeedbackState()) }

    fun dismissCreate() { _dialogState.value = _dialogState.value.copy(create = null) }

    fun create(workerId: String, ticketId: String, question: String) {
        if (workerId.isBlank() || ticketId.isBlank() || question.isBlank()) {
            _dialogState.value = _dialogState.value.copy(
                create = CreateFeedbackState(error = "Worker, ticket and question are all required."),
            )
            return
        }
        val cur = _dialogState.value.create ?: CreateFeedbackState()
        if (cur.submitting) return
        _dialogState.value = _dialogState.value.copy(create = cur.copy(submitting = true, error = null))
        viewModelScope.launch {
            when (val result = repo.create(workerId.trim(), ticketId.trim(), question.trim())) {
                is ApiResult.Success -> {
                    _dialogState.value = _dialogState.value.copy(create = null)
                    reloadAfterAction()
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(FeedbackEffect.NavigateToLogin)
                    _dialogState.value = _dialogState.value.copy(
                        create = CreateFeedbackState(error = result.error.message),
                    )
                }
                is ApiResult.NetworkError ->
                    _dialogState.value = _dialogState.value.copy(create = CreateFeedbackState(error = OFFLINE))
            }
        }
    }

    // ---- Terminal log (web getTerminalLog) ----

    fun openTerminal(workerId: String) {
        if (workerId.isBlank()) return
        _dialogState.value = _dialogState.value.copy(terminal = TerminalLogState(workerId = workerId, loading = true))
        viewModelScope.launch {
            when (val result = repo.terminalLog(workerId)) {
                is ApiResult.Success ->
                    updateTerminal(workerId) { it.copy(loading = false, output = result.data, error = null) }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(FeedbackEffect.NavigateToLogin)
                    updateTerminal(workerId) { it.copy(loading = false, error = result.error.message) }
                }
                is ApiResult.NetworkError ->
                    updateTerminal(workerId) { it.copy(loading = false, error = OFFLINE) }
            }
        }
    }

    fun dismissTerminal() { _dialogState.value = _dialogState.value.copy(terminal = null) }

    private inline fun updateTerminal(workerId: String, transform: (TerminalLogState) -> TerminalLogState) {
        val t = _dialogState.value.terminal
        if (t != null && t.workerId == workerId) {
            _dialogState.value = _dialogState.value.copy(terminal = transform(t))
        }
    }

    private suspend fun reloadAfterAction() {
        when (val reload = repo.list()) {
            is ApiResult.Success ->
                _uiState.value = if (reload.data.isEmpty()) FeedbackUiState.Empty
                else FeedbackUiState.Content(items = reload.data)
            else -> clearActioning(null)
        }
    }

    private fun clearActioning(message: String?) {
        (_uiState.value as? FeedbackUiState.Content)?.let {
            _uiState.value = it.copy(actioningId = null, actionError = message)
        }
    }

    private fun emitFailure(isRefresh: Boolean, message: String) {
        val prior = _uiState.value as? FeedbackUiState.Content
        _uiState.value = if (isRefresh && prior != null) prior.copy(isRefreshing = false, actionError = message)
        else FeedbackUiState.Error(message)
    }

    private fun clearRefreshing() {
        (_uiState.value as? FeedbackUiState.Content)?.let { _uiState.value = it.copy(isRefreshing = false) }
    }

    private companion object {
        const val HTTP_UNAUTHORIZED = 401
        const val OFFLINE = "Couldn't reach the server. Pull down to retry."
    }
}
