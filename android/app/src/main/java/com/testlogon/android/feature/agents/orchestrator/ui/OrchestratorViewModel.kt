package com.testlogon.android.feature.agents.orchestrator.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.agents.orchestrator.data.AgentStatus
import com.testlogon.android.feature.agents.orchestrator.data.LoopAction
import com.testlogon.android.feature.agents.orchestrator.data.OrchestratorMath
import com.testlogon.android.feature.agents.orchestrator.data.OrchestratorRepository
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
 * AGENT-ORCHESTRATOR (web-parity) - drives the orchestrator console for ONE worker. Loads status (+ eligible
 * ticket preview), derives the available loop actions via [OrchestratorMath], and dispatches loop-control /
 * ticket ops, re-fetching status on success. Degrade-on-404 (no orchestrator record) surfaces as
 * [OrchestratorUiState.NoLoop]; a 401 hands off to login.
 */
@HiltViewModel
class OrchestratorViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repo: OrchestratorRepository,
) : ViewModel() {

    private val workerId: String = savedStateHandle.get<String>(ARG_WORKER_ID).orEmpty()

    private val _uiState = MutableStateFlow<OrchestratorUiState>(OrchestratorUiState.Loading)
    val uiState: StateFlow<OrchestratorUiState> = _uiState.asStateFlow()

    private val _effects = Channel<OrchestratorEffect>(Channel.BUFFERED)
    val effects: Flow<OrchestratorEffect> = _effects.receiveAsFlow()

    init { load() }

    fun load() {
        _uiState.value = OrchestratorUiState.Loading
        fetchStatus(thenEligible = true)
    }

    fun refresh() {
        (_uiState.value as? OrchestratorUiState.Content)?.let {
            _uiState.value = it.copy(isRefreshing = true)
        }
        fetchStatus(thenEligible = true)
    }

    private fun fetchStatus(thenEligible: Boolean) {
        viewModelScope.launch {
            when (val result = repo.status(workerId)) {
                is ApiResult.Success -> {
                    val status = result.data
                    if (status == null) {
                        _uiState.value = OrchestratorUiState.NoLoop
                    } else {
                        renderStatus(status)
                        if (thenEligible) fetchEligible()
                    }
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(OrchestratorEffect.NavigateToLogin)
                    _uiState.value = OrchestratorUiState.Error(result.error.message)
                }
                is ApiResult.NetworkError -> _uiState.value = OrchestratorUiState.Error(OFFLINE)
            }
        }
    }

    private fun renderStatus(status: AgentStatus, notice: String? = null) {
        val previous = _uiState.value as? OrchestratorUiState.Content
        _uiState.value = OrchestratorUiState.Content(
            status = status,
            actions = OrchestratorMath.availableActions(status),
            summary = OrchestratorMath.summaryLine(status),
            eligible = previous?.eligible.orEmpty(),
            eligibleLoading = previous?.eligibleLoading ?: false,
            isRefreshing = false,
            actioning = null,
            actionError = null,
            notice = notice,
        )
    }

    fun loadEligible() = fetchEligible()

    private fun fetchEligible() {
        val current = _uiState.value as? OrchestratorUiState.Content ?: return
        _uiState.value = current.copy(eligibleLoading = true)
        viewModelScope.launch {
            when (val result = repo.eligibleTickets(workerId)) {
                is ApiResult.Success -> {
                    val latest = _uiState.value as? OrchestratorUiState.Content ?: return@launch
                    _uiState.value = latest.copy(
                        eligible = result.data?.tickets.orEmpty(),
                        eligibleLoading = false,
                    )
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(OrchestratorEffect.NavigateToLogin)
                    val latest = _uiState.value as? OrchestratorUiState.Content ?: return@launch
                    _uiState.value = latest.copy(eligibleLoading = false)
                }
                is ApiResult.NetworkError -> {
                    val latest = _uiState.value as? OrchestratorUiState.Content ?: return@launch
                    _uiState.value = latest.copy(eligibleLoading = false)
                }
            }
        }
    }

    fun start() = act(LoopAction.START) { repo.start(workerId) }
    fun pause() = act(LoopAction.PAUSE) { repo.pause(workerId) }
    fun resume() = act(LoopAction.RESUME) { repo.resume(workerId) }
    fun stop() = act(LoopAction.STOP) { repo.stop(workerId) }
    fun release() = act(LoopAction.RELEASE) { repo.release(workerId) }
    fun heartbeat() = act(LoopAction.HEARTBEAT, notice = "Heartbeat sent.") { repo.heartbeat(workerId) }

    fun claim(ticketId: String) {
        if (ticketId.isBlank()) return
        act(LoopAction.CLAIM) { repo.claim(workerId, ticketId) }
    }

    fun complete(summary: String?, prUrl: String?) =
        act(LoopAction.COMPLETE) { repo.complete(workerId, summary, prUrl) }

    /**
     * Runs a loop/ticket mutation, then re-fetches status (source of truth). On success a [notice] can be shown;
     * a 401 hands off to login; other failures set actionError without leaving the Content state.
     */
    private fun act(action: LoopAction, notice: String? = null, block: suspend () -> ApiResult<*>) {
        val current = _uiState.value as? OrchestratorUiState.Content ?: return
        if (current.actioning != null) return
        _uiState.value = current.copy(actioning = action, actionError = null, notice = null)
        viewModelScope.launch {
            when (val result = block()) {
                is ApiResult.Success -> refetchStatusAfterAction(notice)
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(OrchestratorEffect.NavigateToLogin)
                    clearActioning(result.error.message)
                }
                is ApiResult.NetworkError -> clearActioning(OFFLINE)
            }
        }
    }

    private suspend fun refetchStatusAfterAction(notice: String?) {
        when (val result = repo.status(workerId)) {
            is ApiResult.Success -> {
                val status = result.data
                if (status == null) _uiState.value = OrchestratorUiState.NoLoop
                else {
                    renderStatus(status, notice = notice)
                    fetchEligible()
                }
            }
            is ApiResult.Failure -> {
                if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(OrchestratorEffect.NavigateToLogin)
                clearActioning(result.error.message)
            }
            is ApiResult.NetworkError -> clearActioning(OFFLINE)
        }
    }

    private fun clearActioning(message: String?) {
        val current = _uiState.value as? OrchestratorUiState.Content ?: return
        _uiState.value = current.copy(actioning = null, actionError = message)
    }

    companion object {
        const val ARG_WORKER_ID = "workerId"
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
