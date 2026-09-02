package com.testlogon.android.feature.agents.run.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.agentrun.AgentRunMath
import com.testlogon.android.data.agentrun.AgentRunRepository
import com.testlogon.android.data.agentrun.AgentRunType
import com.testlogon.android.data.agentrun.PmOperation
import com.testlogon.android.data.agentrun.RunEvent
import com.testlogon.android.data.agentrun.RunState
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
 * AGENT-RUN (web-parity) - drives the generic agent-run console. Reads {type,typeId} from the nav args, then
 * exposes the eligible-tickets -> claim -> execute -> view output/report/metrics lifecycle over
 * [AgentRunRepository]. DevOps additionally exposes approve/reject. State transitions go through the PURE
 * [AgentRunMath.nextState] machine so the UI can never issue an illegal control. Degrade-on-404 (output/report
 * absent -> a neutral "no output yet" rather than an error). Terminal 401 -> [AgentRunEffect.NavigateToLogin];
 * a 403 on the initial load -> [AgentRunUiState.Forbidden] (operator-only). No poll loops.
 */
@HiltViewModel
class AgentRunConsoleViewModel @Inject constructor(
    private val repo: AgentRunRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val type: AgentRunType =
        AgentRunType.from(savedStateHandle[ARG_TYPE]) ?: AgentRunType.CODER
    private val typeId: String =
        (savedStateHandle.get<String>(ARG_TYPE_ID)).orEmpty().ifBlank { type.typeName }

    private val _uiState = MutableStateFlow<AgentRunUiState>(AgentRunUiState.Loading)
    val uiState: StateFlow<AgentRunUiState> = _uiState.asStateFlow()

    private val _effects = Channel<AgentRunEffect>(Channel.BUFFERED)
    val effects: Flow<AgentRunEffect> = _effects.receiveAsFlow()

    private var loadJob: Job? = null

    init { load() }

    fun load() {
        if (loadJob?.isActive == true) return
        _uiState.value = AgentRunUiState.Loading
        loadJob = viewModelScope.launch {
            // PM/DOCS have no eligible-tickets queue; seed the console straight into IDLE with metrics.
            if (type == AgentRunType.PM || type == AgentRunType.DOCS) {
                _uiState.value = baseContent()
                loadMetricsInto()
                return@launch
            }
            when (val result = repo.eligibleTickets(type, typeId, limit = 20)) {
                is ApiResult.Success -> {
                    _uiState.value = baseContent().copy(eligibleTickets = result.data)
                    loadMetricsInto()
                }
                is ApiResult.Failure ->
                    if (result.error.status == HTTP_FORBIDDEN) {
                        _uiState.value = AgentRunUiState.Forbidden
                    } else {
                        if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(AgentRunEffect.NavigateToLogin)
                        _uiState.value = AgentRunUiState.Error(result.error.message)
                    }
                is ApiResult.NetworkError -> _uiState.value = AgentRunUiState.Error(OFFLINE)
            }
        }
    }

    fun onRetry() = load()

    fun selectTicket(ticketId: String) {
        val c = content() ?: return
        _uiState.value = c.copy(selectedTicketId = ticketId, message = null)
    }

    fun selectPmOperation(operation: PmOperation) {
        val c = content() ?: return
        _uiState.value = c.copy(pmOperation = operation, message = null)
    }

    /** Claim the selected ticket to a fresh run id. */
    fun claim() {
        val c = content() ?: return
        val ticketId = c.selectedTicketId ?: return
        if (c.busy) return
        val runId = AgentRunMath.buildRunId(type, System.currentTimeMillis())
        _uiState.value = c.copy(busy = true, message = null, runId = runId)
        viewModelScope.launch {
            when (val r = repo.claim(type, runId, ticketId)) {
                is ApiResult.Success -> transition(RunEvent.ClaimTicket) { it.copy(busy = false) }
                is ApiResult.Failure -> failAction(r.error.status, r.error.message)
                is ApiResult.NetworkError -> failAction(0, OFFLINE)
            }
        }
    }

    /** Execute (coder/qa/devops/architect) or run the PM operation. */
    fun execute() {
        val c = content() ?: return
        if (c.busy || !AgentRunMath.canExecute(c.runState, type)) return
        // Non-PM needs a claimed ticket (and a run id); PM executes to a fresh run id straight from IDLE.
        val ticketId = c.selectedTicketId.orEmpty()
        val runId = c.runId ?: AgentRunMath.buildRunId(type, System.currentTimeMillis())
        _uiState.value = transitionState(c.copy(busy = true, message = null, runId = runId), RunEvent.StartExecute)
        viewModelScope.launch {
            when (val r = repo.execute(type, typeId, runId, ticketId, c.pmOperation)) {
                is ApiResult.Success -> {
                    val out = r.data
                    _uiState.value = transitionState(
                        (content() ?: c).copy(busy = false, output = out, message = null),
                        RunEvent.ExecuteDone,
                        awaitingApproval = out.awaitingApproval,
                    )
                    if (type.hasReport) loadReport(runId)
                }
                is ApiResult.Failure -> failExecute(r.error.status, r.error.message)
                is ApiResult.NetworkError -> failExecute(0, OFFLINE)
            }
        }
    }

    /** Re-read the persisted output (degrade-on-404). */
    fun refreshOutput() {
        val c = content() ?: return
        val runId = c.runId ?: return
        if (c.busy) return
        _uiState.value = c.copy(busy = true, message = null)
        viewModelScope.launch {
            when (val r = repo.output(type, runId)) {
                is ApiResult.Success -> _uiState.value =
                    (content() ?: c).copy(
                        busy = false,
                        output = r.data,
                        message = if (r.data == null) "No output for this run yet." else null,
                    )
                is ApiResult.Failure -> failAction(r.error.status, r.error.message)
                is ApiResult.NetworkError -> failAction(0, OFFLINE)
            }
        }
    }

    fun loadMetrics() {
        val c = content() ?: return
        if (c.loadingMetrics) return
        _uiState.value = c.copy(loadingMetrics = true)
        viewModelScope.launch { loadMetricsInto() }
    }

    fun approve(notes: String?) = decide(approve = true, notes = notes)
    fun reject(notes: String?) = decide(approve = false, notes = notes)

    fun dismissMessage() {
        content()?.let { _uiState.value = it.copy(message = null) }
    }

    // ---- internals ----

    private fun decide(approve: Boolean, notes: String?) {
        val c = content() ?: return
        val runId = c.runId ?: return
        if (c.busy || !AgentRunMath.canDecide(c.runState, type)) return
        _uiState.value = c.copy(busy = true, message = null)
        viewModelScope.launch {
            when (val r = repo.decide(runId, approve, notes?.trim()?.ifBlank { null })) {
                is ApiResult.Success -> _uiState.value = transitionState(
                    (content() ?: c).copy(busy = false, decision = r.data),
                    if (approve) RunEvent.Approve else RunEvent.Reject,
                )
                is ApiResult.Failure -> failAction(r.error.status, r.error.message)
                is ApiResult.NetworkError -> failAction(0, OFFLINE)
            }
        }
    }

    private fun loadReport(runId: String) {
        viewModelScope.launch {
            val r = repo.report(runId)
            if (r is ApiResult.Success) {
                content()?.let { _uiState.value = it.copy(report = r.data) }
            }
        }
    }

    private suspend fun loadMetricsInto() {
        when (val r = repo.metrics(type, typeId, periodDays = 30)) {
            is ApiResult.Success -> content()?.let {
                _uiState.value = it.copy(metrics = r.data, loadingMetrics = false)
            }
            is ApiResult.Failure -> {
                if (r.error.status == HTTP_UNAUTHORIZED) _effects.send(AgentRunEffect.NavigateToLogin)
                content()?.let { _uiState.value = it.copy(loadingMetrics = false) }
            }
            is ApiResult.NetworkError -> content()?.let { _uiState.value = it.copy(loadingMetrics = false) }
        }
    }

    private fun failAction(status: Int, message: String) {
        if (status == HTTP_UNAUTHORIZED) viewModelScope.launch { _effects.send(AgentRunEffect.NavigateToLogin) }
        content()?.let { _uiState.value = it.copy(busy = false, message = message) }
    }

    private fun failExecute(status: Int, message: String) {
        if (status == HTTP_UNAUTHORIZED) viewModelScope.launch { _effects.send(AgentRunEffect.NavigateToLogin) }
        content()?.let { _uiState.value = transitionState(it.copy(busy = false, message = message), RunEvent.Error) }
    }

    private inline fun transition(event: RunEvent, transform: (AgentRunUiState.Content) -> AgentRunUiState.Content) {
        val c = content() ?: return
        _uiState.value = transitionState(transform(c), event)
    }

    private fun transitionState(
        c: AgentRunUiState.Content,
        event: RunEvent,
        awaitingApproval: Boolean = false,
    ): AgentRunUiState.Content =
        c.copy(runState = AgentRunMath.nextState(c.runState, event, awaitingApproval))

    private fun content(): AgentRunUiState.Content? = _uiState.value as? AgentRunUiState.Content

    private fun baseContent() = AgentRunUiState.Content(
        type = type,
        typeId = typeId,
        runState = RunState.IDLE,
    )

    companion object {
        const val ARG_TYPE = "type"
        const val ARG_TYPE_ID = "typeId"
        private const val HTTP_UNAUTHORIZED = 401
        private const val HTTP_FORBIDDEN = 403
        private const val OFFLINE = "Couldn't reach the server. Tap retry."
    }
}
