package com.testlogon.android.feature.workflow

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * WFL — presentation logic for the SuiteCRM Workflow admin rules list + mutations. [load] / [refresh]
 * read the rule list; [enable] / [disable] / [delete] mutate then re-read; [createRule] posts a new rule
 * then re-reads. DEGRADE-ON-404/403 handled by [foldRulesResult]. No poll loop.
 */
@HiltViewModel
class WorkflowRulesViewModel @Inject constructor(
    private val repository: WorkflowRulesRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<WorkflowRulesUiState>(WorkflowRulesUiState.Loading)
    val uiState: StateFlow<WorkflowRulesUiState> = _uiState.asStateFlow()

    private var loadJob: Job? = null

    init {
        load()
    }

    fun load() {
        if (_uiState.value !is WorkflowRulesUiState.Content) {
            _uiState.value = WorkflowRulesUiState.Loading
        }
        fetch(showRefreshing = false)
    }

    fun refresh() {
        (_uiState.value as? WorkflowRulesUiState.Content)?.let {
            _uiState.value = it.copy(isRefreshing = true)
        }
        fetch(showRefreshing = true)
    }

    private fun fetch(showRefreshing: Boolean, message: String? = null) {
        loadJob?.cancel()
        loadJob = viewModelScope.launch {
            when (val result = repository.listRules()) {
                is ApiResult.Success -> _uiState.value = applyMessage(foldRulesResult(result.data, null), message)
                is ApiResult.Failure -> _uiState.value = foldRulesResult(null, result.error)
                is ApiResult.NetworkError ->
                    _uiState.value =
                        foldRulesResult(null, ApiError(ApiError.STATUS_NETWORK, NETWORK_MESSAGE))
            }
        }
    }

    /** Toggle a rule's enabled state (enable when currently disabled, disable otherwise), then re-read. */
    fun toggleEnabled(rule: WorkflowRule) {
        val target = WorkflowRuleMath.nextEnabledState(rule.enabled)
        setBusy(rule.ruleId)
        viewModelScope.launch {
            val result = if (target) repository.enableRule(rule.ruleId) else repository.disableRule(rule.ruleId)
            afterMutation(result, if (target) "Rule enabled" else "Rule disabled")
        }
    }

    /** Delete a rule then re-read. */
    fun delete(ruleId: String) {
        setBusy(ruleId)
        viewModelScope.launch {
            afterMutation(repository.deleteRule(ruleId), "Rule deleted")
        }
    }

    /** Create a rule from the lightweight form, then re-read. onDone is invoked on success. */
    fun createRule(
        name: String,
        description: String,
        targetModule: WorkflowTargetModule,
        triggerType: WorkflowTriggerType,
        enabled: Boolean,
        onDone: () -> Unit,
    ) {
        viewModelScope.launch {
            val body = buildRuleCreateRequest(name, description, targetModule, triggerType, enabled)
            when (repository.createRule(body)) {
                is ApiResult.Success -> {
                    onDone()
                    fetch(showRefreshing = false, message = "Rule created")
                }
                is ApiResult.Failure, is ApiResult.NetworkError -> onDone()
            }
        }
    }

    fun consumeMessage() {
        (_uiState.value as? WorkflowRulesUiState.Content)?.let {
            if (it.message != null) _uiState.value = it.copy(message = null)
        }
    }

    private fun setBusy(ruleId: String?) {
        (_uiState.value as? WorkflowRulesUiState.Content)?.let {
            _uiState.value = it.copy(busyRuleId = ruleId)
        }
    }

    private fun afterMutation(result: ApiResult<*>, successMessage: String) {
        when (result) {
            is ApiResult.Success -> fetch(showRefreshing = false, message = successMessage)
            is ApiResult.Failure, is ApiResult.NetworkError -> setBusy(null)
        }
    }

    private fun applyMessage(state: WorkflowRulesUiState, message: String?): WorkflowRulesUiState =
        if (message != null && state is WorkflowRulesUiState.Content) state.copy(message = message) else state

    private companion object {
        const val NETWORK_MESSAGE = "Couldn't reach the server. Try again."
    }
}

/** WFL — presentation logic for a single rule's run history (read-only). */
@HiltViewModel
class WorkflowRunsViewModel @Inject constructor(
    private val repository: WorkflowRulesRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<WorkflowRunsUiState>(WorkflowRunsUiState.Loading)
    val uiState: StateFlow<WorkflowRunsUiState> = _uiState.asStateFlow()

    fun load(ruleId: String) {
        _uiState.value = WorkflowRunsUiState.Loading
        viewModelScope.launch {
            _uiState.value = when (val result = repository.listRuleRuns(ruleId)) {
                is ApiResult.Success -> foldRunsResult(result.data, null)
                is ApiResult.Failure -> foldRunsResult(null, result.error)
                is ApiResult.NetworkError ->
                    foldRunsResult(null, ApiError(ApiError.STATUS_NETWORK, "Couldn't reach the server."))
            }
        }
    }
}

/** WFL — presentation logic for the drip-sequence list + create. */
@HiltViewModel
class DripSequencesViewModel @Inject constructor(
    private val repository: WorkflowRulesRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<DripSequencesUiState>(DripSequencesUiState.Loading)
    val uiState: StateFlow<DripSequencesUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun load(message: String? = null) {
        if (_uiState.value !is DripSequencesUiState.Content) {
            _uiState.value = DripSequencesUiState.Loading
        }
        viewModelScope.launch {
            _uiState.value = when (val result = repository.listDripSequences()) {
                is ApiResult.Success -> applyMessage(foldDripResult(result.data, null), message)
                is ApiResult.Failure -> foldDripResult(null, result.error)
                is ApiResult.NetworkError ->
                    foldDripResult(null, ApiError(ApiError.STATUS_NETWORK, "Couldn't reach the server."))
            }
        }
    }

    fun createSequence(name: String, description: String, stages: List<DripStage>, onDone: () -> Unit) {
        viewModelScope.launch {
            when (repository.createDripSequence(buildDripCreateRequest(name, description, stages))) {
                is ApiResult.Success -> {
                    onDone()
                    load(message = "Drip sequence created")
                }
                is ApiResult.Failure, is ApiResult.NetworkError -> onDone()
            }
        }
    }

    fun consumeMessage() {
        (_uiState.value as? DripSequencesUiState.Content)?.let {
            if (it.message != null) _uiState.value = it.copy(message = null)
        }
    }

    private fun applyMessage(state: DripSequencesUiState, message: String?): DripSequencesUiState =
        if (message != null && state is DripSequencesUiState.Content) state.copy(message = message) else state
}
