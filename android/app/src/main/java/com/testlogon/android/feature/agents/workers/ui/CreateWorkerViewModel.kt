package com.testlogon.android.feature.agents.workers.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.agents.CreateWorkerRequest
import com.testlogon.android.feature.agents.llmkeys.data.LlmKeysRepository
import com.testlogon.android.feature.agents.workers.data.WorkersRepository
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
 * AGENTS-BASICS (web-parity) - drives the create-worker form. On init it loads the tools + compute options +
 * the caller's LLM keys (a worker REQUIRES an llm_key_id, so the form surfaces them as a picker; if none exist
 * the submit stays disabled and the screen hints to add one first). [submit] POSTs the create and emits
 * [WorkersEffect.CreateSucceeded] so the screen pops back and the list refreshes.
 */
@HiltViewModel
class CreateWorkerViewModel @Inject constructor(
    private val workersRepo: WorkersRepository,
    private val llmKeysRepo: LlmKeysRepository,
) : ViewModel() {

    private val _form = MutableStateFlow(CreateWorkerForm())
    val form: StateFlow<CreateWorkerForm> = _form.asStateFlow()

    private val _effects = Channel<WorkersEffect>(Channel.BUFFERED)
    val effects: Flow<WorkersEffect> = _effects.receiveAsFlow()

    init { loadOptions() }

    private fun loadOptions() {
        viewModelScope.launch {
            val tools = (workersRepo.tools() as? ApiResult.Success)?.data.orEmpty()
            val compute = (workersRepo.computeOptions() as? ApiResult.Success)?.data.orEmpty()
            val keys = (llmKeysRepo.list() as? ApiResult.Success)?.data.orEmpty()
            _form.value = _form.value.copy(
                tools = tools,
                computeOptions = compute,
                llmKeyOptions = keys.map { it.id to (it.label.ifBlank { it.provider }) },
                tool = _form.value.tool.ifBlank { tools.firstOrNull()?.tool.orEmpty() },
                computeType = _form.value.computeType.ifBlank { compute.firstOrNull()?.computeType.orEmpty() },
                instanceType = _form.value.instanceType.ifBlank { compute.firstOrNull()?.instanceType.orEmpty() },
                selectedLlmKeyId = _form.value.selectedLlmKeyId.ifBlank { keys.firstOrNull()?.id.orEmpty() },
                loadingOptions = false,
            )
        }
    }

    fun onLabelChange(v: String) { _form.value = _form.value.copy(label = v, submitError = null) }
    fun onAgentTypeChange(v: String) { _form.value = _form.value.copy(agentType = v) }
    fun onToolChange(v: String) { _form.value = _form.value.copy(tool = v) }
    fun onRepoUrlChange(v: String) { _form.value = _form.value.copy(repoUrl = v) }
    fun onLlmKeyChange(id: String) { _form.value = _form.value.copy(selectedLlmKeyId = id) }

    fun onComputeChange(computeType: String, instanceType: String) {
        _form.value = _form.value.copy(computeType = computeType, instanceType = instanceType)
    }

    fun submit() {
        val current = _form.value
        if (!current.canSubmit) return
        _form.value = current.copy(submitting = true, submitError = null)
        viewModelScope.launch {
            val request = CreateWorkerRequest(
                label = current.label.trim(),
                agentType = current.agentType,
                tool = current.tool,
                computeType = current.computeType,
                instanceType = current.instanceType,
                llmKeyId = current.selectedLlmKeyId,
                repoUrl = current.repoUrl.trim().ifBlank { null },
            )
            when (val result = workersRepo.create(request)) {
                is ApiResult.Success -> {
                    _form.value = _form.value.copy(submitting = false)
                    _effects.send(WorkersEffect.CreateSucceeded)
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _form.value = _form.value.copy(submitting = false)
                        _effects.send(WorkersEffect.NavigateToLogin)
                    } else {
                        _form.value = _form.value.copy(submitting = false, submitError = result.error.message)
                    }
                }
                is ApiResult.NetworkError ->
                    _form.value = _form.value.copy(submitting = false, submitError = OFFLINE)
            }
        }
    }

    companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
