package com.testlogon.android.feature.agents.fleet.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.agents.fleet.data.FleetCapacity
import com.testlogon.android.feature.agents.fleet.data.FleetRepository
import com.testlogon.android.feature.agents.fleet.data.FleetStatus
import com.testlogon.android.feature.agents.fleet.data.WorkerTemplate
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
 * AGENTS-BASICS (web-parity) - drives the FLEET dashboard. Loads status + capacity + templates in parallel;
 * pull-to-refresh re-reads. Bulk start-all / stop-all + create-from-template + delete-template drive an action
 * flag and re-load status on success. A terminal 401 -> [FleetEffect.NavigateToLogin]. No poll loop.
 */
@HiltViewModel
class FleetViewModel @Inject constructor(
    private val repo: FleetRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<FleetUiState>(FleetUiState.Loading)
    val uiState: StateFlow<FleetUiState> = _uiState.asStateFlow()

    private val _effects = Channel<FleetEffect>(Channel.BUFFERED)
    val effects: Flow<FleetEffect> = _effects.receiveAsFlow()

    private var loadJob: Job? = null

    init { load() }

    fun load() {
        if (loadJob?.isActive == true) return
        _uiState.value = FleetUiState.Loading
        fetch()
    }

    fun onRetry() = load()

    fun refresh() {
        if (loadJob?.isActive == true) return
        (_uiState.value as? FleetUiState.Content)?.let {
            _uiState.value = it.copy(isRefreshing = true)
        }
        fetch()
    }

    private fun fetch() {
        loadJob = viewModelScope.launch {
            val statusResult = repo.status()
            if (statusResult is ApiResult.Failure && statusResult.error.status == HTTP_UNAUTHORIZED) {
                _effects.send(FleetEffect.NavigateToLogin)
            }
            val status: FleetStatus? = (statusResult as? ApiResult.Success)?.data
            if (status == null) {
                val msg = when (statusResult) {
                    is ApiResult.Failure -> statusResult.error.message
                    else -> OFFLINE
                }
                _uiState.value = FleetUiState.Error(msg)
                return@launch
            }
            val capacity: FleetCapacity? = (repo.capacity() as? ApiResult.Success)?.data
            val templates: List<WorkerTemplate> = (repo.templates() as? ApiResult.Success)?.data.orEmpty()
            _uiState.value = FleetUiState.Content(
                status = status,
                capacity = capacity,
                templates = templates,
            )
        }
    }

    fun startAll() = bulk { repo.startAll() }
    fun stopAll() = bulk { repo.stopAll() }

    private fun bulk(block: suspend () -> ApiResult<com.testlogon.android.feature.agents.fleet.data.BulkActionResult>) {
        val current = _uiState.value as? FleetUiState.Content ?: return
        if (current.bulkBusy) return
        _uiState.value = current.copy(bulkBusy = true, actionMessage = null, actionError = null)
        viewModelScope.launch {
            when (val result = block()) {
                is ApiResult.Success -> {
                    val r = result.data
                    val msg = "Acted on ${r.count} worker(s)" + if (r.errors.isNotEmpty()) ", ${r.errors.size} error(s)" else ""
                    reloadStatusThen(actionMessage = msg)
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(FleetEffect.NavigateToLogin)
                    clearBulk(result.error.message)
                }
                is ApiResult.NetworkError -> clearBulk(OFFLINE)
            }
        }
    }

    fun createFromTemplate(templateId: String) {
        val current = _uiState.value as? FleetUiState.Content ?: return
        if (current.busyTemplateId != null) return
        _uiState.value = current.copy(busyTemplateId = templateId, actionMessage = null, actionError = null)
        viewModelScope.launch {
            when (val result = repo.createFromTemplate(templateId)) {
                is ApiResult.Success -> reloadStatusThen(actionMessage = "Worker created from template")
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(FleetEffect.NavigateToLogin)
                    clearTemplateBusy(result.error.message)
                }
                is ApiResult.NetworkError -> clearTemplateBusy(OFFLINE)
            }
        }
    }

    fun deleteTemplate(templateId: String) {
        val current = _uiState.value as? FleetUiState.Content ?: return
        if (current.busyTemplateId != null) return
        _uiState.value = current.copy(busyTemplateId = templateId, actionMessage = null, actionError = null)
        viewModelScope.launch {
            when (val result = repo.deleteTemplate(templateId)) {
                is ApiResult.Success -> {
                    val now = _uiState.value as? FleetUiState.Content ?: return@launch
                    _uiState.value = now.copy(
                        templates = now.templates.filterNot { it.id == templateId },
                        busyTemplateId = null,
                        actionMessage = "Template deleted",
                    )
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(FleetEffect.NavigateToLogin)
                    clearTemplateBusy(result.error.message)
                }
                is ApiResult.NetworkError -> clearTemplateBusy(OFFLINE)
            }
        }
    }

    private suspend fun reloadStatusThen(actionMessage: String) {
        val status = (repo.status() as? ApiResult.Success)?.data
        val capacity = (repo.capacity() as? ApiResult.Success)?.data
        val templates = (repo.templates() as? ApiResult.Success)?.data
        val now = _uiState.value as? FleetUiState.Content ?: return
        _uiState.value = now.copy(
            status = status ?: now.status,
            capacity = capacity ?: now.capacity,
            templates = templates ?: now.templates,
            bulkBusy = false,
            busyTemplateId = null,
            actionMessage = actionMessage,
        )
    }

    private fun clearBulk(message: String?) {
        val current = _uiState.value as? FleetUiState.Content ?: return
        _uiState.value = current.copy(bulkBusy = false, actionError = message)
    }

    private fun clearTemplateBusy(message: String?) {
        val current = _uiState.value as? FleetUiState.Content ?: return
        _uiState.value = current.copy(busyTemplateId = null, actionError = message)
    }

    private companion object {
        const val HTTP_UNAUTHORIZED = 401
        const val OFFLINE = "Couldn't reach the server. Pull down to retry."
    }
}
