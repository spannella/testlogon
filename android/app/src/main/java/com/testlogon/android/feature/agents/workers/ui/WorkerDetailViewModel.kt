package com.testlogon.android.feature.agents.workers.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
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
 * AGENTS-BASICS (web-parity) - drives the worker DETAIL screen (worker + embedded provision log + start/stop/
 * terminate). GET .../{id} carries the provision_log inline (there is no separate sessions endpoint - the worker
 * IS the runtime instance, and the provision log is its session/activity record). A terminate emits
 * [WorkersEffect.TerminateSucceeded] so the screen pops back to the list.
 */
@HiltViewModel
class WorkerDetailViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repo: WorkersRepository,
) : ViewModel() {

    private val workerId: String = savedStateHandle.get<String>(ARG_WORKER_ID).orEmpty()

    private val _uiState = MutableStateFlow<WorkerDetailUiState>(WorkerDetailUiState.Loading)
    val uiState: StateFlow<WorkerDetailUiState> = _uiState.asStateFlow()

    private val _effects = Channel<WorkersEffect>(Channel.BUFFERED)
    val effects: Flow<WorkersEffect> = _effects.receiveAsFlow()

    init { load() }

    fun load() {
        _uiState.value = WorkerDetailUiState.Loading
        fetch()
    }

    fun refresh() {
        (_uiState.value as? WorkerDetailUiState.Content)?.let {
            _uiState.value = it.copy(isRefreshing = true)
        }
        fetch()
    }

    private fun fetch() {
        viewModelScope.launch {
            when (val result = repo.get(workerId)) {
                is ApiResult.Success ->
                    _uiState.value = WorkerDetailUiState.Content(worker = result.data)
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(WorkersEffect.NavigateToLogin)
                    _uiState.value = WorkerDetailUiState.Error(result.error.message)
                }
                is ApiResult.NetworkError -> _uiState.value = WorkerDetailUiState.Error(OFFLINE)
            }
        }
    }

    fun start() = act { repo.start(workerId) }
    fun stop() = act { repo.stop(workerId) }

    fun terminate() {
        val current = _uiState.value as? WorkerDetailUiState.Content ?: return
        if (current.actioning) return
        _uiState.value = current.copy(actioning = true, actionError = null)
        viewModelScope.launch {
            when (val result = repo.terminate(workerId)) {
                is ApiResult.Success -> _effects.send(WorkersEffect.TerminateSucceeded)
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(WorkersEffect.NavigateToLogin)
                    clearActioning(result.error.message)
                }
                is ApiResult.NetworkError -> clearActioning(OFFLINE)
            }
        }
    }

    private fun act(block: suspend () -> ApiResult<*>) {
        val current = _uiState.value as? WorkerDetailUiState.Content ?: return
        if (current.actioning) return
        _uiState.value = current.copy(actioning = true, actionError = null)
        viewModelScope.launch {
            when (val result = block()) {
                is ApiResult.Success -> fetch()
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(WorkersEffect.NavigateToLogin)
                    clearActioning(result.error.message)
                }
                is ApiResult.NetworkError -> clearActioning(OFFLINE)
            }
        }
    }

    private fun clearActioning(message: String?) {
        val current = _uiState.value as? WorkerDetailUiState.Content ?: return
        _uiState.value = current.copy(actioning = false, actionError = message)
    }

    companion object {
        const val ARG_WORKER_ID = "workerId"
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
