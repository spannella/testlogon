package com.testlogon.android.feature.agents.workers.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.agents.workers.data.WorkersRepository
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
 * AGENTS-BASICS (web-parity) - drives the WORKERS LIST. A single GET loads the caller's workers; pull-to-refresh
 * re-reads. Per-row start/stop actions set an [WorkersListUiState.Content.actioningId] flag and re-load on
 * success. A terminal 401 -> [WorkersEffect.NavigateToLogin]. No poll loop.
 */
@HiltViewModel
class WorkersListViewModel @Inject constructor(
    private val repo: WorkersRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<WorkersListUiState>(WorkersListUiState.Loading)
    val uiState: StateFlow<WorkersListUiState> = _uiState.asStateFlow()

    private val _effects = Channel<WorkersEffect>(Channel.BUFFERED)
    val effects: Flow<WorkersEffect> = _effects.receiveAsFlow()

    private var loadJob: Job? = null

    init { load() }

    fun load() {
        if (loadJob?.isActive == true) return
        _uiState.value = WorkersListUiState.Loading
        fetch(isRefresh = false)
    }

    fun onRetry() = load()

    fun refresh() {
        if (loadJob?.isActive == true) return
        (_uiState.value as? WorkersListUiState.Content)?.let {
            _uiState.value = it.copy(isRefreshing = true)
        }
        fetch(isRefresh = true)
    }

    private fun fetch(isRefresh: Boolean) {
        loadJob = viewModelScope.launch {
            when (val result = repo.list()) {
                is ApiResult.Success -> {
                    _uiState.value = if (result.data.isEmpty()) {
                        WorkersListUiState.Empty
                    } else {
                        WorkersListUiState.Content(items = result.data)
                    }
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _effects.send(WorkersEffect.NavigateToLogin)
                        clearRefreshing()
                    } else {
                        emitFailure(isRefresh, result.error.message)
                    }
                }
                is ApiResult.NetworkError -> emitFailure(isRefresh, OFFLINE)
            }
        }
    }

    fun start(workerId: String) = act(workerId) { repo.start(workerId) }
    fun stop(workerId: String) = act(workerId) { repo.stop(workerId) }

    private fun act(workerId: String, block: suspend () -> ApiResult<*>) {
        val current = _uiState.value as? WorkersListUiState.Content ?: return
        if (current.actioningId != null) return
        _uiState.value = current.copy(actioningId = workerId, actionError = null)
        viewModelScope.launch {
            when (val result = block()) {
                is ApiResult.Success -> {
                    // Re-read the list so the row reflects the new lifecycle status.
                    when (val reload = repo.list()) {
                        is ApiResult.Success ->
                            _uiState.value = if (reload.data.isEmpty()) {
                                WorkersListUiState.Empty
                            } else {
                                WorkersListUiState.Content(items = reload.data)
                            }
                        else -> clearActioning(null)
                    }
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(WorkersEffect.NavigateToLogin)
                    clearActioning(result.error.message)
                }
                is ApiResult.NetworkError -> clearActioning(OFFLINE)
            }
        }
    }

    private fun clearActioning(message: String?) {
        val current = _uiState.value as? WorkersListUiState.Content ?: return
        _uiState.value = current.copy(actioningId = null, actionError = message)
    }

    private fun emitFailure(isRefresh: Boolean, message: String) {
        val prior = _uiState.value as? WorkersListUiState.Content
        _uiState.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, actionError = message)
        } else {
            WorkersListUiState.Error(message)
        }
    }

    private fun clearRefreshing() {
        (_uiState.value as? WorkersListUiState.Content)?.let {
            _uiState.value = it.copy(isRefreshing = false)
        }
    }

    private companion object {
        const val HTTP_UNAUTHORIZED = 401
        const val OFFLINE = "Couldn't reach the server. Pull down to retry."
    }
}
