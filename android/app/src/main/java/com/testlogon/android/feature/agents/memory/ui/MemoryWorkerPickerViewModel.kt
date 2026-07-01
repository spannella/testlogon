package com.testlogon.android.feature.agents.memory.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.agents.workers.data.Worker
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

/** UI state for the memory worker-picker (there is no agent-types registry; a worker is the memory owner). */
sealed interface MemoryWorkerPickerUiState {
    data object Loading : MemoryWorkerPickerUiState
    data class Content(val workers: List<Worker>) : MemoryWorkerPickerUiState
    data object Empty : MemoryWorkerPickerUiState
    data class Error(val message: String) : MemoryWorkerPickerUiState
}

sealed interface MemoryPickerEffect {
    data object NavigateToLogin : MemoryPickerEffect
}

/**
 * AGENTS-BASICS (web-parity) - the worker picker that feeds the per-worker MEMORY screen. Web reaches
 * /agents/memory/:workerId from a worker context; the mobile client has no such context, so this lists the
 * caller's workers (reusing [WorkersRepository]) and each row opens memory for that workerId.
 */
@HiltViewModel
class MemoryWorkerPickerViewModel @Inject constructor(
    private val workers: WorkersRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<MemoryWorkerPickerUiState>(MemoryWorkerPickerUiState.Loading)
    val uiState: StateFlow<MemoryWorkerPickerUiState> = _uiState.asStateFlow()

    private val _effects = Channel<MemoryPickerEffect>(Channel.BUFFERED)
    val effects: Flow<MemoryPickerEffect> = _effects.receiveAsFlow()

    init { load() }

    fun load() {
        _uiState.value = MemoryWorkerPickerUiState.Loading
        viewModelScope.launch {
            when (val result = workers.list()) {
                is ApiResult.Success ->
                    _uiState.value = if (result.data.isEmpty()) MemoryWorkerPickerUiState.Empty
                    else MemoryWorkerPickerUiState.Content(result.data)
                is ApiResult.Failure -> {
                    if (result.error.status == 401) _effects.send(MemoryPickerEffect.NavigateToLogin)
                    _uiState.value = MemoryWorkerPickerUiState.Error(result.error.message)
                }
                is ApiResult.NetworkError ->
                    _uiState.value = MemoryWorkerPickerUiState.Error("Couldn't reach the server. Tap retry.")
            }
        }
    }

    fun onRetry() = load()
}
