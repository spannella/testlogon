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
 * WFL — presentation logic for the SuiteCRM Workflow admin list/read MVP. READ ONLY: [load] / [refresh]
 * read the rule list ONCE (no poll loop, no writes). DEGRADE-ON-404/403 handled by [foldRulesResult].
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

    private fun fetch(showRefreshing: Boolean) {
        loadJob?.cancel()
        loadJob = viewModelScope.launch {
            when (val result = repository.listRules()) {
                is ApiResult.Success -> _uiState.value = foldRulesResult(result.data, null)
                is ApiResult.Failure -> _uiState.value = foldRulesResult(null, result.error)
                is ApiResult.NetworkError ->
                    _uiState.value =
                        foldRulesResult(null, ApiError(ApiError.STATUS_NETWORK, NETWORK_MESSAGE))
            }
        }
    }

    private companion object {
        const val NETWORK_MESSAGE = "Couldn't reach the server. Try again."
    }
}
