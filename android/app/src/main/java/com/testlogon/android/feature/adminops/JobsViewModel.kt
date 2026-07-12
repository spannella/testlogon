package com.testlogon.android.feature.adminops

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminops.JobsDashboardData
import com.testlogon.android.data.adminops.JobsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed interface JobsUiState {
    data object Loading : JobsUiState
    data class Content(
        val data: JobsDashboardData,
        val isRefreshing: Boolean = false,
        val transientError: AdminOpsErrorType? = null,
        val actionMessage: String? = null,
    ) : JobsUiState
    data object Forbidden : JobsUiState
    data class Error(val type: AdminOpsErrorType) : JobsUiState
}

@HiltViewModel
class JobsViewModel @Inject constructor(
    private val repo: JobsRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<JobsUiState>(JobsUiState.Loading)
    val state: StateFlow<JobsUiState> = _state.asStateFlow()

    init { load(resetLoading = true, isRefresh = false) }

    fun retry() = load(resetLoading = true, isRefresh = false)

    fun refresh() {
        (_state.value as? JobsUiState.Content)?.let {
            _state.value = it.copy(isRefreshing = true, transientError = null)
        }
        load(resetLoading = false, isRefresh = true)
    }

    fun retryJob(actionId: String, userSub: String) {
        val cur = _state.value as? JobsUiState.Content ?: return
        viewModelScope.launch {
            when (val r = repo.retry(actionId, userSub)) {
                is ApiResult.Success -> {
                    _state.value = cur.copy(actionMessage = "Rescheduled ${r.data.actionId}")
                    load(resetLoading = false, isRefresh = true)
                }
                is ApiResult.Failure -> _state.value = cur.copy(
                    transientError = if (r.error.status == 403) AdminOpsErrorType.AUTH else adminOpsErrorFor(r.error.status),
                )
                is ApiResult.NetworkError -> _state.value = cur.copy(transientError = AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun clearActionMessage() {
        (_state.value as? JobsUiState.Content)?.let {
            _state.value = it.copy(actionMessage = null, transientError = null)
        }
    }

    private fun load(resetLoading: Boolean, isRefresh: Boolean) {
        if (resetLoading) _state.value = JobsUiState.Loading
        viewModelScope.launch {
            when (val r = repo.load()) {
                is ApiResult.Success -> _state.value = JobsUiState.Content(r.data)
                is ApiResult.Failure ->
                    if (r.error.status == 403) _state.value = JobsUiState.Forbidden
                    else reduceError(isRefresh, adminOpsErrorFor(r.error.status))
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? JobsUiState.Content
        _state.value = if (isRefresh && prior != null) prior.copy(isRefreshing = false, transientError = type)
        else JobsUiState.Error(type)
    }
}
