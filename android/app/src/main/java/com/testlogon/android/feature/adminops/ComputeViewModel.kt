package com.testlogon.android.feature.adminops

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminops.ComputeDashboardData
import com.testlogon.android.data.adminops.ComputeRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed interface ComputeUiState {
    data object Loading : ComputeUiState
    data class Content(
        val data: ComputeDashboardData,
        val isRefreshing: Boolean = false,
        val transientError: AdminOpsErrorType? = null,
    ) : ComputeUiState
    data object Forbidden : ComputeUiState
    data class Error(val type: AdminOpsErrorType) : ComputeUiState
}

@HiltViewModel
class ComputeViewModel @Inject constructor(
    private val repo: ComputeRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<ComputeUiState>(ComputeUiState.Loading)
    val state: StateFlow<ComputeUiState> = _state.asStateFlow()

    init { load(resetLoading = true, isRefresh = false) }

    fun retry() = load(resetLoading = true, isRefresh = false)

    fun refresh() {
        (_state.value as? ComputeUiState.Content)?.let {
            _state.value = it.copy(isRefreshing = true, transientError = null)
        }
        load(resetLoading = false, isRefresh = true)
    }

    private fun load(resetLoading: Boolean, isRefresh: Boolean) {
        if (resetLoading) _state.value = ComputeUiState.Loading
        viewModelScope.launch {
            when (val r = repo.load()) {
                is ApiResult.Success -> _state.value = ComputeUiState.Content(r.data)
                is ApiResult.Failure ->
                    if (r.error.status == 403) _state.value = ComputeUiState.Forbidden
                    else reduceError(isRefresh, adminOpsErrorFor(r.error.status))
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? ComputeUiState.Content
        _state.value = if (isRefresh && prior != null) prior.copy(isRefreshing = false, transientError = type)
        else ComputeUiState.Error(type)
    }
}
