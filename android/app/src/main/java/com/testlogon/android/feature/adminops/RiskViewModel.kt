package com.testlogon.android.feature.adminops

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminops.RiskDashboardData
import com.testlogon.android.data.adminops.RiskRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed interface RiskUiState {
    data object Loading : RiskUiState
    data class Content(
        val data: RiskDashboardData,
        val isRefreshing: Boolean = false,
        val transientError: AdminOpsErrorType? = null,
    ) : RiskUiState
    data object Forbidden : RiskUiState
    data class Error(val type: AdminOpsErrorType) : RiskUiState
}

@HiltViewModel
class RiskViewModel @Inject constructor(
    private val repo: RiskRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<RiskUiState>(RiskUiState.Loading)
    val state: StateFlow<RiskUiState> = _state.asStateFlow()

    init { load(resetLoading = true, isRefresh = false) }

    fun retry() = load(resetLoading = true, isRefresh = false)

    fun refresh() {
        (_state.value as? RiskUiState.Content)?.let {
            _state.value = it.copy(isRefreshing = true, transientError = null)
        }
        load(resetLoading = false, isRefresh = true)
    }

    private fun load(resetLoading: Boolean, isRefresh: Boolean) {
        if (resetLoading) _state.value = RiskUiState.Loading
        viewModelScope.launch {
            when (val r = repo.load()) {
                is ApiResult.Success -> _state.value = RiskUiState.Content(r.data)
                is ApiResult.Failure ->
                    if (r.error.status == 403) _state.value = RiskUiState.Forbidden
                    else reduceError(isRefresh, adminOpsErrorFor(r.error.status))
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? RiskUiState.Content
        _state.value = if (isRefresh && prior != null) prior.copy(isRefreshing = false, transientError = type)
        else RiskUiState.Error(type)
    }
}
