package com.testlogon.android.feature.adminops

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminops.RateLimitsDashboardData
import com.testlogon.android.data.adminops.RateLimitsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed interface RateLimitsUiState {
    data object Loading : RateLimitsUiState
    data class Content(
        val data: RateLimitsDashboardData,
        val isRefreshing: Boolean = false,
        val transientError: AdminOpsErrorType? = null,
    ) : RateLimitsUiState
    data object Forbidden : RateLimitsUiState
    data class Error(val type: AdminOpsErrorType) : RateLimitsUiState
}

@HiltViewModel
class RateLimitsViewModel @Inject constructor(
    private val repo: RateLimitsRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<RateLimitsUiState>(RateLimitsUiState.Loading)
    val state: StateFlow<RateLimitsUiState> = _state.asStateFlow()

    init { load(resetLoading = true, isRefresh = false) }

    fun retry() = load(resetLoading = true, isRefresh = false)

    fun refresh() {
        (_state.value as? RateLimitsUiState.Content)?.let {
            _state.value = it.copy(isRefreshing = true, transientError = null)
        }
        load(resetLoading = false, isRefresh = true)
    }

    private fun load(resetLoading: Boolean, isRefresh: Boolean) {
        if (resetLoading) _state.value = RateLimitsUiState.Loading
        viewModelScope.launch {
            when (val r = repo.load()) {
                is ApiResult.Success -> _state.value = RateLimitsUiState.Content(r.data)
                is ApiResult.Failure ->
                    if (r.error.status == 403) _state.value = RateLimitsUiState.Forbidden
                    else reduceError(isRefresh, adminOpsErrorFor(r.error.status))
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? RateLimitsUiState.Content
        _state.value = if (isRefresh && prior != null) prior.copy(isRefreshing = false, transientError = type)
        else RateLimitsUiState.Error(type)
    }
}
