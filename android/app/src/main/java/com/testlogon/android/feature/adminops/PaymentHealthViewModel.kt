package com.testlogon.android.feature.adminops

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminops.PaymentHealthData
import com.testlogon.android.data.adminops.PaymentHealthRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed interface PaymentHealthUiState {
    data object Loading : PaymentHealthUiState
    data class Content(
        val data: PaymentHealthData,
        val isRefreshing: Boolean = false,
        val transientError: AdminOpsErrorType? = null,
    ) : PaymentHealthUiState
    data object Forbidden : PaymentHealthUiState
    data class Error(val type: AdminOpsErrorType) : PaymentHealthUiState
}

@HiltViewModel
class PaymentHealthViewModel @Inject constructor(
    private val repo: PaymentHealthRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<PaymentHealthUiState>(PaymentHealthUiState.Loading)
    val state: StateFlow<PaymentHealthUiState> = _state.asStateFlow()

    init {
        load(resetLoading = true, isRefresh = false)
    }

    fun retry() = load(resetLoading = true, isRefresh = false)

    fun refresh() {
        (_state.value as? PaymentHealthUiState.Content)?.let {
            _state.value = it.copy(isRefreshing = true, transientError = null)
        }
        load(resetLoading = false, isRefresh = true)
    }

    private fun load(resetLoading: Boolean, isRefresh: Boolean) {
        if (resetLoading) _state.value = PaymentHealthUiState.Loading
        viewModelScope.launch {
            when (val r = repo.load()) {
                is ApiResult.Success -> _state.value = PaymentHealthUiState.Content(r.data)
                is ApiResult.Failure ->
                    if (r.error.status == 403) _state.value = PaymentHealthUiState.Forbidden
                    else reduceError(isRefresh, adminOpsErrorFor(r.error.status))
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? PaymentHealthUiState.Content
        _state.value = if (isRefresh && prior != null) prior.copy(isRefreshing = false, transientError = type)
        else PaymentHealthUiState.Error(type)
    }
}
