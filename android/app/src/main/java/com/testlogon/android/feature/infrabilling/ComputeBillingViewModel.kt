package com.testlogon.android.feature.infrabilling

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.infrabilling.ComputeBillingRepository
import com.testlogon.android.data.infrabilling.ComputeSpendSnapshot
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B7 Cloud-Infra: Compute billing / spend dashboard. Loads the monthly summary, resource breakdown,
 * ledger, and budget together; lets the user set a monthly budget. Mirrors ComputeSpendingPage.tsx.
 * 403 -> Forbidden.
 */
sealed interface BillingDataState {
    data object Loading : BillingDataState
    data class Content(val snapshot: ComputeSpendSnapshot, val isRefreshing: Boolean = false) : BillingDataState
    data object Forbidden : BillingDataState
    data class Error(val type: AdminOpsErrorType) : BillingDataState
}

data class BillingUiState(
    val data: BillingDataState = BillingDataState.Loading,
    val busy: Boolean = false,
    val message: String? = null,
    val transientError: AdminOpsErrorType? = null,
)

@HiltViewModel
class ComputeBillingViewModel @Inject constructor(
    private val repo: ComputeBillingRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(BillingUiState())
    val state: StateFlow<BillingUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun retry() = load()

    fun refresh() {
        val cur = _state.value
        if (cur.data is BillingDataState.Content) {
            _state.value = cur.copy(data = cur.data.copy(isRefreshing = true), transientError = null)
        }
        fetch(isRefresh = true)
    }

    private fun load() {
        _state.value = _state.value.copy(data = BillingDataState.Loading)
        fetch(isRefresh = false)
    }

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.snapshot()) {
                is ApiResult.Success -> _state.value = _state.value.copy(data = BillingDataState.Content(r.data))
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun setBudget(monthlyDollars: Double) {
        if (_state.value.busy) return
        val cents = (monthlyDollars * 100).toInt()
        if (cents < 100) return
        _state.value = _state.value.copy(busy = true, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.setBudget(cents)) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(busy = false, message = "Budget updated")
                    fetch(isRefresh = true)
                }
                is ApiResult.Failure -> _state.value = _state.value.copy(
                    busy = false,
                    transientError = if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER,
                )
                is ApiResult.NetworkError -> _state.value =
                    _state.value.copy(busy = false, transientError = AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun clearMessage() {
        _state.value = _state.value.copy(message = null, transientError = null)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = _state.value.copy(data = BillingDataState.Forbidden)
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val cur = _state.value
        val hasData = cur.data is BillingDataState.Content
        _state.value = if (isRefresh && hasData) {
            cur.copy(data = (cur.data as BillingDataState.Content).copy(isRefreshing = false), transientError = type)
        } else {
            cur.copy(data = BillingDataState.Error(type))
        }
    }
}
