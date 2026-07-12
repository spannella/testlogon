package com.testlogon.android.feature.kycadmin

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.kycadmin.KycLivenessAdminRepository
import com.testlogon.android.data.kycadmin.KycLivenessDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** A5 — liveness-call verifier queue (list + detail with conduct / record-result / cancel / join). */

val KYC_LIVENESS_STATUSES = listOf("scheduled", "in_progress", "passed", "failed", "cancelled", "expired")

sealed interface LivenessListState {
    data object Loading : LivenessListState
    data class Data(val calls: List<KycLivenessDto>, val isRefreshing: Boolean = false) : LivenessListState
    data object Empty : LivenessListState
    data object Forbidden : LivenessListState
    data class Error(val type: AdminOpsErrorType) : LivenessListState
}

sealed interface LivenessDetailState {
    data object Loading : LivenessDetailState
    data class Data(val call: KycLivenessDto) : LivenessDetailState
    data object Forbidden : LivenessDetailState
    data class Error(val type: AdminOpsErrorType) : LivenessDetailState
}

data class KycLivenessAdminUiState(
    val statusFilter: String = "scheduled",
    val list: LivenessListState = LivenessListState.Loading,
    val detail: LivenessDetailState? = null,
    val actionInFlight: Boolean = false,
    val message: String? = null,
    val transientError: AdminOpsErrorType? = null,
)

@HiltViewModel
class KycLivenessAdminViewModel @Inject constructor(
    private val repo: KycLivenessAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(KycLivenessAdminUiState())
    val state: StateFlow<KycLivenessAdminUiState> = _state.asStateFlow()

    init { fetchList(false) }

    fun retry() = fetchList(false)

    fun setStatus(status: String) {
        if (_state.value.statusFilter == status) return
        _state.value = _state.value.copy(statusFilter = status, list = LivenessListState.Loading)
        fetchList(false)
    }

    fun refresh() {
        val cur = _state.value.list
        _state.value = _state.value.copy(list = if (cur is LivenessListState.Data) cur.copy(isRefreshing = true) else cur, transientError = null)
        fetchList(true)
    }

    private fun fetchList(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.byStatus(_state.value.statusFilter)) {
                is ApiResult.Success -> {
                    val calls = r.data
                    _state.value = _state.value.copy(list = if (calls.isEmpty()) LivenessListState.Empty else LivenessListState.Data(calls))
                }
                is ApiResult.Failure -> _state.value = _state.value.copy(
                    list = when (r.error.status) {
                        403 -> LivenessListState.Forbidden
                        else -> (_state.value.list as? LivenessListState.Data)?.takeIf { isRefresh }?.copy(isRefreshing = false)
                            ?: LivenessListState.Error(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                    },
                    transientError = if (isRefresh && _state.value.list is LivenessListState.Data)
                        (if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER) else null,
                )
                is ApiResult.NetworkError -> _state.value = _state.value.copy(
                    list = (_state.value.list as? LivenessListState.Data)?.takeIf { isRefresh }?.copy(isRefreshing = false)
                        ?: LivenessListState.Error(AdminOpsErrorType.NETWORK),
                    transientError = if (isRefresh && _state.value.list is LivenessListState.Data) AdminOpsErrorType.NETWORK else null,
                )
            }
        }
    }

    fun openDetail(callId: String) {
        _state.value = _state.value.copy(detail = LivenessDetailState.Loading)
        viewModelScope.launch {
            _state.value = _state.value.copy(
                detail = when (val r = repo.detail(callId)) {
                    is ApiResult.Success -> LivenessDetailState.Data(r.data)
                    is ApiResult.Failure -> if (r.error.status == 403) LivenessDetailState.Forbidden
                    else LivenessDetailState.Error(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                    is ApiResult.NetworkError -> LivenessDetailState.Error(AdminOpsErrorType.NETWORK)
                },
            )
        }
    }

    fun conduct(callId: String) = action(callId, "Call marked in progress") { repo.conduct(callId) }
    fun cancel(callId: String) = action(callId, "Call cancelled") { repo.cancel(callId) }
    fun recordResult(callId: String, result: String, notes: String) =
        action(callId, "Result recorded: $result") { repo.result(callId, result, notes) }

    private fun action(callId: String, successMsg: String, block: suspend () -> ApiResult<KycLivenessDto>) {
        if (_state.value.actionInFlight) return
        _state.value = _state.value.copy(actionInFlight = true, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(actionInFlight = false, message = successMsg, detail = LivenessDetailState.Data(r.data))
                    fetchList(true)
                }
                is ApiResult.Failure -> _state.value = _state.value.copy(actionInFlight = false, transientError = if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> _state.value = _state.value.copy(actionInFlight = false, transientError = AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun closeDetail() { _state.value = _state.value.copy(detail = null) }
    fun clearMessage() { _state.value = _state.value.copy(message = null, transientError = null) }
}
