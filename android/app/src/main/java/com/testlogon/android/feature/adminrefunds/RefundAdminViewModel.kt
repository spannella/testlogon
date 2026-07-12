package com.testlogon.android.feature.adminrefunds

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminrefunds.RefundAdminRepository
import com.testlogon.android.data.adminrefunds.RefundRequestDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import kotlinx.coroutines.launch

/**
 * B5 - admin refund-requests queue. A status-filtered list with approve/reject per request. Mirrors
 * /admin/refunds (AdminRefundQueuePage.tsx). A backend 403 -> Forbidden.
 */
sealed interface RefundAdminUiState {
    data object Loading : RefundAdminUiState
    data class Content(
        val requests: List<RefundRequestDto>,
        val statusFilter: String,
        val isRefreshing: Boolean = false,
        val actionInFlightId: String? = null,
        val message: String? = null,
        val transientError: AdminOpsErrorType? = null,
    ) : RefundAdminUiState
    data class Empty(val statusFilter: String) : RefundAdminUiState
    data object Forbidden : RefundAdminUiState
    data class Error(val type: AdminOpsErrorType) : RefundAdminUiState
}

/** The queue statuses the board filters on (mirrors the web queue tabs). */
val REFUND_STATUS_FILTERS: List<String> = listOf("pending", "approved", "rejected")

@HiltViewModel
class RefundAdminViewModel @Inject constructor(
    private val repo: RefundAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<RefundAdminUiState>(RefundAdminUiState.Loading)
    val state: StateFlow<RefundAdminUiState> = _state.asStateFlow()

    private var currentFilter: String = REFUND_STATUS_FILTERS.first()

    init {
        load(currentFilter)
    }

    fun retry() = load(currentFilter)

    fun setFilter(status: String) {
        currentFilter = status
        load(status)
    }

    fun refresh() {
        val cur = _state.value
        if (cur is RefundAdminUiState.Content) _state.value = cur.copy(isRefreshing = true, transientError = null)
        fetch(currentFilter, isRefresh = true)
    }

    private fun load(status: String) {
        currentFilter = status
        _state.value = RefundAdminUiState.Loading
        fetch(status, isRefresh = false)
    }

    private fun fetch(status: String, isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.list(status)) {
                is ApiResult.Success -> {
                    val items = r.data.items
                    _state.value = if (items.isEmpty()) RefundAdminUiState.Empty(status)
                    else RefundAdminUiState.Content(requests = items, statusFilter = status)
                }
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun approve(requestId: String, notes: String?, amountCents: Long?) {
        runAction(requestId) {
            when (val r = repo.approve(requestId, notes, amountCents)) {
                is ApiResult.Success -> ActionResult.Success(r.data.status, "Approved")
                is ApiResult.Failure -> ActionResult.Failure(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> ActionResult.Failure(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun reject(requestId: String, notes: String) {
        runAction(requestId) {
            when (val r = repo.reject(requestId, notes)) {
                is ApiResult.Success -> ActionResult.Success(r.data.status, "Rejected")
                is ApiResult.Failure -> ActionResult.Failure(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> ActionResult.Failure(AdminOpsErrorType.NETWORK)
            }
        }
    }

    private sealed interface ActionResult {
        data class Success(val newStatus: String, val label: String) : ActionResult
        data class Failure(val type: AdminOpsErrorType) : ActionResult
    }

    private fun runAction(requestId: String, block: suspend () -> ActionResult) {
        val cur = _state.value
        if (cur !is RefundAdminUiState.Content || cur.actionInFlightId != null) return
        _state.value = cur.copy(actionInFlightId = requestId, transientError = null, message = null)
        viewModelScope.launch {
            when (val res = block()) {
                is ActionResult.Success -> {
                    val prev = _state.value as? RefundAdminUiState.Content ?: return@launch
                    val updated = prev.requests.map {
                        if (it.refundRequestId == requestId) it.copy(status = res.newStatus) else it
                    }
                    _state.value = prev.copy(requests = updated, actionInFlightId = null, message = "${res.label} refund")
                }
                is ActionResult.Failure -> {
                    val prev = _state.value as? RefundAdminUiState.Content ?: return@launch
                    _state.value = prev.copy(actionInFlightId = null, transientError = res.type)
                }
            }
        }
    }

    fun clearMessage() {
        val cur = _state.value
        if (cur is RefundAdminUiState.Content) _state.value = cur.copy(message = null, transientError = null)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = RefundAdminUiState.Forbidden
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? RefundAdminUiState.Content
        _state.value = if (isRefresh && prior != null) prior.copy(isRefreshing = false, transientError = type)
        else RefundAdminUiState.Error(type)
    }
}
