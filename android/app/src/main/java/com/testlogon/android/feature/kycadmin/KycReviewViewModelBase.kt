package com.testlogon.android.feature.kycadmin

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Base ViewModel for the document-shaped KYC-admin review queues. Subclasses supply the three suspend
 * hooks (load-by-status, load-detail, decide). Keeps the list+detail+decision state machine + the
 * uniform 403->Forbidden / 401->Auth / else->Server error mapping in one place.
 */
abstract class KycReviewViewModelBase(initialStatus: String) : ViewModel() {

    private val _state = MutableStateFlow(KycReviewUiState(statusFilter = initialStatus))
    val state: StateFlow<KycReviewUiState> = _state.asStateFlow()

    /** Fetch the queue for [status]; map each row to a [KycReviewItemUi]. */
    protected abstract suspend fun loadList(status: String): ApiResult<List<KycReviewItemUi>>

    /** Fetch a single item's detail. */
    protected abstract suspend fun loadDetail(id: String): ApiResult<KycReviewDetailUi>

    /** Perform the decision; return the (possibly-updated) detail or Unit-carrying result. */
    protected abstract suspend fun decide(id: String, decision: String, note: String): ApiResult<*>

    protected fun start() = fetchList(false)

    fun retry() = fetchList(false)

    fun setStatus(status: String) {
        if (_state.value.statusFilter == status) return
        _state.value = _state.value.copy(statusFilter = status, list = KycReviewListState.Loading)
        fetchList(false)
    }

    fun refresh() {
        val cur = _state.value.list
        _state.value = _state.value.copy(
            list = if (cur is KycReviewListState.Data) cur.copy(isRefreshing = true) else cur,
            transientError = null,
        )
        fetchList(true)
    }

    private fun fetchList(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = loadList(_state.value.statusFilter)) {
                is ApiResult.Success -> {
                    val items = r.data
                    _state.value = _state.value.copy(
                        list = if (items.isEmpty()) KycReviewListState.Empty else KycReviewListState.Data(items),
                    )
                }
                is ApiResult.Failure -> applyListFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> applyListError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun applyListFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = _state.value.copy(list = KycReviewListState.Forbidden)
        401 -> applyListError(isRefresh, AdminOpsErrorType.AUTH)
        else -> applyListError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun applyListError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val cur = _state.value
        val data = cur.list as? KycReviewListState.Data
        _state.value = if (isRefresh && data != null) {
            cur.copy(list = data.copy(isRefreshing = false), transientError = type)
        } else {
            cur.copy(list = KycReviewListState.Error(type))
        }
    }

    fun openDetail(id: String) {
        _state.value = _state.value.copy(detail = KycReviewDetailState.Loading)
        viewModelScope.launch {
            _state.value = _state.value.copy(
                detail = when (val r = loadDetail(id)) {
                    is ApiResult.Success -> KycReviewDetailState.Data(r.data)
                    is ApiResult.Failure -> if (r.error.status == 403) KycReviewDetailState.Forbidden
                    else KycReviewDetailState.Error(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                    is ApiResult.NetworkError -> KycReviewDetailState.Error(AdminOpsErrorType.NETWORK)
                },
            )
        }
    }

    fun submitDecision(id: String, decision: String, note: String) {
        if (_state.value.actionInFlight) return
        _state.value = _state.value.copy(actionInFlight = true, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = decide(id, decision, note)) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(actionInFlight = false, message = "Decision submitted: ${decision.replace('_', ' ')}")
                    openDetail(id)
                    refresh()
                }
                is ApiResult.Failure -> _state.value = _state.value.copy(
                    actionInFlight = false,
                    transientError = if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER,
                )
                is ApiResult.NetworkError -> _state.value = _state.value.copy(actionInFlight = false, transientError = AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun closeDetail() { _state.value = _state.value.copy(detail = null) }
    fun clearMessage() { _state.value = _state.value.copy(message = null, transientError = null) }
}
