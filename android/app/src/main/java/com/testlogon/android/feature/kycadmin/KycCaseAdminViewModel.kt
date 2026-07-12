package com.testlogon.android.feature.kycadmin

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.kycadmin.KycCaseDetailDto
import com.testlogon.android.data.kycadmin.KycCaseAdminRepository
import com.testlogon.android.data.kycadmin.KycQueueItemDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** A1 — main KYC case review queue. Status filter, list, then a per-case detail with the decision actions. */

/** Statuses to filter the queue by (web KycQueuePage filter). "" == all. */
val KYC_CASE_STATUSES: List<String> = listOf("submitted", "in_review", "needs_more_info", "approved", "rejected")

/** Decision reason codes surfaced in the approve/reject dialog (illustrative common set). */
val KYC_DECISION_REASON_CODES: List<String> = listOf(
    "identity_verified", "documents_valid", "document_illegible", "name_mismatch",
    "expired_document", "suspected_fraud", "screening_hit",
)

sealed interface KycCaseListState {
    data object Loading : KycCaseListState
    data class Data(val items: List<KycQueueItemDto>, val isRefreshing: Boolean = false) : KycCaseListState
    data object Empty : KycCaseListState
    data object Forbidden : KycCaseListState
    data class Error(val type: AdminOpsErrorType) : KycCaseListState
}

sealed interface KycCaseDetailState {
    data object Loading : KycCaseDetailState
    data class Data(val case: KycCaseDetailDto) : KycCaseDetailState
    data object Forbidden : KycCaseDetailState
    data class Error(val type: AdminOpsErrorType) : KycCaseDetailState
}

data class KycCaseAdminUiState(
    val statusFilter: String = "submitted",
    val list: KycCaseListState = KycCaseListState.Loading,
    val detail: KycCaseDetailState? = null,
    val actionInFlight: Boolean = false,
    val message: String? = null,
    val transientError: AdminOpsErrorType? = null,
)

@HiltViewModel
class KycCaseAdminViewModel @Inject constructor(
    private val repo: KycCaseAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(KycCaseAdminUiState())
    val state: StateFlow<KycCaseAdminUiState> = _state.asStateFlow()

    init { loadList() }

    fun retry() = loadList()

    fun setStatusFilter(status: String) {
        if (_state.value.statusFilter == status) return
        _state.value = _state.value.copy(statusFilter = status, list = KycCaseListState.Loading)
        fetchList(false)
    }

    fun refresh() {
        val cur = _state.value.list
        _state.value = _state.value.copy(
            list = if (cur is KycCaseListState.Data) cur.copy(isRefreshing = true) else cur,
            transientError = null,
        )
        fetchList(true)
    }

    private fun loadList() {
        _state.value = _state.value.copy(list = KycCaseListState.Loading)
        fetchList(false)
    }

    private fun fetchList(isRefresh: Boolean) {
        viewModelScope.launch {
            val status = _state.value.statusFilter.ifBlank { null }
            when (val r = repo.queue(status)) {
                is ApiResult.Success -> {
                    val items = r.data.items
                    _state.value = _state.value.copy(
                        list = if (items.isEmpty()) KycCaseListState.Empty else KycCaseListState.Data(items),
                    )
                }
                is ApiResult.Failure -> _state.value = _state.value.copy(
                    list = when (r.error.status) {
                        403 -> KycCaseListState.Forbidden
                        else -> if (isRefresh && _state.value.list is KycCaseListState.Data) {
                            (_state.value.list as KycCaseListState.Data).copy(isRefreshing = false)
                        } else KycCaseListState.Error(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                    },
                    transientError = if (isRefresh && _state.value.list is KycCaseListState.Data)
                        (if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER) else null,
                )
                is ApiResult.NetworkError -> _state.value = _state.value.copy(
                    list = if (isRefresh && _state.value.list is KycCaseListState.Data)
                        (_state.value.list as KycCaseListState.Data).copy(isRefreshing = false)
                    else KycCaseListState.Error(AdminOpsErrorType.NETWORK),
                    transientError = if (isRefresh && _state.value.list is KycCaseListState.Data) AdminOpsErrorType.NETWORK else null,
                )
            }
        }
    }

    fun openDetail(caseId: String) {
        _state.value = _state.value.copy(detail = KycCaseDetailState.Loading)
        viewModelScope.launch {
            _state.value = _state.value.copy(
                detail = when (val r = repo.detail(caseId)) {
                    is ApiResult.Success -> KycCaseDetailState.Data(r.data)
                    is ApiResult.Failure -> if (r.error.status == 403) KycCaseDetailState.Forbidden
                    else KycCaseDetailState.Error(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                    is ApiResult.NetworkError -> KycCaseDetailState.Error(AdminOpsErrorType.NETWORK)
                },
            )
        }
    }

    fun reloadDetail(caseId: String) = openDetail(caseId)

    fun decide(caseId: String, decision: String, reasonCodes: List<String>, note: String) {
        val d = _state.value.detail as? KycCaseDetailState.Data ?: return
        if (_state.value.actionInFlight) return
        _state.value = _state.value.copy(actionInFlight = true, transientError = null, message = null)
        viewModelScope.launch {
            val v = d.case.version
            val r = when (decision) {
                "approve" -> repo.approve(caseId, v, reasonCodes, note)
                "reject" -> repo.reject(caseId, v, reasonCodes, note)
                else -> repo.requestInfo(caseId, v, reasonCodes, note)
            }
            when (r) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(actionInFlight = false, message = "Case ${decision.replace('_', ' ')} submitted")
                    openDetail(caseId)
                    fetchList(true)
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
