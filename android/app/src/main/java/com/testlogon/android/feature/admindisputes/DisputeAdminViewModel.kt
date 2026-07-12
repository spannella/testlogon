package com.testlogon.android.feature.admindisputes

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.admindisputes.DisputeAdminRepository
import com.testlogon.android.data.admindisputes.DisputeDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B5 - admin billing-disputes queue. A status-filtered list with respond (submit evidence) + resolve
 * (won/lost/accepted) per dispute. Mirrors /admin/disputes (AdminDisputeQueuePage.tsx). 403 -> Forbidden.
 */
sealed interface DisputeAdminUiState {
    data object Loading : DisputeAdminUiState
    data class Content(
        val disputes: List<DisputeDto>,
        val statusFilter: String,
        val isRefreshing: Boolean = false,
        val actionInFlightId: String? = null,
        val message: String? = null,
        val transientError: AdminOpsErrorType? = null,
    ) : DisputeAdminUiState
    data class Empty(val statusFilter: String) : DisputeAdminUiState
    data object Forbidden : DisputeAdminUiState
    data class Error(val type: AdminOpsErrorType) : DisputeAdminUiState
}

/** The queue statuses the board filters on (mirrors the web queue tabs). */
val DISPUTE_STATUS_FILTERS: List<String> = listOf("open", "under_review", "won", "lost")

/** Resolution outcomes per DisputeResolveIn (won|lost|accepted). */
val DISPUTE_RESOLUTIONS: List<String> = listOf("won", "lost", "accepted")

@HiltViewModel
class DisputeAdminViewModel @Inject constructor(
    private val repo: DisputeAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<DisputeAdminUiState>(DisputeAdminUiState.Loading)
    val state: StateFlow<DisputeAdminUiState> = _state.asStateFlow()

    private var currentFilter: String = DISPUTE_STATUS_FILTERS.first()

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
        if (cur is DisputeAdminUiState.Content) _state.value = cur.copy(isRefreshing = true, transientError = null)
        fetch(currentFilter, isRefresh = true)
    }

    private fun load(status: String) {
        currentFilter = status
        _state.value = DisputeAdminUiState.Loading
        fetch(status, isRefresh = false)
    }

    private fun fetch(status: String, isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.list(status)) {
                is ApiResult.Success -> {
                    val items = r.data.items
                    _state.value = if (items.isEmpty()) DisputeAdminUiState.Empty(status)
                    else DisputeAdminUiState.Content(disputes = items, statusFilter = status)
                }
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun respond(disputeId: String, evidenceText: String) {
        runAction(disputeId) {
            when (val r = repo.respond(disputeId, evidenceText)) {
                is ApiResult.Success -> ActionResult.Success(r.data.status, null, r.data.evidenceSubmitted, "Evidence submitted")
                is ApiResult.Failure -> ActionResult.Failure(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> ActionResult.Failure(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun resolve(disputeId: String, resolution: String, notes: String?) {
        runAction(disputeId) {
            when (val r = repo.resolve(disputeId, resolution, notes)) {
                is ApiResult.Success -> ActionResult.Success(r.data.status, r.data.resolution, null, "Resolved: ${r.data.resolution}")
                is ApiResult.Failure -> ActionResult.Failure(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> ActionResult.Failure(AdminOpsErrorType.NETWORK)
            }
        }
    }

    private sealed interface ActionResult {
        data class Success(val newStatus: String, val resolution: String?, val evidenceSubmitted: Boolean?, val label: String) : ActionResult
        data class Failure(val type: AdminOpsErrorType) : ActionResult
    }

    private fun runAction(disputeId: String, block: suspend () -> ActionResult) {
        val cur = _state.value
        if (cur !is DisputeAdminUiState.Content || cur.actionInFlightId != null) return
        _state.value = cur.copy(actionInFlightId = disputeId, transientError = null, message = null)
        viewModelScope.launch {
            when (val res = block()) {
                is ActionResult.Success -> {
                    val prev = _state.value as? DisputeAdminUiState.Content ?: return@launch
                    val updated = prev.disputes.map {
                        if (it.disputeId == disputeId) it.copy(
                            status = res.newStatus,
                            resolution = res.resolution ?: it.resolution,
                            evidenceSubmitted = res.evidenceSubmitted ?: it.evidenceSubmitted,
                        ) else it
                    }
                    _state.value = prev.copy(disputes = updated, actionInFlightId = null, message = res.label)
                }
                is ActionResult.Failure -> {
                    val prev = _state.value as? DisputeAdminUiState.Content ?: return@launch
                    _state.value = prev.copy(actionInFlightId = null, transientError = res.type)
                }
            }
        }
    }

    fun clearMessage() {
        val cur = _state.value
        if (cur is DisputeAdminUiState.Content) _state.value = cur.copy(message = null, transientError = null)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = DisputeAdminUiState.Forbidden
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? DisputeAdminUiState.Content
        _state.value = if (isRefresh && prior != null) prior.copy(isRefreshing = false, transientError = type)
        else DisputeAdminUiState.Error(type)
    }
}
