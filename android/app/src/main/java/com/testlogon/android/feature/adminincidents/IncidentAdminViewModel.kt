package com.testlogon.android.feature.adminincidents

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminincidents.IncidentAdminRepository
import com.testlogon.android.data.adminincidents.IncidentDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B5 - admin payment-incidents queue. A status-filtered list; the admin action is submit-response (for
 * DISPUTE incidents; the backend rejects non-dispute incidents with 400). Mirrors /admin/payment-incidents
 * (PaymentIncidentQueuePage.tsx). A backend 403 -> Forbidden.
 */
sealed interface IncidentAdminUiState {
    data object Loading : IncidentAdminUiState
    data class Content(
        val incidents: List<IncidentDto>,
        val statusFilter: String?,
        val isRefreshing: Boolean = false,
        val actionInFlightId: String? = null,
        val message: String? = null,
        val transientError: AdminOpsErrorType? = null,
    ) : IncidentAdminUiState
    data class Empty(val statusFilter: String?) : IncidentAdminUiState
    data object Forbidden : IncidentAdminUiState
    data class Error(val type: AdminOpsErrorType) : IncidentAdminUiState
}

/** The queue statuses the board filters on. null = all. */
val INCIDENT_STATUS_FILTERS: List<String?> = listOf(null, "open", "needs_response", "responded", "resolved")

@HiltViewModel
class IncidentAdminViewModel @Inject constructor(
    private val repo: IncidentAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<IncidentAdminUiState>(IncidentAdminUiState.Loading)
    val state: StateFlow<IncidentAdminUiState> = _state.asStateFlow()

    private var currentFilter: String? = null

    init {
        load(null)
    }

    fun retry() = load(currentFilter)

    fun setFilter(status: String?) {
        currentFilter = status
        load(status)
    }

    fun refresh() {
        val cur = _state.value
        if (cur is IncidentAdminUiState.Content) _state.value = cur.copy(isRefreshing = true, transientError = null)
        fetch(currentFilter, isRefresh = true)
    }

    private fun load(status: String?) {
        currentFilter = status
        _state.value = IncidentAdminUiState.Loading
        fetch(status, isRefresh = false)
    }

    private fun fetch(status: String?, isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.list(status)) {
                is ApiResult.Success -> {
                    val items = r.data.items
                    _state.value = if (items.isEmpty()) IncidentAdminUiState.Empty(status)
                    else IncidentAdminUiState.Content(incidents = items, statusFilter = status)
                }
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun submitResponse(incidentId: String, summary: String, rationale: String?) {
        val cur = _state.value
        if (cur !is IncidentAdminUiState.Content || cur.actionInFlightId != null) return
        _state.value = cur.copy(actionInFlightId = incidentId, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.submitResponse(incidentId, summary, rationale)) {
                is ApiResult.Success -> {
                    val prev = _state.value as? IncidentAdminUiState.Content ?: return@launch
                    val newStatus = r.data.status
                    val updated = if (newStatus != null) {
                        prev.incidents.map { if (it.incidentId == incidentId) it.copy(status = newStatus) else it }
                    } else prev.incidents
                    _state.value = prev.copy(incidents = updated, actionInFlightId = null, message = "Response submitted")
                }
                is ApiResult.Failure -> reduceActionError(r.error.status)
                is ApiResult.NetworkError -> reduceActionError(0, AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun reduceActionError(status: Int, forced: AdminOpsErrorType? = null) {
        val cur = _state.value as? IncidentAdminUiState.Content ?: return
        val type = forced ?: if (status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER
        _state.value = cur.copy(actionInFlightId = null, transientError = type)
    }

    fun clearMessage() {
        val cur = _state.value
        if (cur is IncidentAdminUiState.Content) _state.value = cur.copy(message = null, transientError = null)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = IncidentAdminUiState.Forbidden
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? IncidentAdminUiState.Content
        _state.value = if (isRefresh && prior != null) prior.copy(isRefreshing = false, transientError = type)
        else IncidentAdminUiState.Error(type)
    }
}
