package com.testlogon.android.feature.support.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.support.data.SupportAdminSummary
import com.testlogon.android.feature.support.data.SupportRepository
import com.testlogon.android.feature.support.data.SupportTicket
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B-SUP (batch 7) — ADMIN helpdesk/moderation queue. Loads the full ticket queue (server returns all tickets
 * for an admin) + the admin summary counts, with a client-side status filter. A non-admin who somehow reaches
 * this VM gets a 403 -> [SupportAdminUiState.forbidden] (defence in depth). Per-ticket status/assign happen in
 * the shared ticket-detail screen (opened with isAdmin=true).
 */
data class SupportAdminUiState(
    val loading: Boolean = true,
    val summary: SupportAdminSummary? = null,
    val tickets: List<SupportTicket> = emptyList(),
    val statusFilter: String? = null,
    val error: String? = null,
    val forbidden: Boolean = false,
) {
    val visibleTickets: List<SupportTicket>
        get() = if (statusFilter == null) tickets else tickets.filter { it.rawStatus == statusFilter }
}

@HiltViewModel
class SupportAdminViewModel @Inject constructor(
    private val repository: SupportRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(SupportAdminUiState())
    val uiState: StateFlow<SupportAdminUiState> = _uiState.asStateFlow()

    val statusFilters = listOf("open", "in_progress", "waiting_on_user", "done")

    init { refresh() }

    fun setStatusFilter(status: String?) {
        _uiState.value = _uiState.value.copy(statusFilter = status)
    }

    fun refresh() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(loading = true, error = null, forbidden = false)
            val listResult = repository.listTickets(limit = 100)
            when (listResult) {
                is ApiResult.Success ->
                    _uiState.value = _uiState.value.copy(
                        loading = false,
                        tickets = listResult.data.tickets.sortedByDescending { it.updatedAt },
                        error = null,
                    )
                is ApiResult.Failure -> {
                    val forbidden = listResult.error.status == 403
                    _uiState.value = _uiState.value.copy(
                        loading = false,
                        forbidden = forbidden,
                        error = if (forbidden) null else listResult.error.message,
                    )
                    if (forbidden) return@launch
                }
                is ApiResult.NetworkError ->
                    _uiState.value = _uiState.value.copy(loading = false, error = "You appear to be offline.")
            }
            // Best-effort summary (non-fatal if it fails).
            when (val sumRes = repository.adminSummary()) {
                is ApiResult.Success -> _uiState.value = _uiState.value.copy(summary = sumRes.data)
                else -> Unit
            }
        }
    }
}
