package com.testlogon.android.feature.admindmca

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.admindmca.DmcaAdminRepository
import com.testlogon.android.data.admindmca.DmcaClaimDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B5 - admin DMCA claims dashboard. List of claims with a resolve action per claim. Mirrors /admin/dmca
 * (DmcaDashboardPage.tsx). A backend 403 -> Forbidden.
 */
sealed interface DmcaAdminUiState {
    data object Loading : DmcaAdminUiState
    data class Content(
        val claims: List<DmcaClaimDto>,
        val isRefreshing: Boolean = false,
        val actionInFlightId: String? = null,
        val message: String? = null,
        val transientError: AdminOpsErrorType? = null,
    ) : DmcaAdminUiState
    data object Empty : DmcaAdminUiState
    data object Forbidden : DmcaAdminUiState
    data class Error(val type: AdminOpsErrorType) : DmcaAdminUiState
}

/** DMCA resolutions per the web ep: restored | upheld | court_order | withdrawn. */
val DMCA_RESOLUTIONS: List<String> = listOf("upheld", "restored", "court_order", "withdrawn")

@HiltViewModel
class DmcaAdminViewModel @Inject constructor(
    private val repo: DmcaAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<DmcaAdminUiState>(DmcaAdminUiState.Loading)
    val state: StateFlow<DmcaAdminUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun retry() = load()

    fun refresh() {
        val cur = _state.value
        if (cur is DmcaAdminUiState.Content) _state.value = cur.copy(isRefreshing = true, transientError = null)
        fetch(isRefresh = true)
    }

    private fun load() {
        _state.value = DmcaAdminUiState.Loading
        fetch(isRefresh = false)
    }

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.list()) {
                is ApiResult.Success -> {
                    val items = r.data.items
                    _state.value = if (items.isEmpty()) DmcaAdminUiState.Empty
                    else DmcaAdminUiState.Content(claims = items)
                }
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun resolve(claimId: String, resolution: String, notes: String?) {
        val cur = _state.value
        if (cur !is DmcaAdminUiState.Content || cur.actionInFlightId != null) return
        _state.value = cur.copy(actionInFlightId = claimId, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.resolve(claimId, resolution, notes)) {
                is ApiResult.Success -> {
                    val prev = _state.value as? DmcaAdminUiState.Content ?: return@launch
                    val updated = prev.claims.map {
                        if (it.claimId == claimId) it.copy(status = r.data.status, resolution = r.data.resolution, resolvedAt = r.data.resolvedAt) else it
                    }
                    _state.value = prev.copy(claims = updated, actionInFlightId = null, message = "Resolved: ${r.data.resolution}")
                }
                is ApiResult.Failure -> reduceActionError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun reduceActionError(type: AdminOpsErrorType) {
        val cur = _state.value as? DmcaAdminUiState.Content ?: return
        _state.value = cur.copy(actionInFlightId = null, transientError = type)
    }

    fun clearMessage() {
        val cur = _state.value
        if (cur is DmcaAdminUiState.Content) _state.value = cur.copy(message = null, transientError = null)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = DmcaAdminUiState.Forbidden
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? DmcaAdminUiState.Content
        _state.value = if (isRefresh && prior != null) prior.copy(isRefreshing = false, transientError = type)
        else DmcaAdminUiState.Error(type)
    }
}
