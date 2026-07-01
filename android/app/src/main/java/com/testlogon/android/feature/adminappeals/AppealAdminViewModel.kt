package com.testlogon.android.feature.adminappeals

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminappeals.AppealAdminRepository
import com.testlogon.android.data.adminappeals.AppealDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B5 - admin appeals review queue. A status-filtered list with claim + decide (upheld/modified/reversed)
 * per appeal. Mirrors /admin/appeals (AppealReviewQueuePage.tsx). A backend 403 -> Forbidden.
 */
sealed interface AppealAdminUiState {
    data object Loading : AppealAdminUiState
    data class Content(
        val appeals: List<AppealDto>,
        val statusFilter: String?,
        val isRefreshing: Boolean = false,
        val actionInFlightId: String? = null,
        val message: String? = null,
        val transientError: AdminOpsErrorType? = null,
    ) : AppealAdminUiState
    data class Empty(val statusFilter: String?) : AppealAdminUiState
    data object Forbidden : AppealAdminUiState
    data class Error(val type: AdminOpsErrorType) : AppealAdminUiState
}

/** The queue statuses the board filters on. null = all. */
val APPEAL_STATUS_FILTERS: List<String?> = listOf(null, "submitted", "under_review", "decided")

/** Decision outcomes per AppealDecisionIn (upheld|modified|reversed). */
val APPEAL_DECISIONS: List<String> = listOf("upheld", "modified", "reversed")

@HiltViewModel
class AppealAdminViewModel @Inject constructor(
    private val repo: AppealAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<AppealAdminUiState>(AppealAdminUiState.Loading)
    val state: StateFlow<AppealAdminUiState> = _state.asStateFlow()

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
        if (cur is AppealAdminUiState.Content) _state.value = cur.copy(isRefreshing = true, transientError = null)
        fetch(currentFilter, isRefresh = true)
    }

    private fun load(status: String?) {
        currentFilter = status
        _state.value = AppealAdminUiState.Loading
        fetch(status, isRefresh = false)
    }

    private fun fetch(status: String?, isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.list(status)) {
                is ApiResult.Success -> {
                    val items = r.data.items
                    _state.value = if (items.isEmpty()) AppealAdminUiState.Empty(status)
                    else AppealAdminUiState.Content(appeals = items, statusFilter = status)
                }
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun claim(appealId: String) {
        runAction(appealId) {
            when (val r = repo.claim(appealId)) {
                is ApiResult.Success -> ActionResult.Success("under_review", "Claimed")
                is ApiResult.Failure -> ActionResult.Failure(mapStatus(r.error.status))
                is ApiResult.NetworkError -> ActionResult.Failure(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun decide(appealId: String, decision: String, note: String?) {
        runAction(appealId) {
            when (val r = repo.decide(appealId, decision, note)) {
                is ApiResult.Success -> ActionResult.Success(r.data.status.ifBlank { "decided" }, "Decision: ${r.data.decision}")
                is ApiResult.Failure -> ActionResult.Failure(mapStatus(r.error.status))
                is ApiResult.NetworkError -> ActionResult.Failure(AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun mapStatus(status: Int): AdminOpsErrorType =
        if (status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER

    private sealed interface ActionResult {
        data class Success(val newStatus: String, val label: String) : ActionResult
        data class Failure(val type: AdminOpsErrorType) : ActionResult
    }

    private fun runAction(appealId: String, block: suspend () -> ActionResult) {
        val cur = _state.value
        if (cur !is AppealAdminUiState.Content || cur.actionInFlightId != null) return
        _state.value = cur.copy(actionInFlightId = appealId, transientError = null, message = null)
        viewModelScope.launch {
            when (val res = block()) {
                is ActionResult.Success -> {
                    val prev = _state.value as? AppealAdminUiState.Content ?: return@launch
                    val updated = prev.appeals.map {
                        if (it.appealId == appealId) it.copy(status = res.newStatus) else it
                    }
                    _state.value = prev.copy(appeals = updated, actionInFlightId = null, message = res.label)
                }
                is ActionResult.Failure -> {
                    val prev = _state.value as? AppealAdminUiState.Content ?: return@launch
                    _state.value = prev.copy(actionInFlightId = null, transientError = res.type)
                }
            }
        }
    }

    fun clearMessage() {
        val cur = _state.value
        if (cur is AppealAdminUiState.Content) _state.value = cur.copy(message = null, transientError = null)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = AppealAdminUiState.Forbidden
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? AppealAdminUiState.Content
        _state.value = if (isRefresh && prior != null) prior.copy(isRefreshing = false, transientError = type)
        else AppealAdminUiState.Error(type)
    }
}
