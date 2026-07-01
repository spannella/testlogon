package com.testlogon.android.feature.adfraud

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adfraud.AdFraudDashboard
import com.testlogon.android.data.adfraud.AdFraudRepository
import com.testlogon.android.feature.adminops.AdminOpsErrorType
import com.testlogon.android.feature.adminops.adminOpsErrorFor
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Web-parity admin ad-fraud dashboard. Mirrors /admin/ads/fraud (summary KPIs + flagged events +
 * per-account risk). ADMIN-drivable; a backend 403 -> Forbidden. Actions: confirm/dismiss a flagged
 * event, suspend/unsuspend an account (all require_admin_or_root). After an action succeeds the
 * dashboard is reloaded so counts + statuses stay consistent with the web page's invalidate-and-refetch.
 */
sealed interface AdFraudUiState {
    data object Loading : AdFraudUiState
    data class Content(
        val data: AdFraudDashboard,
        val isRefreshing: Boolean = false,
        val actionInFlight: Boolean = false,
        val actionMessage: String? = null,
        val transientError: AdminOpsErrorType? = null,
    ) : AdFraudUiState
    data object Forbidden : AdFraudUiState
    data class Error(val type: AdminOpsErrorType) : AdFraudUiState
}

@HiltViewModel
class AdFraudDashboardViewModel @Inject constructor(
    private val repo: AdFraudRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<AdFraudUiState>(AdFraudUiState.Loading)
    val state: StateFlow<AdFraudUiState> = _state.asStateFlow()

    init {
        load(resetLoading = true)
    }

    fun retry() = load(resetLoading = true)

    fun refresh() {
        val cur = _state.value
        if (cur is AdFraudUiState.Content) {
            _state.value = cur.copy(isRefreshing = true, transientError = null)
        }
        load(resetLoading = false, isRefresh = true)
    }

    private fun load(resetLoading: Boolean, isRefresh: Boolean = false) {
        if (resetLoading) _state.value = AdFraudUiState.Loading
        viewModelScope.launch {
            when (val r = repo.load()) {
                is ApiResult.Success -> _state.value = AdFraudUiState.Content(r.data)
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun confirmEvent(eventId: String) = runAction("Event confirmed.") { repo.reviewEvent(eventId, "confirm") }
    fun dismissEvent(eventId: String) = runAction("Event dismissed.") { repo.reviewEvent(eventId, "dismiss") }
    fun suspendAccount(accountId: String, reason: String) =
        runAction("Account suspended.") { repo.suspend(accountId, reason) }
    fun unsuspendAccount(accountId: String) =
        runAction("Account reinstated.") { repo.unsuspend(accountId) }

    private fun <T> runAction(successMsg: String, block: suspend () -> ApiResult<T>) {
        val cur = _state.value as? AdFraudUiState.Content ?: return
        if (cur.actionInFlight) return
        _state.value = cur.copy(actionInFlight = true, transientError = null, actionMessage = null)
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> reloadAfterAction(successMsg)
                is ApiResult.Failure -> reduceActionError(
                    if (r.error.status == 403) AdminOpsErrorType.AUTH else adminOpsErrorFor(r.error.status),
                )
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    private suspend fun reloadAfterAction(successMsg: String) {
        when (val r = repo.load()) {
            is ApiResult.Success -> _state.value = AdFraudUiState.Content(r.data, actionMessage = successMsg)
            is ApiResult.Failure -> reduceActionError(adminOpsErrorFor(r.error.status))
            is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
        }
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) {
        if (status == 403) _state.value = AdFraudUiState.Forbidden
        else reduceError(isRefresh, adminOpsErrorFor(status))
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? AdFraudUiState.Content
        _state.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, transientError = type)
        } else {
            AdFraudUiState.Error(type)
        }
    }

    private fun reduceActionError(type: AdminOpsErrorType) {
        val cur = _state.value as? AdFraudUiState.Content ?: return
        _state.value = cur.copy(actionInFlight = false, transientError = type)
    }

    fun clearActionMessage() {
        val cur = _state.value
        if (cur is AdFraudUiState.Content) {
            _state.value = cur.copy(actionMessage = null, transientError = null)
        }
    }
}
