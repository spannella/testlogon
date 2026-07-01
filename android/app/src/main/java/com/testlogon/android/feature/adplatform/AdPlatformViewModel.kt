package com.testlogon.android.feature.adplatform

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adplatform.AdPlatformConsole
import com.testlogon.android.data.adplatform.AdPlatformRepository
import com.testlogon.android.feature.adminops.AdminOpsErrorType
import com.testlogon.android.feature.adminops.adminOpsErrorFor
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Web-parity admin ad-platform console. Mirrors /admin/ad-platform (platform metrics + revenue series +
 * top spenders + moderation queue + kill-switch state). ADMIN-drivable reads + moderate actions; the
 * kill-switch TOGGLE is ROOT-only so it is surfaced read-only (state + a note). A backend 403 on the
 * loads -> Forbidden. After a moderate action succeeds the console reloads.
 */
sealed interface AdPlatformUiState {
    data object Loading : AdPlatformUiState
    data class Content(
        val data: AdPlatformConsole,
        val isRefreshing: Boolean = false,
        val actionInFlight: Boolean = false,
        val actionMessage: String? = null,
        val transientError: AdminOpsErrorType? = null,
    ) : AdPlatformUiState
    data object Forbidden : AdPlatformUiState
    data class Error(val type: AdminOpsErrorType) : AdPlatformUiState
}

@HiltViewModel
class AdPlatformViewModel @Inject constructor(
    private val repo: AdPlatformRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<AdPlatformUiState>(AdPlatformUiState.Loading)
    val state: StateFlow<AdPlatformUiState> = _state.asStateFlow()

    init {
        load(resetLoading = true)
    }

    fun retry() = load(resetLoading = true)

    fun refresh() {
        val cur = _state.value
        if (cur is AdPlatformUiState.Content) {
            _state.value = cur.copy(isRefreshing = true, transientError = null)
        }
        load(resetLoading = false, isRefresh = true)
    }

    private fun load(resetLoading: Boolean, isRefresh: Boolean = false) {
        if (resetLoading) _state.value = AdPlatformUiState.Loading
        viewModelScope.launch {
            when (val r = repo.load()) {
                is ApiResult.Success -> _state.value = AdPlatformUiState.Content(r.data)
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun moderateAccount(accountId: String, action: String, reason: String?) =
        runAction("Account $action applied.") { repo.moderateAccount(accountId, action, reason) }

    fun moderateCreative(creativeId: String, action: String, reason: String?) =
        runAction("Creative $action applied.") { repo.moderateCreative(creativeId, action, reason) }

    private fun <T> runAction(successMsg: String, block: suspend () -> ApiResult<T>) {
        val cur = _state.value as? AdPlatformUiState.Content ?: return
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
            is ApiResult.Success -> _state.value = AdPlatformUiState.Content(r.data, actionMessage = successMsg)
            is ApiResult.Failure -> reduceActionError(adminOpsErrorFor(r.error.status))
            is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
        }
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) {
        if (status == 403) _state.value = AdPlatformUiState.Forbidden
        else reduceError(isRefresh, adminOpsErrorFor(status))
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? AdPlatformUiState.Content
        _state.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, transientError = type)
        } else {
            AdPlatformUiState.Error(type)
        }
    }

    private fun reduceActionError(type: AdminOpsErrorType) {
        val cur = _state.value as? AdPlatformUiState.Content ?: return
        _state.value = cur.copy(actionInFlight = false, transientError = type)
    }

    fun clearActionMessage() {
        val cur = _state.value
        if (cur is AdPlatformUiState.Content) {
            _state.value = cur.copy(actionMessage = null, transientError = null)
        }
    }
}
