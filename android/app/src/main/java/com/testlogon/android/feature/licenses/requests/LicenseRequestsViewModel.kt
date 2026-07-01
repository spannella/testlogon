package com.testlogon.android.feature.licenses.requests

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.licenses.FullLicenseRequest
import com.testlogon.android.data.licenses.LicenseTerms
import com.testlogon.android.data.licenses.LicensesSubRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Inbox (received) vs Sent. */
enum class RequestsTab { INBOX, SENT }

val REQUEST_STATUS_OPTIONS = listOf(
    "all", "pending", "negotiating", "approved", "denied", "withdrawn", "expired",
)

data class LicenseRequestsUiState(
    val tab: RequestsTab = RequestsTab.INBOX,
    val phase: Phase = Phase.Loading,
    val items: List<FullLicenseRequest> = emptyList(),
    val statusFilter: String = "all",
    val isRefreshing: Boolean = false,
    val errorMessage: String? = null,
    val actionInProgressId: String? = null,
    // counter dialog
    val counterTarget: FullLicenseRequest? = null,
    // deny dialog
    val denyTarget: FullLicenseRequest? = null,
) {
    enum class Phase { Loading, Content, Empty, Error }
}

@HiltViewModel
class LicenseRequestsViewModel @Inject constructor(
    private val repository: LicensesSubRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(LicenseRequestsUiState())
    val uiState: StateFlow<LicenseRequestsUiState> = _uiState.asStateFlow()

    private val _effects = Channel<Int>(Channel.BUFFERED)
    val effects: Flow<Int> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun refresh() = load(fromUser = true)

    fun selectTab(tab: RequestsTab) {
        if (tab == _uiState.value.tab) return
        _uiState.update {
            it.copy(tab = tab, items = emptyList(), phase = LicenseRequestsUiState.Phase.Loading)
        }
        load(fromUser = false)
    }

    fun selectStatus(status: String) {
        if (status == _uiState.value.statusFilter) return
        _uiState.update { it.copy(statusFilter = status) }
        load(fromUser = true)
    }

    private fun load(fromUser: Boolean) {
        if (_uiState.value.isRefreshing) return
        val hasContent = _uiState.value.items.isNotEmpty()
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else LicenseRequestsUiState.Phase.Loading,
                isRefreshing = fromUser,
                errorMessage = null,
            )
        }
        val status = _uiState.value.statusFilter.takeIf { it != "all" }
        val tab = _uiState.value.tab
        viewModelScope.launch {
            val result = when (tab) {
                RequestsTab.INBOX -> repository.loadReceived(status)
                RequestsTab.SENT -> repository.loadSent(status)
            }
            when (result) {
                is ApiResult.Success -> _uiState.update {
                    // guard against a tab switch mid-flight
                    if (it.tab != tab) it else it.copy(
                        phase = if (result.data.isEmpty) LicenseRequestsUiState.Phase.Empty else LicenseRequestsUiState.Phase.Content,
                        items = result.data.items,
                        isRefreshing = false,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure -> fail(result.error.message)
                is ApiResult.NetworkError -> fail(OFFLINE)
            }
        }
    }

    private fun fail(message: String) {
        _uiState.update {
            if (it.items.isNotEmpty()) it.copy(isRefreshing = false)
            else it.copy(phase = LicenseRequestsUiState.Phase.Error, isRefreshing = false, errorMessage = message)
        }
    }

    // ---- actions ----

    fun approve(r: FullLicenseRequest) = runAction(r, R.string.licenses_request_approved) {
        repository.approve(r.requestId, r.contentId)
    }

    fun acceptCounter(r: FullLicenseRequest) = runAction(r, R.string.licenses_counter_accepted) {
        repository.acceptCounter(r.requestId, r.contentId)
    }

    fun rejectCounter(r: FullLicenseRequest) = runAction(r, R.string.licenses_counter_rejected) {
        repository.rejectCounter(r.requestId, r.contentId)
    }

    fun withdraw(r: FullLicenseRequest) = runAction(r, R.string.licenses_request_withdrawn) {
        repository.withdraw(r.requestId, r.contentId)
    }

    fun openDeny(r: FullLicenseRequest) = _uiState.update { it.copy(denyTarget = r) }
    fun closeDeny() = _uiState.update { it.copy(denyTarget = null) }

    fun confirmDeny(reason: String) {
        val r = _uiState.value.denyTarget ?: return
        _uiState.update { it.copy(denyTarget = null) }
        runAction(r, R.string.licenses_request_denied_done) {
            repository.deny(r.requestId, r.contentId, reason)
        }
    }

    fun openCounter(r: FullLicenseRequest) = _uiState.update { it.copy(counterTarget = r) }
    fun closeCounter() = _uiState.update { it.copy(counterTarget = null) }

    fun confirmCounter(profitPct: Double, revenuePct: Double, fixedCents: Long) {
        val r = _uiState.value.counterTarget ?: return
        _uiState.update { it.copy(counterTarget = null) }
        runAction(r, R.string.licenses_counter_sent) {
            repository.counter(
                r.requestId,
                r.contentId,
                LicenseTerms(profitSharePct = profitPct, fixedCostCents = fixedCents, revenueSharePct = revenuePct),
            )
        }
    }

    private fun runAction(
        r: FullLicenseRequest,
        @androidx.annotation.StringRes successMsg: Int,
        block: suspend () -> ApiResult<Unit>,
    ) {
        if (_uiState.value.actionInProgressId != null) return
        _uiState.update { it.copy(actionInProgressId = r.requestId) }
        viewModelScope.launch {
            val result = block()
            _uiState.update { it.copy(actionInProgressId = null) }
            if (result is ApiResult.Success) {
                _effects.send(successMsg)
                load(fromUser = false)
            } else {
                _effects.send(R.string.licenses_action_failed)
            }
        }
    }

    private companion object {
        private const val OFFLINE = "Could not reach the server. Pull down to retry."
    }
}
