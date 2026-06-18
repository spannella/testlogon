package com.testlogon.android.feature.licenses

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.licenses.LicensesRepository
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

/**
 * Drives [LicensesUiState] from [LicensesRepository].
 *
 * The hub has three sections (Issued / Requests / Revenue) selected by a SegmentedButton. Switching tabs
 * loads that section's first page (from cache if already loaded, refreshing in the background otherwise);
 * pull-to-refresh re-fetches the active tab. A hard 401 (after the network layer's refresh+retry) maps to
 * SessionExpired; a failed refresh with a cached page shows a stale banner, else Error/Offline. Effects
 * are Channel-backed so they are not replayed.
 */
@HiltViewModel
class LicensesViewModel @Inject constructor(
    private val repository: LicensesRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(LicensesUiState())
    val uiState: StateFlow<LicensesUiState> = _uiState.asStateFlow()

    private val _effects = Channel<LicensesEffect>(Channel.BUFFERED)
    val effects: Flow<LicensesEffect> = _effects.receiveAsFlow()

    init {
        load(_uiState.value.tab, fromUser = false)
    }

    fun onRefresh() = load(_uiState.value.tab, fromUser = true)

    fun onRetry() = load(_uiState.value.tab, fromUser = true)

    fun onSelectTab(tab: LicensesTab) {
        if (tab == _uiState.value.tab) return
        _uiState.update { it.copy(tab = tab, isStale = false, errorMessage = null) }
        // Show cached content for the newly-selected tab immediately, then refresh in the background.
        _uiState.update { it.copy(phase = phaseForCachedOrLoading(tab)) }
        load(tab, fromUser = false)
    }

    private fun phaseForCachedOrLoading(tab: LicensesTab): LicensesUiState.Phase = when (tab) {
        LicensesTab.ISSUED -> repository.cachedIssued()
            ?.let { if (it.isEmpty) LicensesUiState.Phase.Empty else LicensesUiState.Phase.Content }
            ?: LicensesUiState.Phase.Loading
        LicensesTab.REQUESTS -> repository.cachedRequests()
            ?.let { if (it.isEmpty) LicensesUiState.Phase.Empty else LicensesUiState.Phase.Content }
            ?: LicensesUiState.Phase.Loading
        LicensesTab.REVENUE -> repository.cachedRevenue()
            ?.let { if (it.isEmpty) LicensesUiState.Phase.Empty else LicensesUiState.Phase.Content }
            ?: LicensesUiState.Phase.Loading
    }

    private fun hasContentFor(tab: LicensesTab): Boolean = when (tab) {
        LicensesTab.ISSUED -> _uiState.value.issued != null
        LicensesTab.REQUESTS -> _uiState.value.requests != null
        LicensesTab.REVENUE -> _uiState.value.revenue != null
    }

    private fun load(tab: LicensesTab, fromUser: Boolean) {
        if (_uiState.value.isRefreshing) return
        val hasContent = hasContentFor(tab)
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else LicensesUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
                errorMessage = if (hasContent) it.errorMessage else null,
            )
        }
        viewModelScope.launch {
            when (tab) {
                LicensesTab.ISSUED -> reduceIssued(repository.loadIssued())
                LicensesTab.REQUESTS -> reduceRequests(repository.loadRequests())
                LicensesTab.REVENUE -> reduceRevenue(repository.loadRevenue())
            }
        }
    }

    // ---- Issued ----

    private suspend fun reduceIssued(result: ApiResult<com.testlogon.android.data.licenses.IssuedLicensesPage>) {
        when (result) {
            is ApiResult.Success -> _uiState.update {
                it.copy(
                    phase = if (result.data.isEmpty) LicensesUiState.Phase.Empty else LicensesUiState.Phase.Content,
                    issued = result.data,
                    isRefreshing = false,
                    isStale = false,
                    errorMessage = null,
                )
            }
            is ApiResult.Failure -> if (result.error.status == HTTP_UNAUTHORIZED) {
                sessionExpired()
            } else {
                val cached = repository.cachedIssued()
                if (cached != null) staleIssued(cached) else failure(result.error.message, offline = false)
            }
            is ApiResult.NetworkError -> {
                val cached = repository.cachedIssued()
                if (cached != null) staleIssued(cached) else failure(OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private suspend fun staleIssued(cached: com.testlogon.android.data.licenses.IssuedLicensesPage) {
        _uiState.update {
            it.copy(
                phase = if (cached.isEmpty) LicensesUiState.Phase.Empty else LicensesUiState.Phase.Content,
                issued = cached,
                isRefreshing = false,
                isStale = true,
                errorMessage = null,
            )
        }
        _effects.send(LicensesEffect.ShowMessage(R.string.licenses_refresh_failed_stale))
    }

    // ---- Requests ----

    private suspend fun reduceRequests(result: ApiResult<com.testlogon.android.data.licenses.LicenseRequestsPage>) {
        when (result) {
            is ApiResult.Success -> _uiState.update {
                it.copy(
                    phase = if (result.data.isEmpty) LicensesUiState.Phase.Empty else LicensesUiState.Phase.Content,
                    requests = result.data,
                    isRefreshing = false,
                    isStale = false,
                    errorMessage = null,
                )
            }
            is ApiResult.Failure -> if (result.error.status == HTTP_UNAUTHORIZED) {
                sessionExpired()
            } else {
                val cached = repository.cachedRequests()
                if (cached != null) staleRequests(cached) else failure(result.error.message, offline = false)
            }
            is ApiResult.NetworkError -> {
                val cached = repository.cachedRequests()
                if (cached != null) staleRequests(cached) else failure(OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private suspend fun staleRequests(cached: com.testlogon.android.data.licenses.LicenseRequestsPage) {
        _uiState.update {
            it.copy(
                phase = if (cached.isEmpty) LicensesUiState.Phase.Empty else LicensesUiState.Phase.Content,
                requests = cached,
                isRefreshing = false,
                isStale = true,
                errorMessage = null,
            )
        }
        _effects.send(LicensesEffect.ShowMessage(R.string.licenses_refresh_failed_stale))
    }

    // ---- Revenue ----

    private suspend fun reduceRevenue(result: ApiResult<com.testlogon.android.data.licenses.RevenuePage>) {
        when (result) {
            is ApiResult.Success -> _uiState.update {
                it.copy(
                    phase = if (result.data.isEmpty) LicensesUiState.Phase.Empty else LicensesUiState.Phase.Content,
                    revenue = result.data,
                    isRefreshing = false,
                    isStale = false,
                    errorMessage = null,
                )
            }
            is ApiResult.Failure -> if (result.error.status == HTTP_UNAUTHORIZED) {
                sessionExpired()
            } else {
                val cached = repository.cachedRevenue()
                if (cached != null) staleRevenue(cached) else failure(result.error.message, offline = false)
            }
            is ApiResult.NetworkError -> {
                val cached = repository.cachedRevenue()
                if (cached != null) staleRevenue(cached) else failure(OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private suspend fun staleRevenue(cached: com.testlogon.android.data.licenses.RevenuePage) {
        _uiState.update {
            it.copy(
                phase = if (cached.isEmpty) LicensesUiState.Phase.Empty else LicensesUiState.Phase.Content,
                revenue = cached,
                isRefreshing = false,
                isStale = true,
                errorMessage = null,
            )
        }
        _effects.send(LicensesEffect.ShowMessage(R.string.licenses_refresh_failed_stale))
    }

    // ---- Shared reductions ----

    private fun sessionExpired() {
        _uiState.update { it.copy(phase = LicensesUiState.Phase.SessionExpired, isRefreshing = false) }
    }

    private fun failure(message: String, offline: Boolean) {
        _uiState.update {
            it.copy(
                phase = if (offline) LicensesUiState.Phase.Offline else LicensesUiState.Phase.Error,
                isRefreshing = false,
                isStale = false,
                errorMessage = message,
            )
        }
    }

    private companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Could not reach the server. Pull down to retry."
    }
}
