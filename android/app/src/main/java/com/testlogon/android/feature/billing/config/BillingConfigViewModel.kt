package com.testlogon.android.feature.billing.config

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.billing.AdminBillingConfig
import com.testlogon.android.data.billing.BillingConfigAuditEntry
import com.testlogon.android.data.billing.AdminBillingConfigRepository
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-248 — read-only billing-config screen state.
 *
 * Covers Loading, Content (with stale/refreshing flags for the unreliable host), a defensive Empty (404
 * — not normally reachable since the backend returns an effective config), and Error. The ViewModel
 * imports no Retrofit/Moshi/Compose; it consumes [ApiResult] only.
 */
sealed interface BillingConfigUiState {
    data object Loading : BillingConfigUiState
    data class Content(
        val config: AdminBillingConfig,
        val audit: List<BillingConfigAuditEntry> = emptyList(),
        val isStale: Boolean = false,
        val isRefreshing: Boolean = false,
        val resetMessage: String? = null,
    ) : BillingConfigUiState

    /** Defensive: a 404 (route disabled). The effective config normally always returns 200. */
    data object Empty : BillingConfigUiState
    data class Error(val message: UiText, val canRetry: Boolean = true) : BillingConfigUiState
}

/**
 * AND-248 — read-only billing-config presentation logic. Loads on construction; [retry]/[refresh]
 * re-issue the idempotent GET. A failed refresh while content is shown keeps the last-good config visible
 * (`isStale = true`) rather than blanking the screen. A 404 maps to [BillingConfigUiState.Empty]; a 403
 * (root-only) and everything else map to [BillingConfigUiState.Error] (403 is non-retryable).
 */
@HiltViewModel
class BillingConfigViewModel @Inject constructor(
    private val repository: AdminBillingConfigRepository,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    private val _state = MutableStateFlow<BillingConfigUiState>(BillingConfigUiState.Loading)
    val state: StateFlow<BillingConfigUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun retry() = load()

    fun refresh() = load()

    /** Reset billing overrides to defaults. ROOT-only server-side; a 403 surfaces as a message. */
    fun resetToDefaults() {
        viewModelScope.launch {
            when (val r = repository.resetAll()) {
                is ApiResult.Success ->
                    _state.value = BillingConfigUiState.Content(config = r.data, resetMessage = "Reset to defaults.")
                else -> {
                    val status = (r as? ApiResult.Failure)?.error?.status
                    val msg = if (status == 403) "Reset is root-only; your account is not authorised."
                        else "Reset failed. Try again."
                    (_state.value as? BillingConfigUiState.Content)?.let {
                        _state.value = it.copy(resetMessage = msg)
                    }
                }
            }
        }
    }

    private fun load() {
        val current = _state.value
        _state.value = if (current is BillingConfigUiState.Content) {
            current.copy(isRefreshing = true)
        } else {
            BillingConfigUiState.Loading
        }
        viewModelScope.launch {
            when (val result = repository.getBillingConfig()) {
                is ApiResult.Success -> {
                    val audit = (repository.getAudit() as? ApiResult.Success)?.data ?: emptyList()
                    _state.value = BillingConfigUiState.Content(config = result.data, audit = audit)
                }
                else -> _state.update { reduceError(it, result) }
            }
        }
    }

    private fun reduceError(prev: BillingConfigUiState, result: ApiResult<*>): BillingConfigUiState {
        // A failed refresh over existing content: keep the last-good config, flag it stale.
        if (prev is BillingConfigUiState.Content) {
            return prev.copy(isStale = true, isRefreshing = false)
        }
        val status = (result as? ApiResult.Failure)?.error?.status
        if (status == 404) return BillingConfigUiState.Empty
        val error = errorMapper.map(result)
        // 403 (root-only) is not retryable; transient/5xx/network are.
        val canRetry = error.retryable && status != 403
        return BillingConfigUiState.Error(message = error.message, canRetry = canRetry)
    }
}
