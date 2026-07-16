package com.testlogon.android.feature.payouts

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.payouts.PayoutDetail
import com.testlogon.android.data.payouts.PayoutsRepository
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** PAY-53 — payout statement/detail screen state. */
sealed interface PayoutDetailUiState {
    data object Loading : PayoutDetailUiState

    data class Content(val detail: PayoutDetail) : PayoutDetailUiState

    /** The payout id is unknown or not owned by the caller (backend 404/403) — reopen from history. */
    data object NotFound : PayoutDetailUiState

    /** A transient failure (network / 5xx) — the screen offers a retry. */
    data class Error(val message: UiText?) : PayoutDetailUiState
}

/**
 * PAY-53 — payout statement/detail presentation.
 *
 * Fetches the REAL PAY-50 GET /ui/payouts/{payout_id} (lifecycle timeline + transfer ref + method
 * last-4 + fail/return/hold reason). The endpoint is user-scoped: a 404 (unknown) or 403 (not the
 * owner) resolves to [PayoutDetailUiState.NotFound] (a "reopen from history" state); network/5xx
 * resolves to a retryable [PayoutDetailUiState.Error]. This replaces the AND-260 cache-only detail —
 * a cold deep-link (e.g. a payout_paid notification tap) now resolves against the server directly.
 */
@HiltViewModel
class PayoutDetailViewModel @Inject constructor(
    private val repository: PayoutsRepository,
    private val errorMapper: BillingErrorMapper,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val payoutId: String = checkNotNull(savedStateHandle[ARG_PAYOUT_ID]) {
        "PayoutDetailViewModel requires a '$ARG_PAYOUT_ID' nav argument"
    }

    private val _uiState = MutableStateFlow<PayoutDetailUiState>(PayoutDetailUiState.Loading)
    val uiState: StateFlow<PayoutDetailUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun load() {
        _uiState.value = PayoutDetailUiState.Loading
        viewModelScope.launch {
            _uiState.value = when (val result = repository.getPayoutDetail(payoutId)) {
                is ApiResult.Success -> PayoutDetailUiState.Content(result.data)
                is ApiResult.Failure ->
                    if (result.error.status == 404 || result.error.status == 403) {
                        PayoutDetailUiState.NotFound
                    } else {
                        PayoutDetailUiState.Error(errorMapper.map(result).message)
                    }
                is ApiResult.NetworkError -> PayoutDetailUiState.Error(errorMapper.map(result).message)
            }
        }
    }

    companion object {
        const val ARG_PAYOUT_ID = "payoutId"
    }
}
