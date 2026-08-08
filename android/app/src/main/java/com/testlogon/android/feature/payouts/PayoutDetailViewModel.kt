package com.testlogon.android.feature.payouts

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.payouts.PayoutDetail
import com.testlogon.android.data.payouts.PayoutStatus
import com.testlogon.android.data.payouts.PayoutsRepository
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** PAY-53 — payout statement/detail screen state. */
sealed interface PayoutDetailUiState {
    data object Loading : PayoutDetailUiState

    /** [cancelling] is the in-flight guard for the PAR-19 cancel action. */
    data class Content(val detail: PayoutDetail, val cancelling: Boolean = false) : PayoutDetailUiState

    /** The payout id is unknown or not owned by the caller (backend 404/403) — reopen from history. */
    data object NotFound : PayoutDetailUiState

    /** A transient failure (network / 5xx) — the screen offers a retry. */
    data class Error(val message: UiText?) : PayoutDetailUiState
}

/** PAR-19 — one-shot cancel outcomes (rendered as a snackbar; not part of the persistent state). */
sealed interface PayoutDetailEffect {
    data object CancelSucceeded : PayoutDetailEffect

    /** A cancel failure (e.g. the backend rejected a terminal/processing payout with a 4xx). */
    data class CancelFailed(val message: UiText?) : PayoutDetailEffect
}

/**
 * PAY-53 — payout statement/detail presentation.
 *
 * Fetches the REAL PAY-50 GET /ui/payouts/{payout_id} (lifecycle timeline + transfer ref + method
 * last-4 + fail/return/hold reason). The endpoint is user-scoped: a 404 (unknown) or 403 (not the
 * owner) resolves to [PayoutDetailUiState.NotFound] (a "reopen from history" state); network/5xx
 * resolves to a retryable [PayoutDetailUiState.Error]. This replaces the AND-260 cache-only detail —
 * a cold deep-link (e.g. a payout_paid notification tap) now resolves against the server directly.
 *
 * PAR-19 (cancel): [cancel] is a REVERSAL (NOT money-bearing, NOT routed through BillingAuthorizer). It
 * flips [PayoutDetailUiState.Content.cancelling] as an in-flight guard, calls the user-scoped
 * POST /ui/payouts/{id}/cancel, emits a one-shot [PayoutDetailEffect], then RELOADS the detail (the
 * backend is the source of truth for the new status). The backend rejects a terminal/processing payout
 * with a 4xx, which surfaces via [BillingErrorMapper] as a [PayoutDetailEffect.CancelFailed]. It no-ops
 * when there is no content or a cancel is already in flight.
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

    private val _effects = Channel<PayoutDetailEffect>(Channel.BUFFERED)
    val effects: Flow<PayoutDetailEffect> = _effects.receiveAsFlow()

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

    /**
     * PAR-19 — cancel this (cancelable) payout, then reload from the source of truth. No-ops when there
     * is no content or a cancel is already in flight; a failure keeps the current content and emits a
     * one-shot [PayoutDetailEffect.CancelFailed].
     */
    fun cancel() {
        val current = _uiState.value as? PayoutDetailUiState.Content ?: return
        if (current.cancelling) return
        if (current.detail.displayStatus !in CANCELABLE_STATUSES) return
        _uiState.value = current.copy(cancelling = true)
        viewModelScope.launch {
            when (val result = repository.cancelPayout(payoutId)) {
                is ApiResult.Success -> {
                    _effects.send(PayoutDetailEffect.CancelSucceeded)
                    // Re-read from the source of truth; load() drops the cancelling flag with the new Content.
                    load()
                }
                is ApiResult.Failure -> {
                    _uiState.value = current.copy(cancelling = false)
                    _effects.send(PayoutDetailEffect.CancelFailed(errorMapper.map(result).message))
                }
                is ApiResult.NetworkError -> {
                    _uiState.value = current.copy(cancelling = false)
                    _effects.send(PayoutDetailEffect.CancelFailed(errorMapper.map(result).message))
                }
            }
        }
    }

    companion object {
        const val ARG_PAYOUT_ID = "payoutId"

        /**
         * The statuses a user may cancel. Matches the backend user-scoped cancel guard (only a payout
         * still awaiting processing is cancelable). `pending` folds to [PayoutStatus.REQUESTED] in the
         * domain mapper, so REQUESTED covers both.
         */
        val CANCELABLE_STATUSES: Set<PayoutStatus> = setOf(PayoutStatus.REQUESTED)
    }
}
