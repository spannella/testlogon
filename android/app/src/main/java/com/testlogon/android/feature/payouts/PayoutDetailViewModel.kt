package com.testlogon.android.feature.payouts

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import com.testlogon.android.data.payouts.Payout
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject

/** AND-260 — payout detail screen state. */
sealed interface PayoutDetailUiState {
    data class Content(val payout: Payout) : PayoutDetailUiState

    /** The row was not in the cache (cold deep-link / evicted) — there is no GET ui/payouts/{id}. */
    data object NotFound : PayoutDetailUiState
}

/**
 * AND-260 — payout detail presentation logic.
 *
 * There is NO GET ui/payouts/{payout_id} endpoint, so the detail is hydrated entirely from the
 * [PayoutCache] row the history pager already loaded (zero network calls). A cache miss (cold
 * deep-link) resolves to [PayoutDetailUiState.NotFound] -> a "reopen from history" state (R7).
 */
@HiltViewModel
class PayoutDetailViewModel @Inject constructor(
    cache: PayoutCache,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val payoutId: String = checkNotNull(savedStateHandle[ARG_PAYOUT_ID]) {
        "PayoutDetailViewModel requires a '$ARG_PAYOUT_ID' nav argument"
    }

    private val _uiState = MutableStateFlow(
        cache.get(payoutId)?.let { PayoutDetailUiState.Content(it) } ?: PayoutDetailUiState.NotFound,
    )
    val uiState: StateFlow<PayoutDetailUiState> = _uiState.asStateFlow()

    companion object {
        const val ARG_PAYOUT_ID = "payoutId"
    }
}
