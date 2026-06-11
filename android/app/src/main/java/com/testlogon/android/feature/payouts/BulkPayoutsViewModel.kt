package com.testlogon.android.feature.payouts

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.payouts.BulkPayoutsRepository
import com.testlogon.android.data.payouts.PayoutBatch
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-261 — READ-ONLY bulk-payout batch LIST state. */
sealed interface BulkListUiState {
    data object Loading : BulkListUiState
    data object Empty : BulkListUiState

    /** [stale] = a refresh failed but prior content is retained (FR-6). */
    data class Content(val batches: List<PayoutBatch>, val stale: Boolean = false) : BulkListUiState
    data class Error(val message: UiText) : BulkListUiState
}

/** AND-261 — READ-ONLY bulk-payout batch DETAIL state (header + embedded items in one response). */
sealed interface BulkBatchDetailUiState {
    data object Loading : BulkBatchDetailUiState
    data class Content(val batch: PayoutBatch) : BulkBatchDetailUiState
    data class Error(val message: UiText) : BulkBatchDetailUiState
}

/**
 * AND-261 — bulk-payout batch LIST presentation logic.
 *
 * Plain StateFlow<UiState> (NO Paging — the contract is not paged; the list is loaded whole). Matches
 * the consistent state/retry conventions of the other payout VMs (AND-262). Read-only: no mutating
 * intents exist. FR-6: a refresh failure with prior content retains the rows and flags them stale.
 */
@HiltViewModel
class BulkPayoutsListViewModel @Inject constructor(
    private val repo: BulkPayoutsRepository,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    private val _state = MutableStateFlow<BulkListUiState>(BulkListUiState.Loading)
    val state: StateFlow<BulkListUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun load() {
        val prior = (_state.value as? BulkListUiState.Content)?.batches
        if (prior == null) _state.value = BulkListUiState.Loading
        viewModelScope.launch {
            _state.value = when (val r = repo.getBatches()) {
                is ApiResult.Success ->
                    if (r.data.isEmpty()) BulkListUiState.Empty else BulkListUiState.Content(r.data)
                is ApiResult.Failure, is ApiResult.NetworkError ->
                    if (prior != null) {
                        BulkListUiState.Content(prior, stale = true)
                    } else {
                        BulkListUiState.Error(errorMapper.map(r).message)
                    }
            }
        }
    }

    fun retry() = load()
}

/**
 * AND-261 — bulk-payout batch DETAIL presentation logic.
 *
 * Reads `batchId` from [SavedStateHandle] and loads the full batch (header + embedded line items) in a
 * single GET — there is no independent items stream and no second failure path. Read-only.
 */
@HiltViewModel
class BulkPayoutDetailViewModel @Inject constructor(
    private val repo: BulkPayoutsRepository,
    private val errorMapper: BillingErrorMapper,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val batchId: String = checkNotNull(savedStateHandle[ARG_BATCH_ID]) {
        "BulkPayoutDetailViewModel requires a '$ARG_BATCH_ID' nav argument"
    }

    private val _state = MutableStateFlow<BulkBatchDetailUiState>(BulkBatchDetailUiState.Loading)
    val state: StateFlow<BulkBatchDetailUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun load() {
        // Retain prior content on a retry failure (non-destructive); otherwise show Loading.
        if (_state.value !is BulkBatchDetailUiState.Content) _state.value = BulkBatchDetailUiState.Loading
        viewModelScope.launch {
            _state.value = when (val r = repo.getBatch(batchId)) {
                is ApiResult.Success -> BulkBatchDetailUiState.Content(r.data)
                is ApiResult.Failure, is ApiResult.NetworkError ->
                    (_state.value as? BulkBatchDetailUiState.Content)
                        ?: BulkBatchDetailUiState.Error(errorMapper.map(r).message)
            }
        }
    }

    fun retry() = load()

    companion object {
        const val ARG_BATCH_ID = "batchId"
    }
}
