package com.testlogon.android.feature.tracking

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.tracking.Shipment
import com.testlogon.android.data.tracking.TrackingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-215 — tracking section state. Designed to be consumed standalone (this route) or hoisted into a
 * future PurchaseDetailViewModel (AND-218) without change.
 *
 * NotShipped is a distinct, non-error state for a 200 with null carrier/tracking (FR-2 / AC-2).
 */
sealed interface TrackingUiState {
    data object Loading : TrackingUiState
    data class Ready(val shipment: Shipment) : TrackingUiState
    data object NotShipped : TrackingUiState
    data class Error(val message: String, val retryable: Boolean) : TrackingUiState
}

/**
 * AND-215 — carrier-tracking presentation logic. Reads the transaction id from nav args and exposes a
 * single [TrackingUiState]. Read-only; the refresh path is a plain GET (poll is out of scope).
 */
@HiltViewModel
class TrackingViewModel @Inject constructor(
    private val repository: TrackingRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val txnId: String = savedState[ARG_TXN_ID] ?: ""

    private val _state = MutableStateFlow<TrackingUiState>(TrackingUiState.Loading)
    val state: StateFlow<TrackingUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun load() {
        if (txnId.isBlank()) {
            _state.value = TrackingUiState.Error(GENERIC_ERROR, retryable = false)
            return
        }
        _state.update { TrackingUiState.Loading }
        viewModelScope.launch {
            _state.value = reduce(repository.tracking(txnId))
        }
    }

    fun retry() = load()

    companion object {
        const val ARG_TXN_ID = "txnId"
        private const val GENERIC_ERROR = "Couldn't load tracking."
        private const val NOT_FOUND = "Order not found"
        private const val OFFLINE = "You're offline"

        /** Pure reducer: ApiResult -> TrackingUiState. Shared so tests don't need the VM/coroutines. */
        fun reduce(result: ApiResult<com.testlogon.android.data.tracking.CarrierTracking>): TrackingUiState =
            when (result) {
                is ApiResult.Success ->
                    result.data.shipment?.let { TrackingUiState.Ready(it) } ?: TrackingUiState.NotShipped
                is ApiResult.Failure -> {
                    // 404 is documented-assumption non-retryable; other server errors are retryable.
                    val retryable = result.error.status != 404
                    val message = if (result.error.status == 404) NOT_FOUND else result.error.message
                    TrackingUiState.Error(message, retryable = retryable)
                }
                is ApiResult.NetworkError -> TrackingUiState.Error(OFFLINE, retryable = true)
            }
    }
}
