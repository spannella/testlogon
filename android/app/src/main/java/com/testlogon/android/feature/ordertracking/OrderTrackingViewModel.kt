package com.testlogon.android.feature.ordertracking

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.ordertracking.OrderTrackingRepository
import com.testlogon.android.feature.tracking.TrackingUiState
import com.testlogon.android.feature.tracking.TrackingViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * D4 - BUYER order-tracking presentation. Reads the ship-group id from nav args, loads the tracking
 * record, and reuses the shared [TrackingUiState] + [TrackingViewModel.reduce] reducer (so the D4
 * ship-group tracking and the AND-215 per-transaction tracking share one state contract).
 */
@HiltViewModel
class OrderTrackingViewModel @Inject constructor(
    private val repository: OrderTrackingRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val shipGroupId: String = savedState[ARG_SHIP_GROUP] ?: ""

    private val _state = MutableStateFlow<TrackingUiState>(TrackingUiState.Loading)
    val state: StateFlow<TrackingUiState> = _state.asStateFlow()

    init { load() }

    fun load() {
        if (shipGroupId.isBlank()) {
            _state.value = TrackingUiState.Error("Couldn't load tracking.", retryable = false)
            return
        }
        _state.value = TrackingUiState.Loading
        viewModelScope.launch {
            _state.value = TrackingViewModel.reduce(repository.tracking(shipGroupId))
        }
    }

    fun retry() = load()

    companion object {
        const val ARG_SHIP_GROUP = "shipGroup"
    }
}
