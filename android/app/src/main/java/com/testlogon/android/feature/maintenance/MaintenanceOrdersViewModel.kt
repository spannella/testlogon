package com.testlogon.android.feature.maintenance

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * WOV — presentation logic for the Maintenance Work Orders list + create + status MVP.
 *
 * READ: [load] / [refresh] read the system-wide list ONCE (no poll loop). WRITE: [create] posts a
 * property-scoped work order and [transition] moves a work order's status; both refresh the list on
 * success and emit a one-shot event. DEGRADE-ON-404 is handled by [foldOrdersResult] (-> Unavailable).
 */
@HiltViewModel
class MaintenanceOrdersViewModel @Inject constructor(
    private val repository: MaintenanceOrdersRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<MaintenanceOrdersUiState>(MaintenanceOrdersUiState.Loading)
    val uiState: StateFlow<MaintenanceOrdersUiState> = _uiState.asStateFlow()

    private val _events = Channel<MaintenanceEvent>(Channel.BUFFERED)
    val events: Flow<MaintenanceEvent> = _events.receiveAsFlow()

    private var loadJob: Job? = null
    private var writeJob: Job? = null

    init {
        load()
    }

    fun load() {
        if (_uiState.value !is MaintenanceOrdersUiState.Content) {
            _uiState.value = MaintenanceOrdersUiState.Loading
        }
        fetch(showRefreshing = false)
    }

    fun refresh() {
        (_uiState.value as? MaintenanceOrdersUiState.Content)?.let {
            _uiState.value = it.copy(isRefreshing = true)
        }
        fetch(showRefreshing = true)
    }

    private fun fetch(showRefreshing: Boolean) {
        loadJob?.cancel()
        loadJob = viewModelScope.launch {
            when (val result = repository.list()) {
                is ApiResult.Success -> _uiState.value = foldOrdersResult(result.data, null)
                is ApiResult.Failure -> onLoadError(result.error, showRefreshing)
                is ApiResult.NetworkError ->
                    onLoadError(ApiError(ApiError.STATUS_NETWORK, NETWORK_MESSAGE), showRefreshing)
            }
        }
    }

    private fun onLoadError(error: ApiError, wasRefreshing: Boolean) {
        val current = _uiState.value
        // Keep prior content visible on a refresh failure (stale display); otherwise fold to the state.
        _uiState.value = if (wasRefreshing && current is MaintenanceOrdersUiState.Content) {
            current.copy(isRefreshing = false, staleError = error)
        } else {
            foldOrdersResult(null, error)
        }
    }

    /** Create a property-scoped work order; refreshes the list on success. Guards double-submit. */
    fun create(
        propertyId: String,
        title: String,
        description: String?,
        priority: WoPriority,
    ) {
        if (propertyId.isBlank() || title.isBlank()) return
        if (writeJob?.isActive == true) return
        writeJob = viewModelScope.launch {
            when (val result = repository.create(propertyId, title, description, priority)) {
                is ApiResult.Success -> {
                    _events.send(MaintenanceEvent.Created(result.data.workOrderId))
                    fetch(showRefreshing = false)
                }
                is ApiResult.Failure -> _events.send(MaintenanceEvent.WriteFailed(result.error.message))
                is ApiResult.NetworkError -> _events.send(MaintenanceEvent.WriteFailed(NETWORK_MESSAGE))
            }
        }
    }

    /** Transition a work order; no-op when the transition is illegal. Refreshes on success. */
    fun transition(order: MaintenanceOrder, target: WoStatus) {
        if (!canTransition(order.status, target)) return
        if (writeJob?.isActive == true) return
        writeJob = viewModelScope.launch {
            when (val result = repository.transition(order.workOrderId, order.propertyId, target)) {
                is ApiResult.Success -> {
                    _events.send(MaintenanceEvent.Transitioned(order.workOrderId, target))
                    fetch(showRefreshing = false)
                }
                is ApiResult.Failure -> _events.send(MaintenanceEvent.WriteFailed(result.error.message))
                is ApiResult.NetworkError -> _events.send(MaintenanceEvent.WriteFailed(NETWORK_MESSAGE))
            }
        }
    }

    private companion object {
        const val NETWORK_MESSAGE = "Couldn't reach the server. Try again."
    }
}

/** One-shot events for the maintenance surface. */
sealed interface MaintenanceEvent {
    data class Created(val workOrderId: String) : MaintenanceEvent
    data class Transitioned(val workOrderId: String, val target: WoStatus) : MaintenanceEvent
    data class WriteFailed(val message: String) : MaintenanceEvent
}
