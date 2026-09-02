package com.testlogon.android.feature.maintenance

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * WOV-004 — presentation logic for the Maintenance Vendor directory (list + create + status toggle).
 *
 * READ: [load] / [refresh] read the vendor list ONCE (no poll loop). WRITE: [createVendor] posts a new
 * vendor and [toggleStatus] flips a vendor active/inactive; both refresh on success and emit a one-shot
 * event. DEGRADE-ON-404 is handled by [foldVendorsResult] (-> Unavailable). Trade categories are loaded
 * best-effort for the create form; a failure just leaves the fallback category list.
 */
@HiltViewModel
class VendorsViewModel @Inject constructor(
    private val repository: MaintenanceOrdersRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<VendorsUiState>(VendorsUiState.Loading)
    val uiState: StateFlow<VendorsUiState> = _uiState.asStateFlow()

    private val _categories = MutableStateFlow<List<String>>(FALLBACK_CATEGORIES)
    val categories: StateFlow<List<String>> = _categories.asStateFlow()

    private val _events = Channel<VendorEvent>(Channel.BUFFERED)
    val events: Flow<VendorEvent> = _events.receiveAsFlow()

    private var loadJob: Job? = null
    private var writeJob: Job? = null

    init {
        load()
        loadCategories()
    }

    fun load() {
        if (_uiState.value !is VendorsUiState.Content) {
            _uiState.value = VendorsUiState.Loading
        }
        fetch(showRefreshing = false)
    }

    fun refresh() {
        (_uiState.value as? VendorsUiState.Content)?.let {
            _uiState.value = it.copy(isRefreshing = true)
        }
        fetch(showRefreshing = true)
    }

    private fun fetch(showRefreshing: Boolean) {
        loadJob?.cancel()
        loadJob = viewModelScope.launch {
            when (val result = repository.listVendors()) {
                is ApiResult.Success -> _uiState.value = foldVendorsResult(result.data, null)
                is ApiResult.Failure -> onLoadError(result.error, showRefreshing)
                is ApiResult.NetworkError ->
                    onLoadError(ApiError(ApiError.STATUS_NETWORK, NETWORK_MESSAGE), showRefreshing)
            }
        }
    }

    private fun onLoadError(error: ApiError, wasRefreshing: Boolean) {
        val current = _uiState.value
        _uiState.value = if (wasRefreshing && current is VendorsUiState.Content) {
            current.copy(isRefreshing = false, staleError = error)
        } else {
            foldVendorsResult(null, error)
        }
    }

    private fun loadCategories() {
        viewModelScope.launch {
            (repository.vendorCategories() as? ApiResult.Success)?.data
                ?.takeIf { it.isNotEmpty() }
                ?.let { _categories.value = it }
        }
    }

    /** Create a vendor; refreshes the list on success. Guards double-submit. */
    fun createVendor(name: String, tradeCategory: String, email: String?, phone: String?) {
        if (name.isBlank() || tradeCategory.isBlank()) return
        if (writeJob?.isActive == true) return
        writeJob = viewModelScope.launch {
            when (val result = repository.createVendor(name.trim(), tradeCategory, email, phone)) {
                is ApiResult.Success -> {
                    _events.send(VendorEvent.Created(result.data.vendorId))
                    fetch(showRefreshing = false)
                }
                is ApiResult.Failure -> _events.send(VendorEvent.WriteFailed(result.error.message))
                is ApiResult.NetworkError -> _events.send(VendorEvent.WriteFailed(NETWORK_MESSAGE))
            }
        }
    }

    /** Flip a vendor active<->inactive; no-op when the toggle is not a real mutation. Refreshes on success. */
    fun toggleStatus(vendor: Vendor) {
        val target = vendor.status.toggleTarget
        if (!canSetVendorStatus(vendor.status, target)) return
        if (writeJob?.isActive == true) return
        writeJob = viewModelScope.launch {
            when (val result = repository.setVendorStatus(vendor.vendorId, target)) {
                is ApiResult.Success -> {
                    _events.send(VendorEvent.StatusChanged(vendor.vendorId, target))
                    fetch(showRefreshing = false)
                }
                is ApiResult.Failure -> _events.send(VendorEvent.WriteFailed(result.error.message))
                is ApiResult.NetworkError -> _events.send(VendorEvent.WriteFailed(NETWORK_MESSAGE))
            }
        }
    }

    private companion object {
        const val NETWORK_MESSAGE = "Couldn't reach the server. Try again."
        val FALLBACK_CATEGORIES = listOf(
            "plumbing", "electrical", "hvac", "handyman", "cleaning", "landscaping", "general",
        )
    }
}

/** One-shot events for the vendor directory surface. */
sealed interface VendorEvent {
    data class Created(val vendorId: String) : VendorEvent
    data class StatusChanged(val vendorId: String, val target: VendorStatus) : VendorEvent
    data class WriteFailed(val message: String) : VendorEvent
}
