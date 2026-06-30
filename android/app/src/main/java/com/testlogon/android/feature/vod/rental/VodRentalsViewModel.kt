package com.testlogon.android.feature.vod.rental

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.vod.rental.VodRentalRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives [VodRentalsUiState] for the "My Rentals" screen. Loads the caller's rentals (GET ui/vod/rental/list)
 * via the existing [VodRentalRepository]; pull-to-refresh / retry re-fetch. Read-only — no payment path here.
 */
@HiltViewModel
class VodRentalsViewModel @Inject constructor(
    private val repo: VodRentalRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<VodRentalsUiState>(VodRentalsUiState.Loading)
    val uiState: StateFlow<VodRentalsUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun load() {
        _uiState.value = VodRentalsUiState.Loading
        viewModelScope.launch {
            _uiState.value = when (val result = repo.listItems()) {
                is ApiResult.Success -> VodRentalsUiState.Content(result.data)
                is ApiResult.Failure -> VodRentalsUiState.Error(result.error.message)
                is ApiResult.NetworkError -> VodRentalsUiState.Error(NETWORK_MESSAGE)
            }
        }
    }

    private companion object {
        const val NETWORK_MESSAGE = "Couldn't reach the server. Check your connection and try again."
    }
}
