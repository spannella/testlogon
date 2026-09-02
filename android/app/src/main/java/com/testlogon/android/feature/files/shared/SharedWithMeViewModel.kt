package com.testlogon.android.feature.files.shared

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.SharedWithMeItemDto
import com.testlogon.android.feature.files.data.FileSharingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * FM-SHARE - state for the "Shared with me" screen. [available] = false means the sharing surface is not
 * enabled in this environment (degrade-on-404/403) and the UI shows an honest "not available" state.
 * [errorMessage] is only set for GENUINE failures (5xx/network). [items] are the inbound shares as they
 * arrive on the wire; the row renders permission + expiry via FileShareMath.
 */
data class SharedWithMeUiState(
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val available: Boolean = true,
    val items: List<SharedWithMeItemDto> = emptyList(),
    val errorMessage: String? = null,
) {
    val isEmpty: Boolean get() = items.isEmpty()
}

/**
 * FM-SHARE - presentation logic for the "Shared with me" surface. Loads the inbound shares on
 * construction (degrade-on-404/403 -> unavailable state); [refresh] re-fetches.
 */
@HiltViewModel
class SharedWithMeViewModel @Inject constructor(
    private val repository: FileSharingRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(SharedWithMeUiState(isLoading = true))
    val uiState: StateFlow<SharedWithMeUiState> = _uiState.asStateFlow()

    init {
        load(isRefresh = false)
    }

    fun refresh() = load(isRefresh = true)

    fun retry() = load(isRefresh = false)

    private fun load(isRefresh: Boolean) {
        _uiState.update {
            it.copy(isLoading = !isRefresh, isRefreshing = isRefresh, errorMessage = null)
        }
        viewModelScope.launch {
            when (val result = repository.sharedWithMe()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        items = result.data.items,
                        available = result.data.available,
                        isLoading = false,
                        isRefreshing = false,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(isLoading = false, isRefreshing = false, errorMessage = result.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(isLoading = false, isRefreshing = false, errorMessage = "Network error")
                }
            }
        }
    }
}
