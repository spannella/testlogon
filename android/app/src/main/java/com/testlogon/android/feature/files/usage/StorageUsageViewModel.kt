package com.testlogon.android.feature.files.usage

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.UsageDailyItemDto
import com.testlogon.android.core.model.files.UsageStorageFileDto
import com.testlogon.android.feature.files.data.FileSharingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * FM-SHARE - state for the file-manager Storage-usage screen. [available] = false means the usage
 * surface is not enabled in this environment (degrade-on-404/403) and the UI shows an honest "not
 * available" state instead of an error. [errorMessage] is only set for GENUINE failures (5xx/network).
 * The screen renders the current total, the heaviest [topFiles], and the recent per-day [dailyRows].
 */
data class StorageUsageUiState(
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val available: Boolean = true,
    val storageBytesCurrent: Long = 0,
    val topFiles: List<UsageStorageFileDto> = emptyList(),
    val dailyRows: List<UsageDailyItemDto> = emptyList(),
    val rangeFrom: String? = null,
    val rangeTo: String? = null,
    val errorMessage: String? = null,
) {
    val isEmpty: Boolean get() = topFiles.isEmpty() && dailyRows.isEmpty() && storageBytesCurrent == 0L
}

/**
 * FM-SHARE - presentation logic for the Storage-usage surface. Loads the storage snapshot
 * (usage/storage) and the recent daily rows (usage/daily) on construction; [refresh] re-fetches. Both
 * reads degrade-on-404/403 in the repository; if EITHER reports the surface unavailable the screen shows
 * the "not available here" state.
 */
@HiltViewModel
class StorageUsageViewModel @Inject constructor(
    private val repository: FileSharingRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(StorageUsageUiState(isLoading = true))
    val uiState: StateFlow<StorageUsageUiState> = _uiState.asStateFlow()

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
            val storageResult = repository.usageStorage(topN = TOP_FILES)
            val dailyResult = repository.usageDaily()

            // A GENUINE failure on either read wins over a partial render.
            val genuineError = firstErrorMessage(storageResult, dailyResult)
            if (genuineError != null) {
                _uiState.update {
                    it.copy(isLoading = false, isRefreshing = false, errorMessage = genuineError)
                }
                return@launch
            }

            val storage = (storageResult as? ApiResult.Success)?.data
            val daily = (dailyResult as? ApiResult.Success)?.data
            val available = (storage?.available ?: false) && (daily?.available ?: false)

            _uiState.update {
                it.copy(
                    isLoading = false,
                    isRefreshing = false,
                    available = available,
                    storageBytesCurrent = storage?.storage?.storage_bytes_current ?: 0L,
                    topFiles = storage?.storage?.top_files.orEmpty(),
                    dailyRows = daily?.daily?.items.orEmpty(),
                    rangeFrom = daily?.daily?.from,
                    rangeTo = daily?.daily?.to,
                    errorMessage = null,
                )
            }
        }
    }

    /** The first GENUINE (non-degrade) error across the two reads, or null if both are Success. */
    private fun firstErrorMessage(vararg results: ApiResult<*>): String? {
        for (r in results) {
            when (r) {
                is ApiResult.Failure -> return r.error.message
                is ApiResult.NetworkError -> return "Network error"
                is ApiResult.Success -> Unit
            }
        }
        return null
    }

    private companion object {
        const val TOP_FILES = 10
    }
}
