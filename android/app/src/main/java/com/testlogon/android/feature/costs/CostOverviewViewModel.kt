package com.testlogon.android.feature.costs

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.costs.CostOverview
import com.testlogon.android.data.costs.CostsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Drives [CostOverviewUiState] from [CostsRepository]. Mirrors the web CostOverviewPage. */
@HiltViewModel
class CostOverviewViewModel @Inject constructor(
    private val repository: CostsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(CostOverviewUiState())
    val uiState: StateFlow<CostOverviewUiState> = _uiState.asStateFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.overview != null
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else CostsPhase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch {
            when (val result = repository.loadOverview()) {
                is ApiResult.Success -> reduceSuccess(result.data)
                is ApiResult.Failure ->
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = CostsPhase.SessionExpired, isRefreshing = false) }
                    } else {
                        reduceFailure(result.error.message, offline = false)
                    }
                is ApiResult.NetworkError -> reduceFailure(OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private fun reduceSuccess(data: CostOverview) {
        _uiState.update {
            it.copy(
                phase = if (data.isEmpty) CostsPhase.Empty else CostsPhase.Content,
                overview = data,
                isRefreshing = false,
                isStale = false,
                errorMessage = null,
            )
        }
    }

    private fun reduceFailure(message: String, offline: Boolean) {
        val cached = repository.cachedOverview()
        if (cached != null) {
            _uiState.update {
                it.copy(
                    phase = if (cached.isEmpty) CostsPhase.Empty else CostsPhase.Content,
                    overview = cached,
                    isRefreshing = false,
                    isStale = true,
                    errorMessage = null,
                )
            }
        } else {
            _uiState.update {
                it.copy(
                    phase = if (offline) CostsPhase.Offline else CostsPhase.Error,
                    overview = null,
                    isRefreshing = false,
                    isStale = false,
                    errorMessage = message,
                )
            }
        }
    }

    private companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Could not reach the server. Pull down to retry."
    }
}
