package com.testlogon.android.feature.marketing

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.marketing.MarketingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives [MarketingEngagementUiState] for the engagement dashboard (web
 * MarketingEngagementDashboardPage). Loads the 30-day engagement summary (totals + top-performing).
 */
@HiltViewModel
class MarketingEngagementViewModel @Inject constructor(
    private val repository: MarketingRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(MarketingEngagementUiState())
    val uiState: StateFlow<MarketingEngagementUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()

    private fun load() {
        _uiState.update { it.copy(phase = if (it.summary == null) MarketingEngagementUiState.Phase.Loading else it.phase) }
        viewModelScope.launch {
            when (val result = repository.loadEngagement(DAYS)) {
                is ApiResult.Success ->
                    _uiState.update {
                        it.copy(phase = MarketingEngagementUiState.Phase.Content, summary = result.data, errorMessage = null)
                    }
                is ApiResult.Failure ->
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = MarketingEngagementUiState.Phase.SessionExpired) }
                    } else {
                        _uiState.update {
                            it.copy(phase = MarketingEngagementUiState.Phase.Error, errorMessage = result.error.message)
                        }
                    }
                is ApiResult.NetworkError ->
                    _uiState.update {
                        it.copy(phase = MarketingEngagementUiState.Phase.Offline, errorMessage = OFFLINE_FALLBACK)
                    }
            }
        }
    }

    private companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val DAYS = 30
        private const val OFFLINE_FALLBACK = "Could not reach the server. Retry."
    }
}
