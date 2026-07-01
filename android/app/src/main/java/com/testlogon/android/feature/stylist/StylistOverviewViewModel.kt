package com.testlogon.android.feature.stylist

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.stylist.DesignOverview
import com.testlogon.android.data.stylist.StylistRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives [StylistOverviewUiState] from [StylistRepository]. Loads overall + per-page design scores on
 * first composition / pull-to-refresh. "Run Review" triggers a full-page review of a default page set
 * (mirrors the web page) then reloads. Effects are Channel-backed.
 */
@HiltViewModel
class StylistOverviewViewModel @Inject constructor(
    private val repository: StylistRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(StylistOverviewUiState())
    val uiState: StateFlow<StylistOverviewUiState> = _uiState.asStateFlow()

    private val _effects = Channel<StylistEffect>(Channel.BUFFERED)
    val effects: Flow<StylistEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    fun onRunReview() {
        if (_uiState.value.isTriggering) return
        _uiState.update { it.copy(isTriggering = true) }
        viewModelScope.launch {
            val result = repository.triggerReview(DEFAULT_PAGES)
            _uiState.update { it.copy(isTriggering = false) }
            when (result) {
                is ApiResult.Success -> {
                    _effects.send(StylistEffect.ShowMessage(R.string.stylist_review_triggered))
                    load(fromUser = true)
                }
                is ApiResult.Failure ->
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = StylistOverviewUiState.Phase.SessionExpired) }
                    } else {
                        _effects.send(StylistEffect.ShowMessage(R.string.stylist_review_trigger_failed))
                    }
                is ApiResult.NetworkError ->
                    _effects.send(StylistEffect.ShowMessage(R.string.stylist_review_trigger_failed))
            }
        }
    }

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.overview != null
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else StylistOverviewUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
                errorMessage = if (hasContent) it.errorMessage else null,
            )
        }
        viewModelScope.launch {
            when (val result = repository.loadOverview()) {
                is ApiResult.Success -> reduceSuccess(result.data)
                is ApiResult.Failure ->
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update {
                            it.copy(phase = StylistOverviewUiState.Phase.SessionExpired, isRefreshing = false)
                        }
                    } else {
                        reduceFailure(result.error.message, offline = false)
                    }
                is ApiResult.NetworkError -> reduceFailure(OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private fun reduceSuccess(data: DesignOverview) {
        _uiState.update {
            it.copy(
                phase = if (data.isEmpty) StylistOverviewUiState.Phase.Empty else StylistOverviewUiState.Phase.Content,
                overview = data,
                isRefreshing = false,
                isStale = false,
                errorMessage = null,
            )
        }
    }

    private suspend fun reduceFailure(message: String, offline: Boolean) {
        val cached = repository.cachedOverview()
        if (cached != null) {
            _uiState.update {
                it.copy(
                    phase = if (cached.isEmpty) StylistOverviewUiState.Phase.Empty else StylistOverviewUiState.Phase.Content,
                    overview = cached,
                    isRefreshing = false,
                    isStale = true,
                    errorMessage = null,
                )
            }
            _effects.send(StylistEffect.ShowMessage(R.string.stylist_refresh_failed_stale))
        } else {
            _uiState.update {
                it.copy(
                    phase = if (offline) StylistOverviewUiState.Phase.Offline else StylistOverviewUiState.Phase.Error,
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
        private val DEFAULT_PAGES = listOf("/messages", "/feed", "/billing")
    }
}
