package com.testlogon.android.feature.syndicates.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.syndicates.SyndicateDiscoverItem
import com.testlogon.android.feature.syndicates.data.SyndicateRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * PAR-35(a) - render-ready state for the "Discover" syndicates tab. Mutually-exclusive surfaces mirror the
 * My-syndicates list. [Content.isRefreshing] drives pull-to-refresh.
 */
sealed interface SyndicateDiscoverUiState {
    data object Loading : SyndicateDiscoverUiState
    data class Content(
        val items: List<SyndicateDiscoverItem>,
        val isRefreshing: Boolean = false,
        val staleError: ApiError? = null,
    ) : SyndicateDiscoverUiState
    data object Empty : SyndicateDiscoverUiState
    data class Error(val error: ApiError) : SyndicateDiscoverUiState
}

/**
 * PAR-35(a) - drives the Discover tab (GET ui/syndicates/discover). LAZY: [ensureLoaded] triggers the first
 * fetch only when the tab is first shown (so opening the My-syndicates tab never fires discover). refresh()
 * keeps the cached list on failure and surfaces a non-fatal staleError banner. There is NO poll loop and
 * discover mirrors the list-VM reduce shape. limit defaults to 50 (server clamps 1..100).
 */
@HiltViewModel
class SyndicateDiscoverViewModel @Inject constructor(
    private val repository: SyndicateRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<SyndicateDiscoverUiState>(SyndicateDiscoverUiState.Loading)
    val uiState: StateFlow<SyndicateDiscoverUiState> = _uiState.asStateFlow()

    private var started = false

    /** Loads the discover list ONCE (the first time the Discover tab is shown). Idempotent. */
    fun ensureLoaded() {
        if (started) return
        started = true
        load(isRefresh = false)
    }

    fun retry() {
        started = true
        load(isRefresh = false)
    }

    fun refresh() {
        val cached = _uiState.value as? SyndicateDiscoverUiState.Content
        if (cached != null) _uiState.value = cached.copy(isRefreshing = true, staleError = null)
        load(isRefresh = true)
    }

    private fun load(isRefresh: Boolean) {
        val cached = _uiState.value as? SyndicateDiscoverUiState.Content
        if (cached == null && !isRefresh) _uiState.value = SyndicateDiscoverUiState.Loading
        viewModelScope.launch {
            when (val result = repository.discover(limit = DISCOVER_LIMIT)) {
                is ApiResult.Success -> _uiState.value = reduceSuccess(result.data)
                is ApiResult.Failure -> _uiState.value = reduceFailure(result.error, isRefresh, cached)
                is ApiResult.NetworkError ->
                    _uiState.value = reduceFailure(networkError(), isRefresh, cached)
            }
        }
    }

    private fun reduceSuccess(items: List<SyndicateDiscoverItem>): SyndicateDiscoverUiState =
        if (items.isEmpty()) {
            SyndicateDiscoverUiState.Empty
        } else {
            SyndicateDiscoverUiState.Content(items = items, isRefreshing = false, staleError = null)
        }

    private fun reduceFailure(
        error: ApiError,
        isRefresh: Boolean,
        cached: SyndicateDiscoverUiState.Content?,
    ): SyndicateDiscoverUiState =
        if (isRefresh && cached != null) {
            cached.copy(isRefreshing = false, staleError = error)
        } else {
            SyndicateDiscoverUiState.Error(error)
        }

    private fun networkError(): ApiError =
        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    private companion object {
        const val DISCOVER_LIMIT = 50
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
