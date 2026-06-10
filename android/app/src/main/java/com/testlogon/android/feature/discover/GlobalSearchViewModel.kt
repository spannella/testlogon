package com.testlogon.android.feature.discover

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.discover.SearchEntityType
import com.testlogon.android.data.discover.SearchRepository
import com.testlogon.android.data.discover.SearchResults
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

/**
 * AND-185 — global multi-entity search (distinct from the AND-152 message search).
 *
 * The query leg is debounced (300 ms) via the discover-package [debounceCompat] and routed through
 * [flatMapLatest] so the latest query wins and superseded requests are cancelled. Queries < 2 chars stay
 * Idle (no network — cuts chatter against the flaky dev host). Results are grouped into per-entity tabs;
 * the selected tab survives config change via [SavedStateHandle].
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class GlobalSearchViewModel @Inject constructor(
    private val repository: SearchRepository,
    private val saved: SavedStateHandle,
) : ViewModel() {

    private val _query = MutableStateFlow(saved.get<String>(KEY_QUERY).orEmpty())
    val query: StateFlow<String> = _query.asStateFlow()

    private val _selectedTab = MutableStateFlow(
        decodeTab(saved.get<String>(KEY_TAB)),
    )
    val selectedTab: StateFlow<MultiSearchTab> = _selectedTab.asStateFlow()

    /** Bumped by [retry] so an identical query re-issues (distinctUntilChanged would otherwise drop it). */
    private val retryTrigger = MutableStateFlow(0L)

    val uiState: StateFlow<MultiSearchUiState> =
        combine(
            _query.map { it.trim().take(MAX_QUERY_LENGTH) },
            retryTrigger,
        ) { q, trigger -> q to trigger }
            .distinctUntilChanged()
            .debounceCompat(DEBOUNCE_MS)
            .flatMapLatest { (q, _) ->
                if (q.length < MIN_QUERY_LENGTH) {
                    flowOf<MultiSearchUiState>(MultiSearchUiState.Idle)
                } else {
                    flow<MultiSearchUiState> {
                        emit(MultiSearchUiState.Loading)
                        emit(repository.search(q).toUiState(q))
                    }
                }
            }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), MultiSearchUiState.Idle)

    fun onQueryChange(text: String) {
        _query.value = text
        saved[KEY_QUERY] = text
    }

    fun clearQuery() = onQueryChange("")

    fun onTabSelected(tab: MultiSearchTab) {
        _selectedTab.value = tab
        saved[KEY_TAB] = encodeTab(tab)
    }

    /** Re-issue the current query (bumps [retryTrigger] so the same query re-runs). */
    fun retry() {
        retryTrigger.value = retryTrigger.value + 1L
    }

    private fun ApiResult<SearchResults>.toUiState(query: String): MultiSearchUiState = when (this) {
        is ApiResult.Success ->
            if (data.isEmpty) MultiSearchUiState.Empty(query)
            else MultiSearchUiState.Success(data)
        is ApiResult.Failure -> staleOr(query) { MultiSearchUiState.Error(error.message, retryable = true) }
        is ApiResult.NetworkError -> staleOr(query) { MultiSearchUiState.Error(OFFLINE_MESSAGE, retryable = true) }
    }

    private inline fun staleOr(query: String, terminal: () -> MultiSearchUiState): MultiSearchUiState {
        val cached = repository.cached(query)
        return if (cached != null && !cached.isEmpty) MultiSearchUiState.Success(cached, stale = true) else terminal()
    }

    private fun encodeTab(tab: MultiSearchTab): String = when (tab) {
        MultiSearchTab.All -> TAB_ALL
        is MultiSearchTab.Category -> tab.type.name
    }

    private fun decodeTab(value: String?): MultiSearchTab = when (value) {
        null, TAB_ALL -> MultiSearchTab.All
        else -> runCatching { MultiSearchTab.Category(SearchEntityType.valueOf(value)) }
            .getOrDefault(MultiSearchTab.All)
    }

    companion object {
        const val DEBOUNCE_MS = 300L
        const val MIN_QUERY_LENGTH = 2
        const val MAX_QUERY_LENGTH = 200
        const val OFFLINE_MESSAGE = "You're offline. Tap to retry."

        private const val KEY_QUERY = "global_search_query"
        private const val KEY_TAB = "global_search_tab"
        private const val TAB_ALL = "__ALL__"
    }
}

/** AND-185 — the search screen state. */
sealed interface MultiSearchUiState {
    data object Idle : MultiSearchUiState
    data object Loading : MultiSearchUiState
    data class Success(val results: SearchResults, val stale: Boolean = false) : MultiSearchUiState
    data class Empty(val query: String) : MultiSearchUiState
    data class Error(val message: String, val retryable: Boolean) : MultiSearchUiState
}

/** AND-185 — the selected result tab. */
sealed interface MultiSearchTab {
    data object All : MultiSearchTab
    data class Category(val type: SearchEntityType) : MultiSearchTab
}
