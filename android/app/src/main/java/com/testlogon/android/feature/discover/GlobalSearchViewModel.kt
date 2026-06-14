package com.testlogon.android.feature.discover

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.discover.RecentSearch
import com.testlogon.android.data.discover.SearchEntityType
import com.testlogon.android.data.discover.SearchFilters
import com.testlogon.android.data.discover.SearchHistoryRepository
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
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-185 / AND-186 / AND-187 — global multi-entity search (distinct from the AND-152 message search).
 *
 * The query leg is debounced (300 ms) via the discover-package [debounceCompat] and routed through
 * [flatMapLatest] so the latest query wins and superseded requests are cancelled. Queries < 2 chars stay
 * Idle (no network — cuts chatter against the flaky dev host). Results are grouped into per-entity tabs;
 * the selected tab survives config change via [SavedStateHandle].
 *
 * AND-186 layers the filter / recent-searches surface onto the same ViewModel (the spec's interim
 * `SearchFilterController` is subsumed here, per AND-187 — the public state/intent surface is the one the
 * screen binds to):
 *  - [filters] holds the entity-type scope sent as the server `types` param (the ONLY server-side
 *    refinement; see [SearchFilters]). Changing it re-issues the query under the new scope without
 *    losing the query text. The active filter drives a badge + removable chips in the UI.
 *  - Idle (empty query) surfaces server-backed recent searches via [SearchHistoryRepository]; a
 *    successful non-empty search records its query to history; recents can be re-run / removed / cleared.
 *  - Empty results carry [MultiSearchUiState.Empty.filtersActive] so the UI can offer "Clear filters" /
 *    "Search everything" only when a non-default filter is set.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class GlobalSearchViewModel @Inject constructor(
    private val repository: SearchRepository,
    private val historyRepository: SearchHistoryRepository,
    private val saved: SavedStateHandle,
) : ViewModel() {

    private val _query = MutableStateFlow(saved.get<String>(KEY_QUERY).orEmpty())
    val query: StateFlow<String> = _query.asStateFlow()

    private val _selectedTab = MutableStateFlow(
        decodeTab(saved.get<String>(KEY_TAB)),
    )
    val selectedTab: StateFlow<MultiSearchTab> = _selectedTab.asStateFlow()

    private val _filters = MutableStateFlow(decodeFilters(saved.get<String>(KEY_FILTER)))
    val filters: StateFlow<SearchFilters> = _filters.asStateFlow()

    /** Server-backed recent searches, refreshed whenever the query goes empty / on init. */
    private val _recent = MutableStateFlow<List<RecentSearch>>(emptyList())
    val recent: StateFlow<List<RecentSearch>> = _recent.asStateFlow()

    /** Bumped by [retry] so an identical query re-issues (distinctUntilChanged would otherwise drop it). */
    private val retryTrigger = MutableStateFlow(0L)

    val uiState: StateFlow<MultiSearchUiState> =
        combine(
            _query.map { it.trim().take(MAX_QUERY_LENGTH) },
            _filters,
            retryTrigger,
        ) { q, filters, trigger -> Triple(q, filters, trigger) }
            .distinctUntilChanged()
            .debounceCompat(DEBOUNCE_MS)
            .flatMapLatest { (q, filters, _) ->
                if (q.length < MIN_QUERY_LENGTH) {
                    flowOf<MultiSearchUiState>(MultiSearchUiState.Idle)
                } else {
                    flow<MultiSearchUiState> {
                        emit(MultiSearchUiState.Loading)
                        emit(repository.search(q, filters).toUiState(q, filters))
                    }
                }
            }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), MultiSearchUiState.Idle)

    init {
        loadRecent()
    }

    fun onQueryChange(text: String) {
        _query.value = text
        saved[KEY_QUERY] = text
        if (text.isBlank()) loadRecent()
    }

    fun clearQuery() = onQueryChange("")

    fun onTabSelected(tab: MultiSearchTab) {
        _selectedTab.value = tab
        saved[KEY_TAB] = encodeTab(tab)
    }

    /** AND-186 — apply a (possibly non-default) entity filter; re-issues the current query under it. */
    fun applyFilters(filters: SearchFilters) {
        _filters.value = filters
        saved[KEY_FILTER] = encodeFilters(filters)
        // Keep the selected tab consistent with a single-entity scope so the UI doesn't show an
        // out-of-scope tab; ALL leaves the tab as-is.
        filters.entityType?.let { _selectedTab.value = MultiSearchTab.Category(it) }
    }

    /** AND-186 — reset filters to default (re-issues the un-scoped query) and snap the tab back to All. */
    fun clearFilters() {
        _filters.value = SearchFilters.DEFAULT
        saved[KEY_FILTER] = encodeFilters(SearchFilters.DEFAULT)
        _selectedTab.value = MultiSearchTab.All
        saved[KEY_TAB] = encodeTab(MultiSearchTab.All)
    }

    /** AND-186 — re-run a recent search term. */
    fun runRecent(query: String) {
        onQueryChange(query)
    }

    /** AND-186 — remove one recent entry by server item id, then refresh the list. */
    fun removeRecent(id: String) {
        viewModelScope.launch {
            historyRepository.remove(id)
            loadRecent()
        }
    }

    /** AND-186 — clear all recent searches. */
    fun clearRecent() {
        viewModelScope.launch {
            historyRepository.clear()
            loadRecent()
        }
    }

    /** Re-issue the current query (bumps [retryTrigger] so the same query re-runs). */
    fun retry() {
        retryTrigger.value = retryTrigger.value + 1L
    }

    private fun loadRecent() {
        viewModelScope.launch {
            _recent.value = historyRepository.recent()
        }
    }

    private fun ApiResult<SearchResults>.toUiState(query: String, filters: SearchFilters): MultiSearchUiState =
        when (this) {
            is ApiResult.Success ->
                if (data.isEmpty) {
                    MultiSearchUiState.Empty(query, filtersActive = !filters.isDefault)
                } else {
                    recordRecent(query, data.totalCount)
                    MultiSearchUiState.Success(data)
                }
            is ApiResult.Failure -> staleOr(query, filters) { MultiSearchUiState.Error(error.message, retryable = true) }
            is ApiResult.NetworkError -> staleOr(query, filters) { MultiSearchUiState.Error(OFFLINE_MESSAGE, retryable = true) }
        }

    /** Commit a successful search term to server history, then refresh the recent list. */
    private fun recordRecent(query: String, resultCount: Int) {
        viewModelScope.launch {
            historyRepository.record(query, resultCount)
            _recent.value = historyRepository.recent()
        }
    }

    private inline fun staleOr(query: String, filters: SearchFilters, terminal: () -> MultiSearchUiState): MultiSearchUiState {
        val cached = repository.cached(query, filters)
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

    private fun encodeFilters(filters: SearchFilters): String = filters.entityType?.name ?: FILTER_ALL

    private fun decodeFilters(value: String?): SearchFilters = when (value) {
        null, FILTER_ALL -> SearchFilters.DEFAULT
        else -> runCatching { SearchFilters(SearchEntityType.valueOf(value)) }
            .getOrDefault(SearchFilters.DEFAULT)
    }

    companion object {
        const val DEBOUNCE_MS = 300L
        const val MIN_QUERY_LENGTH = 2
        const val MAX_QUERY_LENGTH = 200
        const val OFFLINE_MESSAGE = "You're offline. Tap to retry."

        private const val KEY_QUERY = "global_search_query"
        private const val KEY_TAB = "global_search_tab"
        private const val KEY_FILTER = "global_search_filter"
        private const val TAB_ALL = "__ALL__"
        private const val FILTER_ALL = "__ALL__"
    }
}

/** AND-185 / AND-186 — the search screen state. */
sealed interface MultiSearchUiState {
    data object Idle : MultiSearchUiState
    data object Loading : MultiSearchUiState
    data class Success(val results: SearchResults, val stale: Boolean = false) : MultiSearchUiState

    /** Query ran, zero results for the current scope. [filtersActive] gates the "Clear filters" affordance. */
    data class Empty(val query: String, val filtersActive: Boolean = false) : MultiSearchUiState
    data class Error(val message: String, val retryable: Boolean) : MultiSearchUiState
}

/** AND-185 — the selected result tab. */
sealed interface MultiSearchTab {
    data object All : MultiSearchTab
    data class Category(val type: SearchEntityType) : MultiSearchTab
}
