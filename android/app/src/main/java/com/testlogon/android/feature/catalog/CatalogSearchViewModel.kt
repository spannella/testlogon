package com.testlogon.android.feature.catalog

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.data.catalog.CatalogApi
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.catalog.CatalogRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map
import javax.inject.Inject

/**
 * AND-207 / AND-208 — catalog search presentation logic.
 *
 * The query string is held in [SavedStateHandle] (survives process death) and mirrored into [query] for
 * the field. The paged result stream debounces 300 ms via the catalog-package [debounceCompat], trims,
 * de-duplicates, and gates on a 2-char minimum (below it, an empty page — no network) so chatter against
 * the flaky dev host is cut. [flatMapLatest] cancels the in-flight Pager when the query changes so stale
 * results never overwrite newer ones; [cachedIn] keeps loaded pages across config change. Distinct from
 * the AND-185 global multi-entity search (this hits ui/catalog/items/search and returns catalog items
 * only). The screen derives Idle/Loading/Content/Empty/Error from [query] + the LazyPagingItems
 * load-state; [searchUiState] is the pure, unit-testable derivation.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class CatalogSearchViewModel @Inject constructor(
    private val repository: CatalogRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val _query = MutableStateFlow(savedState.get<String>(KEY_QUERY).orEmpty())
    val query: StateFlow<String> = _query.asStateFlow()

    val results: Flow<PagingData<CatalogItem>> =
        _query
            .map { it.trim() }
            .debounceCompat(DEBOUNCE_MS)
            .distinctUntilChanged()
            .flatMapLatest { q ->
                if (q.length < MIN_QUERY_LENGTH) {
                    flowOf(PagingData.empty<CatalogItem>())
                } else {
                    Pager(
                        config = PagingConfig(
                            pageSize = CatalogApi.PAGE_SIZE,
                            initialLoadSize = CatalogApi.PAGE_SIZE,
                            prefetchDistance = PREFETCH_DISTANCE,
                            enablePlaceholders = false,
                        ),
                        pagingSourceFactory = { CatalogSearchPagingSource(repository, q) },
                    ).flow
                }
            }
            .cachedIn(viewModelScope)

    fun onQueryChange(text: String) {
        _query.value = text
        savedState[KEY_QUERY] = text
    }

    fun onClear() = onQueryChange("")

    companion object {
        const val DEBOUNCE_MS = 300L
        const val MIN_QUERY_LENGTH = 2
        private const val PREFETCH_DISTANCE = 6
        private const val KEY_QUERY = "catalog_search_query"
    }
}

/** AND-207 — the search screen's high-level phase, derived from the query + paging load-state. */
sealed interface CatalogSearchUiState {
    /** Query blank / below the minimum length — neutral "type to search" prompt, no request. */
    data object Idle : CatalogSearchUiState
    data object Loading : CatalogSearchUiState
    data class Content(val query: String) : CatalogSearchUiState
    data class Empty(val query: String) : CatalogSearchUiState
    data class Error(val message: String, val retryable: Boolean) : CatalogSearchUiState
}

/**
 * AND-207 — pure derivation of [CatalogSearchUiState] from the trimmed [query], the paging
 * refresh-load-state ([refreshLoading]/[refreshError] + [errorMessage]/[retryable]), and [itemCount].
 * Extracted so the state machine is unit-testable without Compose.
 */
fun searchUiState(
    query: String,
    refreshLoading: Boolean,
    refreshError: Boolean,
    errorMessage: String?,
    retryable: Boolean,
    itemCount: Int,
): CatalogSearchUiState {
    val trimmed = query.trim()
    return when {
        trimmed.length < CatalogSearchViewModel.MIN_QUERY_LENGTH -> CatalogSearchUiState.Idle
        refreshError && itemCount == 0 ->
            CatalogSearchUiState.Error(errorMessage ?: "", retryable = retryable)
        refreshLoading && itemCount == 0 -> CatalogSearchUiState.Loading
        itemCount == 0 -> CatalogSearchUiState.Empty(trimmed)
        else -> CatalogSearchUiState.Content(trimmed)
    }
}
