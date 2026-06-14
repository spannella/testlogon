package com.testlogon.android.feature.purchases

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.data.purchases.PurchaseListItem
import com.testlogon.android.data.purchases.PurchasesApi
import com.testlogon.android.data.purchases.PurchasesRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.map
import javax.inject.Inject

/**
 * AND-221 / AND-219 — purchase-history + search presentation logic.
 *
 * The query is held in [SavedStateHandle] (survives process death / config change) and mirrored into
 * [query] for the field. The paged stream debounces 300 ms via the purchases-package [debounceCompat],
 * trims, and de-duplicates: a blank query routes to the history list endpoint (0 ms debounce — instant);
 * a non-blank query routes to the search endpoint. [flatMapLatest] cancels the in-flight Pager when the
 * query changes so stale results never overwrite newer ones; [cachedIn] keeps loaded pages across config
 * change. The backend has no pagination, so the source is single-page (Paging 3 only for LoadState /
 * stream plumbing). The screen derives Content/Empty/Loading/Error from [query] + the LazyPagingItems
 * load-state via the pure [purchaseHistoryUiState].
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class PurchaseHistoryViewModel @Inject constructor(
    private val repository: PurchasesRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val _query = MutableStateFlow(savedState.get<String>(KEY_QUERY).orEmpty())
    val query: StateFlow<String> = _query.asStateFlow()

    val items: Flow<PagingData<PurchaseListItem>> =
        _query
            .map { it.trim() }
            .debounceCompat(DEBOUNCE_MS)
            .distinctUntilChanged()
            .flatMapLatest { q ->
                Pager(
                    config = PagingConfig(
                        pageSize = PurchasesApi.PAGE_SIZE,
                        initialLoadSize = PurchasesApi.PAGE_SIZE,
                        prefetchDistance = 1,
                        enablePlaceholders = false,
                    ),
                    pagingSourceFactory = {
                        PurchasesPagingSource(repository, q.ifBlank { null })
                    },
                ).flow
            }
            .cachedIn(viewModelScope)

    fun onQueryChange(text: String) {
        _query.value = text
        savedState[KEY_QUERY] = text
    }

    fun onClear() = onQueryChange("")

    companion object {
        const val KEY_QUERY = "purchases_query"
        const val DEBOUNCE_MS = 300L
    }
}

/** AND-219 — the history screen's high-level phase, derived from the query + paging load-state. */
sealed interface PurchaseHistoryUiState {
    data object Loading : PurchaseHistoryUiState
    data class Content(val query: String) : PurchaseHistoryUiState

    /** Empty history (blank query) — "no purchases yet". */
    data object EmptyHistory : PurchaseHistoryUiState

    /** Empty search result (non-blank query) — "no results for <query>", offers Clear. */
    data class EmptySearch(val query: String) : PurchaseHistoryUiState
    data class Error(val message: String, val retryable: Boolean) : PurchaseHistoryUiState
}

/**
 * AND-219 — pure derivation of [PurchaseHistoryUiState] from the trimmed [query], the paging
 * refresh-load-state ([refreshLoading]/[refreshError] + [errorMessage]/[retryable]), and [itemCount].
 * Distinguishes empty-history vs empty-search so the screen can show distinct copy. Extracted so the
 * state machine is unit-testable without Compose.
 */
fun purchaseHistoryUiState(
    query: String,
    refreshLoading: Boolean,
    refreshError: Boolean,
    errorMessage: String?,
    retryable: Boolean,
    itemCount: Int,
): PurchaseHistoryUiState {
    val trimmed = query.trim()
    return when {
        refreshError && itemCount == 0 ->
            PurchaseHistoryUiState.Error(errorMessage ?: "", retryable = retryable)
        refreshLoading && itemCount == 0 -> PurchaseHistoryUiState.Loading
        itemCount == 0 && trimmed.isEmpty() -> PurchaseHistoryUiState.EmptyHistory
        itemCount == 0 -> PurchaseHistoryUiState.EmptySearch(trimmed)
        else -> PurchaseHistoryUiState.Content(trimmed)
    }
}
