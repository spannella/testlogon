package com.testlogon.android.feature.invoices

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.CombinedLoadStates
import androidx.paging.LoadState
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.data.invoices.InvoiceSummary
import com.testlogon.android.data.invoices.InvoicesRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import javax.inject.Inject

/**
 * AND-249 — coarse, non-paging list state derived from [CombinedLoadStates] for global concerns the
 * PagingData LoadState alone can't carry cleanly: the initial gate, the empty signal, and a non-blocking
 * banner for an append/refresh error while items are already shown. The paging LoadState remains the
 * single source of truth for content loading/error; this only mirrors derived flags.
 */
data class InvoicesUiState(
    val isInitialLoading: Boolean = true,
    val isEmpty: Boolean = false,
    val hasBanner: Boolean = false,
)

/**
 * AND-243/AND-249 — invoices list presentation logic: a cached Paging 3 stream of [InvoiceSummary] plus a
 * coarse [InvoicesUiState] for non-paging concerns.
 *
 * The list's CombinedLoadStates (collected on the screen) drive the loading/empty/error/append branches,
 * so this ViewModel owns the cached pager + a refresh trigger. [refresh] re-anchors via flatMapLatest;
 * the stream is cachedIn(viewModelScope) to survive config changes. AND-249 added [uiState] +
 * [onLoadStateChanged] (derived banner/empty/initial-load flags) so the screen has one consistent place
 * to read coarse state, matching the AND-240 TierMembersViewModel pager convention.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class InvoiceListViewModel @Inject constructor(
    private val repository: InvoicesRepository,
) : ViewModel() {

    private val refreshTrigger = MutableStateFlow(0L)

    val invoices: Flow<PagingData<InvoiceSummary>> =
        refreshTrigger
            .flatMapLatest {
                Pager(
                    config = PagingConfig(
                        pageSize = PAGE_SIZE,
                        prefetchDistance = PREFETCH_DISTANCE,
                        initialLoadSize = PAGE_SIZE,
                        enablePlaceholders = false,
                    ),
                    pagingSourceFactory = { InvoicesPagingSource(repository, PAGE_SIZE) },
                ).flow
            }
            .cachedIn(viewModelScope)

    private val _uiState = MutableStateFlow(InvoicesUiState())
    val uiState: StateFlow<InvoicesUiState> = _uiState.asStateFlow()

    /** Invalidate the list and re-fetch from the first page (pull-to-refresh / [retry]). */
    fun refresh() {
        refreshTrigger.value = refreshTrigger.value + 1L
    }

    /** AND-249 — alias for [refresh]; the screen calls this from the empty/refresh-error retry affordance. */
    fun retry() = refresh()

    /**
     * AND-249 — derive the coarse [InvoicesUiState] from the paged list's [CombinedLoadStates] and the
     * current item count. Called by the screen on every load-state change.
     */
    fun onLoadStateChanged(states: CombinedLoadStates, itemCount: Int) {
        val refresh = states.refresh
        _uiState.value = InvoicesUiState(
            isInitialLoading = refresh is LoadState.Loading && itemCount == 0,
            isEmpty = refresh is LoadState.NotLoading && itemCount == 0,
            // A banner is warranted when content is already shown but an append/refresh failed.
            hasBanner = itemCount > 0 &&
                (states.append is LoadState.Error || states.refresh is LoadState.Error),
        )
    }

    companion object {
        // pageSize 20 matches InvoicesApi.DEFAULT_LIMIT.
        private const val PAGE_SIZE = 20
        private const val PREFETCH_DISTANCE = 5
    }
}
