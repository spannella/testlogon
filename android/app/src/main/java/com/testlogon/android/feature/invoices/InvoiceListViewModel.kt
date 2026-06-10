package com.testlogon.android.feature.invoices

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
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
import kotlinx.coroutines.flow.flatMapLatest
import javax.inject.Inject

/**
 * AND-243 — invoices list presentation logic: a cached Paging 3 stream of [InvoiceSummary].
 *
 * The list's CombinedLoadStates (collected on the screen) drive the loading/empty/error/append branches,
 * so this ViewModel owns the cached pager + a refresh trigger. [refresh] re-anchors via flatMapLatest;
 * the stream is cachedIn(viewModelScope) to survive config changes. Matches the AND-240
 * TierMembersViewModel pager convention.
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

    /** Invalidate the list and re-fetch from the first page (pull-to-refresh). */
    fun refresh() {
        refreshTrigger.value = refreshTrigger.value + 1L
    }

    companion object {
        // pageSize 20 matches InvoicesApi.DEFAULT_LIMIT.
        private const val PAGE_SIZE = 20
        private const val PREFETCH_DISTANCE = 5
    }
}
