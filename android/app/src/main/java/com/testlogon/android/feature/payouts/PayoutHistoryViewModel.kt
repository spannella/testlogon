package com.testlogon.android.feature.payouts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.data.payouts.Payout
import com.testlogon.android.data.payouts.PayoutsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import javax.inject.Inject

/**
 * AND-260 — payout history presentation: a cached Paging 3 stream of [Payout] plus a refresh trigger.
 *
 * The list's CombinedLoadStates (collected on the screen) drive the loading/empty/error/append
 * branches, so this ViewModel owns the cached pager + a refresh trigger ([refresh] re-anchors via
 * flatMapLatest). Each loaded page is pushed into the shared [PayoutCache] so the detail screen can
 * hydrate by id without a network call (there is no GET ui/payouts/{id}). Mirrors the
 * InvoiceListViewModel pager convention.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class PayoutHistoryViewModel @Inject constructor(
    private val repository: PayoutsRepository,
    private val cache: PayoutCache,
) : ViewModel() {

    private val refreshTrigger = MutableStateFlow(0L)

    val payouts: Flow<PagingData<Payout>> =
        refreshTrigger
            .flatMapLatest {
                Pager(
                    config = PagingConfig(
                        pageSize = PAGE_SIZE,
                        prefetchDistance = PREFETCH_DISTANCE,
                        initialLoadSize = PAGE_SIZE,
                        enablePlaceholders = false,
                    ),
                    pagingSourceFactory = {
                        PayoutsPagingSource(repository, PAGE_SIZE, onLoaded = cache::put)
                    },
                ).flow
            }
            .cachedIn(viewModelScope)

    /** Invalidate the list and re-fetch from the first page (pull-to-refresh / retry). */
    fun refresh() {
        refreshTrigger.value = refreshTrigger.value + 1L
    }

    companion object {
        // PAGE_SIZE 20 matches PayoutsApi.DEFAULT_LIMIT.
        private const val PAGE_SIZE = 20
        private const val PREFETCH_DISTANCE = 5
    }
}
