package com.testlogon.android.feature.payouts

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.payouts.Payout
import com.testlogon.android.data.payouts.PayoutsRepository

/**
 * AND-260 — cursor-keyed Paging 3 source over [PayoutsRepository.getPayouts].
 *
 * Keys are opaque cursor strings; the list is forward-only (prevKey always null), so [getRefreshKey]
 * returns null (refresh re-anchors at the first page). endOfPaginationReached is driven by
 * next_cursor == null (mapped to a null nextKey; there is NO has_more boolean). Repository failures
 * become [LoadResult.Error] carrying a mapped, human-readable message; CancellationException propagates
 * because the repository re-throws it. Mirrors the InvoicesPagingSource convention (network source, no
 * Room — the spec's RemoteMediator/Room option is intentionally simplified to an in-memory pager + a
 * loaded-item cache for the cache-hydrated detail screen, avoiding Room schema gotchas).
 *
 * [onLoaded] lets the ViewModel cache loaded rows by id so the detail screen can hydrate without a
 * network call (there is no GET ui/payouts/{id}).
 */
class PayoutsPagingSource(
    private val repository: PayoutsRepository,
    private val pageSize: Int,
    private val onLoaded: (List<Payout>) -> Unit = {},
) : PagingSource<String, Payout>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, Payout> =
        when (val result = repository.getPayouts(cursor = params.key, limit = pageSize)) {
            is ApiResult.Success -> {
                onLoaded(result.data.items)
                LoadResult.Page(
                    data = result.data.items,
                    prevKey = null,
                    nextKey = result.data.nextCursor,
                )
            }
            is ApiResult.Failure -> LoadResult.Error(PayoutsLoadException(result.error.message))
            is ApiResult.NetworkError -> LoadResult.Error(result.cause)
        }

    override fun getRefreshKey(state: PagingState<String, Payout>): String? = null
}

/** Carries a mapped, human-readable message for a non-2xx payout-page load failure. */
class PayoutsLoadException(message: String) : Exception(message)
