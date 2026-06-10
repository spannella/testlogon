package com.testlogon.android.feature.invoices

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.invoices.InvoiceSummary
import com.testlogon.android.data.invoices.InvoicesRepository

/**
 * AND-243 — cursor-keyed Paging 3 source over [InvoicesRepository.getInvoices].
 *
 * Keys are opaque cursor strings; the list is forward-only (prevKey always null), so [getRefreshKey]
 * returns null (refresh re-anchors at the first page). `endOfPaginationReached` is driven by
 * `next_cursor == null` (mapped to a null [androidx.paging.PagingSource.LoadResult.Page.nextKey];
 * there is NO has_more boolean). Repository failures become [LoadResult.Error] carrying a mapped,
 * human-readable message; CancellationException propagates because the repository re-throws it.
 *
 * Matches the existing fan-club [TierMembersPagingSource] convention (network PagingSource, no Room).
 */
class InvoicesPagingSource(
    private val repository: InvoicesRepository,
    private val pageSize: Int,
) : PagingSource<String, InvoiceSummary>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, InvoiceSummary> =
        when (val result = repository.getInvoices(cursor = params.key, limit = pageSize)) {
            is ApiResult.Success -> LoadResult.Page(
                data = result.data.invoices,
                prevKey = null,
                nextKey = result.data.nextCursor,
            )
            is ApiResult.Failure -> LoadResult.Error(InvoicesLoadException(result.error.message))
            is ApiResult.NetworkError -> LoadResult.Error(result.cause)
        }

    override fun getRefreshKey(state: PagingState<String, InvoiceSummary>): String? = null
}

/** Carries a mapped, human-readable message for a non-2xx invoice-page load failure. */
class InvoicesLoadException(message: String) : Exception(message)
