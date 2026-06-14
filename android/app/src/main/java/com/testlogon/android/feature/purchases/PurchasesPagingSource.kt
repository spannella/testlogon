package com.testlogon.android.feature.purchases

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.purchases.PurchaseListItem
import com.testlogon.android.data.purchases.PurchasesRepository

/**
 * AND-221 — single-page Paging 3 source over [PurchasesRepository]. The backend exposes NO pagination
 * (list/search return a bare array bounded only by `limit`), so the source loads one [params.loadSize]
 * bounded page and reports `nextKey = null` always. A null [query] hits the history list endpoint; a
 * non-null (already-trimmed, non-blank) query hits the search endpoint. A query change re-creates the
 * source via the VM's flatMapLatest. Paging 3 is retained only for its LoadState / stream ergonomics
 * (uniform loading/empty/error/retry handling), not incremental load. Repository failures become
 * [LoadResult.Error] so the screen's load-state mapping is uniform and the stream never crashes.
 */
class PurchasesPagingSource(
    private val repository: PurchasesRepository,
    private val query: String?,
) : PagingSource<Int, PurchaseListItem>() {

    override suspend fun load(params: LoadParams<Int>): LoadResult<Int, PurchaseListItem> {
        val result = if (query == null) {
            repository.list(limit = params.loadSize, status = null)
        } else {
            repository.search(query = query, limit = params.loadSize)
        }
        return when (result) {
            is ApiResult.Success -> LoadResult.Page(
                data = result.data,
                prevKey = null,
                nextKey = null,
            )
            is ApiResult.Failure -> LoadResult.Error(PurchasesLoadException(result.error.message))
            is ApiResult.NetworkError -> LoadResult.Error(result.cause)
        }
    }

    // Single page => refresh always restarts from the top.
    override fun getRefreshKey(state: PagingState<Int, PurchaseListItem>): Int? = null
}

/** Carries a mapped, human-readable message for a non-2xx purchases list/search load failure. */
class PurchasesLoadException(message: String) : Exception(message)
