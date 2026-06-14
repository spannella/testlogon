package com.testlogon.android.feature.vod

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.vod.VodRepository
import com.testlogon.android.data.vod.VodSummary

/**
 * AND-191 — cursor-keyed Paging 3 source over [VodRepository.catalogPage]. The [category] / [query]
 * filters are fixed for the lifetime of one source (a filter change re-creates the source via the VM).
 * Forward-only (prevKey null); [getRefreshKey] null; null cursor terminates pagination.
 */
class VodCatalogPagingSource(
    private val repository: VodRepository,
    private val category: String? = null,
    private val query: String? = null,
) : PagingSource<String, VodSummary>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, VodSummary> =
        when (
            val result = repository.catalogPage(
                cursor = params.key,
                limit = params.loadSize,
                category = category,
                query = query,
            )
        ) {
            is ApiResult.Success -> LoadResult.Page(
                data = result.data.items,
                prevKey = null,
                nextKey = result.data.cursor,
            )
            is ApiResult.Failure -> LoadResult.Error(VodLoadException(result.error.message))
            is ApiResult.NetworkError -> LoadResult.Error(result.cause)
        }

    override fun getRefreshKey(state: PagingState<String, VodSummary>): String? = null
}

/** Carries a mapped, human-readable message for a non-2xx VOD-catalog load failure. */
class VodLoadException(message: String) : Exception(message)
