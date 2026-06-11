package com.testlogon.android.feature.earnings.percontent

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.earnings.ContentRevenue
import com.testlogon.android.data.earnings.ContentRevenuePage

/**
 * AND-253 — cursor-keyed Paging 3 source over the content-revenue list.
 *
 * Keys are opaque cursor strings; forward-only paging (prevKey always null), so [getRefreshKey]
 * returns null (refresh re-anchors at the head). [onHeader] is fired once, on the first page (cursor
 * == null), so the screen can render the aggregate header summary. Repository failures become
 * [LoadResult.Error]; CancellationException propagates because the repository re-throws it.
 */
class ContentRevenuePagingSource(
    private val load: suspend (cursor: String?, limit: Int) -> ApiResult<ContentRevenuePage>,
    private val onHeader: (ContentRevenuePage) -> Unit,
) : PagingSource<String, ContentRevenue>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, ContentRevenue> =
        when (val result = load(params.key, params.loadSize)) {
            is ApiResult.Success -> {
                val page = result.data
                if (params.key == null) onHeader(page)
                LoadResult.Page(
                    data = page.items,
                    prevKey = null,
                    nextKey = page.nextCursor,
                )
            }
            is ApiResult.Failure -> LoadResult.Error(ContentRevenueLoadException(result.error.message))
            is ApiResult.NetworkError -> LoadResult.Error(result.cause)
        }

    override fun getRefreshKey(state: PagingState<String, ContentRevenue>): String? = null
}

/** Carries a mapped, human-readable message for a non-2xx page load failure. */
class ContentRevenueLoadException(message: String) : Exception(message)
