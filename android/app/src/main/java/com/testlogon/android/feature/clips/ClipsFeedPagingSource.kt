package com.testlogon.android.feature.clips

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.clips.Clip
import com.testlogon.android.data.clips.ClipsApi
import com.testlogon.android.data.clips.ClipsRepository

/**
 * AND-196 — cursor-keyed Paging 3 source over [ClipsRepository.feed], mirroring the AND-189
 * VideosPagingSource. Keys are opaque `next_cursor` strings; the list is forward-only (prevKey null)
 * and [getRefreshKey] returns null (refresh re-anchors at page 1). Repository failures become
 * [LoadResult.Error]; end-of-list is signalled by a null cursor.
 */
class ClipsFeedPagingSource(
    private val repository: ClipsRepository,
    private val sort: String = ClipsApi.SORT_RECENT,
) : PagingSource<String, Clip>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, Clip> =
        when (val result = repository.feed(cursor = params.key, sort = sort, limit = params.loadSize)) {
            is ApiResult.Success -> LoadResult.Page(
                data = result.data.items,
                prevKey = null,
                nextKey = result.data.nextCursor,
            )
            is ApiResult.Failure -> LoadResult.Error(ClipsLoadException(result.error.message))
            is ApiResult.NetworkError -> LoadResult.Error(result.cause)
        }

    override fun getRefreshKey(state: PagingState<String, Clip>): String? = null
}

/** Carries a mapped, human-readable message for a non-2xx clips-feed load failure. */
class ClipsLoadException(message: String) : Exception(message)
