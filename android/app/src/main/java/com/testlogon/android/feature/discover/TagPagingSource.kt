package com.testlogon.android.feature.discover

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.discover.TagRepository
import com.testlogon.android.data.feed.FeedPost

/**
 * AND-183 — cursor-keyed Paging 3 source over [TagRepository.getTagPage], mirroring the AND-098
 * FeedPagingSource. Keys are opaque `next_cursor` strings; the list is forward-only (prevKey null) and
 * [getRefreshKey] returns null (refresh re-anchors at page 1). Repository failures become
 * [LoadResult.Error]; end-of-list is signalled by a null next cursor.
 */
class TagPagingSource(
    private val repository: TagRepository,
    private val tag: String,
) : PagingSource<String, FeedPost>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, FeedPost> =
        when (val result = repository.getTagPage(tag = tag, cursor = params.key, limit = params.loadSize)) {
            is ApiResult.Success -> LoadResult.Page(
                data = result.data.posts,
                prevKey = null,
                nextKey = result.data.nextCursor,
            )
            is ApiResult.Failure -> LoadResult.Error(TagLoadException(result.error.message))
            is ApiResult.NetworkError -> LoadResult.Error(result.cause)
        }

    override fun getRefreshKey(state: PagingState<String, FeedPost>): String? = null
}

/** Carries a mapped, human-readable message for a non-2xx tag-page load failure. */
class TagLoadException(message: String) : Exception(message)
