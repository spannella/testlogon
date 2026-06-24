package com.testlogon.android.feature.feed.own

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.FeedPost
import com.testlogon.android.data.feed.FeedRepository
import com.testlogon.android.feature.feed.FeedLoadException

/**
 * FD1 — cursor-keyed Paging 3 source over [FeedRepository.getFeedPage] scoped to a single [authorId]
 * (the signed-in user). Mirrors the main feed's forward-only cursor paging; the only difference is the
 * author filter passed to the server.
 */
class MyPostsPagingSource(
    private val repository: FeedRepository,
    private val authorId: String,
) : PagingSource<String, FeedPost>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, FeedPost> =
        when (val result = repository.getFeedPage(cursor = params.key, limit = params.loadSize, authorId = authorId)) {
            is ApiResult.Success -> LoadResult.Page(
                data = result.data.posts,
                prevKey = null,
                nextKey = result.data.nextCursor,
            )
            is ApiResult.Failure -> LoadResult.Error(FeedLoadException(result.error.message))
            is ApiResult.NetworkError -> LoadResult.Error(result.cause)
        }

    override fun getRefreshKey(state: PagingState<String, FeedPost>): String? = null
}
