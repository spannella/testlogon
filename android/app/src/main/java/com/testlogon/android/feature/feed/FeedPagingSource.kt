package com.testlogon.android.feature.feed

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.FeedPost
import com.testlogon.android.data.feed.FeedRepository

/**
 * AND-098 — cursor-keyed Paging 3 source over [FeedRepository.getFeedPage].
 *
 * Keys are opaque cursor strings; the feed is forward-only (prevKey always null) and
 * [getRefreshKey] returns null (refresh re-anchors at the head — a cursor feed cannot resume from an
 * arbitrary anchor). Repository failures (ApiResult.Failure / NetworkError) become [LoadResult.Error];
 * CancellationException propagates because the repository re-throws it. End-of-feed is signalled by a
 * null next cursor (no has_more).
 */
class FeedPagingSource(
    private val repository: FeedRepository,
) : PagingSource<String, FeedPost>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, FeedPost> =
        when (val result = repository.getFeedPage(cursor = params.key, limit = params.loadSize)) {
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

/** Carries a mapped, human-readable message for a non-2xx page load failure. */
class FeedLoadException(message: String) : Exception(message)
