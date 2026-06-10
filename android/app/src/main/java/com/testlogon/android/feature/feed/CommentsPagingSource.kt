package com.testlogon.android.feature.feed

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.Comment
import com.testlogon.android.data.feed.CommentsRepository

/**
 * AND-174 — cursor-keyed Paging 3 source over [CommentsRepository.getComments].
 *
 * Forward-only (prevKey always null); end-of-pagination is a null next cursor (no has_more).
 * [getRefreshKey] returns null (a cursor list re-anchors at the head on refresh). Repository
 * Failure / NetworkError become [LoadResult.Error]; CancellationException propagates because the
 * repository re-throws it.
 */
class CommentsPagingSource(
    private val repository: CommentsRepository,
    private val postId: String,
) : PagingSource<String, Comment>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, Comment> =
        when (val result = repository.getComments(postId = postId, cursor = params.key, limit = params.loadSize)) {
            is ApiResult.Success -> LoadResult.Page(
                data = result.data.items,
                prevKey = null,
                nextKey = result.data.nextCursor,
            )
            is ApiResult.Failure -> LoadResult.Error(CommentLoadException(result.error.message))
            is ApiResult.NetworkError -> LoadResult.Error(result.cause)
        }

    override fun getRefreshKey(state: PagingState<String, Comment>): String? = null
}

/** Carries a mapped, human-readable message for a non-2xx comment-page load failure. */
class CommentLoadException(message: String) : Exception(message)
