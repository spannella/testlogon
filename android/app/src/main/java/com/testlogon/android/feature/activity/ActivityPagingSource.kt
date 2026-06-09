package com.testlogon.android.feature.activity

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.activity.ActivityEvent
import com.testlogon.android.data.activity.ActivityRepository

/**
 * AND-091 — cursor-keyed Paging 3 source over [ActivityRepository.feed].
 *
 * Keys are opaque cursor strings; the feed is forward-only (prevKey always null) and newest-first,
 * so [getRefreshKey] returns null (refresh re-anchors at the head). Repository failures
 * (ApiResult.Failure / NetworkError) become [LoadResult.Error]; CancellationException propagates
 * because the repository re-throws it.
 */
class ActivityPagingSource(
    private val repository: ActivityRepository,
) : PagingSource<String, ActivityEvent>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, ActivityEvent> =
        when (val result = repository.feed(cursor = params.key, limit = params.loadSize)) {
            is ApiResult.Success -> LoadResult.Page(
                data = result.data.items,
                prevKey = null,
                nextKey = result.data.nextCursor,
            )
            is ApiResult.Failure -> LoadResult.Error(ActivityLoadException(result.error.message))
            is ApiResult.NetworkError -> LoadResult.Error(result.cause)
        }

    override fun getRefreshKey(state: PagingState<String, ActivityEvent>): String? = null
}

/** Carries a mapped, human-readable message for a non-2xx page load failure. */
class ActivityLoadException(message: String) : Exception(message)
