package com.testlogon.android.feature.notifications

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.notifications.Notification
import com.testlogon.android.data.notifications.NotificationRepository

/**
 * AND-089 — cursor-keyed Paging 3 source over [NotificationRepository.list].
 *
 * Keys are opaque cursor strings; the feed is forward-only (prevKey always null) and newest-first,
 * so [getRefreshKey] returns null (refresh re-anchors at the head). Repository failures
 * (ApiResult.Failure / NetworkError) become [LoadResult.Error]; CancellationException propagates
 * because the repository re-throws it.
 */
class NotificationsPagingSource(
    private val repository: NotificationRepository,
) : PagingSource<String, Notification>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, Notification> =
        when (val result = repository.list(cursor = params.key, limit = params.loadSize)) {
            is ApiResult.Success -> LoadResult.Page(
                data = result.data.items,
                prevKey = null,
                nextKey = result.data.nextCursor,
            )
            is ApiResult.Failure -> LoadResult.Error(NotificationLoadException(result.error.message))
            is ApiResult.NetworkError -> LoadResult.Error(result.cause)
        }

    override fun getRefreshKey(state: PagingState<String, Notification>): String? = null
}

/** Carries a mapped, human-readable message for a non-2xx page load failure. */
class NotificationLoadException(message: String) : Exception(message)
