package com.testlogon.android.feature.fanclub

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.fanclub.FanClubMessage
import com.testlogon.android.data.fanclub.FanClubRepository

/**
 * AND-239 — cursor-derived Paging 3 source over [FanClubRepository.getMessages].
 *
 * The GET response is a BARE ARRAY with no server cursor (verified): the next (older) page key is the
 * oldest item's `message_id` in the current page, threaded via the `before` query param. Pagination ends
 * when a page is shorter than the requested limit (no `has_more` flag exists). The newest anchor passes
 * `before = null`.
 *
 * Messages come back newest-first from the server; the screen renders with `reverseLayout = true` so the
 * newest sits at the bottom. prevKey is null (forward-only toward older); [getRefreshKey] returns null
 * so a refresh re-anchors at the newest page. Repository failures become [LoadResult.Error].
 */
class ChannelMessagesPagingSource(
    private val repository: FanClubRepository,
    private val channelId: String,
) : PagingSource<String, FanClubMessage>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, FanClubMessage> {
        val limit = params.loadSize
        return when (val result = repository.getMessages(channelId, before = params.key, limit = limit)) {
            is ApiResult.Success -> {
                val page = result.data
                // No server has_more: end when the page is short. Next older key = oldest id this page.
                val nextKey = if (page.size < limit) null else page.lastOrNull()?.id
                LoadResult.Page(
                    data = page,
                    prevKey = null,
                    nextKey = nextKey,
                )
            }
            is ApiResult.Failure -> LoadResult.Error(ChannelMessagesLoadException(result.error.message))
            is ApiResult.NetworkError -> LoadResult.Error(result.cause)
        }
    }

    override fun getRefreshKey(state: PagingState<String, FanClubMessage>): String? = null
}

/** Carries a mapped, human-readable message for a non-2xx message-page load failure. */
class ChannelMessagesLoadException(message: String) : Exception(message)
