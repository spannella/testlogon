package com.testlogon.android.feature.videos

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.videos.VideoSummary
import com.testlogon.android.data.videos.VideosRepository

/**
 * AND-189 — cursor-keyed Paging 3 source over [VideosRepository.listVideos], mirroring the AND-183
 * TagPagingSource. Keys are opaque `cursor` strings; the list is forward-only (prevKey null) and
 * [getRefreshKey] returns null (refresh re-anchors at page 1). Repository failures become
 * [LoadResult.Error]; end-of-list is signalled by a null cursor.
 */
class VideosPagingSource(
    private val repository: VideosRepository,
    private val status: String? = null,
    private val visibility: String? = null,
) : PagingSource<String, VideoSummary>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, VideoSummary> =
        when (
            val result = repository.listVideos(
                cursor = params.key,
                limit = params.loadSize,
                status = status,
                visibility = visibility,
            )
        ) {
            is ApiResult.Success -> LoadResult.Page(
                data = result.data.items,
                prevKey = null,
                nextKey = result.data.cursor,
            )
            is ApiResult.Failure -> LoadResult.Error(VideosLoadException(result.error.message))
            is ApiResult.NetworkError -> LoadResult.Error(result.cause)
        }

    override fun getRefreshKey(state: PagingState<String, VideoSummary>): String? = null
}

/** Carries a mapped, human-readable message for a non-2xx videos-library load failure. */
class VideosLoadException(message: String) : Exception(message)
