package com.testlogon.android.feature.gallery

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.gallery.GalleryRepository
import com.testlogon.android.data.gallery.GalleryVideoItem

/**
 * AND-201 — cursor-keyed Paging 3 source over [GalleryRepository], mirroring the AND-183 TagPagingSource.
 *
 * When [query] is non-null it pages search results; otherwise it browses (optionally filtered by
 * [category]). Keys are the opaque `cursor` strings; the list is forward-only (prevKey null) and a
 * null/absent cursor terminates pagination (a single-page gallery renders without an append footer).
 * Repository failures become [LoadResult.Error]; [getRefreshKey] returns null (refresh re-anchors at
 * page 1).
 */
class GalleryPagingSource(
    private val repository: GalleryRepository,
    private val category: String?,
    private val query: String?,
) : PagingSource<String, GalleryVideoItem>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, GalleryVideoItem> {
        val result = if (!query.isNullOrBlank()) {
            repository.search(query = query, cursor = params.key, limit = params.loadSize)
        } else {
            repository.browse(category = category, cursor = params.key, limit = params.loadSize)
        }
        return when (result) {
            is ApiResult.Success -> LoadResult.Page(
                data = result.data.videos,
                prevKey = null,
                nextKey = result.data.cursor,
            )
            is ApiResult.Failure -> LoadResult.Error(GalleryLoadException(result.error.message))
            is ApiResult.NetworkError -> LoadResult.Error(result.cause)
        }
    }

    override fun getRefreshKey(state: PagingState<String, GalleryVideoItem>): String? = null
}

/** Carries a mapped, human-readable message for a non-2xx gallery-page load failure. */
class GalleryLoadException(message: String) : Exception(message)
