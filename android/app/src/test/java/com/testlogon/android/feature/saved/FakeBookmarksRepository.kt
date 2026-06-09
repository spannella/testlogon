package com.testlogon.android.feature.saved

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.bookmarks.Bookmark
import com.testlogon.android.data.bookmarks.BookmarkPage
import com.testlogon.android.data.bookmarks.BookmarksRepository
import kotlinx.coroutines.CompletableDeferred

/** AND-096 — in-memory [BookmarksRepository] fake for SavedViewModel unit tests. */
class FakeBookmarksRepository(
    private val items: List<Bookmark> = emptyList(),
) : BookmarksRepository {

    var unsaveResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var resaveResult: ApiResult<Unit> = ApiResult.Success(Unit)

    val unsaveCalls = mutableListOf<Pair<String, String>>()
    var resaveCalls = 0

    /** Optional gate to hold the unsave in flight (assert the optimistic window). */
    var unsaveGate: CompletableDeferred<Unit>? = null

    override fun pagingSource(contentType: String?, collectionId: String?): PagingSource<String, Bookmark> =
        StaticPagingSource(items)

    override suspend fun page(
        cursor: String?,
        limit: Int?,
        contentType: String?,
        collectionId: String?,
    ): ApiResult<BookmarkPage> = ApiResult.Success(BookmarkPage(items, null, items.size))

    override suspend fun unsave(contentType: String, contentId: String): ApiResult<Unit> {
        unsaveCalls += contentType to contentId
        unsaveGate?.await()
        return unsaveResult
    }

    override suspend fun resave(bookmark: Bookmark): ApiResult<Unit> {
        resaveCalls++
        return resaveResult
    }

    private class StaticPagingSource(private val items: List<Bookmark>) :
        PagingSource<String, Bookmark>() {
        override suspend fun load(params: LoadParams<String>): LoadResult<String, Bookmark> =
            LoadResult.Page(items, prevKey = null, nextKey = null)

        override fun getRefreshKey(state: PagingState<String, Bookmark>): String? = null
    }

    companion object {
        fun bookmark(contentType: String = "post", contentId: String) = Bookmark(
            contentType = contentType,
            contentId = contentId,
            collectionId = "default",
            title = "Title $contentId",
            subtitle = "Snippet $contentId",
            thumbnailUrl = null,
            savedAtIso = null,
        )

        fun failure(status: Int = 500) = ApiResult.Failure(ApiError(status = status, message = "boom"))
    }
}
