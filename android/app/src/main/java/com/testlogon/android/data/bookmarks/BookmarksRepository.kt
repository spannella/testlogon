package com.testlogon.android.data.bookmarks

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-092 — Saved / bookmarks data layer over [BookmarksApi].
 *
 * Owns the cursor [PagingSource] and the unsave / resave (Undo) mutations, all wrapped in
 * [ApiResult] mapping wire DTOs to the domain [Bookmark]. Mutations are never auto-retried.
 *
 * P0-consumer/bookmarks adds collection CRUD + the move mutation on top (all owner-scoped on the
 * backend). Per the spec's tolerant contract, a 404 on DELETE is treated as already-removed (Success)
 * since the web client relies on server idempotency. Other non-2xx fold into Failure; transport errors
 * fold into NetworkError. CancellationException is re-thrown.
 */
interface BookmarksRepository {

    fun pagingSource(
        contentType: String? = null,
        collectionId: String? = null,
    ): PagingSource<String, Bookmark>

    suspend fun page(
        cursor: String? = null,
        limit: Int? = null,
        contentType: String? = null,
        collectionId: String? = null,
    ): ApiResult<BookmarkPage>

    /** Remove a bookmark; a 404 is tolerated as already-removed (Success). */
    suspend fun unsave(contentType: String, contentId: String): ApiResult<Unit>

    /** Re-create a bookmark (Undo). */
    suspend fun resave(bookmark: Bookmark): ApiResult<Unit>

    /** Move a bookmark into [collectionId]; owner-scoped (404 if not owned). */
    suspend fun move(contentType: String, contentId: String, collectionId: String): ApiResult<Unit>

    // ── Collections ──────────────────────────────────────────────────────────

    suspend fun collections(): ApiResult<List<BookmarkCollection>>

    /** Create a collection; 400 (max_collections_reached) surfaces as Failure. */
    suspend fun createCollection(name: String): ApiResult<BookmarkCollection>

    suspend fun renameCollection(collectionId: String, name: String): ApiResult<Unit>

    suspend fun deleteCollection(collectionId: String): ApiResult<Unit>
}

@Singleton
class BookmarksRepositoryImpl @Inject constructor(
    private val api: BookmarksApi,
    private val errorParser: ApiErrorParser,
) : BookmarksRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override fun pagingSource(contentType: String?, collectionId: String?): PagingSource<String, Bookmark> =
        BookmarksPagingSource(this, contentType, collectionId)

    override suspend fun page(
        cursor: String?,
        limit: Int?,
        contentType: String?,
        collectionId: String?,
    ): ApiResult<BookmarkPage> = withContext(io) {
        apiCall { api.listBookmarks(limit, cursor, contentType, collectionId) }.let { r ->
            when (r) {
                is ApiResult.Success -> ApiResult.Success(
                    BookmarkPage(
                        items = r.data.bookmarks.map { it.toDomain() },
                        nextCursor = r.data.nextCursor,
                        totalCount = r.data.totalCount,
                    ),
                )
                is ApiResult.Failure -> r
                is ApiResult.NetworkError -> r
            }
        }
    }

    override suspend fun unsave(contentType: String, contentId: String): ApiResult<Unit> =
        withContext(io) {
            when (val r = apiCall { api.deleteBookmark(contentType, contentId) }) {
                is ApiResult.Success -> ApiResult.Success(Unit)
                // Tolerate already-removed (idempotent delete) as success.
                is ApiResult.Failure -> if (r.error.status == HTTP_NOT_FOUND) {
                    ApiResult.Success(Unit)
                } else {
                    r
                }
                is ApiResult.NetworkError -> r
            }
        }

    override suspend fun resave(bookmark: Bookmark): ApiResult<Unit> = withContext(io) {
        val body = CreateBookmarkDto(
            contentType = bookmark.contentType.ifBlank { null },
            contentId = bookmark.contentId,
            collectionId = bookmark.collectionId,
        )
        when (val r = apiCall { api.createBookmark(body) }) {
            is ApiResult.Success -> ApiResult.Success(Unit)
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun move(contentType: String, contentId: String, collectionId: String): ApiResult<Unit> =
        withContext(io) {
            when (val r = apiCall { api.moveBookmark(contentType, contentId, MoveBookmarkBody(collectionId)) }) {
                is ApiResult.Success -> ApiResult.Success(Unit)
                is ApiResult.Failure -> r
                is ApiResult.NetworkError -> r
            }
        }

    override suspend fun collections(): ApiResult<List<BookmarkCollection>> = withContext(io) {
        when (val r = apiCall { api.listCollections() }) {
            is ApiResult.Success -> ApiResult.Success(r.data.collections.map { it.toDomain() })
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun createCollection(name: String): ApiResult<BookmarkCollection> = withContext(io) {
        when (val r = apiCall { api.createCollection(CollectionNameBody(name)) }) {
            is ApiResult.Success -> ApiResult.Success(r.data.toDomain())
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun renameCollection(collectionId: String, name: String): ApiResult<Unit> = withContext(io) {
        when (val r = apiCall { api.renameCollection(collectionId, CollectionNameBody(name)) }) {
            is ApiResult.Success -> ApiResult.Success(Unit)
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun deleteCollection(collectionId: String): ApiResult<Unit> = withContext(io) {
        when (val r = apiCall { api.deleteCollection(collectionId) }) {
            is ApiResult.Success -> ApiResult.Success(Unit)
            // Tolerate already-deleted.
            is ApiResult.Failure -> if (r.error.status == HTTP_NOT_FOUND) ApiResult.Success(Unit) else r
            is ApiResult.NetworkError -> r
        }
    }

    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private companion object {
        const val HTTP_NOT_FOUND = 404
    }
}

/**
 * Cursor-keyed Paging 3 source over [BookmarksRepository.page]. Forward-only (prevKey null);
 * [getRefreshKey] returns null so refresh re-anchors at the head (opaque cursors).
 */
class BookmarksPagingSource(
    private val repository: BookmarksRepository,
    private val contentType: String?,
    private val collectionId: String?,
) : PagingSource<String, Bookmark>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, Bookmark> =
        when (
            val result = repository.page(
                cursor = params.key,
                limit = params.loadSize,
                contentType = contentType,
                collectionId = collectionId,
            )
        ) {
            is ApiResult.Success -> LoadResult.Page(
                data = result.data.items,
                prevKey = null,
                nextKey = result.data.nextCursor,
            )
            is ApiResult.Failure -> LoadResult.Error(BookmarkLoadException(result.error.message))
            is ApiResult.NetworkError -> LoadResult.Error(result.cause)
        }

    override fun getRefreshKey(state: PagingState<String, Bookmark>): String? = null
}

/** Carries a mapped, human-readable message for a non-2xx page load failure. */
class BookmarkLoadException(message: String) : Exception(message)
