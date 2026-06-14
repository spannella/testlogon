package com.testlogon.android.data.bookmarks

import com.testlogon.android.core.data.feed.BookmarkStateDao
import com.testlogon.android.core.data.feed.BookmarkStateEntity
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-176 — feed-side bookmark toggle: the single writer of per-post saved state, backed by the shared
 * Room [BookmarkStateDao] and reconciled against the REAL /ui/bookmarks endpoints (AND-092 reused, not
 * forked).
 *
 * Optimistic flow (mirrors the like/hide pattern of AND-173/175): a toggle upserts/deletes the local
 * row so [observeSavedIds] / [isBookmarked] emit immediately; then it calls the network and either
 * clears the pending flag (success) or rolls the row back (hard failure). Per the web client's tolerant
 * contract (PostCard.tsx), a 409 on add (already bookmarked) and a 404 on delete (already removed) are
 * treated as success — the desired end-state already holds.
 *
 * Mutations are never auto-retried (POST/DELETE are non-idempotent). CancellationException is re-thrown.
 */
interface FeedBookmarkRepository {

    /** Reactive set of saved content ids (post ids for feed posts) for the feed icon. */
    val savedIds: Flow<Set<String>>

    /** Reactive saved-state for a single post. */
    fun isBookmarked(postId: String): Flow<Boolean>

    /** Optimistic write to cache, then network reconcile. [bookmarked] is the desired end-state. */
    suspend fun setBookmarked(postId: String, bookmarked: Boolean): ApiResult<Unit>

    /** Seed the cache for the given visible post ids via GET /ui/bookmarks/status (best-effort). */
    suspend fun hydrate(postIds: List<String>): ApiResult<Unit>
}

@Singleton
class FeedBookmarkRepositoryImpl @Inject constructor(
    private val api: BookmarksApi,
    private val dao: BookmarkStateDao,
    private val errorParser: ApiErrorParser,
) : FeedBookmarkRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override val savedIds: Flow<Set<String>> =
        dao.observeIds().map { it.toHashSet() }

    override fun isBookmarked(postId: String): Flow<Boolean> =
        dao.isBookmarked(CONTENT_TYPE_POST, postId)

    override suspend fun setBookmarked(postId: String, bookmarked: Boolean): ApiResult<Unit> =
        withContext(io) {
            if (bookmarked) addBookmark(postId) else removeBookmark(postId)
        }

    private suspend fun addBookmark(postId: String): ApiResult<Unit> {
        // 1. Optimistic: upsert a pending row so the icon fills immediately.
        dao.upsert(
            BookmarkStateEntity(
                contentType = CONTENT_TYPE_POST,
                contentId = postId,
                collectionId = DEFAULT_COLLECTION,
                createdAtEpochMs = System.currentTimeMillis(),
                pending = true,
            ),
        )
        return when (val r = apiCall { api.createBookmark(CreateBookmarkDto(CONTENT_TYPE_POST, postId, DEFAULT_COLLECTION)) }) {
            is ApiResult.Success -> {
                dao.setPending(CONTENT_TYPE_POST, postId, pending = false)
                ApiResult.Success(Unit)
            }
            is ApiResult.Failure ->
                // 409 = already bookmarked -> desired state already holds (idempotent success).
                if (r.error.status == HTTP_CONFLICT) {
                    dao.setPending(CONTENT_TYPE_POST, postId, pending = false)
                    ApiResult.Success(Unit)
                } else {
                    dao.delete(CONTENT_TYPE_POST, postId) // rollback
                    r
                }
            is ApiResult.NetworkError -> {
                dao.delete(CONTENT_TYPE_POST, postId) // rollback
                r
            }
        }
    }

    private suspend fun removeBookmark(postId: String): ApiResult<Unit> {
        val previous = dao.find(CONTENT_TYPE_POST, postId)
        // 1. Optimistic: drop the row so the icon empties immediately.
        dao.delete(CONTENT_TYPE_POST, postId)
        return when (val r = apiCall { api.deleteBookmark(CONTENT_TYPE_POST, postId) }) {
            is ApiResult.Success -> ApiResult.Success(Unit)
            is ApiResult.Failure ->
                // 404 = already removed -> desired state already holds (idempotent success).
                if (r.error.status == HTTP_NOT_FOUND) {
                    ApiResult.Success(Unit)
                } else {
                    if (previous != null) dao.upsert(previous) // rollback restore
                    r
                }
            is ApiResult.NetworkError -> {
                if (previous != null) dao.upsert(previous) // rollback restore
                r
            }
        }
    }

    override suspend fun hydrate(postIds: List<String>): ApiResult<Unit> = withContext(io) {
        val ids = postIds.filter { it.isNotBlank() }.distinct()
        if (ids.isEmpty()) return@withContext ApiResult.Success(Unit)
        when (val r = apiCall { api.bookmarkStatus(ids.joinToString(",")) }) {
            is ApiResult.Success -> {
                r.data.statuses.forEach { (id, saved) ->
                    if (saved) {
                        if (dao.find(CONTENT_TYPE_POST, id) == null) {
                            dao.upsert(
                                BookmarkStateEntity(
                                    contentType = CONTENT_TYPE_POST,
                                    contentId = id,
                                    collectionId = DEFAULT_COLLECTION,
                                    createdAtEpochMs = System.currentTimeMillis(),
                                    pending = false,
                                ),
                            )
                        }
                    } else {
                        // Only drop non-pending rows so an in-flight optimistic add is not clobbered.
                        val row = dao.find(CONTENT_TYPE_POST, id)
                        if (row != null && !row.pending) dao.delete(CONTENT_TYPE_POST, id)
                    }
                }
                ApiResult.Success(Unit)
            }
            is ApiResult.Failure -> r
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
        const val CONTENT_TYPE_POST = "post"
        const val DEFAULT_COLLECTION = "default"
        const val HTTP_NOT_FOUND = 404
        const val HTTP_CONFLICT = 409
    }
}
