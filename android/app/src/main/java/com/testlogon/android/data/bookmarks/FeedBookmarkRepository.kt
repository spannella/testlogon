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
 * AND-176 — in-feed / in-player bookmark toggle: the single writer of per-item saved state, backed by
 * the shared Room [BookmarkStateDao] and reconciled against the REAL /ui/bookmarks endpoints (AND-092
 * reused, not forked).
 *
 * Optimistic flow (mirrors the like/hide pattern of AND-173/175): a toggle upserts/deletes the local
 * row so the saved-ids flow / [isBookmarked] emit immediately; then it calls the network and either
 * clears the pending flag (success) or rolls the row back (hard failure). Per the web client's tolerant
 * contract (PostCard.tsx), a 409 on add (already bookmarked) and a 404 on delete (already removed) are
 * treated as success — the desired end-state already holds.
 *
 * P0-consumer/bookmarks generalises every operation over an explicit `contentType` so the clips player
 * ("video") shares the exact same optimistic machinery as the feed ("post"). The bare-postId overloads
 * are retained for source compatibility with [FeedViewModel]. The composite (contentType, contentId)
 * is the Room primary key, so post and video rows never collide.
 *
 * Mutations are never auto-retried (POST/DELETE are non-idempotent). CancellationException is re-thrown.
 */
interface FeedBookmarkRepository {

    /** Reactive set of saved POST ids (feed icon). Post-scoped so video rows never leak in. */
    val savedIds: Flow<Set<String>>

    /** Reactive set of saved ids for a given content type (e.g. "video" for the clips player). */
    fun savedIdsFor(contentType: String): Flow<Set<String>>

    /** Reactive saved-state for a single post. */
    fun isBookmarked(postId: String): Flow<Boolean>

    /** Reactive saved-state for a single (contentType, contentId). */
    fun isBookmarked(contentType: String, contentId: String): Flow<Boolean>

    /** Optimistic write to cache, then network reconcile. [bookmarked] is the desired end-state (post). */
    suspend fun setBookmarked(postId: String, bookmarked: Boolean): ApiResult<Unit>

    /** Optimistic write for an arbitrary content type. [bookmarked] is the desired end-state. */
    suspend fun setBookmarked(contentType: String, contentId: String, bookmarked: Boolean): ApiResult<Unit>

    /** Seed the cache for the given visible POST ids via GET /ui/bookmarks/status (best-effort). */
    suspend fun hydrate(postIds: List<String>): ApiResult<Unit>

    /** Seed the cache for the given visible ids of [contentType] via GET /ui/bookmarks/status. */
    suspend fun hydrate(contentType: String, contentIds: List<String>): ApiResult<Unit>
}

@Singleton
class FeedBookmarkRepositoryImpl @Inject constructor(
    private val api: BookmarksApi,
    private val dao: BookmarkStateDao,
    private val errorParser: ApiErrorParser,
) : FeedBookmarkRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override val savedIds: Flow<Set<String>> =
        dao.observeIdsForType(CONTENT_TYPE_POST).map { it.toHashSet() }

    override fun savedIdsFor(contentType: String): Flow<Set<String>> =
        dao.observeIdsForType(contentType).map { it.toHashSet() }

    override fun isBookmarked(postId: String): Flow<Boolean> =
        dao.isBookmarked(CONTENT_TYPE_POST, postId)

    override fun isBookmarked(contentType: String, contentId: String): Flow<Boolean> =
        dao.isBookmarked(contentType, contentId)

    override suspend fun setBookmarked(postId: String, bookmarked: Boolean): ApiResult<Unit> =
        setBookmarked(CONTENT_TYPE_POST, postId, bookmarked)

    override suspend fun setBookmarked(contentType: String, contentId: String, bookmarked: Boolean): ApiResult<Unit> =
        withContext(io) {
            if (bookmarked) addBookmark(contentType, contentId) else removeBookmark(contentType, contentId)
        }

    private suspend fun addBookmark(contentType: String, contentId: String): ApiResult<Unit> {
        // 1. Optimistic: upsert a pending row so the icon fills immediately.
        dao.upsert(
            BookmarkStateEntity(
                contentType = contentType,
                contentId = contentId,
                collectionId = DEFAULT_COLLECTION,
                createdAtEpochMs = System.currentTimeMillis(),
                pending = true,
            ),
        )
        return when (val r = apiCall { api.createBookmark(CreateBookmarkDto(contentType, contentId, DEFAULT_COLLECTION)) }) {
            is ApiResult.Success -> {
                dao.setPending(contentType, contentId, pending = false)
                ApiResult.Success(Unit)
            }
            is ApiResult.Failure ->
                // 409 = already bookmarked -> desired state already holds (idempotent success).
                if (r.error.status == HTTP_CONFLICT) {
                    dao.setPending(contentType, contentId, pending = false)
                    ApiResult.Success(Unit)
                } else {
                    dao.delete(contentType, contentId) // rollback
                    r
                }
            is ApiResult.NetworkError -> {
                dao.delete(contentType, contentId) // rollback
                r
            }
        }
    }

    private suspend fun removeBookmark(contentType: String, contentId: String): ApiResult<Unit> {
        val previous = dao.find(contentType, contentId)
        // 1. Optimistic: drop the row so the icon empties immediately.
        dao.delete(contentType, contentId)
        return when (val r = apiCall { api.deleteBookmark(contentType, contentId) }) {
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

    override suspend fun hydrate(postIds: List<String>): ApiResult<Unit> =
        hydrate(CONTENT_TYPE_POST, postIds)

    override suspend fun hydrate(contentType: String, contentIds: List<String>): ApiResult<Unit> = withContext(io) {
        val ids = contentIds.filter { it.isNotBlank() }.distinct()
        if (ids.isEmpty()) return@withContext ApiResult.Success(Unit)
        // The status endpoint only honours composite "type:id" keys (bare ids are skipped server-side).
        val query = ids.joinToString(",") { "$contentType:$it" }
        when (val r = apiCall { api.bookmarkStatus(query) }) {
            is ApiResult.Success -> {
                r.data.statuses.forEach { (composite, saved) ->
                    // Server echoes keys as "type:id"; tolerate a bare id too.
                    val cid = if (composite.contains(':')) composite.substringAfter(':') else composite
                    if (saved) {
                        if (dao.find(contentType, cid) == null) {
                            dao.upsert(
                                BookmarkStateEntity(
                                    contentType = contentType,
                                    contentId = cid,
                                    collectionId = DEFAULT_COLLECTION,
                                    createdAtEpochMs = System.currentTimeMillis(),
                                    pending = false,
                                ),
                            )
                        }
                    } else {
                        // Only drop non-pending rows so an in-flight optimistic add is not clobbered.
                        val row = dao.find(contentType, cid)
                        if (row != null && !row.pending) dao.delete(contentType, cid)
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
