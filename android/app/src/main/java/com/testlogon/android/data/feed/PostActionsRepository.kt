package com.testlogon.android.data.feed

import com.testlogon.android.core.data.feed.PostSuppressionDao
import com.testlogon.android.core.data.feed.PostSuppressionEntity
import com.testlogon.android.core.data.feed.PostSuppressionKind
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
 * AND-175 — hide / not-interested data layer over [EngagementApi] + [PostSuppressionDao].
 *
 * Optimistic-first: every action upserts the suppression row (so the feed filters the post out
 * immediately) BEFORE the network call, then reconciles. On 2xx the row's pending flag is cleared; on
 * a hard failure the row is deleted (rollback). A 404 is treated as success-equivalent for hide (the
 * post is already gone -> keep it suppressed). Not-interested reuses POST /feed/hide (there is no
 * negative-preference endpoint; /feed/interesting is a POSITIVE boost — AND-175 §FR-3). Undo for both
 * is POST /feed/unhide (idempotent). The durable Room set survives process death (FR-7).
 *
 * [suppressed] is the single source of truth for client-side feed filtering, derived from observeAll().
 */
interface PostActionsRepository {

    /** Reactive set of suppressed post ids (hidden or not-interested). */
    val suppressed: Flow<Set<String>>

    suspend fun hide(postId: String): ApiResult<Unit>
    suspend fun notInterested(postId: String): ApiResult<Unit>

    /** Undo for both Hide and Not-interested: POST /feed/unhide. */
    suspend fun unhide(postId: String): ApiResult<Unit>
}

@Singleton
class PostActionsRepositoryImpl @Inject constructor(
    private val api: EngagementApi,
    private val dao: PostSuppressionDao,
    private val errorParser: ApiErrorParser,
) : PostActionsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override val suppressed: Flow<Set<String>> =
        dao.observeAll().map { rows -> rows.mapTo(HashSet()) { it.postId } }

    override suspend fun hide(postId: String): ApiResult<Unit> =
        suppress(postId, PostSuppressionKind.HIDDEN)

    override suspend fun notInterested(postId: String): ApiResult<Unit> =
        suppress(postId, PostSuppressionKind.NOT_INTERESTED)

    private suspend fun suppress(postId: String, kind: PostSuppressionKind): ApiResult<Unit> =
        withContext(io) {
            // 1. Optimistic: upsert pending row so the feed drops the post immediately.
            dao.upsert(
                PostSuppressionEntity(
                    postId = postId,
                    kind = kind.name,
                    createdAtEpochMs = System.currentTimeMillis(),
                    pending = true,
                ),
            )
            when (val result = ackCall { api.hide(HidePostRequest(postId)) }) {
                is ApiResult.Success -> {
                    dao.setPending(postId, pending = false)
                    ApiResult.Success(Unit)
                }
                is ApiResult.Failure -> {
                    // 404 = already gone -> keep suppression (success-equivalent).
                    if (result.error.status == HTTP_NOT_FOUND) {
                        dao.setPending(postId, pending = false)
                        ApiResult.Success(Unit)
                    } else {
                        dao.delete(postId) // rollback
                        result
                    }
                }
                is ApiResult.NetworkError -> {
                    dao.delete(postId) // rollback
                    result
                }
            }
        }

    override suspend fun unhide(postId: String): ApiResult<Unit> = withContext(io) {
        // Optimistic restore: drop the suppression row first so the post can return to the feed.
        dao.delete(postId)
        when (val result = ackCall { api.unhide(HidePostRequest(postId)) }) {
            is ApiResult.Success -> ApiResult.Success(Unit)
            is ApiResult.Failure ->
                if (result.error.status == HTTP_NOT_FOUND) ApiResult.Success(Unit) else result
            is ApiResult.NetworkError -> result
        }
    }

    private suspend fun ackCall(block: suspend () -> Unit): ApiResult<Unit> = try {
        block()
        ApiResult.Success(Unit)
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
