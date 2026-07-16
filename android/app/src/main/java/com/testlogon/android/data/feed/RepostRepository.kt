package com.testlogon.android.data.feed

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
 * SOCIAL-002 — repost / un-repost data layer over [RepostApi]. Mirrors the tolerant, idempotent-success
 * contract of [com.testlogon.android.data.bookmarks.FeedBookmarkRepository]:
 *  - a 409 on repost (the viewer already reposted) is treated as success — the desired end-state holds;
 *  - a 404 on undo (nothing to remove) is likewise success.
 * On success the authoritative server `repost_count` is returned so the optimistic overlay can reconcile;
 * when the server omits it (or on the idempotent 409/404 branch) `null` is returned, meaning "keep the
 * optimistic count". Mutations are never auto-retried (POST/DELETE are non-idempotent);
 * CancellationException is re-thrown.
 */
interface RepostRepository {

    /**
     * Repost [postId] with an optional ≤500-char [quote]. Returns the new authoritative repost_count on
     * success (or null when the server omitted it / the post was already reposted).
     */
    suspend fun repost(postId: String, quote: String?): ApiResult<Int?>

    /** Undo the viewer's repost of [postId]. Returns the new authoritative repost_count (or null). */
    suspend fun undo(postId: String): ApiResult<Int?>
}

@Singleton
class RepostRepositoryImpl @Inject constructor(
    private val api: RepostApi,
    private val errorParser: ApiErrorParser,
) : RepostRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun repost(postId: String, quote: String?): ApiResult<Int?> = withContext(io) {
        when (val r = apiCall { api.repost(postId, RepostRequest(quote = quote?.takeIf { it.isNotBlank() })) }) {
            is ApiResult.Success -> ApiResult.Success(r.data.repostCount)
            is ApiResult.Failure ->
                // 409 = already reposted -> desired state already holds (idempotent success).
                if (r.error.status == HTTP_CONFLICT) ApiResult.Success(null) else r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun undo(postId: String): ApiResult<Int?> = withContext(io) {
        when (val r = apiCall { api.undoRepost(postId) }) {
            is ApiResult.Success -> ApiResult.Success(r.data.repostCount)
            is ApiResult.Failure ->
                // 404 = nothing to undo -> desired state already holds (idempotent success).
                if (r.error.status == HTTP_NOT_FOUND) ApiResult.Success(null) else r
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
        const val HTTP_CONFLICT = 409
    }
}
