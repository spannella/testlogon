package com.testlogon.android.data.feed

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
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
 * AND-097 / AND-100 — feed + single-post data layer over [FeedApi].
 *
 * Wraps the cursor-paged `GET /feed` and `GET /posts/{post_id}` in [ApiResult], mapping wire DTOs to
 * the redaction-safe domain model ([FeedMapper]). Network-only (no Room cache in M2 scope); failures
 * fold into ApiResult.Failure / NetworkError and the repository never throws to callers
 * (CancellationException is re-thrown so Paging / structured-concurrency cancellation works).
 */
interface FeedRepository {

    /** One page of the feed keyed by the opaque [cursor] (null = head). */
    suspend fun getFeedPage(
        cursor: String? = null,
        limit: Int? = FeedApi.DEFAULT_PAGE_SIZE,
    ): ApiResult<FeedPage>

    /** A single post by id. */
    suspend fun getPost(postId: String): ApiResult<FeedPost>
}

@Singleton
class FeedRepositoryImpl @Inject constructor(
    private val api: FeedApi,
    private val errorParser: ApiErrorParser,
) : FeedRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getFeedPage(cursor: String?, limit: Int?): ApiResult<FeedPage> =
        withContext(io) {
            apiCall { api.getFeed(cursor = cursor, limit = limit) }.map { it.toDomain() }
        }

    override suspend fun getPost(postId: String): ApiResult<FeedPost> =
        withContext(io) {
            apiCall { api.getPost(postId) }.map { it.toDomain() }
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
}
