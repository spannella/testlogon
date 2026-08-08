package com.testlogon.android.data.feed

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * PAR-13 — Retrofit interface for the caller's PENDING scheduled posts.
 *
 * Verified live contract (Python newsfeed.py:3926 / C++ main.cpp:18014 + :17917):
 *  - GET /posts/scheduled — caller-owned scheduled posts, oldest-publish first. Query: limit (1..50,
 *    default 20), cursor (opaque). Response { items:[post dict], next_cursor }.
 *  - POST /posts/{post_id}/cancel — cancels a scheduled post (status scheduled -> cancelled). Returns
 *    the updated post dict; 403 not-owner / 404 missing / 409 not-scheduled.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; auth +
 * CSRF are attached by the core-network interceptor chain. Methods are suspend + throw HttpException.
 */
interface ScheduledPostsApi {

    @GET("posts/scheduled")
    suspend fun getScheduledPosts(
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): ScheduledPostsPageDto

    @POST("posts/{post_id}/cancel")
    suspend fun cancelScheduledPost(@Path("post_id") postId: String): ScheduledPostDto

    companion object {
        const val DEFAULT_PAGE_SIZE = 20
    }
}

/** PAR-13 — one cursor page of scheduled posts. Mirrors the feed page shape (items + next_cursor). */
@JsonClass(generateAdapter = true)
data class ScheduledPostsPageDto(
    @Json(name = "items") val items: List<ScheduledPostDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

/**
 * PAR-13 — a scheduled post row (the fields relevant to a pending-schedule management view). The backend
 * returns the full post dict; we deserialize only what the screen renders. Unknown fields are ignored.
 */
@JsonClass(generateAdapter = true)
data class ScheduledPostDto(
    @Json(name = "post_id") val postId: String,
    @Json(name = "author_id") val authorId: String = "",
    @Json(name = "status") val status: String? = null,
    @Json(name = "body") val body: String? = null,
    @Json(name = "body_plain") val bodyPlain: String? = null,
    @Json(name = "publish_at") val publishAt: Long? = null,
    @Json(name = "schedule_timezone") val scheduleTimezone: String? = null,
    @Json(name = "scheduled_at_local") val scheduledAtLocal: String? = null,
    @Json(name = "image_urls") val imageUrls: List<String>? = null,
    @Json(name = "visibility") val visibility: String? = null,
)

/** PAR-13 — redaction-safe domain model for a pending scheduled post. */
data class ScheduledPost(
    val postId: String,
    val bodyPreview: String,
    val publishAtEpochSeconds: Long?,
    val scheduledAtLocal: String?,
    val scheduleTimezone: String?,
    val visibility: String?,
    val hasMedia: Boolean,
)

/** PAR-13 — one page of scheduled posts + the next cursor. */
data class ScheduledPostsPage(
    val items: List<ScheduledPost>,
    val nextCursor: String?,
)

internal fun ScheduledPostDto.toDomain(): ScheduledPost = ScheduledPost(
    postId = postId,
    bodyPreview = (bodyPlain ?: body).orEmpty().trim(),
    publishAtEpochSeconds = publishAt,
    scheduledAtLocal = scheduledAtLocal,
    scheduleTimezone = scheduleTimezone,
    visibility = visibility,
    hasMedia = !imageUrls.isNullOrEmpty(),
)

internal fun ScheduledPostsPageDto.toDomain(): ScheduledPostsPage = ScheduledPostsPage(
    items = items.map { it.toDomain() },
    nextCursor = nextCursor,
)

/**
 * PAR-13 — data layer over [ScheduledPostsApi]. Wraps the GET list + POST cancel in [ApiResult] via the
 * same apiCall{} pattern the feed repository uses (CancellationException re-thrown so structured
 * cancellation works; HTTP -> Failure; IO -> NetworkError). Network-only, never throws to callers.
 */
interface ScheduledPostsRepository {
    suspend fun getScheduledPosts(
        cursor: String? = null,
        limit: Int? = ScheduledPostsApi.DEFAULT_PAGE_SIZE,
    ): ApiResult<ScheduledPostsPage>

    suspend fun cancelScheduledPost(postId: String): ApiResult<ScheduledPost>
}

@Singleton
class ScheduledPostsRepositoryImpl @Inject constructor(
    private val api: ScheduledPostsApi,
    private val errorParser: ApiErrorParser,
) : ScheduledPostsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getScheduledPosts(cursor: String?, limit: Int?): ApiResult<ScheduledPostsPage> =
        withContext(io) {
            apiCall { api.getScheduledPosts(limit = limit, cursor = cursor) }.map { it.toDomain() }
        }

    override suspend fun cancelScheduledPost(postId: String): ApiResult<ScheduledPost> =
        withContext(io) {
            apiCall { api.cancelScheduledPost(postId) }.map { it.toDomain() }
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
