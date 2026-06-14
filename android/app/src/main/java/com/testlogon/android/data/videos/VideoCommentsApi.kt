package com.testlogon.android.data.videos

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.auth.AuthStateStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/** GET/POST/DELETE /ui/videos/{video_id}/comments. */
interface VideoCommentsApi {
    @GET("ui/videos/{video_id}/comments")
    suspend fun list(
        @Path("video_id") videoId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = 50,
    ): VideoCommentPageDto

    @POST("ui/videos/{video_id}/comments")
    suspend fun add(
        @Path("video_id") videoId: String,
        @Body body: AddVideoCommentReq,
    ): VideoCommentDto

    @DELETE("ui/videos/{video_id}/comments/{comment_id}")
    suspend fun delete(
        @Path("video_id") videoId: String,
        @Path("comment_id") commentId: String,
    )
}

// Unknown JSON keys (created_at, video_id, etc.) are ignored by Moshi codegen, so we keep only what we use.
@JsonClass(generateAdapter = true)
data class VideoCommentDto(
    @Json(name = "comment_id") val commentId: String,
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "text") val text: String? = null,
)

@JsonClass(generateAdapter = true)
data class VideoCommentPageDto(
    @Json(name = "comments") val comments: List<VideoCommentDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class AddVideoCommentReq(@Json(name = "text") val text: String)

/** Framework-free domain model for a video comment. */
data class VideoComment(
    val id: String,
    val authorId: String,
    val text: String,
    val canDelete: Boolean,
)

@Singleton
class VideoCommentsRepository @Inject constructor(
    private val api: VideoCommentsApi,
    private val errorParser: ApiErrorParser,
    private val authStateStore: AuthStateStore,
) {
    private val io = Dispatchers.IO

    suspend fun list(videoId: String): ApiResult<List<VideoComment>> = withContext(io) {
        val me = authStateStore.userSub.first()
        call { api.list(videoId).comments.map { it.toDomain(me) } }
    }

    suspend fun add(videoId: String, text: String): ApiResult<VideoComment> = withContext(io) {
        val me = authStateStore.userSub.first()
        call { api.add(videoId, AddVideoCommentReq(text)).toDomain(me) }
    }

    suspend fun delete(videoId: String, commentId: String): ApiResult<Unit> = withContext(io) {
        call { api.delete(videoId, commentId) }
    }

    private fun VideoCommentDto.toDomain(me: String?): VideoComment = VideoComment(
        id = commentId,
        authorId = userId,
        text = text.orEmpty(),
        canDelete = userId.isNotBlank() && userId == me,
    )

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
