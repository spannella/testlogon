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
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * GET/POST/PATCH/DELETE /ui/videos/{video_id}/comments (+ reactions).
 *
 * #7/#8 — the backend (video_listing.py) already supports feed-comment parity: image comments
 * (kind=image + image_url), REPLY THREADS (parent_comment_id), EDIT (PATCH {text}), and emoji
 * REACTIONS (POST .../reactions {emoji}, POST .../unreact {emoji}) returning reactions_counts +
 * my_reactions. This client surfaces all of that.
 */
interface VideoCommentsApi {
    @GET("ui/videos/{video_id}/comments")
    suspend fun list(
        @Path("video_id") videoId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = 100,
    ): VideoCommentPageDto

    @POST("ui/videos/{video_id}/comments")
    suspend fun add(
        @Path("video_id") videoId: String,
        @Body body: AddVideoCommentReq,
    ): VideoCommentDto

    @PATCH("ui/videos/{video_id}/comments/{comment_id}")
    suspend fun edit(
        @Path("video_id") videoId: String,
        @Path("comment_id") commentId: String,
        @Body body: EditVideoCommentReq,
    ): VideoCommentDto

    @POST("ui/videos/{video_id}/comments/{comment_id}/reactions")
    suspend fun react(
        @Path("video_id") videoId: String,
        @Path("comment_id") commentId: String,
        @Body body: VideoCommentReactionReq,
    ): VideoCommentDto

    @POST("ui/videos/{video_id}/comments/{comment_id}/unreact")
    suspend fun unreact(
        @Path("video_id") videoId: String,
        @Path("comment_id") commentId: String,
        @Body body: VideoCommentReactionReq,
    ): VideoCommentDto

    @DELETE("ui/videos/{video_id}/comments/{comment_id}")
    suspend fun delete(
        @Path("video_id") videoId: String,
        @Path("comment_id") commentId: String,
    )
}

// Unknown JSON keys are ignored by Moshi codegen; we keep the fields the UI consumes.
@JsonClass(generateAdapter = true)
data class VideoCommentDto(
    @Json(name = "comment_id") val commentId: String,
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "text") val text: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "edited_at") val editedAt: Long? = null,
    @Json(name = "parent_comment_id") val parentCommentId: String? = null,
    @Json(name = "kind") val kind: String = "text",
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "image_alt_text") val imageAltText: String? = null,
    // Reactions: emoji -> count, and the caller's own reactions.
    @Json(name = "reactions_counts") val reactionsCounts: Map<String, Int> = emptyMap(),
    @Json(name = "my_reactions") val myReactions: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class VideoCommentPageDto(
    @Json(name = "comments") val comments: List<VideoCommentDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class AddVideoCommentReq(
    @Json(name = "text") val text: String? = null,
    @Json(name = "kind") val kind: String = "text",
    @Json(name = "parent_comment_id") val parentCommentId: String? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
)

@JsonClass(generateAdapter = true)
data class EditVideoCommentReq(@Json(name = "text") val text: String)

@JsonClass(generateAdapter = true)
data class VideoCommentReactionReq(@Json(name = "emoji") val emoji: String)

/** Framework-free domain model for a video comment (feed-parity fields). */
data class VideoComment(
    val id: String,
    val authorId: String,
    val text: String,
    val canDelete: Boolean,
    val canEdit: Boolean,
    val parentCommentId: String?,
    val kind: String,
    val imageUrl: String?,
    val edited: Boolean,
    val reactions: Map<String, Int>,
    val myReactions: Set<String>,
) {
    val isReply: Boolean get() = !parentCommentId.isNullOrBlank()
}

@Singleton
class VideoCommentsRepository @Inject constructor(
    private val api: VideoCommentsApi,
    private val errorParser: ApiErrorParser,
    private val authStateStore: AuthStateStore,
) {
    private val io = Dispatchers.IO

    /** The emoji reaction set the server allows (kept in sync with video_comments.ALLOWED_REACTION_EMOJIS). */
    companion object {
        val ALLOWED_REACTIONS = listOf("👍", "❤️", "😂", "🔥", "😮")
    }

    suspend fun list(videoId: String): ApiResult<List<VideoComment>> = withContext(io) {
        val me = authStateStore.userSub.first()
        call { api.list(videoId).comments.map { it.toDomain(me) } }
    }

    suspend fun add(
        videoId: String,
        text: String?,
        parentCommentId: String? = null,
        imageUrl: String? = null,
    ): ApiResult<VideoComment> = withContext(io) {
        val me = authStateStore.userSub.first()
        val kind = if (!imageUrl.isNullOrBlank()) "image" else "text"
        call {
            api.add(
                videoId,
                AddVideoCommentReq(
                    text = text?.takeIf { it.isNotBlank() },
                    kind = kind,
                    parentCommentId = parentCommentId?.takeIf { it.isNotBlank() },
                    imageUrl = imageUrl?.takeIf { it.isNotBlank() },
                ),
            ).toDomain(me)
        }
    }

    suspend fun edit(videoId: String, commentId: String, text: String): ApiResult<VideoComment> =
        withContext(io) {
            val me = authStateStore.userSub.first()
            call { api.edit(videoId, commentId, EditVideoCommentReq(text)).toDomain(me) }
        }

    suspend fun react(videoId: String, commentId: String, emoji: String): ApiResult<VideoComment> =
        withContext(io) {
            val me = authStateStore.userSub.first()
            call { api.react(videoId, commentId, VideoCommentReactionReq(emoji)).toDomain(me) }
        }

    suspend fun unreact(videoId: String, commentId: String, emoji: String): ApiResult<VideoComment> =
        withContext(io) {
            val me = authStateStore.userSub.first()
            call { api.unreact(videoId, commentId, VideoCommentReactionReq(emoji)).toDomain(me) }
        }

    suspend fun delete(videoId: String, commentId: String): ApiResult<Unit> = withContext(io) {
        call { api.delete(videoId, commentId) }
    }

    private fun VideoCommentDto.toDomain(me: String?): VideoComment {
        val mine = userId.isNotBlank() && userId == me
        return VideoComment(
            id = commentId,
            authorId = userId,
            text = text.orEmpty(),
            canDelete = mine,
            canEdit = mine && kind == "text",
            parentCommentId = parentCommentId?.takeIf { it.isNotBlank() },
            kind = kind,
            imageUrl = imageUrl?.takeIf { it.isNotBlank() },
            edited = editedAt != null,
            reactions = reactionsCounts.filterValues { it > 0 },
            myReactions = myReactions.toSet(),
        )
    }

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
