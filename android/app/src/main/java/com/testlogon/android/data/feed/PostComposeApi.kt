package com.testlogon.android.data.feed

import android.content.Context
import android.net.Uri
import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.RequestBody.Companion.toRequestBody
import retrofit2.HttpException
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.Multipart
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Part
import retrofit2.http.Path
import java.io.IOException
import java.net.SocketTimeoutException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Create-a-post (newsfeed compose) over POST /posts (CreatePostRequest) + image upload via the generic
 * multipart POST /uploads/image. A basic post is `{ body, visibility }`; optional unlock price, future
 * publish_at (epoch seconds), attached image_urls and/or a video_id are all supported.
 */
@JsonClass(generateAdapter = true)
data class CreatePostReq(
    val body: String,
    val visibility: String = "public",
    @Json(name = "lock_type") val lockType: String? = null,
    @Json(name = "unlock_price_cents") val unlockPriceCents: Long? = null,
    @Json(name = "publish_at") val publishAt: Long? = null,
    /** IANA timezone the user scheduled in (e.g. America/New_York) + the local wall-clock string. */
    @Json(name = "schedule_timezone") val scheduleTimezone: String? = null,
    @Json(name = "scheduled_at_local") val scheduledAtLocal: String? = null,
    @Json(name = "image_urls") val imageUrls: List<String>? = null,
    @Json(name = "video_id") val videoId: String? = null,
    // #2 (B-FEEDMEDIA) — multiple videos in one post (mixed media: images AND videos coexist). The
    // backend merges a legacy single video_id into video_ids[0]; we send the full list here.
    @Json(name = "video_ids") val videoIds: List<String>? = null,
    // Arbitrary text-option poll: post_type="poll" + poll_data (question/options/choice_mode).
    @Json(name = "post_type") val postType: String? = null,
    @Json(name = "poll_data") val pollData: NewsfeedPollDataReq? = null,
)

/** Arbitrary poll create payload for POST /posts (post_type="poll"). Mirrors backend PollDataIn. */
@JsonClass(generateAdapter = true)
data class NewsfeedPollDataReq(
    @Json(name = "questions") val questions: List<NewsfeedPollQuestionReq>,
    @Json(name = "closes_at") val closesAt: Long? = null,
    @Json(name = "anonymous") val anonymous: Boolean = true,
    @Json(name = "allow_vote_change") val allowVoteChange: Boolean = true,
    /** Sender-controlled: allow voters to add their own write-in options. */
    @Json(name = "allow_write_in") val allowWriteIn: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class NewsfeedPollQuestionReq(
    @Json(name = "text") val text: String,
    @Json(name = "choice_mode") val choiceMode: String = "single",
    @Json(name = "options") val options: List<NewsfeedPollOptionReq>,
    @Json(name = "max_selections") val maxSelections: Int? = null,
    @Json(name = "allow_write_in") val allowWriteIn: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class NewsfeedPollOptionReq(
    @Json(name = "text") val text: String,
)

@JsonClass(generateAdapter = true)
data class CreatePostResp(
    @Json(name = "post_id") val postId: String? = null,
)

/**
 * FD1 / FD-EDIT — edit an existing post (PATCH /posts/{post_id}, EditPostRequest). Carries every field a
 * creator commonly changes in place: the text body, the attached image urls, the audience (visibility)
 * and the paid-lock (lock_type + unlock_price_cents). All fields are optional server-side; we send body
 * via the legacy `body` key (the backend accepts it). Per the B-POST contract, edit `visibility` is one
 * of "public"|"followers" and `lock_type` is "fixed_price" (with unlock_price_cents) or "none" (unlocks).
 */
@JsonClass(generateAdapter = true)
data class EditPostReq(
    val body: String,
    @Json(name = "image_urls") val imageUrls: List<String>? = null,
    /**
     * #3 — the attached VOD video. The backend treats video_id and image_urls as mutually exclusive,
     * so callers send exactly one. Per the B-POST edit contract: a value SETS/replaces the video, an
     * empty string CLEARS it (we always include the key on a video-aware edit so the backend's
     * model_fields_set sees it).
     */
    @Json(name = "video_id") val videoId: String? = null,
    // #2 (B-FEEDMEDIA) — replace the post's full set of videos (mixed media: photos AND videos coexist).
    // Included on a video-aware edit so the backend's model_fields_set picks it up; an empty list clears
    // all videos.
    @Json(name = "video_ids") val videoIds: List<String>? = null,
    @Json(name = "visibility") val visibility: String? = null,
    @Json(name = "lock_type") val lockType: String? = null,
    @Json(name = "unlock_price_cents") val unlockPriceCents: Long? = null,
)

/**
 * FD-EDIT — the editable fields of an owned post, fetched fresh so the edit screen pre-fills the CURRENT
 * body / photos / audience / lock. The owner's own GET /posts/{id} is NOT redacted server-side, so these
 * carry real values even for a locked post (unlike the redaction-safe consumer [FeedPost]).
 */
@JsonClass(generateAdapter = true)
data class EditablePostDto(
    @Json(name = "post_id") val postId: String = "",
    @Json(name = "body") val body: String? = null,
    @Json(name = "body_plain") val bodyPlain: String? = null,
    @Json(name = "image_urls") val imageUrls: List<String>? = null,
    @Json(name = "visibility") val visibility: String? = null,
    @Json(name = "locked") val locked: Boolean = false,
    @Json(name = "lock_type") val lockType: String? = null,
    @Json(name = "unlock_price_cents") val unlockPriceCents: Long? = null,
    /** #3 — the currently-attached video (owner GET is un-redacted), so the edit screen can show it. */
    @Json(name = "video") val video: VideoDto? = null,
    /** #2 — the full ordered list of attached videos (owner GET, un-redacted). */
    @Json(name = "videos") val videos: List<VideoDto>? = null,
)

@JsonClass(generateAdapter = true)
data class UploadImageResp(
    val url: String? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
    val key: String? = null,
) {
    val resolved: String? get() = url ?: imageUrl ?: key
}

interface PostComposeApi {
    @POST("posts")
    suspend fun createPost(@Body body: CreatePostReq): CreatePostResp

    @Multipart
    @POST("uploads/image")
    suspend fun uploadImage(@Part file: MultipartBody.Part): UploadImageResp

    /** FD1 — edit an owned post's text/media. 403 if not the owner, 404 if missing. */
    @PATCH("posts/{post_id}")
    suspend fun editPost(@Path("post_id") postId: String, @Body body: EditPostReq)

    /** FD-EDIT — fetch an owned post's editable fields (owner GET is un-redacted). */
    @retrofit2.http.GET("posts/{post_id}")
    suspend fun getEditablePost(@Path("post_id") postId: String): EditablePostDto

    /** FD1 — delete an owned post. 403 if not the owner, 404 if missing. */
    @DELETE("posts/{post_id}")
    suspend fun deletePost(@Path("post_id") postId: String)
}

/** Visibility options exposed in the compose screen (wire values per the backend). */
enum class PostVisibility(val wire: String, val label: String) {
    PUBLIC("public", "Public"),
    FOLLOWERS("followers", "Followers"),
    SUBSCRIBERS("subscribers", "Subscribers"),
}

/**
 * #24 — narrow seam for uploading a picked image and getting back its platform URL, so callers that
 * only need image upload (e.g. the comments VM) can depend on this instead of the whole compose repo
 * and unit tests can fake it without an Android Context.
 */
interface CommentImageUploader {
    suspend fun uploadImage(uri: Uri): ApiResult<String>
}

@Singleton
class PostComposeRepository @Inject constructor(
    private val api: PostComposeApi,
    private val errorParser: ApiErrorParser,
    @ApplicationContext private val context: Context,
) : CommentImageUploader {
    suspend fun createPost(
        body: String,
        visibility: PostVisibility,
        unlockPriceCents: Long?,
        publishAtEpochSeconds: Long?,
        imageUrls: List<String> = emptyList(),
        // #2 — 0..n attached video ids (mixed media). First id is also sent as the legacy video_id for
        // back-compat with older servers; the new server reads video_ids.
        videoIds: List<String> = emptyList(),
        // Arbitrary text-option poll data; when non-null the post is created as post_type="poll".
        pollData: NewsfeedPollDataReq? = null,
    ): ApiResult<Unit> = call {
        val tz = if (publishAtEpochSeconds != null) TimeZone.getDefault().id else null
        val localStr = publishAtEpochSeconds?.let {
            SimpleDateFormat("yyyy-MM-dd'T'HH:mm", Locale.US)
                .apply { timeZone = TimeZone.getDefault() }
                .format(Date(it * 1000L))
        }
        api.createPost(
            CreatePostReq(
                body = body,
                visibility = visibility.wire,
                lockType = if (unlockPriceCents != null) "fixed_price" else null,
                unlockPriceCents = unlockPriceCents,
                publishAt = publishAtEpochSeconds,
                scheduleTimezone = tz,
                scheduledAtLocal = localStr,
                imageUrls = imageUrls.ifEmpty { null },
                videoId = videoIds.firstOrNull(),
                videoIds = videoIds.ifEmpty { null },
                postType = if (pollData != null) "poll" else null,
                pollData = pollData,
            ),
        )
        Unit
    }

    /** FD1 — edit an owned post's text body (text-only convenience overload). */
    suspend fun editPost(postId: String, body: String): ApiResult<Unit> = call {
        api.editPost(postId, EditPostReq(body = body.trim()))
        Unit
    }

    /**
     * FD-EDIT — edit an owned post's body + photos + audience + paid-lock in one PATCH (B-POST contract).
     * [imageUrls] is sent verbatim (empty list REMOVES all photos server-side); [visibility] is one of
     * [PostVisibility]; a non-null [unlockPriceCents] sets a fixed-price lock, else the post is unlocked.
     */
    suspend fun editPost(
        postId: String,
        body: String,
        visibility: PostVisibility,
        imageUrls: List<String>,
        unlockPriceCents: Long?,
        // #2 — when [videoChanged] is true the post's videos are being replaced wholesale with [videoIds]
        // (mixed media: photos AND videos may now coexist, so images are always sent too). An empty
        // [videoIds] clears all videos. When [videoChanged] is false the video keys are omitted entirely.
        videoChanged: Boolean = false,
        videoIds: List<String> = emptyList(),
    ): ApiResult<Unit> = call {
        api.editPost(
            postId,
            EditPostReq(
                body = body.trim(),
                imageUrls = imageUrls,
                // Include the keys only when videos changed so the backend's model_fields_set picks them
                // up. Send both the legacy single key (first id, "" to clear) and the full list.
                videoId = if (videoChanged) (videoIds.firstOrNull() ?: "") else null,
                videoIds = if (videoChanged) videoIds else null,
                visibility = visibility.wire,
                lockType = if (unlockPriceCents != null) "fixed_price" else "none",
                unlockPriceCents = if (unlockPriceCents != null) unlockPriceCents else 0L,
            ),
        )
        Unit
    }

    /** FD-EDIT — load an owned post's current editable fields for pre-filling the edit screen. */
    suspend fun getEditablePost(postId: String): ApiResult<EditablePostDto> = call {
        api.getEditablePost(postId)
    }

    /** FD1 — delete an owned post. */
    suspend fun deletePost(postId: String): ApiResult<Unit> = call {
        api.deletePost(postId)
        Unit
    }

    /** Upload a picked image; returns its url for [createPost]'s image_urls. */
    override suspend fun uploadImage(uri: Uri): ApiResult<String> = withContext(Dispatchers.IO) {
        val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: return@withContext ApiResult.NetworkError(IOException("Could not read the selected image"))
        uploadImageBytes(bytes, "image.jpg")
    }

    private suspend fun uploadImageBytes(bytes: ByteArray, name: String): ApiResult<String> = try {
        val part = MultipartBody.Part.createFormData("file", name, bytes.toRequestBody("image/jpeg".toMediaType()))
        val url = api.uploadImage(part).resolved
        if (url != null) ApiResult.Success(url) else ApiResult.Failure(ApiError(status = 0, message = "Image upload failed"))
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = withContext(Dispatchers.IO) {
        try {
            ApiResult.Success(block())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }
}
