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
import retrofit2.http.Multipart
import retrofit2.http.POST
import retrofit2.http.Part
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
)

@JsonClass(generateAdapter = true)
data class CreatePostResp(
    @Json(name = "post_id") val postId: String? = null,
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
}

/** Visibility options exposed in the compose screen (wire values per the backend). */
enum class PostVisibility(val wire: String, val label: String) {
    PUBLIC("public", "Public"),
    FOLLOWERS("followers", "Followers"),
    SUBSCRIBERS("subscribers", "Subscribers"),
}

@Singleton
class PostComposeRepository @Inject constructor(
    private val api: PostComposeApi,
    private val errorParser: ApiErrorParser,
    @ApplicationContext private val context: Context,
) {
    suspend fun createPost(
        body: String,
        visibility: PostVisibility,
        unlockPriceCents: Long?,
        publishAtEpochSeconds: Long?,
        imageUrls: List<String> = emptyList(),
        videoId: String? = null,
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
                lockType = if (unlockPriceCents != null) "price" else null,
                unlockPriceCents = unlockPriceCents,
                publishAt = publishAtEpochSeconds,
                scheduleTimezone = tz,
                scheduledAtLocal = localStr,
                imageUrls = imageUrls.ifEmpty { null },
                videoId = videoId,
            ),
        )
        Unit
    }

    /** Upload a picked image; returns its url for [createPost]'s image_urls. */
    suspend fun uploadImage(uri: Uri): ApiResult<String> = withContext(Dispatchers.IO) {
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
