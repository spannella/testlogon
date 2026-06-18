package com.testlogon.android.data.videos

import android.content.Context
import android.net.Uri
import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.BuildConfig
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.upload.StorageUploadClient
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import retrofit2.HttpException
import retrofit2.http.Body
import retrofit2.http.POST
import java.io.IOException
import java.net.SocketTimeoutException
import java.security.MessageDigest
import javax.inject.Inject
import javax.inject.Singleton

/** POST /ui/videos/upload/presign. */
@JsonClass(generateAdapter = true)
data class VodPresignReq(
    val filename: String,
    @Json(name = "content_type") val contentType: String,
    @Json(name = "file_size_bytes") val fileSizeBytes: Long,
    val title: String,
    val description: String,
    @Json(name = "folder_path") val folderPath: String = "",
)

@JsonClass(generateAdapter = true)
data class VodPresignResp(
    @Json(name = "upload_url") val uploadUrl: String? = null,
    @Json(name = "presigned_url") val presignedUrl: String? = null,
    val key: String? = null,
    @Json(name = "s3_key") val s3Key: String? = null,
    @Json(name = "ticket_id") val ticketId: String? = null,
    @Json(name = "video_id") val videoId: String? = null,
) {
    val putUrl: String? get() = uploadUrl ?: presignedUrl
    val objectKey: String? get() = key ?: s3Key
}

/** POST /ui/videos/upload/complete. */
@JsonClass(generateAdapter = true)
data class VodCompleteReq(
    @Json(name = "ticket_id") val ticketId: String?,
    val key: String?,
    @Json(name = "content_type") val contentType: String,
    @Json(name = "client_checksum") val clientChecksum: String,
)

@JsonClass(generateAdapter = true)
data class VodCompleteResp(
    val ok: Boolean = false,
    @Json(name = "video_id") val videoId: String? = null,
    val status: String? = null,
)

interface VideoUploadApi {
    @POST("ui/videos/upload/presign")
    suspend fun presign(@Body body: VodPresignReq): VodPresignResp

    @POST("ui/videos/upload/complete")
    suspend fun complete(@Body body: VodCompleteReq): VodCompleteResp
}

/** Orchestrates the VOD upload: presign -> PUT (cookieless) -> complete. */
@Singleton
class VideoUploadRepository @Inject constructor(
    private val api: VideoUploadApi,
    private val uploader: StorageUploadClient,
    private val errorParser: ApiErrorParser,
    @ApplicationContext private val context: Context,
) {
    /** Uploads [uri] as a VOD with [title]/[description]; returns the new video id on success. */
    suspend fun upload(uri: Uri, title: String, description: String): ApiResult<String> =
        withContext(Dispatchers.IO) {
            val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: return@withContext ApiResult.NetworkError(IOException("Could not read the selected video"))
            val name = (uri.lastPathSegment ?: "video").substringAfterLast('/').ifBlank { "video.mp4" }
            uploadBytes(bytes, if (name.endsWith(".mp4")) name else "$name.mp4", title, description)
        }

    private suspend fun uploadBytes(bytes: ByteArray, filename: String, title: String, description: String): ApiResult<String> =
        withContext(Dispatchers.IO) {
            try {
                val checksum = MessageDigest.getInstance("MD5").digest(bytes)
                    .joinToString("") { "%02x".format(it) }
                val presign = api.presign(
                    VodPresignReq(
                        filename = filename,
                        contentType = CONTENT_TYPE,
                        fileSizeBytes = bytes.size.toLong(),
                        title = title.trim(),
                        description = description.trim(),
                    ),
                )
                val putUrl = presign.putUrl
                    ?: return@withContext ApiResult.Failure(ApiError(status = 0, message = "Upload could not start"))
                val absolute = if (putUrl.startsWith("/")) BuildConfig.API_BASE_URL.trimEnd('/') + putUrl else putUrl
                val put = uploader.put(absolute, CONTENT_TYPE, bytes.toRequestBody(CONTENT_TYPE.toMediaType()))
                if (!put.success) {
                    return@withContext ApiResult.Failure(ApiError(status = put.httpStatus, message = "Upload failed"))
                }
                val done = api.complete(
                    VodCompleteReq(
                        ticketId = presign.ticketId,
                        key = presign.objectKey,
                        contentType = CONTENT_TYPE,
                        clientChecksum = checksum,
                    ),
                )
                ApiResult.Success(done.videoId ?: presign.videoId.orEmpty())
            } catch (e: CancellationException) {
                throw e
            } catch (e: HttpException) {
                ApiResult.Failure(errorParser.from(e))
            } catch (e: IOException) {
                ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
            }
        }

    private companion object {
        const val CONTENT_TYPE = "video/mp4"
    }
}
