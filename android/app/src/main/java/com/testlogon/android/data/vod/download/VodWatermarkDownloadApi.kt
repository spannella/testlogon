package com.testlogon.android.data.vod.download

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-195 — Retrofit interface + wire DTOs for the forensically-watermarked VOD download flow.
 *
 * Verified contract (reference/src/api/endpoints/vodWatermarkDownload.ts; openapi.index.txt + pretty.json):
 *  - POST ui/vod/watermark-download/{video_id}          -> VodWatermarkDownloadResponse  (NO request body)
 *  - GET  ui/vod/watermark-download/{video_id}/status   -> VodWatermarkDownloadStatusResponse
 *
 * The begin POST has NO body (viewer identity is server-side from the session). Server-side burn-in
 * only: the backend renders a per-viewer watermarked copy (FFmpeg) and returns a `download_url`. The
 * render is async (processing -> poll -> ready/failed); the dev backend completes synchronously with a
 * `/mock/s3/...` url. The forensic token is `watermark_payload`. Begin is idempotent within the cache
 * window (`cached` flag). Entitlement is gated server-side.
 */
interface VodWatermarkDownloadApi {

    @POST("ui/vod/watermark-download/{video_id}")
    suspend fun beginWatermarkDownload(@Path("video_id") videoId: String): VodWatermarkDownloadResponseDto

    @GET("ui/vod/watermark-download/{video_id}/status")
    suspend fun pollWatermarkStatus(@Path("video_id") videoId: String): VodWatermarkDownloadStatusResponseDto

    companion object {
        const val STATUS_READY = "ready"
        const val STATUS_PROCESSING = "processing"
        const val STATUS_FAILED = "failed"
        const val STATUS_NOT_FOUND = "not_found"
    }
}

/** VodWatermarkDownloadResponse — required: status, render_id. download_url present when ready. */
@JsonClass(generateAdapter = true)
data class VodWatermarkDownloadResponseDto(
    @Json(name = "status") val status: String,
    @Json(name = "render_id") val renderId: String,
    @Json(name = "download_url") val downloadUrl: String? = null,
    @Json(name = "cached") val cached: Boolean = false,
    @Json(name = "watermark_payload") val watermarkPayload: String? = null,
    @Json(name = "output_size_bytes") val outputSizeBytes: Long? = null,
)

/** VodWatermarkDownloadStatusResponse — required: status (ready|processing|failed|not_found). */
@JsonClass(generateAdapter = true)
data class VodWatermarkDownloadStatusResponseDto(
    @Json(name = "status") val status: String,
    @Json(name = "render_id") val renderId: String? = null,
    @Json(name = "download_url") val downloadUrl: String? = null,
    @Json(name = "output_size_bytes") val outputSizeBytes: Long? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "error") val error: String? = null,
)
