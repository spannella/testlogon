package com.testlogon.android.data.privacy

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import okhttp3.ResponseBody
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Streaming

/**
 * AND-385 - Retrofit interface for the privacy / data-export surface.
 *
 * Verified endpoints (CORRECTED from the draft; OpenAPI index lines 1732-1734, 1742 +
 * src/api/endpoints/accountDeletion.ts):
 *   POST ui/privacy/account-deletion/export                req=PrivacyExportRequestIn -> 201:PrivacyExportStatusOut
 *   GET  ui/privacy/account-deletion/export/{requestId}    -> 200:PrivacyExportStatusOut (single poll, NO collection)
 *   GET  ui/privacy/account-deletion/export/{requestId}/download  @Streaming binary
 *   GET  ui/privacy/requests                               -> 200:DataRequestListOut (export + deletion rows)
 *
 * Provided on the SHARED authenticated Retrofit by [PrivacyApiModule] - no new OkHttp / Retrofit. Paths are
 * relative (no leading slash) so they resolve against the shared base URL; cookies, Authorization and
 * X-CSRF-Token are attached project-wide by the core-network interceptor chain - this interface stays
 * header-agnostic. The POST is non-idempotent and is NEVER auto-retried (a duplicate export job is wasteful);
 * the idempotent GETs may be retried by the caller. The download is @Streaming so the artifact is not buffered
 * fully into memory; bytes are copied to a MediaStore OutputStream on Dispatchers.IO.
 */
interface PrivacyApi {

    @Headers("Content-Type: application/json")
    @POST("ui/privacy/account-deletion/export")
    suspend fun requestExport(
        @Body body: ExportRequestBodyDto,
    ): Response<ExportStatusDto>

    @GET("ui/privacy/account-deletion/export/{requestId}")
    suspend fun getExport(
        @Path("requestId") requestId: String,
    ): Response<ExportStatusDto>

    @Streaming
    @GET("ui/privacy/account-deletion/export/{requestId}/download")
    suspend fun downloadExport(
        @Path("requestId") requestId: String,
    ): Response<ResponseBody>

    @GET("ui/privacy/requests")
    suspend fun listPrivacyRequests(): Response<DataRequestListDto>
}

/**
 * AND-385 - POST body = PrivacyExportRequestIn: a map of data-category keys to include-flags. The web client
 * (AccountDeletionPage.tsx EXPORT_CATEGORIES) defaults every category to true; see [ExportCategories].
 */
@JsonClass(generateAdapter = true)
data class ExportRequestBodyDto(
    @Json(name = "categories") val categories: Map<String, Boolean>,
)

/**
 * AND-385 - response = PrivacyExportStatusOut (required: request_id, status, created_at). CORRECTED: timestamps
 * are INTEGER epoch SECONDS (not ISO strings); the size field is `file_size_bytes`; expiry is
 * `download_expires_at`; there is NO `error` field. Defaults are defensive so a partial/extra-key body never
 * throws; the inline `data` payload is tolerated and never logged.
 */
@JsonClass(generateAdapter = true)
data class ExportStatusDto(
    @Json(name = "request_id") val requestId: String,
    @Json(name = "status") val status: String,
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "completed_at") val completedAt: Long? = null,
    @Json(name = "download_url") val downloadUrl: String? = null,
    @Json(name = "download_expires_at") val downloadExpiresAt: Long? = null,
    @Json(name = "file_size_bytes") val fileSizeBytes: Long? = null,
    @Json(name = "categories_requested") val categoriesRequested: Int = 0,
)

/**
 * AND-385 - history list = DataRequestListOut. CORRECTED: the envelope key is `requests` (not `items`); each row
 * is a DataRequest carrying request_type "export" | "deletion".
 */
@JsonClass(generateAdapter = true)
data class DataRequestListDto(
    @Json(name = "requests") val requests: List<DataRequestDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

/**
 * AND-385 - a single privacy request row (DataRequest). For an export row the download URL/size live under the
 * `export_*` keys; deletion rows carry grace-period fields we do not consume here. Defensive defaults so a
 * partial body never throws.
 */
@JsonClass(generateAdapter = true)
data class DataRequestDto(
    @Json(name = "request_id") val requestId: String,
    @Json(name = "request_type") val requestType: String,
    @Json(name = "status") val status: String,
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "completed_at") val completedAt: Long? = null,
    @Json(name = "export_size_bytes") val exportSizeBytes: Long? = null,
    @Json(name = "export_download_url") val exportDownloadUrl: String? = null,
)
