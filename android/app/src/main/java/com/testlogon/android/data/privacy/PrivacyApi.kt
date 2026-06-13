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

    // AND-386 - account-deletion request/cancel surface (extends the AND-385 PrivacyApi; same module,
    // same shared authenticated Retrofit). Endpoints RECONCILED against openapi.index.txt +
    // src/api/endpoints/accountDeletion.ts (spec §4/§5/§16):
    //   GET  ui/privacy/account-deletion/requests                     -> 200:AccountDeletionListOut
    //   GET  ui/privacy/account-deletion/requests/{requestId}         -> 200:AccountDeletionStatusOut
    //   POST ui/privacy/account-deletion/request   body req           -> 201:AccountDeletionStatusOut
    //   POST ui/privacy/account-deletion/requests/{requestId}/cancel  -> 200:AccountDeletionCancelOut
    // There is NO singleton status GET; the active state is derived from the list (status == "pending").
    // The two POSTs are non-idempotent and are NEVER auto-retried; the GETs are idempotent.

    @GET("ui/privacy/account-deletion/requests")
    suspend fun listDeletions(): Response<AccountDeletionListDto>

    @GET("ui/privacy/account-deletion/requests/{requestId}")
    suspend fun getDeletion(
        @Path("requestId") requestId: String,
    ): Response<AccountDeletionStatusDto>

    @Headers("Content-Type: application/json")
    @POST("ui/privacy/account-deletion/request")
    suspend fun requestDeletion(
        @Body body: AccountDeletionRequestDto,
    ): Response<AccountDeletionStatusDto>

    @POST("ui/privacy/account-deletion/requests/{requestId}/cancel")
    suspend fun cancelDeletion(
        @Path("requestId") requestId: String,
    ): Response<AccountDeletionCancelDto>
}

/**
 * AND-386 - POST body = AccountDeletionRequestIn. [confirmText] MUST equal the server sentinel
 * "DELETE MY ACCOUNT" (spec §5/§16, claim 5); [password] is the user's re-entered password
 * (required, 1..200); [reason] is optional (<= 500). The password is sent over the dev-only
 * plaintext channel and is NEVER persisted or logged (spec §8).
 */
@JsonClass(generateAdapter = true)
data class AccountDeletionRequestDto(
    @Json(name = "password") val password: String,
    @Json(name = "confirm_text") val confirmText: String,
    @Json(name = "reason") val reason: String? = null,
)

/**
 * AND-386 - AccountDeletionStatusOut. CORRECTED (spec §5/§16, claim 9): ALL timestamps are INTEGER epoch
 * SECONDS (not ISO strings); the creation field is `created_at` (there is NO `requested_at`). The pending
 * state is `status == "pending"` (NOT "pending_deletion"). Defaults are defensive so a partial / extra-key
 * body never throws; identifiers/timestamps here are NEVER logged (spec §8 / AC-8).
 */
@JsonClass(generateAdapter = true)
data class AccountDeletionStatusDto(
    @Json(name = "request_id") val requestId: String,
    @Json(name = "status") val status: String,
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "scheduled_for") val scheduledFor: Long? = null,
    @Json(name = "grace_days_remaining") val graceDaysRemaining: Int? = null,
    @Json(name = "can_cancel") val canCancel: Boolean = false,
    @Json(name = "retention_hold") val retentionHold: Boolean = false,
    @Json(name = "retention_hold_reason") val retentionHoldReason: String? = null,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "completed_at") val completedAt: Long? = null,
    @Json(name = "user_sub") val userSub: String? = null,
)

/**
 * AND-386 - AccountDeletionListOut. The caller's deletion requests; the active pending request is the
 * entry whose `status == "pending"` (mirrors the web client's `requests.find(r => r.status === "pending")`).
 */
@JsonClass(generateAdapter = true)
data class AccountDeletionListDto(
    @Json(name = "requests") val requests: List<AccountDeletionStatusDto> = emptyList(),
    @Json(name = "total") val total: Int = 0,
)

/**
 * AND-386 - AccountDeletionCancelOut (cancel returns 200 + this body, NOT 204/empty - spec §5/§16, claim 8).
 * `cancelled_at` is epoch SECONDS. Defensive defaults so a partial body never throws.
 */
@JsonClass(generateAdapter = true)
data class AccountDeletionCancelDto(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "request_id") val requestId: String,
    @Json(name = "status") val status: String,
    @Json(name = "cancelled_at") val cancelledAt: Long = 0L,
)

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
