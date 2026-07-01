package com.testlogon.android.data.licenses

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface + Moshi DTOs for the full license-REQUESTS workflow (inbox + sent + actions).
 *
 * Mirrors frontend/src/api/endpoints/licenseRequests.ts. The list endpoints return LicenseRequestOut
 * items (with optional counter_terms); every action takes the request_id in the path and content_id as
 * a query param (matching the FastAPI signatures in app/routers/license_requests.py). Approve and
 * accept-counter return an approval envelope; the other actions return the updated request. Session
 * cookies + X-CSRF-Token are attached by interceptors.
 */
interface LicenseRequestsActionsApi {

    /** Requests the caller has RECEIVED (owner inbox). */
    @GET("ui/licenses/requests/received")
    suspend fun getReceivedRequests(
        @Query("status") status: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): FullLicenseRequestListDto

    /** Requests the caller has SENT (full shape incl. counter_terms). */
    @GET("ui/licenses/requests/sent")
    suspend fun getSentRequests(
        @Query("status") status: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): FullLicenseRequestListDto

    // ---- owner (inbox) actions ----

    @POST("ui/licenses/requests/{requestId}/approve")
    suspend fun approve(
        @Path("requestId") requestId: String,
        @Query("content_id") contentId: String,
    ): LicenseRequestApprovalDto

    @POST("ui/licenses/requests/{requestId}/deny")
    suspend fun deny(
        @Path("requestId") requestId: String,
        @Query("content_id") contentId: String,
        @Body body: DenyReqDto,
    ): FullLicenseRequestDto

    @POST("ui/licenses/requests/{requestId}/counter")
    suspend fun counter(
        @Path("requestId") requestId: String,
        @Query("content_id") contentId: String,
        @Body body: CounterReqDto,
    ): FullLicenseRequestDto

    // ---- requester (sent) actions ----

    @POST("ui/licenses/requests/{requestId}/accept-counter")
    suspend fun acceptCounter(
        @Path("requestId") requestId: String,
        @Query("content_id") contentId: String,
    ): LicenseRequestApprovalDto

    @POST("ui/licenses/requests/{requestId}/reject-counter")
    suspend fun rejectCounter(
        @Path("requestId") requestId: String,
        @Query("content_id") contentId: String,
    ): FullLicenseRequestDto

    @POST("ui/licenses/requests/{requestId}/withdraw")
    suspend fun withdraw(
        @Path("requestId") requestId: String,
        @Query("content_id") contentId: String,
    ): FullLicenseRequestDto
}

// ---- request bodies ----

@JsonClass(generateAdapter = true)
data class DenyReqDto(val reason: String = "")

@JsonClass(generateAdapter = true)
data class CounterReqDto(
    @Json(name = "counter_terms") val counterTerms: LicenseTermsDto,
)

// ---- response DTOs (full LicenseRequestOut shape) ----

@JsonClass(generateAdapter = true)
data class FullLicenseRequestListDto(
    val items: List<FullLicenseRequestDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class FullLicenseRequestDto(
    @Json(name = "request_id") val requestId: String,
    @Json(name = "content_id") val contentId: String = "",
    @Json(name = "content_type") val contentType: String = "",
    @Json(name = "requester_id") val requesterId: String = "",
    @Json(name = "requester_display_name") val requesterDisplayName: String = "",
    @Json(name = "owner_id") val ownerId: String = "",
    @Json(name = "owner_display_name") val ownerDisplayName: String = "",
    val status: String = "",
    @Json(name = "proposed_terms") val proposedTerms: LicenseTermsDto? = null,
    @Json(name = "counter_terms") val counterTerms: LicenseTermsDto? = null,
    @Json(name = "denial_reason") val denialReason: String = "",
    val message: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
    @Json(name = "expires_at") val expiresAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class LicenseRequestApprovalDto(
    val request: FullLicenseRequestDto,
)
