package com.testlogon.android.data.dmca

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.Headers
import retrofit2.http.POST

/**
 * AND-384 - Retrofit interface for filing a DMCA (copyright takedown) notice.
 *
 * Verified endpoint (CORRECTED from the draft's non-existent /ui/dmca/takedown):
 *   POST v1/dmca/claims  req=DmcaClaimIn -> 201:DmcaClaimCreateOut, 422:HTTPValidationError
 *   (op submit_dmca_claim, openapi.index.txt line 2193; src/api/endpoints/dmca.ts submitDmcaClaim).
 *
 * Provided on the SHARED authenticated Retrofit by [DmcaApiModule] - no new OkHttp / Retrofit. The path is
 * relative (no leading slash) so it resolves against the shared base URL; cookies, Authorization and
 * X-CSRF-Token are attached project-wide by the core-network interceptor chain - this interface stays
 * header-agnostic. The POST is non-idempotent and is NEVER auto-retried (a duplicate legal notice is a real
 * harm); retry is user-initiated only.
 *
 * The success status is 201 (NOT 200). The response uses `claim_id` and an INTEGER epoch `created_at`; it has
 * NO `reference` / `case_id` field.
 */
interface DmcaApi {

    @Headers("Content-Type: application/json")
    @POST("v1/dmca/claims")
    suspend fun submitClaim(
        @Body body: DmcaClaimRequest,
    ): Response<DmcaClaimCreateResponse>
}

/**
 * AND-384 - POST body = DmcaClaimIn.
 *
 * Required (server): `claimant_name` (2..256), `claimant_email` (5..320), `claimant_address` (10..1000),
 * `content_url` (5..2000), `original_work_description` (20..5000), `sworn_statement`==true,
 * `good_faith_belief`==true, `signature` (2..256).
 *
 * Optional with server defaults: `claimant_phone` (<=30, default ""), `content_type` (enum, default "other"),
 * `content_id` (<=256, default ""). Absent optionals are serialized as null (the backend treats null/absent
 * as the default). `content_type` enum: feed_post | feed_media | message_media | video | other. Flat
 * content_url/content_type/content_id (no nested content_ref object - CORRECTED).
 */
@JsonClass(generateAdapter = true)
data class DmcaClaimRequest(
    @Json(name = "claimant_name") val claimantName: String,
    @Json(name = "claimant_email") val claimantEmail: String,
    @Json(name = "claimant_address") val claimantAddress: String,
    @Json(name = "claimant_phone") val claimantPhone: String? = null,
    @Json(name = "content_url") val contentUrl: String,
    @Json(name = "content_type") val contentType: String = DmcaContentType.OTHER,
    @Json(name = "content_id") val contentId: String? = null,
    @Json(name = "original_work_description") val originalWorkDescription: String,
    @Json(name = "sworn_statement") val swornStatement: Boolean,
    @Json(name = "good_faith_belief") val goodFaithBelief: Boolean,
    @Json(name = "signature") val signature: String,
)

/**
 * AND-384 - 201 response = DmcaClaimCreateOut. CORRECTED: no `reference`, no `case_id`; `created_at` is an
 * INTEGER epoch (seconds), NOT an ISO-8601 string. Defaults are defensive so a partial body never throws.
 */
@JsonClass(generateAdapter = true)
data class DmcaClaimCreateResponse(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "claim_id") val claimId: String,
    @Json(name = "status") val status: String = "received",
    @Json(name = "content_removed") val contentRemoved: Boolean = false,
    @Json(name = "strike_number") val strikeNumber: Int = 0,
    @Json(name = "created_at") val createdAt: Long = 0L,
)

/**
 * AND-384 - the DmcaClaimIn.content_type wire enum, modelled as String constants with an UNKNOWN-tolerant
 * accessor (never throw on an unexpected value). [ALL] is the dropdown ordering offered in the form.
 */
object DmcaContentType {
    const val FEED_POST = "feed_post"
    const val FEED_MEDIA = "feed_media"
    const val MESSAGE_MEDIA = "message_media"
    const val VIDEO = "video"
    const val OTHER = "other"

    /** Stable ordering offered by the form's dropdown (web shows these five; "other" is the default). */
    val ALL: List<String> = listOf(FEED_POST, FEED_MEDIA, MESSAGE_MEDIA, VIDEO, OTHER)

    /** Normalizes any wire value to a known code, falling back to [OTHER] for an unknown/blank value. */
    fun normalize(value: String?): String = if (value in ALL) value!! else OTHER
}
