package com.testlogon.android.data.messaging.legalhold

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-164 — Retrofit interface for the READ-ONLY legal-holds / compliance surface.
 *
 * Kept SEPARATE from [com.testlogon.android.data.messaging.MessagingApi] (per the gotchas) so the large
 * MessagingApi + its test FakeApi stay untouched. Paths are relative; cookies/Authorization/CSRF ride
 * the shared interceptor chain. This is a READ ticket: ONLY the list GET is bound. The write siblings
 * (`POST .../legal-holds` create, `POST .../legal-holds/{hold_id}/release`) exist server-side but are
 * intentionally NOT bound here — the client never creates, releases, or modifies a hold.
 *
 * Endpoint verified against reference/openapi.index.txt (line 329) + reference/openapi.pretty.json
 * (components.schemas.LegalHoldOut):
 *  - list  GET messaging/conversations/{conversation_id}/legal-holds?status=&limit=
 *          -> 200 (bare LegalHoldOut[] array; response schema is empty in OpenAPI)
 *          errors 401/403/404/422/429 -> MessageControlsErrorOut{detail, error_code?}
 *
 * Query params: `status` (enum active|released, default active server-side), `limit`. The web client does
 * NOT call this endpoint and renders no hold UI — the native indicator is a new affordance.
 */
interface LegalHoldApi {

    /** Idempotent GET. Default `status=active` so only enforcing holds are returned. */
    @GET("messaging/conversations/{conversationId}/legal-holds")
    suspend fun listLegalHolds(
        @Path("conversationId") conversationId: String,
        @Query("status") status: String? = STATUS_ACTIVE,
        @Query("limit") limit: Int? = null,
    ): List<LegalHoldDto>

    companion object {
        const val STATUS_ACTIVE = "active"
        const val STATUS_RELEASED = "released"
    }
}

/**
 * AND-164 — LegalHoldOut. Required: hold_id, tenant_id, conversation_id, case_id, reason, status,
 * created_at, created_by_user_id. `message_id == null` => conversation-level hold; non-null => that
 * message. `created_at`/`released_at` are INTEGER epochs (seconds). Optional fields are nullable so
 * unknown/absent variants parse cleanly (Moshi tolerant defaults).
 */
@JsonClass(generateAdapter = true)
data class LegalHoldDto(
    @Json(name = "hold_id") val holdId: String,
    @Json(name = "tenant_id") val tenantId: String? = null,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "message_id") val messageId: String? = null,
    @Json(name = "case_id") val caseId: String,
    @Json(name = "report_id") val reportId: String? = null,
    val reason: String,
    val status: String,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "created_by_user_id") val createdByUserId: String? = null,
    @Json(name = "released_at") val releasedAt: Long? = null,
    @Json(name = "released_by_user_id") val releasedByUserId: String? = null,
)
