package com.testlogon.android.data.messaging

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.Headers
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-141 — Retrofit interface for the per-conversation drafts collection.
 *
 * Endpoints verified against the backend OpenAPI + reference/src/api/endpoints/messaging.ts:
 *  - list   -> GET    .../drafts                    (limit, cursor) -> DraftListOut
 *  - create -> POST   .../drafts                    DraftCreateIn (Idempotency-Key header) -> 201 DraftEnvelope
 *  - get    -> GET    .../drafts/{draftId}          -> DraftEnvelope
 *  - patch  -> PATCH  .../drafts/{draftId}          DraftPatchIn -> 200 DraftEnvelope
 *  - delete -> DELETE .../drafts/{draftId}          -> 204
 *
 * The resource is a COLLECTION of text-only drafts (each with a draft_id); there is no singular
 * resource and no PUT. The Android client surfaces the most-recent draft as the single active one.
 */
interface DraftApi {

    @GET("messaging/conversations/{cid}/drafts")
    suspend fun listDrafts(
        @Path("cid") conversationId: String,
        @Query("limit") limit: Int = 20,
        @Query("cursor") cursor: String? = null,
    ): DraftListDto

    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{cid}/drafts")
    suspend fun createDraft(
        @Path("cid") conversationId: String,
        @Header("Idempotency-Key") idempotencyKey: String,
        @Body body: DraftCreateDto,
    ): DraftEnvelopeDto

    @GET("messaging/conversations/{cid}/drafts/{draftId}")
    suspend fun getDraft(
        @Path("cid") conversationId: String,
        @Path("draftId") draftId: String,
    ): DraftEnvelopeDto

    @Headers("Content-Type: application/json")
    @PATCH("messaging/conversations/{cid}/drafts/{draftId}")
    suspend fun patchDraft(
        @Path("cid") conversationId: String,
        @Path("draftId") draftId: String,
        @Body body: DraftPatchDto,
    ): DraftEnvelopeDto

    @DELETE("messaging/conversations/{cid}/drafts/{draftId}")
    suspend fun deleteDraft(
        @Path("cid") conversationId: String,
        @Path("draftId") draftId: String,
    )
}

/** DraftCreateIn — text (1..4000) + optional client_updated_at hint (epoch ms). */
@JsonClass(generateAdapter = true)
data class DraftCreateDto(
    val text: String,
    @Json(name = "client_updated_at") val clientUpdatedAt: Long? = null,
)

/** DraftPatchIn — same shape as create. */
@JsonClass(generateAdapter = true)
data class DraftPatchDto(
    val text: String,
    @Json(name = "client_updated_at") val clientUpdatedAt: Long? = null,
)

/** Enveloped single-draft response: { "draft": DraftOut }. */
@JsonClass(generateAdapter = true)
data class DraftEnvelopeDto(
    val draft: DraftDto,
)

/** List response: { items: DraftOut[], next_cursor? }. */
@JsonClass(generateAdapter = true)
data class DraftListDto(
    val items: List<DraftDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

/** DraftOut — timestamps are integer epochs (ms per the web adapter); text-only (no attachments). */
@JsonClass(generateAdapter = true)
data class DraftDto(
    @Json(name = "draft_id") val draftId: String,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "owner_user_id") val ownerUserId: String = "",
    val text: String,
    val version: Int = 1,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
    @Json(name = "client_updated_at") val clientUpdatedAt: Long? = null,
    @Json(name = "tenant_id") val tenantId: String? = null,
)
