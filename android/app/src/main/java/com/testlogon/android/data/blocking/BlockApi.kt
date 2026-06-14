package com.testlogon.android.data.blocking

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-382 - Retrofit interface + Moshi DTOs for user-level block / unblock.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; the
 * persistent cookie jar, Authorization: Bearer and X-CSRF-Token are attached by the core-network
 * interceptor chain established in AND-027. All methods are suspend; non-2xx surfaces as
 * HttpException via the [retrofit2.Response] envelope inspected in the repository.
 *
 * Contract verified against reference/src/api/endpoints/blocking.ts and the OpenAPI index (see spec
 * sec.16). NOTE the CORRECTED shapes: block AND unblock are BOTH JSON-body POSTs under /ui/social/...
 * (unblock is NOT a DELETE), the request field is target_user_id (not blocked_user_id), and all four
 * return HTTP 200 (no 201/204). The list key is blocked_users (not items), the timestamp is
 * blocked_at (not created_at), and items carry NO handle field.
 */
interface BlockApi {

    /**
     * POST ui/social/block - req=BlockRequest, resp=200:BlockActionResponse.
     * Non-idempotent mutation; never auto-retried. CSRF token attached by the interceptor chain.
     */
    @POST("ui/social/block")
    suspend fun block(@Body body: BlockRequestDto): Response<BlockActionDto>

    /**
     * POST ui/social/unblock - req=UnblockRequest, resp=200:BlockActionResponse.
     * A POST (not a DELETE); never auto-retried.
     */
    @POST("ui/social/unblock")
    suspend fun unblock(@Body body: UnblockRequestDto): Response<BlockActionDto>

    /** GET ui/social/blocked - resp=200:BlockedUsersListResponse, params limit,cursor. Idempotent. */
    @GET("ui/social/blocked")
    suspend fun listBlocks(
        @Query("limit") limit: Int = 50,
        @Query("cursor") cursor: String? = null,
    ): Response<BlockedUsersListDto>

    /** GET ui/social/block-status/{targetUserId} - resp=200:BlockStatusResponse. Idempotent. */
    @GET("ui/social/block-status/{targetUserId}")
    suspend fun blockStatus(@Path("targetUserId") targetUserId: String): Response<BlockStatusDto>
}

// ---- DTOs (AND-382). :app feature DTOs use @JsonClass(generateAdapter=true) codegen. ----

@JsonClass(generateAdapter = true)
data class BlockRequestDto(
    @Json(name = "target_user_id") val targetUserId: String,
    // Optional; server maxLength 500. Omitted from the wire when null.
    @Json(name = "reason") val reason: String? = null,
)

@JsonClass(generateAdapter = true)
data class UnblockRequestDto(
    @Json(name = "target_user_id") val targetUserId: String,
)

/**
 * BlockActionResponse { ok: bool (default true), status: string, target_user_id: string }.
 * status is "blocked" | "unblocked" per src/api/types.ts, but the client treats ANY 200 as success
 * and does NOT branch on status (FR-6 idempotency; citation audit sec.16 #16).
 */
@JsonClass(generateAdapter = true)
data class BlockActionDto(
    val ok: Boolean = true,
    val status: String = "",
    @Json(name = "target_user_id") val targetUserId: String = "",
)

/** BlockStatusResponse { is_blocked_by_me: bool, is_blocking_me: bool }. */
@JsonClass(generateAdapter = true)
data class BlockStatusDto(
    @Json(name = "is_blocked_by_me") val isBlockedByMe: Boolean = false,
    @Json(name = "is_blocking_me") val isBlockingMe: Boolean = false,
)

/** BlockedUsersListResponse { blocked_users: BlockedUserItem[], next_cursor?: string, total_count: int }. */
@JsonClass(generateAdapter = true)
data class BlockedUsersListDto(
    @Json(name = "blocked_users") val blockedUsers: List<BlockedUserDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "total_count") val totalCount: Int = 0,
)

/** BlockedUserItem { user_id, display_name?, profile_photo_url?, blocked_at }. No handle, no created_at. */
@JsonClass(generateAdapter = true)
data class BlockedUserDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "profile_photo_url") val profilePhotoUrl: String? = null,
    @Json(name = "blocked_at") val blockedAt: String = "",
)
