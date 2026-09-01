package com.testlogon.android.data.contacts

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Thin client for the EXISTING social follow graph (`app/routers/social.py`, prefix /ui/social).
 *
 * Historically Android only wired follow / unfollow / status (3 of the router's routes). This closes
 * the graph gap by adding the read + snooze routes:
 *   - GET  ui/social/{userId}/followers        (paged list + total)
 *   - GET  ui/social/{userId}/following         (paged list + total)
 *   - GET  ui/social/{userId}/counts            (follower / following totals)
 *   - GET  ui/social/mutual/{targetUserId}      (mutual followers)
 *   - GET  ui/social/following/snoozed          (the viewer's snoozed followings)
 *   - POST ui/social/following/{userId}/snooze  (snooze a following for N days)
 *   - DELETE ui/social/following/{userId}/snooze (un-snooze; idempotent)
 *
 * Block / unblock / blocked-list / block-status live in the separate, already-wired
 * `com.testlogon.android.data.blocking.BlockApi` (same /ui/social prefix) and are reused as-is.
 *
 * Paths are relative (no leading slash) so they resolve against the shared authenticated Retrofit
 * base URL; the cookie jar, Authorization: Bearer and X-CSRF-Token are attached by the core-network
 * interceptor chain. Read routes return [Response] so the repository can degrade-on-404 via the
 * error envelope; the two original body-returning routes keep their simpler signatures.
 */
interface FollowApi {

    /** POST /ui/social/follow */
    @POST("ui/social/follow")
    suspend fun follow(@Body body: FollowTargetDto): FollowActionDto

    /** POST /ui/social/unfollow */
    @POST("ui/social/unfollow")
    suspend fun unfollow(@Body body: FollowTargetDto): UnfollowActionDto

    /** GET /ui/social/status/{targetUserId} — is_following / is_followed_by / is_mutual (+block). */
    @GET("ui/social/status/{targetUserId}")
    suspend fun followStatus(@Path("targetUserId") targetUserId: String): FollowStatusDto

    /** GET /ui/social/{userId}/followers — paged followers of [userId]. */
    @GET("ui/social/{userId}/followers")
    suspend fun followers(
        @Path("userId") userId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
    ): Response<FollowListDto>

    /** GET /ui/social/{userId}/following — paged followings of [userId]. */
    @GET("ui/social/{userId}/following")
    suspend fun following(
        @Path("userId") userId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
    ): Response<FollowListDto>

    /** GET /ui/social/{userId}/counts — follower / following totals. */
    @GET("ui/social/{userId}/counts")
    suspend fun counts(@Path("userId") userId: String): Response<FollowCountsDto>

    /** GET /ui/social/mutual/{targetUserId} — followers the viewer and target share. */
    @GET("ui/social/mutual/{targetUserId}")
    suspend fun mutual(
        @Path("targetUserId") targetUserId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
    ): Response<FollowListDto>

    /** GET /ui/social/following/snoozed — the viewer's currently-snoozed followings. */
    @GET("ui/social/following/snoozed")
    suspend fun snoozedFollowing(): Response<SnoozedFollowingListDto>

    /** POST /ui/social/following/{userId}/snooze — snooze [userId]'s content for [body].days. */
    @POST("ui/social/following/{userId}/snooze")
    suspend fun snoozeFollowing(
        @Path("userId") userId: String,
        @Body body: SnoozeFollowingDto,
    ): Response<SnoozeActionDto>

    /** DELETE /ui/social/following/{userId}/snooze — remove snooze (idempotent). */
    @DELETE("ui/social/following/{userId}/snooze")
    suspend fun unsnoozeFollowing(@Path("userId") userId: String): Response<UnsnoozeActionDto>
}

@JsonClass(generateAdapter = true)
data class FollowTargetDto(
    @Json(name = "target_user_id") val targetUserId: String,
)

@JsonClass(generateAdapter = true)
data class FollowActionDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "status") val status: String = "",
    @Json(name = "follower_count") val followerCount: Int = 0,
    @Json(name = "following_count") val followingCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class UnfollowActionDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "status") val status: String = "",
)

@JsonClass(generateAdapter = true)
data class FollowStatusDto(
    @Json(name = "is_following") val isFollowing: Boolean = false,
    @Json(name = "is_followed_by") val isFollowedBy: Boolean = false,
    @Json(name = "is_mutual") val isMutual: Boolean = false,
    @Json(name = "is_blocked_by_me") val isBlockedByMe: Boolean = false,
    @Json(name = "is_blocking_me") val isBlockingMe: Boolean = false,
)

/** A single follow-list entry (FollowUser in social.py). */
@JsonClass(generateAdapter = true)
data class FollowUserDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "profile_photo_url") val profilePhotoUrl: String? = null,
    @Json(name = "is_following") val isFollowing: Boolean = false,
    @Json(name = "is_mutual") val isMutual: Boolean = false,
    @Json(name = "snoozed_until") val snoozedUntil: Long? = null,
    @Json(name = "is_snoozed") val isSnoozed: Boolean = false,
)

/** FollowListResponse { items, next_cursor?, total_count }. */
@JsonClass(generateAdapter = true)
data class FollowListDto(
    @Json(name = "items") val items: List<FollowUserDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "total_count") val totalCount: Int = 0,
)

/** FollowCountsResponse { follower_count, following_count }. */
@JsonClass(generateAdapter = true)
data class FollowCountsDto(
    @Json(name = "follower_count") val followerCount: Int = 0,
    @Json(name = "following_count") val followingCount: Int = 0,
)

/** SnoozeFollowingIn { days: 1..90 }. */
@JsonClass(generateAdapter = true)
data class SnoozeFollowingDto(
    @Json(name = "days") val days: Int,
)

/** SnoozeFollowingOut { ok, snoozed_until }. */
@JsonClass(generateAdapter = true)
data class SnoozeActionDto(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "snoozed_until") val snoozedUntil: Long = 0,
)

/** UnsnoozeFollowingOut { ok }. */
@JsonClass(generateAdapter = true)
data class UnsnoozeActionDto(
    @Json(name = "ok") val ok: Boolean = true,
)

/** A single snoozed-following row (SnoozedFollowingOut in models.py). */
@JsonClass(generateAdapter = true)
data class SnoozedFollowingDto(
    @Json(name = "following_sub") val followingSub: String,
    @Json(name = "following_name") val followingName: String? = null,
    @Json(name = "following_avatar_url") val followingAvatarUrl: String? = null,
    @Json(name = "followed_at") val followedAt: Long = 0,
    @Json(name = "snoozed_until") val snoozedUntil: Long = 0,
    @Json(name = "snooze_remaining_hours") val snoozeRemainingHours: Int? = null,
)

/** SnoozedFollowingListOut { snoozed, total }. */
@JsonClass(generateAdapter = true)
data class SnoozedFollowingListDto(
    @Json(name = "snoozed") val snoozed: List<SnoozedFollowingDto> = emptyList(),
    @Json(name = "total") val total: Int = 0,
)
