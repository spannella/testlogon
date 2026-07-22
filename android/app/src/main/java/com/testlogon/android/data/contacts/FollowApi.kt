package com.testlogon.android.data.contacts

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * Thin client for the EXISTING social follow graph (`app/routers/social.py`):
 * follow / unfollow + bidirectional follow-status. The Android app already had
 * BlockApi but no follow wiring — this closes that gap for the Contacts card.
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
