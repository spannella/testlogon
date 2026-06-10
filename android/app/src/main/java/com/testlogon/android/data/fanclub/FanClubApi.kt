package com.testlogon.android.data.fanclub

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-238 / AND-239 / AND-240 — Retrofit interface + Moshi DTOs for the fan-club (creator community)
 * surface: tier-grouped channels, per-channel message threads, fan-club tiers, and tier members.
 *
 * DEDICATED service (NOT MessagingApi) so the messaging FakeApi and MessagingEvent sealed type are
 * untouched. Fan-club channel messages do NOT reuse the messaging SSE stream: the web reference polls
 * (refetchInterval 5000, src/pages/fan-club/FanClubPage.tsx) and there is no fan-club SSE topic in the
 * contract — so the Android client uses pull-to-refresh + Paging invalidation (poll/refresh), matching
 * the AND-239 non-goal "polling/pull-only".
 *
 * VERIFIED against reference/openapi.index.txt + reference/src/api/endpoints/fan-club.ts +
 * reference/src/api/types.ts (TierOut L4658, ChannelOut L4677, ChannelMessageOut L4693,
 * MemberBadgeData L4707). Timestamps are epoch-seconds Longs.
 *
 * Endpoint citations (reference/openapi.index.txt):
 *  - GET    ui/fan-club/channels                         op=api_list_channels_...        -> bare ChannelOut[]
 *  - GET    ui/fan-club/tiers                            op=api_list_tiers_...           -> bare TierOut[]
 *  - GET    ui/fan-club/tiers/{tier_id}/members          op=api_tier_members_...         (params tier_id,limit,cursor)
 *  - GET    ui/fan-club/channels/{channel_id}/messages   op=api_get_channel_messages_... (params limit,before) -> bare ChannelMessageOut[]
 *  - POST   ui/fan-club/channels/{channel_id}/messages   op=api_send_channel_message_... req=ChannelMessageIn -> ChannelMessageOut (201)
 *  - POST   ui/fan-club/channels/{channel_id}/messages/{message_id}/react op=api_add_reaction_... (free-form body, untyped resp)
 *  - DELETE ui/fan-club/channels/{channel_id}/messages/{message_id}       op=api_delete_channel_message_... (resp 200)
 *
 * AUTH NOTE: session cookies + Authorization Bearer + X-CSRF-Token are attached by the shared
 * core-network interceptors; 401 -> single POST /ui/session/refresh + retry is handled by
 * SessionAuthenticator. No per-method auth headers are needed (unlike the X-User-Id subscriptions API).
 *
 * GAPS (cited in the report): the members 200 body schema is untyped in OpenAPI and has NO web caller —
 * [TierMembersPageDto] is a PROPOSED contract (the repository normalizes envelope-vs-bare-list). The
 * react request/response body is declared free-form (additionalProperties:true) with no web caller —
 * [ReactionRequestDto] {"emoji"} is an ASSUMED single-emoji toggle.
 */
interface FanClubApi {

    /**
     * AND-238 — a creator's fan-club channels (bare JSON array of ChannelOut). [creatorId] is an
     * OPTIONAL query param (omit -> caller's own context). Idempotent GET.
     */
    @GET("ui/fan-club/channels")
    suspend fun getChannels(
        @Query("creator_id") creatorId: String?,
    ): List<ChannelDto>

    /** AND-238/AND-240 — the fan-club's tiers (bare JSON array of TierOut). Idempotent GET. */
    @GET("ui/fan-club/tiers")
    suspend fun getTiers(): List<TierDto>

    /**
     * AND-240 — members of a tier. Path param is `tier_id` (verified). Idempotent GET. Response shape
     * is unverified (untyped OpenAPI 200, no web caller); deserialized into [TierMembersPageDto].
     */
    @GET("ui/fan-club/tiers/{tier_id}/members")
    suspend fun getTierMembers(
        @Path("tier_id") tierId: String,
        @Query("cursor") cursor: String?,
        @Query("limit") limit: Int,
    ): TierMembersPageDto

    /**
     * AND-239 — a channel's messages (bare JSON array of ChannelMessageOut). [before] is the oldest
     * message id of the previous (newer) page; server default limit=50, max 200. Idempotent GET.
     */
    @GET("ui/fan-club/channels/{channel_id}/messages")
    suspend fun getMessages(
        @Path("channel_id") channelId: String,
        @Query("before") before: String?,
        @Query("limit") limit: Int,
    ): List<ChannelMessageDto>

    /** AND-239 — post a text message (ChannelMessageIn). 201 -> single ChannelMessageOut. */
    @Headers("Content-Type: application/json")
    @POST("ui/fan-club/channels/{channel_id}/messages")
    suspend fun postMessage(
        @Path("channel_id") channelId: String,
        @Body body: ChannelMessageInDto,
    ): ChannelMessageDto

    /**
     * AND-239 — toggle a reaction on a message. ASSUMED single-emoji toggle body; the OpenAPI body is
     * free-form and the web client never calls it. Response is untyped (read as Response<Unit>).
     */
    @Headers("Content-Type: application/json")
    @POST("ui/fan-club/channels/{channel_id}/messages/{message_id}/react")
    suspend fun react(
        @Path("channel_id") channelId: String,
        @Path("message_id") messageId: String,
        @Body body: ReactionRequestDto,
    ): Response<Unit>

    /** AND-239 — delete a message. Success is HTTP 200 (NOT 204); treat 200/204 + empty body as ok. */
    @DELETE("ui/fan-club/channels/{channel_id}/messages/{message_id}")
    suspend fun deleteMessage(
        @Path("channel_id") channelId: String,
        @Path("message_id") messageId: String,
    ): Response<Unit>
}

// ---- Channel DTOs (AND-238) ----

/** Fan-club channel. Verified: types.ts ChannelOut (L4677). Epoch-seconds Longs; no avatar/position. */
@JsonClass(generateAdapter = true)
data class ChannelDto(
    @Json(name = "channel_id") val channelId: String,
    @Json(name = "creator_id") val creatorId: String? = null,
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "min_tier_level") val minTierLevel: Int = 0,
    @Json(name = "message_count") val messageCount: Int = 0,
    @Json(name = "last_message_at") val lastMessageAt: Long = 0,
    @Json(name = "last_message_preview") val lastMessagePreview: String? = null,
    @Json(name = "pinned_message_id") val pinnedMessageId: String? = null,
    @Json(name = "slowmode_seconds") val slowmodeSeconds: Int = 0,
    @Json(name = "max_message_length") val maxMessageLength: Int = 0,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

// ---- Tier DTOs (AND-238 / AND-240) ----

/** Fan-club tier. Verified: types.ts TierOut (L4658). NO price field (price lives on plan_id). */
@JsonClass(generateAdapter = true)
data class TierDto(
    @Json(name = "tier_id") val tierId: String,
    @Json(name = "creator_id") val creatorId: String? = null,
    @Json(name = "plan_id") val planId: String? = null,
    @Json(name = "name") val name: String,
    @Json(name = "level") val level: Int = 0,
    @Json(name = "color") val color: String? = null,
    @Json(name = "badge_emoji") val badgeEmoji: String? = null,
    @Json(name = "badge_image_url") val badgeImageUrl: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "member_count") val memberCount: Int = 0,
    @Json(name = "sort_order") val sortOrder: Int = 0,
    @Json(name = "active") val active: Boolean = true,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

// ---- Tier member DTOs (AND-240) ----

/**
 * Tier members page. UNVERIFIED proposed contract (untyped OpenAPI 200 + no web caller). The
 * repository also normalizes a bare-list response into a single page.
 */
@JsonClass(generateAdapter = true)
data class TierMembersPageDto(
    @Json(name = "items") val items: List<TierMemberDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "total") val total: Int? = null,
)

/** A single tier member. UNVERIFIED field names (see [TierMembersPageDto]); all optional but user id. */
@JsonClass(generateAdapter = true)
data class TierMemberDto(
    @Json(name = "user_id") val userId: String? = null,
    @Json(name = "username") val username: String? = null,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "avatar_url") val avatarUrl: String? = null,
    @Json(name = "tier_id") val tierId: String? = null,
    @Json(name = "tier_name") val tierName: String? = null,
    @Json(name = "subscribed_since") val subscribedSince: Long? = null,
)

// ---- Channel message DTOs (AND-239) ----

/** Channel message. Verified: types.ts ChannelMessageOut (L4693). `kind` discriminator; epoch seconds. */
@JsonClass(generateAdapter = true)
data class ChannelMessageDto(
    @Json(name = "message_id") val messageId: String,
    @Json(name = "channel_id") val channelId: String? = null,
    @Json(name = "sender_id") val senderId: String = "",
    @Json(name = "sender_display_name") val senderDisplayName: String = "",
    @Json(name = "sender_badge") val senderBadge: MemberBadgeDto? = null,
    @Json(name = "text") val text: String = "",
    @Json(name = "kind") val kind: String = "text",
    @Json(name = "reply_to_message_id") val replyToMessageId: String? = null,
    // reactions: Map<emoji, Map<userId, bool>> (verified). count = inner.size; reacted = key contains me.
    @Json(name = "reactions") val reactions: Map<String, Map<String, Boolean>> = emptyMap(),
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "deleted") val deleted: Boolean = false,
)

/** Sender tier badge. Verified: types.ts MemberBadgeData (L4707). */
@JsonClass(generateAdapter = true)
data class MemberBadgeDto(
    @Json(name = "tier_name") val tierName: String? = null,
    @Json(name = "tier_level") val tierLevel: Int? = null,
    @Json(name = "badge_emoji") val badgeEmoji: String? = null,
    @Json(name = "badge_color") val badgeColor: String? = null,
    @Json(name = "badge_image_url") val badgeImageUrl: String? = null,
)

/** Post-message request. Verified: ChannelMessageIn { text (1..2000), reply_to_message_id? }. */
@JsonClass(generateAdapter = true)
data class ChannelMessageInDto(
    @Json(name = "text") val text: String,
    @Json(name = "reply_to_message_id") val replyToMessageId: String? = null,
)

/** Reaction toggle request. ASSUMED single-emoji body (free-form per OpenAPI; no web caller). */
@JsonClass(generateAdapter = true)
data class ReactionRequestDto(
    @Json(name = "emoji") val emoji: String,
)
