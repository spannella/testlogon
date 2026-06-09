package com.testlogon.android.data.activity

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-091 — wire DTOs for the account activity feed.
 *
 * Verified contract (reference/src/api/types.ts: ActivityItem / ActivityFeedPageResponse, and OpenAPI
 * GET /ui/activity/feed -> ActivityFeedResponse / ActivityOut):
 *  - item id is "activity_id" (NOT "id"); kind is "activity_type" (NOT "type").
 *  - "actor_id" is required; "target_type"/"target_id" default to "" (empty -> null in domain).
 *  - created_at is an epoch-SECONDS integer (NOT an ISO-8601 string, NOT ms).
 *  - there is NO server "ip"/"user_agent"/top-level "detail"; any hint lives in free-form "metadata".
 *  - envelope carries "items", nullable "next_cursor", and integer "total_unread".
 *
 * Only "activity_id"/"actor_id"/"activity_type" are server-required; everything else is defaulted to
 * mirror the server defaults. Moshi codegen, consistent with the other feature DTOs.
 */
@JsonClass(generateAdapter = true)
data class ActivityEventDto(
    @Json(name = "activity_id") val activityId: String,
    @Json(name = "actor_id") val actorId: String = "",
    @Json(name = "activity_type") val activityType: String = "",
    @Json(name = "target_type") val targetType: String = "",
    @Json(name = "target_id") val targetId: String = "",
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "read") val read: Boolean = false,
    @Json(name = "metadata") val metadata: Map<String, Any?> = emptyMap(),
)

@JsonClass(generateAdapter = true)
data class ActivityFeedResponseDto(
    @Json(name = "items") val items: List<ActivityEventDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "total_unread") val totalUnread: Int = 0,
)
