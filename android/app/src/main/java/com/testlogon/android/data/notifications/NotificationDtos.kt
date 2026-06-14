package com.testlogon.android.data.notifications

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-084 — wire DTOs for the in-app notification center.
 *
 * Shapes are the verified contract from reference/src/api/types.ts (NotificationOut,
 * NotificationListResponse, MarkNotificationsReadReq) and reference/src/api/endpoints/notifications.ts
 * (getNotifications, getNotificationUnreadCount, markNotificationsRead, markAllNotificationsRead).
 *
 * Field-name notes (verified):
 *  - item id is "notification_id" (NOT "id"); type is "notification_type" (NOT "type").
 *  - read flag is "read" (NOT "is_read").
 *  - created_at is an epoch-SECONDS integer (NOT an ISO-8601 string, NOT ms).
 *  - there is NO "deep_link" field; routable hints (if any) live in the free-form "data" object.
 *  - the list envelope carries "next_cursor" (nullable) and a non-null "unread_count".
 *  - mark-read / mark-all-read responses are { ok, marked_count } (frontend contract; the OpenAPI
 *    leaves the 200 body untyped). unread-count returns { count }.
 *
 * Only "notification_id" is server-required; every other field is defaulted to mirror the server
 * default. Uses Moshi codegen (@JsonClass(generateAdapter = true)), consistent with the other DTOs.
 */
@JsonClass(generateAdapter = true)
data class NotificationDto(
    @Json(name = "notification_id") val notificationId: String,
    @Json(name = "notification_type") val notificationType: String = "",
    val title: String = "",
    val body: String = "",
    val read: Boolean = false,
    @Json(name = "created_at") val createdAt: Long = 0L,
    val data: Map<String, Any?> = emptyMap(),
    @Json(name = "batch_key") val batchKey: String? = null,
    @Json(name = "batch_count") val batchCount: Int = 1,
    @Json(name = "batch_actors") val batchActors: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class NotificationListResponseDto(
    val items: List<NotificationDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "unread_count") val unreadCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class MarkNotificationsReadReq(
    @Json(name = "notification_ids") val notificationIds: List<String>,
)

@JsonClass(generateAdapter = true)
data class MarkReadResp(
    val ok: Boolean = false,
    @Json(name = "marked_count") val markedCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class UnreadCountResp(
    val count: Int = 0,
)
