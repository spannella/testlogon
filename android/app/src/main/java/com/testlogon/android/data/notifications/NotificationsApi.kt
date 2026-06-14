package com.testlogon.android.data.notifications

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Query

/**
 * AND-084 — Retrofit interface for the notification center surface.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL;
 * cookies, Authorization and X-CSRF-Token are attached by the core-network interceptor chain (so no
 * headers are declared per-method beyond Content-Type on the mutating POSTs). All methods are
 * suspend and return the typed DTO body; non-2xx surfaces as retrofit2.HttpException.
 *
 * Endpoints verified against reference/src/api/endpoints/notifications.ts and OpenAPI index:
 *  - list        -> GET  ui/notifications              (params cursor,limit; resp NotificationListResponse)
 *  - markRead    -> POST ui/notifications/mark-read    (req MarkNotificationsReadIn {notification_ids})
 *  - markAllRead -> POST ui/notifications/mark-all-read (empty {} body)
 *  - unreadCount -> GET  ui/notifications/unread-count ({count})
 */
interface NotificationsApi {

    /** Paginated, newest-first list. Idempotent GET. Only cursor + limit are accepted. */
    @GET("ui/notifications")
    suspend fun list(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): NotificationListResponseDto

    /** Mark a set of notifications read. Mutating POST (CSRF injected by the interceptor chain). */
    @Headers("Content-Type: application/json")
    @POST("ui/notifications/mark-read")
    suspend fun markRead(@Body body: MarkNotificationsReadReq): MarkReadResp

    /** Mark all read. The web client POSTs an empty JSON object so Content-Type is set explicitly. */
    @Headers("Content-Type: application/json")
    @POST("ui/notifications/mark-all-read")
    suspend fun markAllRead(@Body body: Map<String, String> = emptyMap()): MarkReadResp

    /** Unread badge count. Idempotent GET. Wire field is "count". */
    @GET("ui/notifications/unread-count")
    suspend fun unreadCount(): UnreadCountResp
}
