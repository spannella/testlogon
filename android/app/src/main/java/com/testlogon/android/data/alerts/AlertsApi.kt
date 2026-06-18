package com.testlogon.android.data.alerts

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Query

/**
 * Retrofit interface + Moshi DTOs for the alerts (system notifications) inbox.
 *
 * Endpoints verified against frontend/src/api/endpoints/alerts.ts + the AlertsResp/Alert/MarkReadReq
 * shapes in frontend/src/api/types.ts (the OpenAPI 200 bodies are untyped, so the frontend TS types
 * are authoritative). The inbox screen needs: list (GET ui/alerts, cursor-paged), per-item mark-read
 * (POST ui/alerts/mark_read), mark-all-read (POST ui/alerts/mark-all-read) and the unread count
 * (GET ui/alerts/unread-count). Session cookies / Bearer / X-CSRF-Token are attached by interceptors.
 */
interface AlertsApi {

    /** Alerts inbox page; [unreadOnly] limits to unread, [cursor] pages forward. */
    @GET("ui/alerts")
    suspend fun getAlerts(
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
        @Query("unread_only") unreadOnly: Boolean? = null,
    ): AlertsRespDto

    /** Marks the given alert ids read. */
    @POST("ui/alerts/mark_read")
    suspend fun markRead(@Body body: MarkReadReqDto): MarkReadRespDto

    /** Marks every alert read. */
    @POST("ui/alerts/mark-all-read")
    suspend fun markAllRead(): MarkAllReadRespDto

    /** Unread badge count. */
    @GET("ui/alerts/unread-count")
    suspend fun unreadCount(): UnreadCountDto
}

// ---- DTOs ----

@JsonClass(generateAdapter = true)
data class AlertsRespDto(
    val alerts: List<AlertDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class AlertDto(
    @Json(name = "alert_id") val alertId: String,
    val event: String? = null,
    val title: String? = null,
    val read: Boolean = false,
    @Json(name = "read_at") val readAt: Long? = null,
    val ts: Long? = null,
    val priority: String? = null,
    @Json(name = "action_url") val actionUrl: String? = null,
    val category: String? = null,
)

@JsonClass(generateAdapter = true)
data class MarkReadReqDto(
    @Json(name = "alert_ids") val alertIds: List<String>,
)

@JsonClass(generateAdapter = true)
data class MarkReadRespDto(
    val ok: Boolean = false,
    val updated: Int = 0,
)

@JsonClass(generateAdapter = true)
data class MarkAllReadRespDto(
    val ok: Boolean = false,
    val count: Int = 0,
    @Json(name = "marked_count") val markedCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class UnreadCountDto(
    val count: Int = 0,
    @Json(name = "unread_count") val unreadCount: Int = 0,
)
