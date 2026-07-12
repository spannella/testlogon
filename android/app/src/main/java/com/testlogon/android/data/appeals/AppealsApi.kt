package com.testlogon.android.data.appeals

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface + Moshi DTOs for the user-facing appeals feature.
 *
 * Mirrors the web /appeals page: list my appeals (GET v1/appeals, cursor-paged), submit a new appeal
 * (POST v1/appeals) and withdraw one still in flight (POST v1/appeals/{id}/withdraw). The admin
 * (/v1/admin/appeals) endpoints are deliberately omitted -- this is the member-facing surface only.
 * Session cookies / Bearer / X-CSRF-Token are attached by interceptors. The base URL carries the
 * trailing slash, so every path here is relative and WITHOUT a leading slash.
 */
interface AppealsApi {

    /** The signed-in member's appeals; [status] filters, [cursor] pages forward. */
    @GET("v1/appeals")
    suspend fun listMyAppeals(
        @Query("status") status: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): AppealListDto

    /** Files a new appeal against an enforcement action. */
    @POST("v1/appeals")
    suspend fun submitAppeal(@Body body: AppealCreateReqDto): AppealCreateRespDto

    /** Withdraws an appeal that is still submitted / under review. */
    @POST("v1/appeals/{id}/withdraw")
    suspend fun withdrawAppeal(@Path("id") id: String): AppealWithdrawRespDto
}

// ---- DTOs ----

@JsonClass(generateAdapter = true)
data class AppealListDto(
    val items: List<AppealDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class AppealDto(
    @Json(name = "appeal_id") val appealId: String,
    @Json(name = "enforcement_id") val enforcementId: String = "",
    @Json(name = "enforcement_type") val enforcementType: String? = null,
    @Json(name = "source_ticket_id") val sourceTicketId: String? = null,
    @Json(name = "appeal_text") val appealText: String = "",
    val status: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
    @Json(name = "decided_at") val decidedAt: Long? = null,
    @Json(name = "decision_note") val decisionNote: String? = null,
    @Json(name = "modified_enforcement_type") val modifiedEnforcementType: String? = null,
    @Json(name = "modified_duration_days") val modifiedDurationDays: Int? = null,
)

@JsonClass(generateAdapter = true)
data class AppealCreateReqDto(
    @Json(name = "enforcement_id") val enforcementId: String,
    @Json(name = "appeal_text") val appealText: String,
)

@JsonClass(generateAdapter = true)
data class AppealCreateRespDto(
    val ok: Boolean = false,
    @Json(name = "appeal_id") val appealId: String? = null,
    val status: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class AppealWithdrawRespDto(
    val ok: Boolean = false,
    @Json(name = "appeal_id") val appealId: String? = null,
    val status: String? = null,
)
