package com.testlogon.android.data.report

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.Headers
import retrofit2.http.POST

/**
 * AND-383 - Retrofit interface for the cross-cutting Trust and Safety moderation report endpoint that
 * backs USER and CONTENT reports (profile photo / feed post / comment / media). MESSAGE reports are NOT
 * routed here: they reuse AND-163's message-scoped endpoint via
 * [com.testlogon.android.data.messaging.report.ReportApi.reportMessage].
 *
 * Kept SEPARATE from the messaging ReportApi (and from the large MessagingApi) so the existing
 * hand-written fakes stay untouched, per the project gotchas. Provided on the SHARED Retrofit by
 * [ModerationReportApiModule] - no new OkHttp / Retrofit / dependency. The path is relative (no leading
 * slash) so it resolves against the shared base URL; cookies, Authorization and X-CSRF-Token are attached
 * project-wide by the core-network interceptor chain - this interface stays header-agnostic. The POST is
 * non-idempotent and is never auto-retried.
 *
 * Endpoint verified against the spec API contract (CORRECTED): there is NO /ui/report endpoint.
 *  - POST moderation/reports  req=CreateModerationReportIn -> 200:CreateModerationReportOut, 422:HTTPValidationError
 *    (op create_moderation_report_compat_moderation_reports_post; a /v1/moderation/reports alias shares the schema).
 *
 * The success status is 200 (NOT 201, NOT 409). `status` is one of "submitted" | "deduplicated";
 * "deduplicated" maps to the benign "already reported" confirmation (FR-8). `created_at` is an INTEGER epoch.
 */
interface ModerationReportApi {

    @Headers("Content-Type: application/json")
    @POST("moderation/reports")
    suspend fun reportModeration(
        @Body body: ModerationReportRequestDto,
    ): Response<ModerationReportResponseDto>
}

/**
 * AND-383 - POST body = CreateModerationReportIn. Required: `content_type`, `content_id`,
 * `topics` (1..5 wire codes), `reason_text` (5..2000 after trim). The remaining disambiguators are
 * optional and only set per kind: `profile_user_id` for a profile_photo (USER) report; `post_id` /
 * `comment_id` / `media_index` for feed (CONTENT) reports. Absent optionals are serialized as null.
 */
@JsonClass(generateAdapter = true)
data class ModerationReportRequestDto(
    @Json(name = "content_type") val contentType: String,
    @Json(name = "content_id") val contentId: String,
    @Json(name = "topics") val topics: List<String>,
    @Json(name = "reason_text") val reasonText: String,
    @Json(name = "post_id") val postId: String? = null,
    @Json(name = "comment_id") val commentId: String? = null,
    @Json(name = "media_index") val mediaIndex: Int? = null,
    @Json(name = "conversation_id") val conversationId: String? = null,
    @Json(name = "message_id") val messageId: String? = null,
    @Json(name = "profile_user_id") val profileUserId: String? = null,
)

/**
 * AND-383 - 200 response = CreateModerationReportOut. `status` is one of "submitted" | "deduplicated"
 * (the latter is the idempotent "already reported" case - NOT a 409). `created_at` is an INTEGER epoch.
 */
@JsonClass(generateAdapter = true)
data class ModerationReportResponseDto(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "report_id") val reportId: String,
    @Json(name = "ticket_id") val ticketId: String = "",
    @Json(name = "status") val status: String = "submitted",
    @Json(name = "created_at") val createdAt: Long = 0L,
)
