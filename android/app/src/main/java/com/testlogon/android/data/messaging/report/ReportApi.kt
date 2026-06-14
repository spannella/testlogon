package com.testlogon.android.data.messaging.report

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-163 — Retrofit interface for user-initiated abuse reporting of a message.
 *
 * Kept SEPARATE from [com.testlogon.android.data.messaging.MessagingApi] on purpose (per the project
 * gotchas) so the large MessagingApi + its hand-written test FakeApi stay untouched. Paths are relative
 * (no leading slash) so they resolve against the shared Retrofit base URL; cookies, Authorization and
 * `X-CSRF-Token` are attached by the core-network interceptor chain. The POST is non-idempotent and is
 * never auto-retried.
 *
 * Endpoint verified against reference/openapi.index.txt (line 360) + reference/openapi.pretty.json
 * (components.schemas.ReportMessageIn / ReportMessageOut) and the web client
 * (reference/src/api/endpoints/messaging.ts: reportMessage):
 *  - report  POST messaging/conversations/{conversation_id}/messages/{message_id}/report
 *            req=ReportMessageIn{reason_code(2..64), statement(5..2000)} -> 200:ReportMessageOut
 *            errors 401/403/404/422/429 -> MessageControlsErrorOut{detail, error_code?}
 *
 * There is NO conversation-level report endpoint and NO reasons-catalog endpoint in the OpenAPI; the
 * reason set is a compile-time constant (see [ReportReason]). The success status is 200 (NOT 201), the
 * status field is the const "submitted", and created_at is an INTEGER epoch.
 */
interface ReportApi {

    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{conversationId}/messages/{messageId}/report")
    suspend fun reportMessage(
        @Path("conversationId") conversationId: String,
        @Path("messageId") messageId: String,
        @Body body: ReportMessageRequestDto,
    ): ReportMessageResponseDto
}

/**
 * AND-163 — POST body = ReportMessageIn. Both fields REQUIRED: `reason_code` is a free string (2..64,
 * one of the [ReportReason] codes is sent verbatim) and `statement` is the reporter's note (5..2000).
 */
@JsonClass(generateAdapter = true)
data class ReportMessageRequestDto(
    @Json(name = "reason_code") val reasonCode: String,
    val statement: String,
)

/**
 * AND-163 — 200 response = ReportMessageOut. `status` is the const "submitted"; `created_at` is an
 * INTEGER epoch (seconds). There are no target_type/target_id fields.
 */
@JsonClass(generateAdapter = true)
data class ReportMessageResponseDto(
    val ok: Boolean = true,
    @Json(name = "report_id") val reportId: String,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "message_id") val messageId: String,
    @Json(name = "reason_code") val reasonCode: String,
    val status: String = "submitted",
    @Json(name = "created_at") val createdAt: Long = 0L,
)
